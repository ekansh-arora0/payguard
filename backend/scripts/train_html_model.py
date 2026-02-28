import asyncio
import csv
import hashlib
import itertools
import os
import pickle
import time
from collections import Counter
from pathlib import Path

import httpx
import kagglehub
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader, Dataset


class URLHTMLDataset(Dataset):
    def __init__(self, data, tabular_data=None, url_maxlen=200, html_maxlen=4096):
        self.data = data
        self.tabular_data = tabular_data
        self.url_maxlen = url_maxlen
        self.html_maxlen = html_maxlen

    def __len__(self):
        return len(self.data)

    def _tokenize(self, text, maxlen):
        # Simple character-level tokenization
        tokens = [ord(c) % 256 for c in text[:maxlen]]
        # Pad or truncate to maxlen
        if len(tokens) < maxlen:
            tokens = tokens + [0] * (maxlen - len(tokens))
        else:
            tokens = tokens[:maxlen]
        return torch.tensor(tokens, dtype=torch.long)

    def __getitem__(self, idx):
        url, label, html = self.data[idx]
        url_tokens = self._tokenize(url, self.url_maxlen)
        html_tokens = self._tokenize(html, self.html_maxlen)
        label = torch.tensor(label, dtype=torch.long)

        if self.tabular_data is not None:
            tabular_features = torch.tensor(self.tabular_data[idx], dtype=torch.float)
            return url_tokens, html_tokens, tabular_features, label
        return url_tokens, html_tokens, label


DATASET_NAME = os.environ.get("PG_DATASET", "sid321axn/malicious-urls-dataset")

OUTPUT = Path(__file__).parent.parent / "models" / "best_html_rf.pkl"

LIMIT = int(os.environ.get("PG_TRAIN_LIMIT", "0"))

CONCURRENCY = int(os.environ.get("PG_CRAWL_CONCURRENCY", "100"))

TIMEOUT = float(os.environ.get("PG_CRAWL_TIMEOUT", "3.0"))

CACHE_DIR = Path(__file__).parent.parent / "cache" / "html"
CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _label_from_row(row):
    v = (
        (
            row.get("label")
            or row.get("Label")
            or row.get("type")
            or row.get("Type")
            or ""
        )
        .strip()
        .lower()
    )
    if v in ("good", "benign", "legit", "safe"):
        return 1
    if v in ("bad", "malicious", "phishing", "defacement", "spam"):
        return 0
    try:
        return 1 if int(v) == 1 else 0
    except Exception:
        return 0


def _url_from_row(row):
    return (
        row.get("url")
        or row.get("URL")
        or row.get("Urls")
        or row.get("uri")
        or row.get("link")
        or ""
    ).strip()


async def _fetch_html(client, url):
    try:
        if not url:
            return None
        h = hashlib.sha1(url.encode("utf-8")).hexdigest()
        fp = CACHE_DIR / f"{h}.html"
        if fp.exists():
            try:
                return fp.read_text(encoding="utf-8", errors="ignore")[:100000]
            except Exception:
                pass
        resp = await client.get(
            url, headers={"User-Agent": "PayGuard/Trainer/1.0"}, follow_redirects=True
        )
        if resp.status_code >= 500:
            return None
        txt = resp.text[:100000]
        try:
            fp.write_text(txt, encoding="utf-8", errors="ignore")
        except Exception:
            pass
        return txt
    except Exception:
        return None


class GatedHighway(nn.Module):
    def __init__(self, size):
        super().__init__()
        self.transform_gate = nn.Linear(size, size)
        self.transform = nn.Linear(size, size)
        self.relu = nn.ReLU()

    def forward(self, x):
        T = torch.sigmoid(self.transform_gate(x))
        H = self.relu(self.transform(x))
        return H * T + x * (1 - T)


class Attention(nn.Module):
    def __init__(self, feature_dim, step_dim, bias=True, **kwargs):
        super().__init__(**kwargs)
        self.supports_masking = True
        self.bias = bias
        self.feature_dim = feature_dim
        self.step_dim = step_dim
        self.features_alpha = nn.Parameter(torch.randn(feature_dim))
        self.context_vector = nn.Parameter(torch.randn(step_dim))
        if bias:
            self.bias_alpha = nn.Parameter(torch.zeros(step_dim))
        else:
            self.bias_alpha = None

    def forward(self, x, mask=None):
        eij = torch.matmul(x, self.features_alpha)
        if self.bias_alpha is not None:
            eij = eij + self.bias_alpha
        eij = torch.tanh(eij)
        a = torch.exp(eij)
        if mask is not None:
            a = a * mask
        a = a / torch.sum(a, 1, keepdim=True) + 1e-10
        weighted_input = x * torch.unsqueeze(a, -1)
        return torch.sum(weighted_input, 1)


class URLHTMLBiLSTM_GHAB_CNN(nn.Module):
    def __init__(
        self,
        vocab_size=256,
        embedding_dim=64,
        lstm_hidden_dim=128,
        num_classes=2,
        url_maxlen=200,
        html_maxlen=4096,
        tabular_feature_dim=0,
    ):
        super().__init__()
        self.url_maxlen = url_maxlen
        self.html_maxlen = html_maxlen
        self.tabular_feature_dim = tabular_feature_dim

        # URL processing (BiLSTM)
        self.url_embedding = nn.Embedding(vocab_size, embedding_dim)
        self.url_bilstm = nn.LSTM(
            embedding_dim, lstm_hidden_dim, bidirectional=True, batch_first=True
        )
        self.url_attention = Attention(lstm_hidden_dim * 2, url_maxlen)
        self.url_highway = GatedHighway(lstm_hidden_dim * 2)

        # HTML processing (CNN)
        self.html_embedding = nn.Embedding(vocab_size, embedding_dim)
        self.html_conv1 = nn.Conv1d(embedding_dim, 128, kernel_size=7, padding=3)
        self.html_bn1 = nn.BatchNorm1d(128)
        self.html_conv2 = nn.Conv1d(128, 128, kernel_size=7, padding=3)
        self.html_bn2 = nn.BatchNorm1d(128)
        self.html_pool = nn.AdaptiveMaxPool1d(1)
        self.html_highway = GatedHighway(128)

        # Tabular processing
        if self.tabular_feature_dim > 0:
            self.tabular_fc = nn.Linear(
                self.tabular_feature_dim, 64
            )  # Simple FC layer for tabular features
            self.tabular_bn = nn.BatchNorm1d(64)

        # Combined processing
        self.dropout = nn.Dropout(p=float(os.environ.get("PG_CNN_DROPOUT", "0.2")))

        # Calculate input dimension for the combined fully connected layer
        combined_fc_input_dim = lstm_hidden_dim * 2 + 128
        if self.tabular_feature_dim > 0:
            combined_fc_input_dim += 64  # Add dimension from tabular_fc output

        self.fc_combined = nn.Linear(combined_fc_input_dim, num_classes)

    def forward(self, url_input, html_input, tabular_input=None):
        # URL branch
        url_embedded = self.url_embedding(url_input)
        url_lstm_out, _ = self.url_bilstm(url_embedded)
        url_att_out = self.url_attention(url_lstm_out)
        url_features = self.url_highway(url_att_out)

        # HTML branch
        html_embedded = self.html_embedding(html_input)
        html_embedded = html_embedded.transpose(1, 2)
        html_conv_out = F.relu(self.html_bn1(self.html_conv1(html_embedded)))
        html_conv_out = F.relu(self.html_bn2(self.html_conv2(html_conv_out)))
        html_pool_out = self.html_pool(html_conv_out).squeeze(-1)
        html_features = self.html_highway(html_pool_out)

        # Tabular branch
        if self.tabular_feature_dim > 0 and tabular_input is not None:
            tabular_features = F.relu(self.tabular_bn(self.tabular_fc(tabular_input)))
            combined_features = torch.cat(
                (url_features, html_features, tabular_features), dim=1
            )
        else:
            combined_features = torch.cat((url_features, html_features), dim=1)

        combined_features = self.dropout(combined_features)
        return self.fc_combined(combined_features)


def _parse_list(env_var, type_func):
    val = os.environ.get(env_var)
    if val:
        try:
            return [type_func(x.strip()) for x in val.split(",")]
        except ValueError:
            print(
                f"Warning: Could not parse {env_var} as a list of {type_func.__name__}. Using default."
            )
    return None


async def main():
    # Device configuration
    if torch.backends.mps.is_available() and torch.backends.mps.is_built():
        device = torch.device("mps")
        print("Using MPS device.")
    else:
        device = torch.device("cpu")
        print("MPS device not found, using CPU.")
    rows = []
    print("Starting data loading...")
    von_data = None
    try:
        with open("/Users/ekans/payguard/combined_dataset_all.pkl", "rb") as f:
            von_data = pickle.load(f)
        print("Loaded combined_dataset_all.pkl")
    except FileNotFoundError:
        print("combined_dataset_all.pkl not found. Proceeding without Von dataset.")
    except Exception as e:
        print(f"Error loading combined_dataset_all.pkl: {e}")

    try:
        try:
            import kagglehub

            print(f"Attempting to download dataset from Kaggle: {DATASET_NAME}")
            path = kagglehub.dataset_download(DATASET_NAME)
            print(f"Dataset downloaded to: {path}")

            base = Path(path)
            cands = list(base.glob("**/*.csv")) + list(base.glob("**/*.txt"))
            for f in cands:
                with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                    sniffer = csv.Sniffer()
                    sample = fh.read(4096)
                    fh.seek(0)
                    dialect = sniffer.sniff(sample) if sample else csv.excel
                    reader = csv.DictReader(fh, dialect=dialect)
                    for r in reader:
                        rows.append(r)
                        if LIMIT and len(rows) >= LIMIT:
                            break
                if LIMIT and len(rows) >= LIMIT:
                    break

            # Download and process the new Kaggle dataset
            print(
                "Attempting to download additional dataset from Kaggle: taruntiwarihp/phishing-site-urls"
            )
            new_path = kagglehub.dataset_download("taruntiwarihp/phishing-site-urls")
            print(f"Additional dataset downloaded to: {new_path}")

            new_base = Path(new_path)
            new_cands = list(new_base.glob("**/*.csv")) + list(
                new_base.glob("**/*.txt")
            )
            for f in new_cands:
                with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                    sniffer = csv.Sniffer()
                    sample = fh.read(4096)
                    fh.seek(0)
                    dialect = sniffer.sniff(sample) if sample else csv.excel
                    reader = csv.DictReader(fh, dialect=dialect)
                    for r in reader:
                        rows.append(r)
                        if LIMIT and len(rows) >= LIMIT:
                            break
                if LIMIT and len(rows) >= LIMIT:
                    break

        except Exception:
            local = os.environ.get("PG_DATASET_PATH")
            if not local:
                print(
                    "PG_DATASET_PATH not set and kagglehub unavailable, skipping Kaggle data."
                )
            else:
                try:
                    print(f"Attempting to load dataset from local path: {local}")
                    with open(local, "r", encoding="utf-8", errors="ignore") as fh:
                        reader = csv.DictReader(fh)
                        for r in reader:
                            rows.append(r)
                            if LIMIT and len(rows) >= LIMIT:
                                break
                    print(f"Loaded {len(rows)} rows from PG_DATASET_PATH.")
                except Exception as e:
                    print(f"Error loading PG_DATASET_PATH: {e}")
    except Exception as e:
        print(
            f"An unexpected error occurred during Kaggle/PG_DATASET_PATH loading: {e}"
        )

    local_dataset_path = os.environ.get("PG_LOCAL_DATASET_PATH")
    if local_dataset_path:
        try:
            print(f"Attempting to load dataset from local path: {local_dataset_path}")
            with open(local_dataset_path, "r", encoding="utf-8", errors="ignore") as fh:
                reader = csv.DictReader(fh)
                for r in reader:
                    rows.append(r)
                    if LIMIT and len(rows) >= LIMIT:
                        break
            print(f"Loaded {len(rows)} rows from PG_LOCAL_DATASET_PATH.")
        except Exception as e:
            print(f"Error loading PG_LOCAL_DATASET_PATH: {e}")

    if not rows:
        raise RuntimeError("No data loaded from any source.")
    print(f"Total rows loaded: {len(rows)}")

    von_tabular_features = None
    von_tabular_labels = None
    if von_data and "von_train_x" in von_data and "von_train_y" in von_data:
        # Assuming von_train_x is a pandas DataFrame and von_train_y is a pandas Series
        von_tabular_features = von_data["von_train_x"]
        von_tabular_labels = von_data["von_train_y"]
        print(
            f"Loaded Von tabular data with {von_tabular_features.shape[0]} samples and {von_tabular_features.shape[1]} features."
        )

    kaggle_pairs = []
    for r in rows:
        u = _url_from_row(r)
        y = _label_from_row(r)
        if u:
            kaggle_pairs.append((u, y))
        if LIMIT and len(kaggle_pairs) >= LIMIT:
            break
    print(f"Prepared {len(kaggle_pairs)} URL-label pairs from Kaggle data.")

    pairs = []
    if von_tabular_features is not None and von_tabular_labels is not None:
        min_len = min(len(kaggle_pairs), len(von_tabular_features))
        print(
            f"Aligning Von tabular features with Kaggle URL-label pairs. Using {min_len} samples."
        )
        for i in range(min_len):
            pairs.append(
                (kaggle_pairs[i][0], kaggle_pairs[i][1], von_tabular_features[i])
            )
        von_tabular_features = von_tabular_features[
            :min_len
        ]  # Truncate von_tabular_features if it was larger
    else:
        pairs = kaggle_pairs
        von_tabular_features = None  # Ensure it's None if not used

    print(
        f"Final prepared {len(pairs)} URL-label pairs (with/without tabular features) for fetching."
    )

    tabular_feature_dim = (
        von_tabular_features.shape[1] if von_tabular_features is not None else 0
    )

    sem = asyncio.Semaphore(CONCURRENCY)
    prefetch = True  # os.environ.get("PG_PREFETCH", "0") == "1"
    results = []
    if prefetch:
        print(
            f"Starting HTML fetching for {len(pairs)} URLs with concurrency {CONCURRENCY} and timeout {TIMEOUT}s..."
        )
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:

            async def worker(u, y, tabular_f=None):
                async with sem:
                    h = await _fetch_html(client, u)
                    if h:
                        return (
                            (u, y, h, tabular_f) if tabular_f is not None else (u, y, h)
                        )
                    return None

            if von_tabular_features is not None:
                # If tabular features are present, pairs already contain them
                tasks = [worker(p[0], p[1], p[2]) for p in pairs]
            else:
                tasks = [worker(u, y) for u, y in pairs]
            results = await asyncio.gather(*tasks)
        print("HTML fetching complete.")
    # Filter out None results
    initial_results_count = len(results)
    results = [r for r in results if r is not None]
    print(
        f"Successfully fetched HTML for {len(results)} out of {initial_results_count} URLs."
    )

    # Prepare data for URLHTMLBiLSTM_GHAB_CNN model
    if not results:
        raise RuntimeError("No data available for URLHTMLBiLSTM_GHAB_CNN training.")

    if von_tabular_features is not None:
        urls, labels, htmls, tabular_features = zip(*results)
        tabular_features = list(tabular_features)
    else:
        urls, labels, htmls = zip(*results)
        tabular_features = None

    urls = list(urls)
    labels = list(labels)
    htmls = list(htmls)
    print(f"Data prepared for model training: {len(urls)} samples.")

    # Split data for the new model
    if tabular_features is not None:
        url_tr, url_te, html_tr, html_te, tabular_tr, tabular_te, y_tr, y_te = (
            train_test_split(
                urls,
                htmls,
                tabular_features,
                labels,
                test_size=0.2,
                random_state=42,
                stratify=labels,
            )
        )
        url_tr, url_val, html_tr, html_val, tabular_tr, tabular_val, y_tr, y_val = (
            train_test_split(
                url_tr,
                html_tr,
                tabular_tr,
                y_tr,
                test_size=0.2,
                random_state=42,
                stratify=y_tr,
            )
        )
    else:
        url_tr, url_te, html_tr, html_te, y_tr, y_te = train_test_split(
            urls, htmls, labels, test_size=0.2, random_state=42, stratify=labels
        )
        url_tr, url_val, html_tr, html_val, y_tr, y_val = train_test_split(
            url_tr, html_tr, y_tr, test_size=0.2, random_state=42, stratify=y_tr
        )

    # Create datasets and dataloaders for the new model
    if tabular_features is not None:
        ds_tr_bilstm = URLHTMLDataset(
            list(zip(url_tr, y_tr, html_tr)), tabular_data=tabular_tr
        )
        ds_val_bilstm = URLHTMLDataset(
            list(zip(url_val, y_val, html_val)), tabular_data=tabular_val
        )
        ds_te_bilstm = URLHTMLDataset(
            list(zip(url_te, y_te, html_te)), tabular_data=tabular_te
        )
    else:
        ds_tr_bilstm = URLHTMLDataset(list(zip(url_tr, y_tr, html_tr)))
        ds_val_bilstm = URLHTMLDataset(list(zip(url_val, y_val, html_val)))
        ds_te_bilstm = URLHTMLDataset(list(zip(url_te, y_te, html_te)))

    batch_size = int(os.environ.get("PG_BATCH_SIZE", "32"))
    dl_tr_bilstm = DataLoader(ds_tr_bilstm, batch_size=batch_size, shuffle=True)
    dl_val_bilstm = DataLoader(ds_val_bilstm, batch_size=batch_size)
    dl_te_bilstm = DataLoader(ds_te_bilstm, batch_size=batch_size)

    # Determine tabular feature dimension
    tabular_feature_dim = 0
    if tabular_features is not None and len(tabular_features) > 0:
        tabular_feature_dim = tabular_features[0].shape[0]

    # Hyperparameters for the new model
    epochs_list_bilstm = _parse_list("PG_BILSTM_EPOCHS_LIST", int) or [
        int(os.environ.get("PG_BILSTM_EPOCHS", "7"))
    ]
    dropout_list_bilstm = _parse_list("PG_BILSTM_DROPOUT_LIST", float) or [
        float(os.environ.get("PG_BILSTM_DROPOUT", "0.2"))
    ]
    lr_list_bilstm = _parse_list("PG_BILSTM_LR_LIST", float) or [
        float(os.environ.get("PG_BILSTM_LR", "1e-3"))
    ]
    patience_bilstm = int(os.environ.get("PG_BILSTM_PATIENCE", "3"))

    # Class weights for the new model
    cw_bilstm = Counter(y_tr)
    total_bilstm = sum(cw_bilstm.values())
    w0_bilstm = total_bilstm / (2.0 * cw_bilstm.get(0, 1))
    w1_bilstm = total_bilstm / (2.0 * cw_bilstm.get(1, 1))
    class_w_bilstm = torch.tensor([w0_bilstm, w1_bilstm], dtype=torch.float).to(device)

    best_val_acc_bilstm = 0.0
    best_cfg_bilstm = None
    best_model_bilstm = None

    for epochs, dropout, lr in itertools.product(
        epochs_list_bilstm, dropout_list_bilstm, lr_list_bilstm
    ):
        print(
            f"\nStarting training for config: Epochs={epochs}, Dropout={dropout}, LR={lr}"
        )
        config_start_time = time.time()
        model_bilstm_current = URLHTMLBiLSTM_GHAB_CNN(
            tabular_feature_dim=tabular_feature_dim
        ).to(device)
        model_bilstm_current.dropout.p = float(dropout)
        opt_bilstm = torch.optim.Adam(model_bilstm_current.parameters(), lr=lr)
        crit_bilstm = nn.CrossEntropyLoss(weight=class_w_bilstm)
        model_bilstm_current.train()
        no_improve_bilstm = 0
        for ep in range(epochs):
            epoch_start_time = time.time()
            print(f"Epoch {ep+1}/{epochs}")
            for i, batch_data in enumerate(dl_tr_bilstm):
                print(f"  Batch {i}/{len(dl_tr_bilstm)}")
                opt_bilstm.zero_grad()
                if tabular_feature_dim > 0:
                    url_b, html_b, tabular_b, y_b = batch_data
                    url_b, html_b, tabular_b, y_b = (
                        url_b.to(device),
                        html_b.to(device),
                        tabular_b.to(device),
                        y_b.to(device),
                    )
                    out_bilstm = model_bilstm_current(url_b, html_b, tabular_b)
                else:
                    url_b, html_b, y_b = batch_data
                    url_b, html_b, y_b = (
                        url_b.to(device),
                        html_b.to(device),
                        y_b.to(device),
                    )
                    out_bilstm = model_bilstm_current(url_b, html_b)
                loss_bilstm = crit_bilstm(out_bilstm, y_b)
                loss_bilstm.backward()
                opt_bilstm.step()

                current_time = time.time()
                elapsed_time = current_time - epoch_start_time
                remaining_epochs = epochs - (ep + 1)
                estimated_remaining_time = elapsed_time * remaining_epochs
                print(
                    f"  Elapsed: {elapsed_time:.2f}s, Estimated total remaining: {estimated_remaining_time:.2f}s"
                )

            # Validate
            model_bilstm_current.eval()
            vtotal_bilstm, vcorrect_bilstm = 0, 0
            with torch.no_grad():
                for batch_data in dl_val_bilstm:
                    if tabular_feature_dim > 0:
                        url_v, html_v, tabular_v, y_v = batch_data
                        url_v, html_v, tabular_v, y_v = (
                            url_v.to(device),
                            html_v.to(device),
                            tabular_v.to(device),
                            y_v.to(device),
                        )
                        ov_bilstm = model_bilstm_current(url_v, html_v, tabular_v)
                    else:
                        url_v, html_v, y_v = batch_data
                        url_v, html_v, y_v = (
                            url_v.to(device),
                            html_v.to(device),
                            y_v.to(device),
                        )
                        ov_bilstm = model_bilstm_current(url_v, html_v)
                    pv_bilstm = ov_bilstm.argmax(dim=1)
                    vcorrect_bilstm += (pv_bilstm == y_v).sum().item()
                    vtotal_bilstm += y_v.size(0)
            val_acc_bilstm = vcorrect_bilstm / vtotal_bilstm if vtotal_bilstm else 0.0
            print(
                f"BiLSTM-GHAB-CNN VAL acc ep {ep+1}/{epochs} lr={lr} drop={dropout}: {val_acc_bilstm:.4f}"
            )
            if val_acc_bilstm > best_val_acc_bilstm:
                best_val_acc_bilstm = val_acc_bilstm
                best_cfg_bilstm = (epochs, dropout, lr)
                best_model_bilstm = URLHTMLBiLSTM_GHAB_CNN(
                    tabular_feature_dim=tabular_feature_dim
                ).to(device)
                best_model_bilstm.load_state_dict(model_bilstm_current.state_dict())
                no_improve_bilstm = 0
            else:
                no_improve_bilstm += 1
                if no_improve_bilstm >= patience_bilstm:
                    print("BiLSTM-GHAB-CNN Early stopping")
                    break
            model_bilstm_current.train()

    # Test best BiLSTM-GHAB-CNN model
    if best_model_bilstm is None:
        best_model_bilstm = model_bilstm_current
        best_cfg_bilstm = (
            epochs_list_bilstm[0],
            dropout_list_bilstm[0],
            lr_list_bilstm[0],
        )
    print(
        f"\nEvaluating best model with config: Epochs={best_cfg_bilstm[0]}, Dropout={best_cfg_bilstm[1]}, LR={best_cfg_bilstm[2]}"
    )
    best_model_bilstm.eval()
    total_bilstm, correct_bilstm = 0, 0
    all_pred_bilstm, all_true_bilstm = [], []
    with torch.no_grad():
        for batch_data in dl_te_bilstm:
            if tabular_feature_dim > 0:
                url_b, html_b, tabular_b, y_b = batch_data
                url_b, html_b, tabular_b, y_b = (
                    url_b.to(device),
                    html_b.to(device),
                    tabular_b.to(device),
                    y_b.to(device),
                )
                out_bilstm = best_model_bilstm(url_b, html_b, tabular_b)
            else:
                url_b, html_b, y_b = batch_data
                url_b, html_b, y_b = url_b.to(device), html_b.to(device), y_b.to(device)
                out_bilstm = best_model_bilstm(url_b, html_b)
            pred_bilstm = out_bilstm.argmax(dim=1)
            all_pred_bilstm.extend(pred_bilstm.cpu().numpy().tolist())
            all_true_bilstm.extend(y_b.cpu().numpy().tolist())
            correct_bilstm += (pred_bilstm == y_b).sum().item()
            total_bilstm += y_b.size(0)

    print(
        f"BiLSTM-GHAB-CNN best cfg epochs={best_cfg_bilstm[0]} dropout={best_cfg_bilstm[1]} lr={best_cfg_bilstm[2]}"
    )
    print(confusion_matrix(all_true_bilstm, all_pred_bilstm))
    print(classification_report(all_true_bilstm, all_pred_bilstm, digits=4))
    ts_path_bilstm = (
        Path(__file__).parent.parent / "models" / "best_url_html_bilstm_ghab_cnn.pt"
    )
    ts_path_bilstm.parent.mkdir(parents=True, exist_ok=True)
    if tabular_feature_dim > 0:
        traced_bilstm = torch.jit.trace(
            best_model_bilstm,
            (
                torch.randint(0, 256, (1, 200), dtype=torch.long, device=device),
                torch.randint(0, 256, (1, 4096), dtype=torch.long, device=device),
                torch.randn(1, tabular_feature_dim, device=device),
            ),
        )
    else:
        traced_bilstm = torch.jit.trace(
            best_model_bilstm,
            (
                torch.randint(0, 256, (1, 200), dtype=torch.long, device=device),
                torch.randint(0, 256, (1, 4096), dtype=torch.long, device=device),
            ),
        )
    traced_bilstm.save(str(ts_path_bilstm))
    print(f"Model saved to: {ts_path_bilstm}")


if __name__ == "__main__":
    asyncio.run(main())
