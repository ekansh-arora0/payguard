#!/usr/bin/env python3
"""
PayGuard ML Model Training Pipeline
====================================
Trains all ML models for the PayGuard risk engine:
  1. XGBoost URL phishing classifier (enhanced 30+ features)
  2. HTML Random Forest classifier
  3. HTML CNN (character-level)
  4. DistilBERT text phishing classifier (fine-tuned)

Usage:
    python3 scripts/train_all_models.py

Datasets downloaded automatically from Kaggle via kagglehub.
Models saved to /models/ directory.
"""

import os
import re
import sys
import time
import hashlib
import asyncio
import csv
from pathlib import Path
from urllib.parse import urlparse
from collections import Counter

import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.preprocessing import StandardScaler
import xgboost as xgb

# PyTorch
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader

ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)
BACKEND_MODELS_DIR = ROOT / "backend" / "models"
BACKEND_MODELS_DIR.mkdir(parents=True, exist_ok=True)

# Device selection
if torch.backends.mps.is_available() and torch.backends.mps.is_built():
    DEVICE = torch.device("mps")
    print("[INFO] Using Apple MPS device")
elif torch.cuda.is_available():
    DEVICE = torch.device("cuda")
    print("[INFO] Using CUDA device")
else:
    DEVICE = torch.device("cpu")
    print("[INFO] Using CPU device")


# ============================================================
# SECTION 1: Data Loading
# ============================================================

def load_datasets():
    """Load and merge phishing URL datasets from Kaggle."""
    import kagglehub

    print("\n" + "=" * 60)
    print("LOADING DATASETS")
    print("=" * 60)

    # Dataset 1: malicious-urls-dataset (651K URLs, 4 categories)
    path1 = kagglehub.dataset_download("sid321axn/malicious-urls-dataset")
    df1 = pd.read_csv(Path(path1) / "malicious_phish.csv")
    # Map: benign=0 (safe), phishing/defacement/malware=1 (dangerous)
    df1["label"] = df1["type"].map(
        {"benign": 0, "phishing": 1, "defacement": 1, "malware": 1}
    )
    df1 = df1.rename(columns={"url": "url"})[["url", "label"]].dropna()
    print(f"  Dataset 1: {len(df1)} URLs ({df1['label'].value_counts().to_dict()})")

    # Dataset 2: phishing-site-urls (549K URLs, binary)
    path2 = kagglehub.dataset_download("taruntiwarihp/phishing-site-urls")
    df2 = pd.read_csv(Path(path2) / "phishing_site_urls.csv")
    df2["label"] = df2["Label"].map({"good": 0, "bad": 1})
    df2 = df2.rename(columns={"URL": "url"})[["url", "label"]].dropna()
    print(f"  Dataset 2: {len(df2)} URLs ({df2['label'].value_counts().to_dict()})")

    df = pd.concat([df1, df2], ignore_index=True).drop_duplicates(subset="url")
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"  Combined:  {len(df)} unique URLs ({df['label'].value_counts().to_dict()})")
    return df


# ============================================================
# SECTION 2: Feature Engineering (Enhanced)
# ============================================================

# Top-level domains commonly abused
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".work", ".buzz", ".rest", ".fit", ".bid", ".click", ".link",
    ".stream", ".download", ".win", ".racing", ".review", ".date",
    ".accountant", ".science", ".party", ".cricket", ".faith",
}

BRAND_KEYWORDS = {
    "paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "bank", "chase", "wellsfargo",
    "citibank", "hsbc", "barclays", "linkedin", "dropbox", "icloud",
    "outlook", "yahoo", "ebay", "coinbase", "binance", "metamask",
}

SUSPICIOUS_URL_WORDS = {
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "password", "credential", "authenticate", "suspend",
    "limited", "unlock", "restore", "wallet", "billing", "invoice",
}


def extract_url_features(url: str) -> dict:
    """Extract 30+ features from a URL for phishing detection."""
    u = url.lower().strip()
    if not u.startswith(("http://", "https://", "ftp://")):
        u_parsed = urlparse("http://" + u)
    else:
        u_parsed = urlparse(u)

    hostname = u_parsed.hostname or ""
    path = u_parsed.path or ""
    query = u_parsed.query or ""
    fragment = u_parsed.fragment or ""

    # Length features
    url_length = len(url)
    hostname_length = len(hostname)
    path_length = len(path)
    query_length = len(query)

    # Count features
    dot_count = url.count(".")
    slash_count = url.count("/")
    hyphen_count = url.count("-")
    underscore_count = url.count("_")
    at_count = url.count("@")
    question_count = url.count("?")
    equals_count = url.count("=")
    ampersand_count = url.count("&")
    tilde_count = url.count("~")
    percent_count = url.count("%")

    # Special characters in hostname
    hostname_dots = hostname.count(".")
    hostname_hyphens = hostname.count("-")

    # Digit ratio
    digit_count = sum(c.isdigit() for c in url)
    letter_count = sum(c.isalpha() for c in url)
    digit_ratio = digit_count / max(len(url), 1)
    digit_in_hostname = sum(c.isdigit() for c in hostname) / max(len(hostname), 1)

    # Protocol
    is_https = int(url.lower().startswith("https://"))

    # IP address as hostname
    is_ip = int(bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname)))

    # Port in URL
    has_port = int(u_parsed.port is not None and u_parsed.port not in (80, 443))

    # Subdomain depth
    subdomain_count = max(0, hostname_dots - 1) if hostname else 0

    # TLD check
    tld = ""
    if "." in hostname:
        tld = "." + hostname.rsplit(".", 1)[-1]
    suspicious_tld = int(tld in SUSPICIOUS_TLDS)

    # Path features
    path_depth = path.count("/") - 1 if path else 0
    double_slash_in_path = int("//" in path[1:]) if len(path) > 1 else 0

    # Shortening service patterns
    shorteners = {"bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly"}
    is_shortened = int(hostname in shorteners)

    # Keyword features
    has_login = int(any(w in u for w in ["login", "signin", "log-in", "sign-in"]))
    has_secure = int("secure" in u)
    has_account = int("account" in u)
    has_verify = int(any(w in u for w in ["verify", "confirm", "validate"]))
    has_update = int("update" in u)
    has_suspend = int(any(w in u for w in ["suspend", "locked", "limited", "restrict"]))
    has_banking = int(any(w in u for w in ["bank", "paypal", "wallet", "billing"]))

    # Brand impersonation (brand in subdomain or path, not as actual domain)
    brand_in_url = 0
    for brand in BRAND_KEYWORDS:
        if brand in u:
            # Check if brand is NOT the actual domain (potential impersonation)
            parts = hostname.split(".")
            actual_domain = parts[-2] if len(parts) >= 2 else hostname
            if brand != actual_domain and brand in hostname:
                brand_in_url = 1
                break

    # Entropy of URL (high entropy = random/obfuscated)
    if url:
        freq = Counter(url)
        probs = [c / len(url) for c in freq.values()]
        entropy = -sum(p * np.log2(p) for p in probs if p > 0)
    else:
        entropy = 0.0

    # Suspicious word count in URL
    suspicious_word_count = sum(1 for w in SUSPICIOUS_URL_WORDS if w in u)

    return {
        # Original 12 features (for backwards compatibility check)
        "url_length": url_length,
        "dot_count": dot_count,
        "slash_count": slash_count,
        "hyphen_count": hyphen_count,
        "underscore_count": underscore_count,
        "question_count": question_count,
        "equals_count": equals_count,
        "ampersand_count": ampersand_count,
        "has_login": has_login,
        "has_secure": has_secure,
        "has_account": has_account,
        "has_verify": has_verify,
        # New enhanced features
        "hostname_length": hostname_length,
        "path_length": path_length,
        "query_length": query_length,
        "at_count": at_count,
        "tilde_count": tilde_count,
        "percent_count": percent_count,
        "hostname_dots": hostname_dots,
        "hostname_hyphens": hostname_hyphens,
        "digit_ratio": digit_ratio,
        "digit_in_hostname": digit_in_hostname,
        "is_https": is_https,
        "is_ip": is_ip,
        "has_port": has_port,
        "subdomain_count": subdomain_count,
        "suspicious_tld": suspicious_tld,
        "path_depth": path_depth,
        "double_slash_in_path": double_slash_in_path,
        "is_shortened": is_shortened,
        "has_update": has_update,
        "has_suspend": has_suspend,
        "has_banking": has_banking,
        "brand_in_url": brand_in_url,
        "entropy": entropy,
        "suspicious_word_count": suspicious_word_count,
    }


def extract_features_batch(urls: pd.Series) -> pd.DataFrame:
    """Extract features for a batch of URLs."""
    features = []
    for url in urls:
        try:
            features.append(extract_url_features(str(url)))
        except Exception:
            features.append(extract_url_features("http://error.invalid"))
    return pd.DataFrame(features)


# ============================================================
# SECTION 3: XGBoost URL Phishing Model
# ============================================================

def train_xgboost(df: pd.DataFrame):
    """Train an enhanced XGBoost phishing URL classifier."""
    print("\n" + "=" * 60)
    print("TRAINING XGBOOST URL CLASSIFIER (36 features)")
    print("=" * 60)

    t0 = time.time()

    # Extract features
    print("  Extracting features...")
    X = extract_features_batch(df["url"])
    y = df["label"].values
    feature_names = list(X.columns)
    print(f"  Features: {len(feature_names)}")
    print(f"  Samples:  {len(y)} (safe={sum(y==0)}, dangerous={sum(y==1)})")

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train, y_train, test_size=0.1, random_state=42, stratify=y_train
    )

    # Scale
    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_val_sc = scaler.transform(X_val)
    X_test_sc = scaler.transform(X_test)

    # Class weight for imbalanced data
    neg_count = sum(y_train == 0)
    pos_count = sum(y_train == 1)
    scale_pos = neg_count / max(pos_count, 1)

    print(f"  Scale pos weight: {scale_pos:.2f}")
    print("  Training XGBoost...")

    dtrain = xgb.DMatrix(X_train_sc, label=y_train, feature_names=feature_names)
    dval = xgb.DMatrix(X_val_sc, label=y_val, feature_names=feature_names)
    dtest = xgb.DMatrix(X_test_sc, label=y_test, feature_names=feature_names)

    params = {
        "objective": "binary:logistic",
        "eval_metric": ["logloss", "auc"],
        "max_depth": 8,
        "learning_rate": 0.05,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "min_child_weight": 5,
        "gamma": 0.1,
        "reg_alpha": 0.1,
        "reg_lambda": 1.0,
        "scale_pos_weight": scale_pos,
        "tree_method": "hist",
        "seed": 42,
    }

    model = xgb.train(
        params,
        dtrain,
        num_boost_round=500,
        evals=[(dtrain, "train"), (dval, "val")],
        early_stopping_rounds=30,
        verbose_eval=50,
    )

    # Evaluate
    y_pred_proba = model.predict(dtest)
    y_pred = (y_pred_proba > 0.5).astype(int)
    auc = roc_auc_score(y_test, y_pred_proba)

    print(f"\n  TEST RESULTS:")
    print(f"  AUC: {auc:.4f}")
    print(classification_report(y_test, y_pred, target_names=["safe", "phishing"], digits=4))
    print(confusion_matrix(y_test, y_pred))

    # Save — compatible with risk_engine.py loader
    model_path = MODELS_DIR / "best_excel_xgb.json"
    scaler_path = MODELS_DIR / "best_excel_xgb_scaler.pkl"
    model.save_model(str(model_path))
    joblib.dump(scaler, scaler_path)

    # Also save as .pkl for legacy compatibility
    joblib.dump({"model": model, "scaler": scaler}, MODELS_DIR / "best_excel_xgb.pkl")

    elapsed = time.time() - t0
    print(f"\n  Saved: {model_path} ({model_path.stat().st_size / 1024:.0f} KB)")
    print(f"  Saved: {scaler_path}")
    print(f"  XGBoost training took {elapsed:.1f}s")

    return model, scaler, feature_names


# ============================================================
# SECTION 4: We need to update risk_engine._url_features to
#            match the new 36-feature set. Save feature names.
# ============================================================

def save_feature_names(feature_names):
    """Save feature names so risk_engine can reference them."""
    import json
    path = MODELS_DIR / "url_feature_names.json"
    with open(path, "w") as f:
        json.dump(feature_names, f, indent=2)
    print(f"  Saved feature names: {path}")


# ============================================================
# SECTION 5: HTML Random Forest (uses crawled HTML)
# ============================================================

def extract_html_features(html: str) -> list:
    """Extract features from HTML content — matches risk_engine._html_features."""
    cl = html.lower()
    scripts = re.findall(r"<script[^>]*>", html, flags=re.I)
    ext_scripts = re.findall(r'<script[^>]*src=["\'][^"\']+["\']', html, flags=re.I)
    inline_scripts = len(scripts) - len(ext_scripts)
    iframes = html.count("<iframe")
    anchors = html.count("<a")
    events = len(re.findall(r'\son[a-z]+\s*=\s*["\'][^"\']+["\']', html, flags=re.I))
    mailto = len(re.findall(r'href\s*=\s*["\']mailto:', html, flags=re.I))
    return [
        len(html),
        html.count("<"),
        int("<form" in cl),
        int("<input" in cl),
        int("<script" in cl),
        html.count("!"),
        int("login" in cl),
        int("password" in cl),
        int("verify" in cl),
        int("secure" in cl),
        html.count("href"),
        html.count("<img"),
        iframes,
        anchors,
        len(ext_scripts),
        inline_scripts,
        events,
        mailto,
    ]


CACHE_DIR = ROOT / "backend" / "cache" / "html"


async def fetch_html_batch(urls, labels, max_urls=20000, concurrency=150, timeout=4.0):
    """Fetch HTML content for URLs (with caching)."""
    import httpx

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    sem = asyncio.Semaphore(concurrency)
    results = []
    fetched = 0
    cached = 0
    failed = 0

    async def worker(url, label):
        nonlocal fetched, cached, failed
        h = hashlib.sha1(url.encode("utf-8")).hexdigest()
        fp = CACHE_DIR / f"{h}.html"

        # Check cache first
        if fp.exists():
            try:
                html = fp.read_text(encoding="utf-8", errors="ignore")[:100000]
                if len(html) > 100:
                    cached += 1
                    return (url, label, html)
            except Exception:
                pass

        async with sem:
            try:
                async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                    resp = await client.get(
                        url if url.startswith("http") else f"http://{url}",
                        headers={"User-Agent": "Mozilla/5.0 PayGuard/Trainer"},
                    )
                    if resp.status_code < 400:
                        html = resp.text[:100000]
                        if len(html) > 100:
                            try:
                                fp.write_text(html, encoding="utf-8", errors="ignore")
                            except Exception:
                                pass
                            fetched += 1
                            return (url, label, html)
            except Exception:
                pass
            failed += 1
            return None

    # Sample URLs for crawling (balanced)
    safe_urls = [(u, l) for u, l in zip(urls, labels) if l == 0]
    bad_urls = [(u, l) for u, l in zip(urls, labels) if l == 1]
    n_per_class = min(max_urls // 2, len(safe_urls), len(bad_urls))

    import random
    random.seed(42)
    sample = random.sample(safe_urls, n_per_class) + random.sample(bad_urls, n_per_class)
    random.shuffle(sample)

    print(f"  Fetching HTML for {len(sample)} URLs (concurrency={concurrency})...")
    batch_size = 500
    for i in range(0, len(sample), batch_size):
        batch = sample[i : i + batch_size]
        tasks = [worker(u, l) for u, l in batch]
        batch_results = await asyncio.gather(*tasks)
        results.extend([r for r in batch_results if r is not None])
        print(f"    Progress: {min(i + batch_size, len(sample))}/{len(sample)} "
              f"(got {len(results)} pages, {cached} cached, {failed} failed)")

    print(f"  HTML fetch complete: {len(results)} pages ({cached} cached, {fetched} fresh, {failed} failed)")
    return results


def train_html_rf(html_data):
    """Train HTML Random Forest classifier."""
    print("\n" + "=" * 60)
    print("TRAINING HTML RANDOM FOREST CLASSIFIER")
    print("=" * 60)

    t0 = time.time()
    from sklearn.ensemble import RandomForestClassifier

    X = np.array([extract_html_features(html) for _, _, html in html_data])
    y = np.array([label for _, label, _ in html_data])
    print(f"  Samples: {len(y)} (safe={sum(y==0)}, dangerous={sum(y==1)})")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc = scaler.transform(X_test)

    print("  Training Random Forest (500 trees)...")
    model = RandomForestClassifier(
        n_estimators=500,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_train_sc, y_train)

    y_pred = model.predict(X_test_sc)
    y_proba = model.predict_proba(X_test_sc)[:, 1]
    auc = roc_auc_score(y_test, y_proba)

    print(f"\n  TEST RESULTS:")
    print(f"  AUC: {auc:.4f}")
    print(classification_report(y_test, y_pred, target_names=["safe", "phishing"], digits=4))

    # Save — matches risk_engine loader format
    out_path = MODELS_DIR / "best_html_rf_current.pkl"
    joblib.dump({"model": model, "scaler": scaler}, out_path)
    # Also save to legacy path
    joblib.dump({"model": model, "scaler": scaler}, MODELS_DIR / "best_html_rf.pkl")

    elapsed = time.time() - t0
    print(f"  Saved: {out_path} ({out_path.stat().st_size / 1024 / 1024:.1f} MB)")
    print(f"  HTML RF training took {elapsed:.1f}s")

    return model, scaler


# ============================================================
# SECTION 6: HTML CNN (character-level)
# ============================================================

class HTMLCharCNN(nn.Module):
    """Character-level CNN for HTML phishing detection."""

    def __init__(self, vocab_size=256, embed_dim=64, num_classes=2, seq_len=4096):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim)
        self.conv1 = nn.Conv1d(embed_dim, 128, kernel_size=7, padding=3)
        self.bn1 = nn.BatchNorm1d(128)
        self.conv2 = nn.Conv1d(128, 128, kernel_size=5, padding=2)
        self.bn2 = nn.BatchNorm1d(128)
        self.conv3 = nn.Conv1d(128, 64, kernel_size=3, padding=1)
        self.bn3 = nn.BatchNorm1d(64)
        self.pool = nn.AdaptiveMaxPool1d(1)
        self.dropout = nn.Dropout(0.3)
        self.fc = nn.Linear(64, num_classes)

    def forward(self, x):
        x = self.embedding(x)  # (B, seq_len, embed_dim)
        x = x.transpose(1, 2)  # (B, embed_dim, seq_len)
        x = F.relu(self.bn1(self.conv1(x)))
        x = F.relu(self.bn2(self.conv2(x)))
        x = F.relu(self.bn3(self.conv3(x)))
        x = self.pool(x).squeeze(-1)  # (B, 64)
        x = self.dropout(x)
        return self.fc(x)


class HTMLCharDataset(Dataset):
    def __init__(self, htmls, labels, max_len=4096):
        self.htmls = htmls
        self.labels = labels
        self.max_len = max_len

    def __len__(self):
        return len(self.htmls)

    def __getitem__(self, idx):
        html = self.htmls[idx][:self.max_len]
        arr = np.frombuffer(html.encode("utf-8", "ignore"), dtype=np.uint8)
        if len(arr) < self.max_len:
            arr = np.concatenate([arr, np.zeros(self.max_len - len(arr), dtype=np.uint8)])
        else:
            arr = arr[:self.max_len]
        return torch.from_numpy(arr.copy()).long(), torch.tensor(self.labels[idx], dtype=torch.long)


def train_html_cnn(html_data):
    """Train character-level HTML CNN."""
    print("\n" + "=" * 60)
    print("TRAINING HTML CNN (character-level)")
    print("=" * 60)

    t0 = time.time()
    htmls = [html for _, _, html in html_data]
    labels = [label for _, label, _ in html_data]

    X_train_h, X_test_h, y_train, y_test = train_test_split(
        htmls, labels, test_size=0.2, random_state=42, stratify=labels
    )
    X_train_h, X_val_h, y_train, y_val = train_test_split(
        X_train_h, y_train, test_size=0.15, random_state=42, stratify=y_train
    )

    train_ds = HTMLCharDataset(X_train_h, y_train)
    val_ds = HTMLCharDataset(X_val_h, y_val)
    test_ds = HTMLCharDataset(X_test_h, y_test)

    train_dl = DataLoader(train_ds, batch_size=64, shuffle=True, num_workers=0)
    val_dl = DataLoader(val_ds, batch_size=64, num_workers=0)
    test_dl = DataLoader(test_ds, batch_size=64, num_workers=0)

    # Class weights
    cw = Counter(y_train)
    total = sum(cw.values())
    w = torch.tensor([total / (2 * cw[0]), total / (2 * cw[1])], dtype=torch.float).to(DEVICE)

    model = HTMLCharCNN().to(DEVICE)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.CrossEntropyLoss(weight=w)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=2, factor=0.5)

    best_val_acc = 0
    patience_counter = 0
    best_state = None
    epochs = 15

    print(f"  Training for up to {epochs} epochs...")
    for ep in range(epochs):
        model.train()
        train_loss = 0
        for batch_x, batch_y in train_dl:
            batch_x, batch_y = batch_x.to(DEVICE), batch_y.to(DEVICE)
            optimizer.zero_grad()
            out = model(batch_x)
            loss = criterion(out, batch_y)
            loss.backward()
            optimizer.step()
            train_loss += loss.item()

        # Validate
        model.eval()
        correct, total_v = 0, 0
        with torch.no_grad():
            for batch_x, batch_y in val_dl:
                batch_x, batch_y = batch_x.to(DEVICE), batch_y.to(DEVICE)
                out = model(batch_x)
                pred = out.argmax(dim=1)
                correct += (pred == batch_y).sum().item()
                total_v += batch_y.size(0)
        val_acc = correct / total_v
        scheduler.step(1 - val_acc)
        print(f"    Epoch {ep+1}/{epochs}  loss={train_loss/len(train_dl):.4f}  val_acc={val_acc:.4f}")

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= 4:
                print("    Early stopping")
                break

    # Load best and evaluate on test
    if best_state:
        model.load_state_dict(best_state)
    model = model.to(DEVICE)
    model.eval()

    all_pred, all_true = [], []
    with torch.no_grad():
        for batch_x, batch_y in test_dl:
            batch_x = batch_x.to(DEVICE)
            out = model(batch_x)
            pred = out.argmax(dim=1)
            all_pred.extend(pred.cpu().numpy().tolist())
            all_true.extend(batch_y.numpy().tolist())

    print(f"\n  TEST RESULTS:")
    print(classification_report(all_true, all_pred, target_names=["safe", "phishing"], digits=4))

    # Save as TorchScript
    model = model.cpu()
    model.eval()
    dummy = torch.randint(0, 256, (1, 4096), dtype=torch.long)
    traced = torch.jit.trace(model, dummy)
    out_path = BACKEND_MODELS_DIR / "best_html_cnn.pt"
    traced.save(str(out_path))

    elapsed = time.time() - t0
    print(f"  Saved: {out_path} ({out_path.stat().st_size / 1024:.0f} KB)")
    print(f"  HTML CNN training took {elapsed:.1f}s")

    return model


# ============================================================
# SECTION 7: DistilBERT Text Phishing Classifier
# ============================================================

def train_bert(df: pd.DataFrame):
    """Fine-tune DistilBERT for phishing text classification."""
    print("\n" + "=" * 60)
    print("FINE-TUNING DISTILBERT FOR PHISHING TEXT CLASSIFICATION")
    print("=" * 60)

    t0 = time.time()
    from transformers import (
        DistilBertForSequenceClassification,
        AutoTokenizer,
        get_linear_schedule_with_warmup,
    )

    # Use URLs as text input (the model learns URL patterns)
    # Also prefix with any available text context
    texts = df["url"].tolist()
    labels = df["label"].tolist()

    # Subsample for BERT (full dataset would take too long)
    max_samples = 100000
    if len(texts) > max_samples:
        import random
        random.seed(42)
        indices = random.sample(range(len(texts)), max_samples)
        texts = [texts[i] for i in indices]
        labels = [labels[i] for i in indices]

    print(f"  Samples: {len(texts)} (safe={sum(l==0 for l in labels)}, phishing={sum(l==1 for l in labels)})")

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.15, random_state=42, stratify=labels
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train, y_train, test_size=0.1, random_state=42, stratify=y_train
    )

    tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
    model = DistilBertForSequenceClassification.from_pretrained(
        "distilbert-base-uncased", num_labels=2
    )
    model = model.to(DEVICE)

    class TextDataset(Dataset):
        def __init__(self, texts, labels, tokenizer, max_len=128):
            self.texts = texts
            self.labels = labels
            self.tokenizer = tokenizer
            self.max_len = max_len

        def __len__(self):
            return len(self.texts)

        def __getitem__(self, idx):
            enc = self.tokenizer(
                self.texts[idx],
                truncation=True,
                padding="max_length",
                max_length=self.max_len,
                return_tensors="pt",
            )
            return {
                "input_ids": enc["input_ids"].squeeze(0),
                "attention_mask": enc["attention_mask"].squeeze(0),
                "labels": torch.tensor(self.labels[idx], dtype=torch.long),
            }

    train_ds = TextDataset(X_train, y_train, tokenizer)
    val_ds = TextDataset(X_val, y_val, tokenizer)
    test_ds = TextDataset(X_test, y_test, tokenizer)

    train_dl = DataLoader(train_ds, batch_size=32, shuffle=True, num_workers=0)
    val_dl = DataLoader(val_ds, batch_size=64, num_workers=0)
    test_dl = DataLoader(test_ds, batch_size=64, num_workers=0)

    optimizer = torch.optim.AdamW(model.parameters(), lr=2e-5, weight_decay=0.01)
    total_steps = len(train_dl) * 3  # 3 epochs
    scheduler = get_linear_schedule_with_warmup(
        optimizer, num_warmup_steps=total_steps // 10, num_training_steps=total_steps
    )

    best_val_acc = 0
    best_state = None
    epochs = 3

    print(f"  Training for {epochs} epochs...")
    for ep in range(epochs):
        model.train()
        total_loss = 0
        for i, batch in enumerate(train_dl):
            input_ids = batch["input_ids"].to(DEVICE)
            attention_mask = batch["attention_mask"].to(DEVICE)
            labels_b = batch["labels"].to(DEVICE)

            outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels_b)
            loss = outputs.loss
            loss.backward()

            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            optimizer.zero_grad()
            total_loss += loss.item()

            if (i + 1) % 100 == 0:
                print(f"    Epoch {ep+1} batch {i+1}/{len(train_dl)} loss={total_loss/(i+1):.4f}")

        # Validate
        model.eval()
        correct, total_v = 0, 0
        with torch.no_grad():
            for batch in val_dl:
                input_ids = batch["input_ids"].to(DEVICE)
                attention_mask = batch["attention_mask"].to(DEVICE)
                labels_b = batch["labels"].to(DEVICE)
                outputs = model(input_ids=input_ids, attention_mask=attention_mask)
                pred = outputs.logits.argmax(dim=1)
                correct += (pred == labels_b).sum().item()
                total_v += labels_b.size(0)
        val_acc = correct / total_v
        print(f"    Epoch {ep+1}/{epochs}  avg_loss={total_loss/len(train_dl):.4f}  val_acc={val_acc:.4f}")

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}

    # Evaluate on test
    if best_state:
        model.load_state_dict(best_state)
        model = model.to(DEVICE)
    model.eval()

    all_pred, all_true = [], []
    with torch.no_grad():
        for batch in test_dl:
            input_ids = batch["input_ids"].to(DEVICE)
            attention_mask = batch["attention_mask"].to(DEVICE)
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            pred = outputs.logits.argmax(dim=1)
            all_pred.extend(pred.cpu().numpy().tolist())
            all_true.extend(batch["labels"].numpy().tolist())

    print(f"\n  TEST RESULTS:")
    print(classification_report(all_true, all_pred, target_names=["safe", "phishing"], digits=4))

    # Save model and tokenizer
    out_dir = ROOT / "bert_phishing_detector"
    out_dir.mkdir(parents=True, exist_ok=True)
    model.cpu().save_pretrained(str(out_dir))
    tokenizer.save_pretrained(str(out_dir))

    elapsed = time.time() - t0
    print(f"  Saved: {out_dir}")
    print(f"  BERT training took {elapsed:.1f}s")

    return model, tokenizer


# ============================================================
# SECTION 8: Update risk_engine._url_features to use new features
# ============================================================

def update_risk_engine_features():
    """
    Update risk_engine.py to use the new 36-feature URL feature set,
    while keeping backward compatibility.
    """
    print("\n" + "=" * 60)
    print("UPDATING RISK ENGINE FEATURE EXTRACTION")
    print("=" * 60)

    engine_path = ROOT / "backend" / "risk_engine.py"
    content = engine_path.read_text()

    # Find and replace _url_features method
    old_method = '''    def _url_features(self, url: str) -> np.ndarray:
        u = url.lower()
        feats = [
            len(url),
            url.count('.'),
            url.count('/'),
            url.count('-'),
            url.count('_'),
            url.count('?'),
            url.count('='),
            url.count('&'),
            int('login' in u),
            int('secure' in u),
            int('account' in u),
            int('verify' in u),
        ]
        return np.array(feats, dtype=float).reshape(1, -1)'''

    new_method = '''    def _url_features(self, url: str) -> np.ndarray:
        """Extract URL features for ML model prediction.
        Returns 36 features when enhanced model is loaded, 12 for legacy."""
        u = url.lower().strip()
        # Check if we have the enhanced model (36 features) or legacy (12)
        try:
            n_features = self.ml_model.num_features() if hasattr(self.ml_model, 'num_features') else 12
        except Exception:
            n_features = 12

        if n_features > 12:
            from urllib.parse import urlparse as _urlparse
            from collections import Counter as _Counter
            if not u.startswith(("http://", "https://", "ftp://")):
                _up = _urlparse("http://" + u)
            else:
                _up = _urlparse(u)
            hostname = _up.hostname or ""
            path = _up.path or ""
            query = _up.query or ""
            _SUSPICIOUS_TLDS = {".tk",".ml",".ga",".cf",".gq",".xyz",".top",".club",".work",".buzz",".rest",".fit",".bid",".click",".link",".stream",".download",".win",".racing",".review",".date",".accountant",".science",".party",".cricket",".faith"}
            _BRAND_KW = {"paypal","apple","google","microsoft","amazon","netflix","facebook","instagram","whatsapp","bank","chase","wellsfargo","citibank","hsbc","barclays","linkedin","dropbox","icloud","outlook","yahoo","ebay","coinbase","binance","metamask"}
            hostname_dots = hostname.count(".")
            tld = ("." + hostname.rsplit(".", 1)[-1]) if "." in hostname else ""
            digit_count = sum(c.isdigit() for c in url)
            brand_in_url = 0
            for _b in _BRAND_KW:
                if _b in u:
                    parts = hostname.split(".")
                    actual = parts[-2] if len(parts) >= 2 else hostname
                    if _b != actual and _b in hostname:
                        brand_in_url = 1
                        break
            if url:
                freq = _Counter(url)
                probs = [c / len(url) for c in freq.values()]
                entropy = -sum(p * np.log2(p) for p in probs if p > 0)
            else:
                entropy = 0.0
            _SUSP_WORDS = {"login","signin","verify","secure","account","update","confirm","password","credential","authenticate","suspend","limited","unlock","restore","wallet","billing","invoice"}
            feats = [
                len(url), url.count("."), url.count("/"), url.count("-"),
                url.count("_"), url.count("?"), url.count("="), url.count("&"),
                int(any(w in u for w in ["login","signin","log-in","sign-in"])),
                int("secure" in u), int("account" in u),
                int(any(w in u for w in ["verify","confirm","validate"])),
                len(hostname), len(path), len(query), url.count("@"),
                url.count("~"), url.count("%"), hostname_dots, hostname.count("-"),
                sum(c.isdigit() for c in url) / max(len(url), 1),
                sum(c.isdigit() for c in hostname) / max(len(hostname), 1),
                int(url.lower().startswith("https://")),
                int(bool(re.match(r"^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$", hostname))),
                int(_up.port is not None and _up.port not in (80, 443)),
                max(0, hostname_dots - 1),
                int(tld in _SUSPICIOUS_TLDS),
                path.count("/") - 1 if path else 0,
                int("//" in path[1:]) if len(path) > 1 else 0,
                int(hostname in {"bit.ly","goo.gl","tinyurl.com","t.co","is.gd","ow.ly","buff.ly"}),
                int("update" in u),
                int(any(w in u for w in ["suspend","locked","limited","restrict"])),
                int(any(w in u for w in ["bank","paypal","wallet","billing"])),
                brand_in_url, entropy,
                sum(1 for w in _SUSP_WORDS if w in u),
            ]
        else:
            feats = [
                len(url), url.count('.'), url.count('/'), url.count('-'),
                url.count('_'), url.count('?'), url.count('='), url.count('&'),
                int('login' in u), int('secure' in u),
                int('account' in u), int('verify' in u),
            ]
        return np.array(feats, dtype=float).reshape(1, -1)'''

    if old_method in content:
        content = content.replace(old_method, new_method)
        engine_path.write_text(content)
        print("  Updated _url_features method in risk_engine.py (36 features)")
    else:
        print("  WARNING: Could not find _url_features method to replace")
        print("  You may need to update it manually")


# ============================================================
# MAIN
# ============================================================

async def main():
    print("=" * 60)
    print("PayGuard ML Training Pipeline")
    print("=" * 60)

    # 1. Load datasets
    df = load_datasets()

    # 2. Train XGBoost
    xgb_model, xgb_scaler, feature_names = train_xgboost(df)
    save_feature_names(feature_names)

    # 3. Fetch HTML for CNN/RF training
    print("\n" + "=" * 60)
    print("FETCHING HTML FOR CNN/RF TRAINING")
    print("=" * 60)

    html_data = await fetch_html_batch(
        df["url"].tolist(),
        df["label"].tolist(),
        max_urls=20000,  # 10K per class
        concurrency=150,
        timeout=4.0,
    )

    if len(html_data) >= 500:
        # 4. Train HTML Random Forest
        train_html_rf(html_data)

        # 5. Train HTML CNN
        train_html_cnn(html_data)
    else:
        print(f"  Only got {len(html_data)} HTML pages — skipping HTML models")

    # 6. Train BERT
    train_bert(df)

    # 7. Update risk engine
    update_risk_engine_features()

    print("\n" + "=" * 60)
    print("ALL TRAINING COMPLETE")
    print("=" * 60)
    print(f"  Models saved to: {MODELS_DIR}")
    print(f"  Backend models:  {BACKEND_MODELS_DIR}")
    print()
    print("  Files produced:")
    for p in sorted(MODELS_DIR.glob("*")):
        if p.is_file():
            size = p.stat().st_size
            if size > 1024 * 1024:
                print(f"    {p.name:40s} {size / 1024 / 1024:.1f} MB")
            else:
                print(f"    {p.name:40s} {size / 1024:.0f} KB")
    for p in sorted(BACKEND_MODELS_DIR.glob("*")):
        if p.is_file():
            print(f"    backend/models/{p.name:23s} {p.stat().st_size / 1024:.0f} KB")


if __name__ == "__main__":
    asyncio.run(main())
