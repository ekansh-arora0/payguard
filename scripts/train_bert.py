#!/usr/bin/env python3
"""
Fine-tune DistilBERT on phishing URLs.
Designed to complete in <10 minutes on Apple Silicon MPS.
"""
import os
import pickle
import random
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader, Dataset
from transformers import (
    DistilBertForSequenceClassification,
    DistilBertTokenizerFast,
    get_linear_schedule_with_warmup,
)

ROOT = Path(__file__).resolve().parent.parent
BERT_DIR = ROOT / "bert_phishing_detector"
CACHE_PATH = "/tmp/payguard_urls.pkl"

# Hyperparameters — tuned for speed
N_SAMPLES = 16000       # 8K per class
MAX_LEN = 64            # URLs are short, 64 tokens enough
BATCH_SIZE = 128
EPOCHS = 3
LR = 5e-5
DEVICE = "mps" if torch.backends.mps.is_available() else "cpu"


class URLDataset(Dataset):
    def __init__(self, urls, labels, tokenizer, max_len):
        self.urls = urls
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.urls)

    def __getitem__(self, idx):
        enc = self.tokenizer(
            self.urls[idx],
            max_length=self.max_len,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )
        return {
            "input_ids": enc["input_ids"].squeeze(0),
            "attention_mask": enc["attention_mask"].squeeze(0),
            "labels": torch.tensor(self.labels[idx], dtype=torch.long),
        }


def load_data():
    """Load balanced sample from cached URL data."""
    print(f"Loading cached data from {CACHE_PATH}...")
    with open(CACHE_PATH, "rb") as f:
        df = pickle.load(f)

    # DataFrame with columns: url, label, hash
    phish = df[df["label"] == 1]
    legit = df[df["label"] == 0]
    print(f"  Total: {len(phish)} phishing, {len(legit)} legitimate")

    half = N_SAMPLES // 2
    phish_sample = phish.sample(n=min(half, len(phish)), random_state=42)
    legit_sample = legit.sample(n=min(half, len(legit)), random_state=42)
    combined = pd.concat([phish_sample, legit_sample]).sample(frac=1, random_state=42)

    urls = combined["url"].tolist()
    labels = combined["label"].tolist()
    # Normalize: ensure all URLs have a protocol prefix
    urls = [u if u.startswith(("http://", "https://", "ftp://")) else "http://" + u for u in urls]
    print(f"  Sampled: {len(urls)} URLs ({sum(labels)} phishing, {len(labels)-sum(labels)} legit)")
    return urls, labels


def train():
    print(f"Device: {DEVICE}", flush=True)
    print(f"Config: {N_SAMPLES} samples, {EPOCHS} epochs, batch={BATCH_SIZE}, lr={LR}", flush=True)
    print(flush=True)

    # Load tokenizer and model
    print("Loading tokenizer...", flush=True)
    tokenizer = DistilBertTokenizerFast.from_pretrained(str(BERT_DIR))
    print("Loading model from pretrained distilbert-base-uncased...", flush=True)
    model = DistilBertForSequenceClassification.from_pretrained(
        "distilbert-base-uncased", num_labels=2
    )
    print(f"Moving model to {DEVICE}...", flush=True)
    model = model.to(DEVICE)

    # Load data
    urls, labels = load_data()

    # Split 90/10
    split = int(0.9 * len(urls))
    print("Creating datasets...", flush=True)
    train_ds = URLDataset(urls[:split], labels[:split], tokenizer, MAX_LEN)
    val_ds = URLDataset(urls[split:], labels[split:], tokenizer, MAX_LEN)

    train_dl = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True, num_workers=0)
    val_dl = DataLoader(val_ds, batch_size=BATCH_SIZE, num_workers=0)

    print(f"Train: {len(train_ds)}, Val: {len(val_ds)}", flush=True)
    print(f"Steps per epoch: {len(train_dl)}", flush=True)

    # Optimizer & scheduler
    optimizer = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=0.01)
    total_steps = len(train_dl) * EPOCHS
    scheduler = get_linear_schedule_with_warmup(
        optimizer, num_warmup_steps=total_steps // 10, num_training_steps=total_steps
    )

    # Training loop
    best_acc = 0.0
    for epoch in range(EPOCHS):
        model.train()
        total_loss = 0
        correct = 0
        total = 0
        t0 = time.time()

        for step, batch in enumerate(train_dl):
            input_ids = batch["input_ids"].to(DEVICE)
            attention_mask = batch["attention_mask"].to(DEVICE)
            lab = batch["labels"].to(DEVICE)

            outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=lab)
            loss = outputs.loss
            logits = outputs.logits

            total_loss += loss.item()
            preds = logits.argmax(dim=-1)
            correct += (preds == lab).sum().item()
            total += lab.size(0)

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            optimizer.zero_grad()

            if (step + 1) % 10 == 0:
                elapsed = time.time() - t0
                print(f"  Epoch {epoch+1} step {step+1}/{len(train_dl)} "
                      f"loss={total_loss/(step+1):.4f} acc={correct/total:.4f} "
                      f"[{elapsed:.0f}s]")

        train_acc = correct / total
        avg_loss = total_loss / len(train_dl)
        epoch_time = time.time() - t0
        print(f"Epoch {epoch+1}/{EPOCHS}: loss={avg_loss:.4f}, train_acc={train_acc:.4f}, time={epoch_time:.0f}s")

        # Validation
        model.eval()
        val_correct = 0
        val_total = 0
        with torch.no_grad():
            for batch in val_dl:
                input_ids = batch["input_ids"].to(DEVICE)
                attention_mask = batch["attention_mask"].to(DEVICE)
                lab = batch["labels"].to(DEVICE)
                outputs = model(input_ids=input_ids, attention_mask=attention_mask)
                preds = outputs.logits.argmax(dim=-1)
                val_correct += (preds == lab).sum().item()
                val_total += lab.size(0)

        val_acc = val_correct / val_total
        print(f"  Val accuracy: {val_acc:.4f}")

        if val_acc > best_acc:
            best_acc = val_acc
            # Save best model
            model.save_pretrained(str(BERT_DIR))
            tokenizer.save_pretrained(str(BERT_DIR))
            print(f"  Saved best model (val_acc={val_acc:.4f})")

    print(f"\nTraining complete. Best val accuracy: {best_acc:.4f}")
    print(f"Model saved to {BERT_DIR}")


if __name__ == "__main__":
    train()
