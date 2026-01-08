#!/usr/bin/env python3
"""
PayGuard ML Benchmark System
Real production testing against actual phishing datasets with precision/recall/F1/ROC metrics
"""

import os
import sys
import json
import pickle
import hashlib
import pandas as pd
import numpy as np
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
import re
import warnings
warnings.filterwarnings('ignore')

# ML imports
try:
    from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.svm import LinearSVC
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix, classification_report, roc_curve, auc,
        precision_recall_curve, average_precision_score, roc_auc_score
    )
    from sklearn.pipeline import Pipeline
    from sklearn.calibration import CalibratedClassifierCV
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("⚠️  scikit-learn not installed. Run: pip install scikit-learn")

@dataclass
class BenchmarkResult:
    """Results from a single benchmark run"""
    dataset_name: str
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    roc_auc: float
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    total_samples: int
    training_samples: int
    test_samples: int
    timestamp: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


class PhishingFeatureExtractor:
    """Extract features from text for phishing detection"""
    
    # Common phishing indicators
    URGENCY_WORDS = [
        'urgent', 'immediately', 'action required', 'verify', 'confirm',
        'suspend', 'limited time', 'expire', 'deadline', 'asap', 'now',
        'alert', 'warning', 'critical', 'important', 'attention'
    ]
    
    FINANCIAL_WORDS = [
        'bank', 'account', 'credit', 'debit', 'wire', 'transfer', 'payment',
        'invoice', 'tax', 'refund', 'lottery', 'prize', 'winner', 'million',
        'inheritance', 'beneficiary', 'funds', 'money', 'cash', 'dollars'
    ]
    
    CREDENTIAL_WORDS = [
        'password', 'login', 'username', 'credential', 'sign in', 'verify',
        'update', 'reset', 'secure', 'authentication', 'ssn', 'social security'
    ]
    
    THREAT_WORDS = [
        'locked', 'suspended', 'terminated', 'fraud', 'unauthorized',
        'compromised', 'hacked', 'breach', 'illegal', 'violation'
    ]
    
    def extract_features(self, text: str) -> Dict[str, float]:
        """Extract numerical features from text"""
        text_lower = text.lower()
        features = {}
        
        # Word count features
        features['word_count'] = len(text.split())
        features['char_count'] = len(text)
        features['avg_word_length'] = np.mean([len(w) for w in text.split()]) if text.split() else 0
        
        # Urgency indicators
        features['urgency_count'] = sum(1 for w in self.URGENCY_WORDS if w in text_lower)
        features['financial_count'] = sum(1 for w in self.FINANCIAL_WORDS if w in text_lower)
        features['credential_count'] = sum(1 for w in self.CREDENTIAL_WORDS if w in text_lower)
        features['threat_count'] = sum(1 for w in self.THREAT_WORDS if w in text_lower)
        
        # URL features
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        features['url_count'] = len(urls)
        features['has_url'] = 1 if urls else 0
        
        # Suspicious patterns
        features['exclamation_count'] = text.count('!')
        features['caps_ratio'] = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        features['digit_ratio'] = sum(1 for c in text if c.isdigit()) / max(len(text), 1)
        features['special_char_ratio'] = sum(1 for c in text if not c.isalnum() and not c.isspace()) / max(len(text), 1)
        
        # Email patterns
        features['email_count'] = len(re.findall(r'[\w\.-]+@[\w\.-]+', text))
        
        # Phone patterns
        features['phone_count'] = len(re.findall(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', text))
        
        # Currency mentions
        features['currency_mentions'] = len(re.findall(r'[$£€¥]\d+|\d+\s*(?:dollars?|pounds?|euros?)', text_lower))
        
        return features


class PayGuardMLBenchmark:
    """Main benchmarking system for PayGuard ML models"""
    
    def __init__(self, base_path: str = "/Users/ekans/payguard"):
        self.base_path = Path(base_path)
        self.results_dir = self.base_path / "benchmark_results"
        self.results_dir.mkdir(exist_ok=True)
        self.models_dir = self.base_path / "trained_models"
        self.models_dir.mkdir(exist_ok=True)
        self.feature_extractor = PhishingFeatureExtractor()
        self.datasets: Dict[str, pd.DataFrame] = {}
        self.results: List[BenchmarkResult] = []
        
    def load_spam_dataset(self) -> pd.DataFrame:
        """Load spam.csv dataset"""
        spam_path = self.base_path / "spam.csv"
        if not spam_path.exists():
            raise FileNotFoundError(f"spam.csv not found at {spam_path}")
        
        df = pd.read_csv(spam_path, encoding='latin-1', usecols=[0, 1])
        df.columns = ['label', 'text']
        df['is_phishing'] = (df['label'] == 'spam').astype(int)
        df['source'] = 'spam_sms'
        print(f"  ✓ Loaded spam.csv: {len(df)} samples ({df['is_phishing'].sum()} spam)")
        return df
    
    def load_nigerian_fraud(self) -> pd.DataFrame:
        """Load Nigerian fraud dataset"""
        path = self.base_path / "Phishing-Email-Dataset" / "Nigerian_Fraud.csv"
        if not path.exists():
            raise FileNotFoundError(f"Nigerian_Fraud.csv not found")
        
        df = pd.read_csv(path, nrows=10000)  # Sample for speed
        df = df[['subject', 'body']].dropna()
        df['text'] = df['subject'].fillna('') + ' ' + df['body'].fillna('')
        df['is_phishing'] = 1  # All are fraud
        df['source'] = 'nigerian_fraud'
        print(f"  ✓ Loaded Nigerian_Fraud.csv: {len(df)} samples (all phishing)")
        return df[['text', 'is_phishing', 'source']]
    
    def load_phishing_emails(self) -> pd.DataFrame:
        """Load PhishingEmailData.csv"""
        path = self.base_path / "Phishing-Email-Dataset" / "PhishingEmailData.csv"
        if not path.exists():
            raise FileNotFoundError(f"PhishingEmailData.csv not found")
        
        df = pd.read_csv(path)
        df['text'] = df['Email_Subject'].fillna('') + ' ' + df['Email_Content'].fillna('')
        df['is_phishing'] = 1  # All are phishing
        df['source'] = 'phishing_email'
        print(f"  ✓ Loaded PhishingEmailData.csv: {len(df)} samples (all phishing)")
        return df[['text', 'is_phishing', 'source']]
    
    def load_enron_dataset(self) -> pd.DataFrame:
        """Load Enron legitimate emails"""
        path = self.base_path / "Phishing-Email-Dataset" / "Enron.csv"
        if not path.exists():
            return pd.DataFrame()
        
        df = pd.read_csv(path, nrows=5000)
        if 'body' in df.columns:
            df['text'] = df['body'].fillna('')
        elif 'text' in df.columns:
            pass
        else:
            return pd.DataFrame()
        
        df['is_phishing'] = 0  # Legitimate emails
        df['source'] = 'enron_legitimate'
        print(f"  ✓ Loaded Enron.csv: {len(df)} samples (all legitimate)")
        return df[['text', 'is_phishing', 'source']]
    
    def load_all_datasets(self) -> pd.DataFrame:
        """Load and combine all datasets"""
        print("\n📊 Loading datasets...")
        
        dfs = []
        
        # Load each dataset
        try:
            dfs.append(self.load_spam_dataset())
        except Exception as e:
            print(f"  ⚠️  Could not load spam.csv: {e}")
        
        try:
            dfs.append(self.load_nigerian_fraud())
        except Exception as e:
            print(f"  ⚠️  Could not load Nigerian_Fraud.csv: {e}")
        
        try:
            dfs.append(self.load_phishing_emails())
        except Exception as e:
            print(f"  ⚠️  Could not load PhishingEmailData.csv: {e}")
        
        try:
            enron = self.load_enron_dataset()
            if len(enron) > 0:
                dfs.append(enron)
        except Exception as e:
            print(f"  ⚠️  Could not load Enron.csv: {e}")
        
        if not dfs:
            raise ValueError("No datasets could be loaded!")
        
        # Combine all datasets
        combined = pd.concat(dfs, ignore_index=True)
        
        # Clean text
        combined['text'] = combined['text'].fillna('').astype(str)
        combined = combined[combined['text'].str.len() > 10]  # Filter very short texts
        
        print(f"\n📈 Combined dataset: {len(combined)} samples")
        print(f"   - Phishing/Spam: {combined['is_phishing'].sum()} ({100*combined['is_phishing'].mean():.1f}%)")
        print(f"   - Legitimate: {(~combined['is_phishing'].astype(bool)).sum()} ({100*(1-combined['is_phishing'].mean()):.1f}%)")
        
        return combined
    
    def train_and_evaluate(self, X_train, X_test, y_train, y_test, 
                          model_name: str, model, dataset_name: str) -> BenchmarkResult:
        """Train model and compute all metrics"""
        
        # Create pipeline with TF-IDF
        pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(max_features=10000, ngram_range=(1, 2), 
                                      stop_words='english', min_df=2)),
            ('clf', model)
        ])
        
        # Train
        pipeline.fit(X_train, y_train)
        
        # Predict
        y_pred = pipeline.predict(X_test)
        
        # Get probabilities for ROC if available
        if hasattr(pipeline, 'predict_proba'):
            y_prob = pipeline.predict_proba(X_test)[:, 1]
            roc_auc = roc_auc_score(y_test, y_prob)
        else:
            roc_auc = 0.0
        
        # Compute confusion matrix
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        
        result = BenchmarkResult(
            dataset_name=dataset_name,
            model_name=model_name,
            accuracy=accuracy_score(y_test, y_pred),
            precision=precision_score(y_test, y_pred, zero_division=0),
            recall=recall_score(y_test, y_pred, zero_division=0),
            f1_score=f1_score(y_test, y_pred, zero_division=0),
            roc_auc=roc_auc,
            true_positives=int(tp),
            true_negatives=int(tn),
            false_positives=int(fp),
            false_negatives=int(fn),
            total_samples=len(y_test) + len(y_train),
            training_samples=len(y_train),
            test_samples=len(y_test),
            timestamp=datetime.now().isoformat()
        )
        
        return result, pipeline
    
    def run_full_benchmark(self) -> Dict[str, Any]:
        """Run complete benchmark suite"""
        
        if not SKLEARN_AVAILABLE:
            return {"error": "scikit-learn not installed"}
        
        print("\n" + "="*60)
        print("🔬 PayGuard ML Benchmark Suite")
        print("="*60)
        
        # Load data
        df = self.load_all_datasets()
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            df['text'], df['is_phishing'], 
            test_size=0.2, random_state=42, stratify=df['is_phishing']
        )
        
        print(f"\n🔄 Training/Test split: {len(X_train)}/{len(X_test)}")
        
        # Models to evaluate
        models = {
            'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42),
            'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
            'Naive Bayes': MultinomialNB(),
            'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
            'Linear SVM': CalibratedClassifierCV(LinearSVC(random_state=42, max_iter=2000))
        }
        
        print("\n🏋️ Training models...")
        results = []
        best_pipeline = None
        best_f1 = 0
        
        for name, model in models.items():
            print(f"\n  Training {name}...", end=" ")
            try:
                result, pipeline = self.train_and_evaluate(
                    X_train, X_test, y_train, y_test,
                    name, model, "combined_phishing"
                )
                results.append(result)
                print(f"✓ F1={result.f1_score:.3f}, AUC={result.roc_auc:.3f}")
                
                if result.f1_score > best_f1:
                    best_f1 = result.f1_score
                    best_pipeline = pipeline
                    best_model_name = name
            except Exception as e:
                print(f"✗ Error: {e}")
        
        # Save best model
        if best_pipeline:
            model_path = self.models_dir / "best_phishing_detector.pkl"
            with open(model_path, 'wb') as f:
                pickle.dump(best_pipeline, f)
            print(f"\n💾 Best model saved: {best_model_name} (F1={best_f1:.3f})")
        
        # Generate report
        report = self._generate_report(results)
        
        # Save results
        results_path = self.results_dir / f"benchmark_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_path, 'w') as f:
            json.dump({
                'results': [r.to_dict() for r in results],
                'report': report,
                'timestamp': datetime.now().isoformat()
            }, f, indent=2)
        
        print(f"\n📁 Results saved to: {results_path}")
        
        return report
    
    def _generate_report(self, results: List[BenchmarkResult]) -> Dict[str, Any]:
        """Generate summary report"""
        
        if not results:
            return {"error": "No results"}
        
        # Find best model
        best = max(results, key=lambda r: r.f1_score)
        
        report = {
            "summary": {
                "total_models_tested": len(results),
                "best_model": best.model_name,
                "best_f1_score": best.f1_score,
                "best_accuracy": best.accuracy,
                "best_precision": best.precision,
                "best_recall": best.recall,
                "best_roc_auc": best.roc_auc
            },
            "all_results": [
                {
                    "model": r.model_name,
                    "accuracy": f"{r.accuracy:.4f}",
                    "precision": f"{r.precision:.4f}",
                    "recall": f"{r.recall:.4f}",
                    "f1_score": f"{r.f1_score:.4f}",
                    "roc_auc": f"{r.roc_auc:.4f}"
                }
                for r in sorted(results, key=lambda r: r.f1_score, reverse=True)
            ],
            "confusion_matrix": {
                "best_model": best.model_name,
                "true_positives": best.true_positives,
                "true_negatives": best.true_negatives,
                "false_positives": best.false_positives,
                "false_negatives": best.false_negatives
            },
            "dataset_info": {
                "total_samples": best.total_samples,
                "training_samples": best.training_samples,
                "test_samples": best.test_samples
            }
        }
        
        # Print report
        print("\n" + "="*60)
        print("📊 BENCHMARK RESULTS")
        print("="*60)
        print(f"\n{'Model':<25} {'Accuracy':<10} {'Precision':<10} {'Recall':<10} {'F1':<10} {'AUC':<10}")
        print("-"*75)
        for r in sorted(results, key=lambda r: r.f1_score, reverse=True):
            print(f"{r.model_name:<25} {r.accuracy:.4f}    {r.precision:.4f}     {r.recall:.4f}    {r.f1_score:.4f}   {r.roc_auc:.4f}")
        
        print(f"\n🏆 Best Model: {best.model_name}")
        print(f"   F1 Score: {best.f1_score:.4f}")
        print(f"   Precision: {best.precision:.4f} (False positive rate: {best.false_positives/(best.false_positives+best.true_negatives):.2%})")
        print(f"   Recall: {best.recall:.4f} (Detection rate: {best.recall:.2%})")
        print(f"   ROC-AUC: {best.roc_auc:.4f}")
        
        return report
    
    def predict(self, text: str) -> Dict[str, Any]:
        """Use best trained model to predict"""
        model_path = self.models_dir / "best_phishing_detector.pkl"
        
        if not model_path.exists():
            return {"error": "No trained model. Run benchmark first."}
        
        with open(model_path, 'rb') as f:
            pipeline = pickle.load(f)
        
        prediction = pipeline.predict([text])[0]
        proba = pipeline.predict_proba([text])[0]
        
        return {
            "is_phishing": bool(prediction),
            "confidence": float(max(proba)),
            "phishing_probability": float(proba[1]),
            "legitimate_probability": float(proba[0])
        }


def main():
    """Main entry point"""
    benchmark = PayGuardMLBenchmark()
    
    print("\n🛡️ PayGuard Production ML Benchmark")
    print("Testing against real phishing datasets...\n")
    
    report = benchmark.run_full_benchmark()
    
    # Test prediction
    print("\n" + "="*60)
    print("🧪 LIVE PREDICTION TEST")
    print("="*60)
    
    test_texts = [
        "URGENT: Your account has been suspended. Click here to verify: http://fake-bank.com/login",
        "Hey, want to grab lunch tomorrow? Let me know what works for you.",
        "WINNER! You've won $1,000,000! Send your bank details to claim your prize!",
        "Meeting reminder: Team sync at 3pm in Conference Room B"
    ]
    
    for text in test_texts:
        result = benchmark.predict(text)
        status = "🚨 PHISHING" if result.get('is_phishing') else "✅ SAFE"
        conf = result.get('confidence', 0) * 100
        print(f"\n{status} ({conf:.1f}% confidence)")
        print(f"   Text: {text[:60]}...")


if __name__ == "__main__":
    main()
