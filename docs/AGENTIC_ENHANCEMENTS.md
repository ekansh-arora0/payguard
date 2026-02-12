# Agentic Enhancements and System Analysis

## Architecture Overview

- Backend: FastAPI, MongoDB via motor, rule-based risk engine with optional ML.
- Frontend: React CRA; Chrome extension calls GET /api/risk.
- Datasets: von (char-level 150 features), html (12 content features), excel (12 URL features).

## Dependencies

- Inference: scikit-learn, xgboost, joblib, shap.
- Optional tuning: optuna.

## Performance Bottlenecks

- SSL check network latency; content fetch avoided for hot path.
- Rule-based scoring limited accuracy; ML improves trust_score while staying under 500ms.

## Agentic Capabilities

- Active learning: /api/feedback/label endpoint stores labels for retraining.
- Online calibration: optional calibrated model artifacts supported by loader.
- Hybrid ensemble: Excel URL model used as hot path; optional additional models can be blended.
- Explainability: SHAP-derived feature highlights added to risk_factors and safety_indicators.
- Auto-tuning: optuna-based scripts recommended for periodic tuning with canary rollout.
- Monitoring: metrics collection logs per-request latency and outputs.

## Dataset Audit

- Usage: combined_dataset_all.pkl includes von/html/excel splits for train/val/test.
- Dependencies: compile_datasets.py reads excel files and dataset/* parts.
- Deletion: retain backups; remove only after verification; follow secure deletion policy.

## Backward Compatibility

- API responses remain consistent; new fields are only internal or optional.
- ML path falls back to rule-based when model unavailable.

## Security and Compliance

- No secrets logged; API key validation unchanged.
- Model artifacts versioned by path; rollback by switching artifact.

## Rollback

- Disable ML by removing or changing model path; rule-based remains.

## Version Control

- Track changes in repository; model artifacts named per dataset; recommend git-lfs for large files.