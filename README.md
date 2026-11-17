# PhishGuard 🛡️ — Phishing URL Detection System

A full-stack ML-powered phishing URL detector with dual-engine analysis (Machine Learning + Live Security Assessment).

## 🚀 Live Demo
Deployed on Render: [phishguard.onrender.com](https://phishguard.onrender.com)

## ✨ Features
- 🤖 **ML Engine** — RandomForest trained on 235,795 URLs (PhiUSIIL dataset), 50 features
- 🔍 **Live Security Assessment** — DNS, SSL/TLS, redirect chain, PhishTank reputation
- 🎨 **Modern UI** — Dark-themed dashboard with probability gauge and feature table
- ⚡ **REST API** — JSON API for programmatic access

## 🏗️ Tech Stack
- **Backend:** Python 3.11, Flask 3.0, scikit-learn 1.5, XGBoost, LightGBM
- **Frontend:** Vanilla JS, CSS3 (Inter + JetBrains Mono fonts)
- **ML Model:** RandomForest (F1=1.00, AUC=1.00 on PhiUSIIL test set)

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/analyze` | Full URL analysis (ML + Security) |
| GET | `/api/model-info` | Model metadata and metrics |
| GET | `/api/health` | Health check |

### Example
```bash
curl -X POST https://phishguard.onrender.com/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://secure-login-paypal.tk/verify"}'
```

## 🖥️ Local Setup

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard

# Virtual environment
python -m venv venv
venv\Scripts\activate   # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Run (model already included in /models)
python app.py
```

Open http://127.0.0.1:5000

## 📊 Model Performance

| Model | Accuracy | F1-Score | ROC-AUC |
|-------|----------|----------|---------|
| RandomForest ⭐ | 100.00% | 1.0000 | 1.0000 |
| XGBoost | 100.00% | 1.0000 | 1.0000 |
| LightGBM | 100.00% | 1.0000 | 1.0000 |
| GradientBoosting | 100.00% | 1.0000 | 1.0000 |
| LogisticRegression | 99.99% | 0.9999 | 1.0000 |

## 📁 Project Structure
```
phishguard/
├── app.py                  # Flask app + API routes
├── feature_extractor.py    # URLFeatureExtractor + SecurityAssessor
├── train_model.py          # ML training pipeline
├── requirements.txt        # Dependencies
├── render.yaml             # Render deployment config
├── Procfile                # Gunicorn start command
├── models/
│   ├── phishing_model.joblib
│   └── model_metadata.json
├── templates/index.html    # Frontend
└── static/css/ + js/       # Styles and JavaScript
```

## 🎓 University Project
Data Science & Vulnerability Assessment — Phishing URL Detection System
