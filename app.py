"""
Flask Web Application — Phishing URL Detection System
Two-module analysis: ML prediction + Live security assessment
"""

import os
import json
import time
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

from feature_extractor import URLFeatureExtractor, SecurityAssessor

# ========================================================================
# App setup
# ========================================================================

app = Flask(__name__)
CORS(app)

BASE_DIR = Path(__file__).parent
MODEL_DIR = BASE_DIR / 'models'

# ========================================================================
# Load Model
# ========================================================================

MODEL = None
MODEL_META = None

def load_model():
    global MODEL, MODEL_META
    model_path = MODEL_DIR / 'phishing_model.joblib'
    meta_path  = MODEL_DIR / 'model_metadata.json'

    if model_path.exists():
        MODEL = joblib.load(model_path)
        print(f"[✓] Model loaded from {model_path}")
    else:
        print("[!] No trained model found. Run train_model.py first.")

    if meta_path.exists():
        with open(meta_path, 'r') as f:
            MODEL_META = json.load(f)
        print(f"[✓] Metadata loaded. Best model: {MODEL_META.get('best_model', 'Unknown')}")


# ========================================================================
# ML Prediction
# ========================================================================

def ml_predict(url: str):
    """
    Extract URL features that overlap with training features and predict.
    Returns dict with verdict, probability, and feature values.
    """
    if MODEL is None or MODEL_META is None:
        return {
            'verdict': 'UNKNOWN',
            'confidence': 0.0,
            'error': 'Model not loaded. Please run train_model.py first.'
        }

    extractor = URLFeatureExtractor(url)
    url_feats = extractor.extract_url_features()

    training_features = MODEL_META.get('feature_names', [])

    # Build feature vector aligned to training columns
    feature_vector = []
    feature_dict = {}
    for feat in training_features:
        val = url_feats.get(feat, 0)
        # Coerce to float
        try:
            val = float(val)
        except (TypeError, ValueError):
            val = 0.0
        feature_vector.append(val)
        feature_dict[feat] = val

    X = np.array(feature_vector).reshape(1, -1)

    try:
        pred = MODEL.predict(X)[0]
        proba = MODEL.predict_proba(X)[0]

        # label: 1 = legitimate, 0 = phishing
        is_phishing = int(pred) == 0
        phishing_prob = float(proba[0])  # probability of class 0 (phishing)
        legit_prob    = float(proba[1])

        verdict = 'PHISHING' if is_phishing else 'LEGITIMATE'
        confidence = phishing_prob if is_phishing else legit_prob

        return {
            'verdict': verdict,
            'confidence': round(confidence * 100, 2),
            'phishing_probability': round(phishing_prob * 100, 2),
            'legitimate_probability': round(legit_prob * 100, 2),
            'features_used': feature_dict,
            'model_name': MODEL_META.get('best_model', 'Unknown'),
            'error': None
        }
    except Exception as e:
        return {
            'verdict': 'ERROR',
            'confidence': 0.0,
            'error': str(e)
        }


# ========================================================================
# Routes
# ========================================================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Full analysis: ML + Security assessment."""
    data = request.get_json()
    url = (data or {}).get('url', '').strip()

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # Basic URL normalization
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    start_time = time.time()

    # --- ML prediction (fast, URL-features only) ---
    ml_result = ml_predict(url)

    # --- Security assessment (live checks, slower) ---
    assessor = SecurityAssessor(url)
    try:
        security_report = assessor.full_assessment()
    except Exception as e:
        security_report = {'error': str(e), 'risk_flags': [], 'risk_score': 0}

    # --- Combine results ---
    ml_verdict  = ml_result.get('verdict', 'UNKNOWN')
    sec_risk    = security_report.get('risk_score', 0)
    risk_flags  = security_report.get('risk_flags', [])

    # Overall verdict: if either ML says phishing OR risk flags are high
    if ml_verdict == 'PHISHING' or sec_risk >= 4:
        overall = 'PHISHING'
    elif ml_verdict == 'LEGITIMATE' and sec_risk <= 1:
        overall = 'LEGITIMATE'
    else:
        overall = 'SUSPICIOUS'

    elapsed = round(time.time() - start_time, 2)

    response = {
        'url': url,
        'overall_verdict': overall,
        'analysis_time_seconds': elapsed,
        'ml_analysis': ml_result,
        'security_assessment': {
            'risk_score': sec_risk,
            'risk_flags': risk_flags,
            'dns': security_report.get('dns', {}),
            'ssl': security_report.get('ssl', {}),
            'redirects': security_report.get('redirects', {}),
            'phishtank': security_report.get('phishtank', {}),
            'domain': security_report.get('domain', ''),
            'tld': security_report.get('tld', ''),
        }
    }

    return jsonify(response)


@app.route('/api/model-info', methods=['GET'])
def model_info():
    if MODEL_META is None:
        return jsonify({'error': 'Model not loaded'}), 404
    return jsonify({
        'model': MODEL_META.get('best_model'),
        'trained_at': MODEL_META.get('trained_at'),
        'features': MODEL_META.get('feature_names'),
        'results': MODEL_META.get('results')
    })


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'model_loaded': MODEL is not None
    })


# ========================================================================
# Entry point
# ========================================================================

# Load model on startup (works for both direct run and gunicorn)
load_model()

if __name__ == '__main__':
    load_model()
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV', 'production') != 'production'
    print("\n[✓] Starting Phishing URL Detection System...")
    print(f"    URL: http://127.0.0.1:{port}\n")
    app.run(debug=debug, host='0.0.0.0', port=port)

