from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import sys
import os
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.extraction import extract_features, get_feature_names
from src.deep_model import urls_to_sequences

app = Flask(__name__)
CORS(app)

MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')
models = {}
cnn_model = None

try:
    models['lr']       = joblib.load(os.path.join(MODEL_DIR, 'lr_model.joblib'))
    models['rf']       = joblib.load(os.path.join(MODEL_DIR, 'rf_model.joblib'))
    models['xgb']      = joblib.load(os.path.join(MODEL_DIR, 'xgb_model.joblib'))
    models['ensemble'] = joblib.load(os.path.join(MODEL_DIR, 'ensemble_model.joblib'))
    print("ML models loaded.")
except Exception as e:
    print(f"ML model loading issue: {e}")

try:
    from tensorflow.keras.models import load_model
    cnn_path = os.path.join(MODEL_DIR, 'cnn_model.keras')
    if os.path.exists(cnn_path):
        cnn_model = load_model(cnn_path)
        print("CNN deep learning model loaded.")
    else:
        print("CNN model file not found, running without deep learning.")
except Exception as e:
    print(f"CNN loading issue: {e}")


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/api/v1/models', methods=['GET'])
def get_models():
    available = [
        {"id": "xgb",      "name": "XGBoost Classifier"},
        {"id": "rf",       "name": "Random Forest Classifier"},
        {"id": "lr",       "name": "Logistic Regression"},
    ]
    if 'ensemble' in models:
        available.insert(0, {"id": "ensemble", "name": "ML Ensemble — RF + XGBoost"})
    if cnn_model is not None and 'ensemble' in models:
        available.insert(0, {"id": "hybrid", "name": "Hybrid — ML + Deep Learning CNN (Recommended)"})
    elif cnn_model is not None:
        available.insert(0, {"id": "cnn", "name": "Deep Learning CNN"})
    return jsonify({"models": available})


@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json() if request.is_json else request.form
    url = data.get('url', '')
    model_id = data.get('model', 'hybrid')

    if not url:
        return jsonify({'error': "Please provide a URL"}), 400

    # Extract lexical features
    raw_features = extract_features(url)
    feature_names = get_feature_names()
    X_input = pd.DataFrame([raw_features])[feature_names]

    ml_prob_val = None
    cnn_prob_val = None

    # Determine prediction based on selected model
    if model_id == 'hybrid' and cnn_model is not None and 'ensemble' in models:
        # Hybrid: Weighted average favoring the powerful CNN (85%) over the ML ensemble (15%)
        ml_prob_val = float(models['ensemble'].predict_proba(X_input)[0][1])
        seq = urls_to_sequences([url])
        cnn_prob_val = float(cnn_model.predict(seq, verbose=0)[0][0])
        prob_malicious = (0.15 * ml_prob_val) + (0.85 * cnn_prob_val)
        prob_safe = 1.0 - prob_malicious
    elif model_id == 'cnn' and cnn_model is not None:
        seq = urls_to_sequences([url])
        cnn_prob_val = float(cnn_model.predict(seq, verbose=0)[0][0])
        prob_malicious = cnn_prob_val
        prob_safe = 1.0 - prob_malicious
    else:
        # Fall back to ML models
        if model_id not in models:
            model_id = next(iter(models), 'ensemble')
        model = models[model_id]
        prob = model.predict_proba(X_input)[0]
        ml_prob_val = float(prob[1])
        prob_safe = float(prob[0])
        prob_malicious = ml_prob_val

    safety_score = round(prob_safe * 100, 1)
    risk_score   = round(prob_malicious * 100, 1)

    contributions = build_contributions(raw_features)

    flags = []
    reasons = []

    if raw_features['use_of_ip']:
        flags.append("Direct IP Masking")
        reasons.append("URL uses a raw IP address instead of a legitimate domain name, a tactic commonly used by phishing hosts to evade domain blocklists.")
    if raw_features['has_shortening_service']:
        flags.append("URL Shortener Detected")
        reasons.append("URL relies on a link shortening service which hides the final target destination URL from users.")
    if raw_features['domain_entropy'] > 4.0:
        flags.append(f"High Domain Entropy ({raw_features['domain_entropy']:.2f})")
        reasons.append("Domain name exhibits unusually high character randomness (high Shannon entropy), typical of dynamically generated algorithm domains (DGA).")
    if raw_features['num_special_chars'] > 7:
        flags.append(f"Excessive Special Characters ({raw_features['num_special_chars']})")
        reasons.append("Contains a high density of special symbols (@, %, -, ?, =), which is frequently used to obscure malicious parameters.")
    if raw_features['digit_ratio'] > 0.25:
        flags.append(f"High Digit Ratio ({raw_features['digit_ratio']*100:.1f}%)")
        reasons.append("Elevated proportion of numerical characters inside the URL string, commonly found in auto-generated phishing paths.")
    if raw_features['has_javascript_code']:
        flags.append("JavaScript Code Pattern")
        reasons.append("Detected pseudo-protocol 'javascript:' code inside the URL structure.")
    if raw_features['has_text_encoding']:
        flags.append("Percent Obfuscation")
        reasons.append("Percent-encoding (%xx obfuscation) detected, which attempts to trick text-matching security scanners.")
    if raw_features['abnormal_url']:
        flags.append("Hostname Anomaly")
        reasons.append("Hostname structure does not match standard RFC domain syntax.")
    if raw_features['subdomain_count'] > 2:
        flags.append(f"Deep Subdomains ({raw_features['subdomain_count']})")
        reasons.append("Multiple nested subdomains detected, often used to mimic brand names on cheap parent domains.")
    if raw_features['has_at_symbol']:
        flags.append("@ Symbol Redirection")
        reasons.append("Contains an '@' symbol, which causes browsers to ignore preceding credentials and load the host following the symbol.")
    if raw_features['suspicious_tld']:
        flags.append("Suspicious TLD")
        reasons.append("Top-Level Domain (TLD) belongs to a high-risk or free TLD registry frequently abused for rogue campaigns.")

    if not flags:
        flags.append("Clean Structural Signature")
        reasons.append("No anomalous lexical, structural, or obfuscation indicators found in the URL.")

    status = "SAFE"
    if risk_score > 65:
        status = "CRITICAL"
    elif risk_score > 35:
        status = "WARNING"

    # Radar Threat Vector Metrics (0 - 100 scale)
    radar_metrics = {
        'Obfuscation': min(100, int(raw_features['has_text_encoding']*40 + raw_features['has_at_symbol']*30 + raw_features['num_special_chars']*6)),
        'Domain Entropy': min(100, int(raw_features['domain_entropy'] * 22)),
        'URL & Path Depth': min(100, int((raw_features['url_len'] / 110.0) * 100)),
        'Subdomain Density': min(100, int(raw_features['subdomain_count'] * 33)),
        'Threat Signature': min(100, int(raw_features['use_of_ip']*45 + raw_features['suspicious_tld']*45 + raw_features['has_shortening_service']*35 + raw_features['has_javascript_code']*45)),
        'Digit Ratio': min(100, int(raw_features['digit_ratio'] * 100))
    }

    # Get predictions for all individual models for comparative charts
    all_model_scores = {}
    if 'rf' in models:
        all_model_scores['Random Forest'] = round(float(models['rf'].predict_proba(X_input)[0][1]) * 100, 1)
    if 'xgb' in models:
        all_model_scores['XGBoost'] = round(float(models['xgb'].predict_proba(X_input)[0][1]) * 100, 1)
    if 'ensemble' in models:
        all_model_scores['ML Ensemble'] = round(float(models['ensemble'].predict_proba(X_input)[0][1]) * 100, 1)
    if cnn_prob_val is not None:
        all_model_scores['CNN Deep Learning'] = round(cnn_prob_val * 100, 1)
    all_model_scores['Hybrid (85/15)'] = risk_score

    return jsonify({
        'url': url,
        'model_used': model_id,
        'safety_score': safety_score,
        'risk_score': risk_score,
        'status': status,
        'flags': flags,
        'reasons': reasons,
        'feature_contributions': contributions,
        'ml_score': round(ml_prob_val * 100, 1) if ml_prob_val is not None else None,
        'cnn_score': round(cnn_prob_val * 100, 1) if cnn_prob_val is not None else None,
        'radar_metrics': radar_metrics,
        'all_model_scores': all_model_scores,
        'raw_stats': {
            'Length': raw_features['url_len'],
            'Hostname Length': raw_features['hostname_length'],
            'Domain Entropy': round(raw_features['domain_entropy'], 2),
            'Special Chars': raw_features['num_special_chars'],
            'Path Depth': raw_features['path_depth'],
            'Subdomains': raw_features['subdomain_count'],
            'Digit Ratio': f"{round(raw_features['digit_ratio'] * 100, 1)}%",
            'Suspicious TLD': "Yes" if raw_features['suspicious_tld'] else "No",
            'IP Address': "Yes" if raw_features['use_of_ip'] else "No",
            'Obfuscated (%xx)': "Yes" if raw_features['has_text_encoding'] else "No"
        }
    })


def build_contributions(f):
    contrib = {}
    contrib['URL Length'] = min(20, (f['url_len'] - 30) * 0.2) if f['url_len'] > 50 else -3
    contrib['Domain Entropy'] = f['domain_entropy'] * 4 if f['domain_entropy'] > 3.5 else -3
    contrib['Special Chars'] = f['num_special_chars'] * 2

    if f['use_of_ip']:       contrib['IP Masking'] = 30
    if f['has_shortening_service']: contrib['URL Shortener'] = 25
    if f['has_javascript_code']:    contrib['JS Injection'] = 40
    if f['has_text_encoding']:      contrib['Obfuscation'] = 20
    if f['subdomain_count'] > 2:    contrib['Subdomains'] = 15
    if f['has_at_symbol']:          contrib['At Symbol'] = 20
    if f['suspicious_tld']:         contrib['Suspicious TLD'] = 25

    return contrib


if __name__ == '__main__':
    app.run(debug=True, port=5000)