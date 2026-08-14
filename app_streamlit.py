import streamlit as st
import pandas as pd
import numpy as np
import os, sys
import joblib
import plotly.graph_objects as go
import plotly.express as px

# Ensure project modules can be imported
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from src.extraction import extract_features, get_feature_names
from src.deep_model import urls_to_sequences

# Page Configuration
st.set_page_config(
    page_title="PhishAegis { Malicious Urls Detector System }",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Dark Theme CSS
st.markdown("""
<style>
    .stApp {
        background-color: #090d16;
        color: #f8fafc;
    }
    .main-header {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(135deg, #60a5fa 0%, #a855f7 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1rem;
        color: #94a3b8;
        margin-bottom: 1.5rem;
    }
    .spec-card {
        background: rgba(15, 23, 42, 0.75);
        border: 1px solid rgba(255, 255, 255, 0.12);
        padding: 0.8rem 1.2rem;
        border-radius: 0.75rem;
        margin-bottom: 1.5rem;
        display: flex;
        justify-content: space-around;
    }
    .verdict-badge {
        display: inline-block;
        padding: 0.5rem 1.5rem;
        border-radius: 0.5rem;
        font-size: 1.4rem;
        font-weight: 800;
        text-transform: uppercase;
        margin-bottom: 1rem;
    }
    .badge-SAFE {
        background: rgba(16, 185, 129, 0.15);
        color: #10b981;
        border: 1px solid #10b981;
    }
    .badge-WARNING {
        background: rgba(245, 158, 11, 0.15);
        color: #f59e0b;
        border: 1px solid #f59e0b;
    }
    .badge-CRITICAL {
        background: rgba(244, 63, 94, 0.15);
        color: #f43f5e;
        border: 1px solid #f43f5e;
    }
    .reason-box {
        background: rgba(15, 23, 42, 0.6);
        border-left: 4px solid #3b82f6;
        padding: 0.8rem 1rem;
        border-radius: 0.4rem;
        margin-bottom: 0.6rem;
    }
</style>
""", unsafe_allow_html=True)

# Load Models (Local or Hugging Face Hub)
@st.cache_resource
def load_all_models(hf_repo_id=None):
    model_dir = os.path.join(os.path.dirname(__file__), 'models')
    os.makedirs(model_dir, exist_ok=True)
    models = {}
    cnn_model = None

    # Hugging Face Hub downloader fallback
    def get_model_path(filename):
        local_path = os.path.join(model_dir, filename)
        if os.path.exists(local_path):
            return local_path
        if hf_repo_id:
            try:
                from huggingface_hub import hf_hub_download
                st.info(f"Downloading {filename} from Hugging Face Hub...")
                return hf_hub_download(
                    repo_id=hf_repo_id,
                    filename=filename,
                    local_dir=model_dir,
                    token=hf_token
                )
            except Exception as e:
                st.warning(f"Could not download {filename} from HF Hub: {e}")
        return None

    # 1. Load ML Models
    for name, fname in [('lr', 'lr_model.joblib'), ('rf', 'rf_model.joblib'), 
                        ('xgb', 'xgb_model.joblib'), ('ensemble', 'ensemble_model.joblib')]:
        path = get_model_path(fname)
        if path and os.path.exists(path):
            try:
                models[name] = joblib.load(path)
            except Exception as e:
                st.warning(f"Note loading {fname}: {e}")

    # 2. Load CNN Deep Learning Model (.h5 preferred for cross-version compatibility)
    cnn_path = get_model_path('cnn_model.h5') or get_model_path('cnn_model.keras')
    if cnn_path and os.path.exists(cnn_path):
        try:
            from tensorflow.keras.models import load_model
            cnn_model = load_model(cnn_path)
        except Exception as e:
            st.warning(f"Note loading CNN: {e}")

    return models, cnn_model

# Check if HF_REPO_ID and HF_TOKEN are set in secrets/environment
hf_repo_id = None
hf_token = None
try:
    hf_repo_id = st.secrets.get("HF_REPO_ID", None)
    hf_token = st.secrets.get("HF_TOKEN", None)
except Exception:
    hf_repo_id = os.environ.get("HF_REPO_ID", None)
    hf_token = os.environ.get("HF_TOKEN", None)

models, cnn_model = load_all_models(hf_repo_id)

# Sidebar Setup
st.sidebar.markdown("### 🛡️ PhishAegis Settings")
st.sidebar.markdown("---")

model_options = []
if cnn_model is not None and 'ensemble' in models:
    model_options.append("Hybrid (85% CNN + 15% ML)")
if cnn_model is not None:
    model_options.append("Deep Learning CNN")
if 'ensemble' in models:
    model_options.append("ML Ensemble (RF+XGB)")
if 'xgb' in models:
    model_options.append("XGBoost Classifier")
if 'rf' in models:
    model_options.append("Random Forest Classifier")

selected_engine = st.sidebar.selectbox("Detection Engine", model_options if model_options else ["ML Ensemble"])

st.sidebar.markdown("---")
st.sidebar.markdown("**Architecture Specs:**")
st.sidebar.markdown("- **CNN Weight:** 85%")
st.sidebar.markdown("- **ML Weight:** 15%")
st.sidebar.markdown("- **Corpus Size:** 150,000 URLs")

# Header Section
st.markdown('<div class="main-header">🛡️ PhishAegis</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Malicious URLs Detector System — Real-Time Deep & Lexical Inspection</div>', unsafe_allow_html=True)

# URL Input Section
url_input = st.text_input("Enter URL to analyze:", placeholder="https://paypa1-verify-account.com/login", key="input_url")
analyze_clicked = st.button("⚡ Analyze URL", use_container_width=True)

if analyze_clicked and url_input.strip():
    url = url_input.strip()
    
    # Feature Extraction
    raw_features = extract_features(url)
    feature_names = get_feature_names()
    X_input = pd.DataFrame([raw_features])[feature_names]

    ml_prob_val = None
    cnn_prob_val = None

    if 'ensemble' in models:
        ml_prob_val = float(models['ensemble'].predict_proba(X_input)[0][1])
    elif 'xgb' in models:
        ml_prob_val = float(models['xgb'].predict_proba(X_input)[0][1])

    if cnn_model is not None:
        seq = urls_to_sequences([url])
        cnn_prob_val = float(cnn_model.predict(seq, verbose=0)[0][0])

    # Determine risk score based on selected engine
    if "Hybrid" in selected_engine and cnn_prob_val is not None and ml_prob_val is not None:
        prob_malicious = (0.15 * ml_prob_val) + (0.85 * cnn_prob_val)
    elif "CNN" in selected_engine and cnn_prob_val is not None:
        prob_malicious = cnn_prob_val
    elif ml_prob_val is not None:
        prob_malicious = ml_prob_val
    else:
        prob_malicious = 0.5

    risk_score = round(prob_malicious * 100, 1)
    safety_score = round((1.0 - prob_malicious) * 100, 1)

    status = "SAFE"
    if risk_score > 65:
        status = "CRITICAL"
    elif risk_score > 35:
        status = "WARNING"

    st.markdown("---")

    # Top Verdict Banner
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f'<div class="verdict-badge badge-{status}">{status}</div>', unsafe_allow_html=True)
    with col2:
        st.metric("Phishing Risk Score", f"{risk_score}%", delta=f"{risk_score}%" if status != "SAFE" else None, delta_color="inverse")
    with col3:
        st.metric("CNN Deep Learning Score", f"{round(cnn_prob_val*100, 1)}%" if cnn_prob_val else "N/A")
    with col4:
        st.metric("ML Ensemble Score", f"{round(ml_prob_val*100, 1)}%" if ml_prob_val else "N/A")

    st.caption(f"Scanned URL: `{url}`")

    # Threat Flags & Reasons
    flags = []
    reasons = []

    if raw_features['use_of_ip']:
        flags.append("Direct IP Masking")
        reasons.append("URL uses a raw IP address instead of a legitimate domain name.")
    if raw_features['has_shortening_service']:
        flags.append("URL Shortener Detected")
        reasons.append("URL relies on a link shortening service hiding the target URL.")
    if raw_features['domain_entropy'] > 4.0:
        flags.append(f"High Domain Entropy ({raw_features['domain_entropy']:.2f})")
        reasons.append("Domain name exhibits high character randomness typical of DGA domains.")
    if raw_features['num_special_chars'] > 7:
        flags.append(f"Excessive Special Chars ({raw_features['num_special_chars']})")
        reasons.append("Contains a high density of special symbols (@, %, -, ?, =).")
    if raw_features['digit_ratio'] > 0.25:
        flags.append(f"High Digit Ratio ({raw_features['digit_ratio']*100:.1f}%)")
        reasons.append("Elevated proportion of numerical characters in the URL string.")
    if raw_features['has_javascript_code']:
        flags.append("JavaScript Code Pattern")
        reasons.append("Detected pseudo-protocol 'javascript:' code inside the URL.")
    if raw_features['has_text_encoding']:
        flags.append("Percent Obfuscation (%xx)")
        reasons.append("Percent-encoding obfuscation detected.")
    if raw_features['subdomain_count'] > 2:
        flags.append(f"Deep Subdomains ({raw_features['subdomain_count']})")
        reasons.append("Multiple nested subdomains detected.")
    if raw_features['has_at_symbol']:
        flags.append("@ Symbol Redirection")
        reasons.append("Contains '@' symbol causing browser credential override.")
    if raw_features['suspicious_tld']:
        flags.append("Suspicious TLD")
        reasons.append("Top-Level Domain belongs to a high-risk or free TLD registry.")

    if not flags:
        flags.append("Clean Structural Signature")
        reasons.append("No anomalous lexical, structural, or obfuscation indicators found.")

    # Visual Charts Grid
    st.markdown("### 📊 Analytics & Threat Visualization")
    c1, c2 = st.columns(2)

    with c1:
        # Radar Chart
        radar_categories = ['Obfuscation', 'Domain Entropy', 'URL Depth', 'Subdomains', 'Threat Patterns', 'Digit Ratio']
        radar_values = [
            min(100, int(raw_features['has_text_encoding']*40 + raw_features['has_at_symbol']*30 + raw_features['num_special_chars']*6)),
            min(100, int(raw_features['domain_entropy'] * 22)),
            min(100, int((raw_features['url_len'] / 110.0) * 100)),
            min(100, int(raw_features['subdomain_count'] * 33)),
            min(100, int(raw_features['use_of_ip']*45 + raw_features['suspicious_tld']*45 + raw_features['has_shortening_service']*35)),
            min(100, int(raw_features['digit_ratio'] * 100))
        ]
        
        fig_radar = go.Figure(data=go.Scatterpolar(
            r=radar_values,
            theta=radar_categories,
            fill='toself',
            fillcolor='rgba(244, 63, 94, 0.25)' if status != "SAFE" else 'rgba(16, 185, 129, 0.25)',
            line=dict(color='#f43f5e' if status != "SAFE" else '#10b981', width=2)
        ))
        fig_radar.update_layout(
            polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
            showlegend=False,
            title="🕸️ Threat Vector Radar Profile",
            template="plotly_dark",
            height=350
        )
        st.plotly_chart(fig_radar, use_container_width=True)

    with c2:
        # Model Comparison Chart
        all_scores = {}
        if 'rf' in models:
            all_scores['Random Forest'] = round(float(models['rf'].predict_proba(X_input)[0][1]) * 100, 1)
        if 'xgb' in models:
            all_scores['XGBoost'] = round(float(models['xgb'].predict_proba(X_input)[0][1]) * 100, 1)
        if 'ensemble' in models:
            all_scores['ML Ensemble'] = round(float(models['ensemble'].predict_proba(X_input)[0][1]) * 100, 1)
        if cnn_prob_val:
            all_scores['CNN Deep Learning'] = round(cnn_prob_val * 100, 1)
        all_scores['Hybrid (85/15)'] = risk_score

        df_scores = pd.DataFrame({'Model': list(all_scores.keys()), 'Risk %': list(all_scores.values())})
        fig_models = px.bar(df_scores, x='Model', y='Risk %', title="🤖 Model Prediction Comparison", color='Risk %', color_continuous_scale='Reds' if status != "SAFE" else 'Greens')
        fig_models.update_layout(template="plotly_dark", height=350, yaxis_range=[0, 100])
        st.plotly_chart(fig_models, use_container_width=True)

    # Detailed Forensic Reasons
    st.markdown("### 🔍 Forensic Analysis & Threat Reasons")
    for f, r in zip(flags, reasons):
        st.markdown(f'<div class="reason-box"><strong>• {f}</strong><br><span style="color:#94a3b8; font-size:0.9rem;">{r}</span></div>', unsafe_allow_html=True)

    # Raw Statistics Grid
    st.markdown("### 📈 Calculated URL Statistics")
    stat_cols = st.columns(5)
    stat_data = [
        ("URL Length", raw_features['url_len']),
        ("Hostname Length", raw_features['hostname_length']),
        ("Domain Entropy", f"{raw_features['domain_entropy']:.2f}"),
        ("Special Chars", raw_features['num_special_chars']),
        ("Path Depth", raw_features['path_depth']),
        ("Subdomains", raw_features['subdomain_count']),
        ("Digit Ratio", f"{raw_features['digit_ratio']*100:.1f}%"),
        ("Suspicious TLD", "Yes" if raw_features['suspicious_tld'] else "No"),
        ("IP Address", "Yes" if raw_features['use_of_ip'] else "No"),
        ("Obfuscated (%xx)", "Yes" if raw_features['has_text_encoding'] else "No")
    ]
    for idx, (lbl, val) in enumerate(stat_data):
        with stat_cols[idx % 5]:
            st.metric(lbl, str(val))
