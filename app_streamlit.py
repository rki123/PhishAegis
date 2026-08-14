"""
DIAGNOSTIC VERSION — shows the exact crash traceback in the UI
instead of "Oh no. Error running app."
"""
import streamlit as st
import traceback
import os, sys

st.set_page_config(page_title="PhishAegis — Diagnostic", page_icon="🛡️", layout="wide")

st.title("🛡️ PhishAegis — Diagnostic Mode")
st.info("This diagnostic build shows exact error details. Replace with app_streamlit.py once resolved.")

# ── STEP 1: Check imports ──────────────────────────────────────────────────────
st.subheader("Step 1: Import Check")
import_errors = []

try:
    import pandas as pd
    st.success("✅ pandas OK")
except Exception as e:
    st.error(f"❌ pandas: {e}"); import_errors.append("pandas")

try:
    import numpy as np
    st.success("✅ numpy OK")
except Exception as e:
    st.error(f"❌ numpy: {e}"); import_errors.append("numpy")

try:
    import joblib
    st.success("✅ joblib OK")
except Exception as e:
    st.error(f"❌ joblib: {e}"); import_errors.append("joblib")

try:
    import sklearn
    st.success(f"✅ scikit-learn {sklearn.__version__} OK")
except Exception as e:
    st.error(f"❌ sklearn: {e}"); import_errors.append("sklearn")

try:
    import xgboost
    st.success(f"✅ xgboost {xgboost.__version__} OK")
except Exception as e:
    st.error(f"❌ xgboost: {e}"); import_errors.append("xgboost")

try:
    import plotly
    st.success("✅ plotly OK")
except Exception as e:
    st.error(f"❌ plotly: {e}"); import_errors.append("plotly")

try:
    import tensorflow as tf
    st.success(f"✅ tensorflow {tf.__version__} OK")
except ImportError:
    st.warning("⚠️ tensorflow not installed (CNN will be skipped)")
except Exception as e:
    st.error(f"❌ tensorflow error: {e}")

# ── STEP 2: Check src imports ──────────────────────────────────────────────────
st.subheader("Step 2: Local Module Check")
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

try:
    from src.extraction import extract_features, get_feature_names
    st.success("✅ src.extraction OK")
except Exception as e:
    st.error(f"❌ src.extraction failed:\n```\n{traceback.format_exc()}\n```")

try:
    from src.deep_model import urls_to_sequences
    st.success("✅ src.deep_model OK")
except Exception as e:
    st.error(f"❌ src.deep_model failed:\n```\n{traceback.format_exc()}\n```")

# ── STEP 3: Secrets Check ──────────────────────────────────────────────────────
st.subheader("Step 3: Secrets Check")
try:
    hf_repo_id = st.secrets.get("HF_REPO_ID", None)
    hf_token   = st.secrets.get("HF_TOKEN", None)
    st.success(f"✅ HF_REPO_ID = `{hf_repo_id}`")
    st.success(f"✅ HF_TOKEN = `{'set (hidden)' if hf_token else 'NOT SET'}`")
except Exception as e:
    hf_repo_id = os.environ.get("HF_REPO_ID", None)
    hf_token   = os.environ.get("HF_TOKEN", None)
    st.warning(f"Secrets fallback to env vars: HF_REPO_ID={hf_repo_id}")

# ── STEP 4: Load each model individually ──────────────────────────────────────
st.subheader("Step 4: Individual Model Load Test")
model_dir = os.path.join(os.path.dirname(__file__), 'models')
os.makedirs(model_dir, exist_ok=True)

def try_download(fname):
    """Try to download a file from HF Hub. Return local path or None."""
    local = os.path.join(model_dir, fname)
    if os.path.exists(local):
        st.info(f"  📂 `{fname}` found locally at `{local}`")
        return local
    if hf_repo_id:
        try:
            from huggingface_hub import hf_hub_download
            path = hf_hub_download(repo_id=hf_repo_id, filename=fname,
                                   local_dir=model_dir, token=hf_token)
            st.success(f"  ⬇️ `{fname}` downloaded → `{path}`")
            return path
        except Exception as e:
            st.error(f"  ❌ Download `{fname}` failed: {e}\n```\n{traceback.format_exc()}\n```")
    else:
        st.warning(f"  ⚠️ `{fname}` not local and HF_REPO_ID not set")
    return None

for name, fname in [('LR', 'lr_model.joblib'), ('RF', 'rf_model.joblib'),
                    ('XGB', 'xgb_model.joblib'), ('Ensemble', 'ensemble_model.joblib')]:
    st.markdown(f"**{name} ({fname})**")
    try:
        path = try_download(fname)
        if path:
            model = joblib.load(path)
            st.success(f"  ✅ {name} loaded: `{type(model).__name__}`")
        else:
            st.warning(f"  ⚠️ {name} skipped — file unavailable")
    except Exception as e:
        st.error(f"  ❌ {name} load FAILED:")
        st.code(traceback.format_exc())

# CNN
st.markdown("**CNN (cnn_model.h5 / cnn_model.keras)**")
try:
    import tensorflow as tf
    for cnn_fname in ['cnn_model.h5', 'cnn_model.keras']:
        path = try_download(cnn_fname)
        if path:
            from tensorflow.keras.models import load_model
            cnn = load_model(path)
            st.success(f"  ✅ CNN loaded from `{cnn_fname}`")
            break
    else:
        st.warning("  ⚠️ CNN model file not found")
except ImportError:
    st.warning("  ⚠️ TensorFlow not installed — CNN skipped")
except Exception as e:
    st.error("  ❌ CNN load FAILED:")
    st.code(traceback.format_exc())

st.markdown("---")
st.success("✅ Diagnostic complete. Check above for any ❌ errors.")
