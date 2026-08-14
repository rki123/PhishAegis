# PhishAegis { Malicious Urls Detector System }

[![Python 3.10](https://img.shields.io/badge/python-3.10-blue.svg)](https://www.python.org/downloads/release/python-31011/)
[![TensorFlow 2.10](https://img.shields.io/badge/TensorFlow-2.10_DirectML-orange.svg)](https://tensorflow.org)
[![GPU Accelerated](https://img.shields.io/badge/GPU-NVIDIA_RTX_4060-76b900.svg)](https://developer.nvidia.com/)
[![Streamlit Deployment](https://img.shields.io/badge/Deploy-Hugging_Face_Spaces-red.svg)](https://huggingface.co/spaces)

A state-of-the-art **Hybrid Machine Learning + Deep Learning System** designed to detect malicious phishing URLs in real time. **PhishAegis** combines traditional Machine Learning algorithms (Random Forest, XGBoost) with a GPU-accelerated **Character-Level Convolutional Neural Network (CNN)**.

---

## 🌟 Key Features & Benchmark Results

| Model / Component | Type | Accuracy | Key Highlights |
|---|---|---|---|
| Logistic Regression | Baseline ML | 58.1% | Linear baseline on 16 normalized features |
| Random Forest | Tree ML | 84.2% | 300 estimators, max depth 25 |
| XGBoost | Boosting ML | 82.2% | Gradient boosted decision trees |
| ML Ensemble (RF + XGB) | Soft Voting | 84.0% | Combined lexical decision boundary |
| **Character-Level CNN** | **Deep Learning** | **93.9%** | **Parallel 1D Conv (3, 5, 7), SpatialDropout & L2** |
| **PhishAegis Hybrid** | **Meta-Ensemble** | **93.9% - 94.4%** | **Weighted Fusion (85% CNN + 15% ML)** |

### 🚀 Highlights:
- **GPU Acceleration**: Native DirectML GPU acceleration utilizing NVIDIA GeForce RTX 4060 on Windows.
- **Leakage Prevention**: All URLs stripped of `http://`, `https://`, and `www.` prefixes prior to feature extraction to eliminate protocol bias.
- **Dataset Bias Correction**: Automated injection step to re-balance biased TLD and repository domain labels.
- **Explainable AI (XAI)**: Feature-level risk contribution scoring and threat vector radar profiling.
- **Dual Deployment**: Interactive Flask Dashboard + Full-featured Streamlit Hugging Face Space.
- **Dark Mode Extension**: Chrome Manifest V3 extension with live tab threat scanning.

---

## 📁 Project Structure

```
├── Dataset.csv                          # Dataset (~650k raw URLs)
├── Malicious_URLs_Detection.ipynb       # GPU-Accelerated Training Notebook
├── app_streamlit.py                     # Streamlit App for Hugging Face Spaces Deployment
├── requirements_hf.txt                  # Deployment dependencies for Hugging Face
├── requirements.txt                     # Local environment dependencies
├── src/
│   ├── extraction.py                    # 16 Normalized Lexical Features (Entropy, Depth, IP, TLD)
│   ├── deep_model.py                    # Character-Level 1D CNN Architecture + Regularization
│   └── augmentation.py                  # Synthetic URL Mutation Utilities
├── models/                              # Trained Model Artifacts
│   ├── rf_model.joblib
│   ├── xgb_model.joblib
│   ├── lr_model.joblib
│   ├── ensemble_model.joblib
│   └── cnn_model.keras
├── webapp/                              # Flask Web Application & API Server
│   ├── app.py                           # REST API Endpoint (/predict)
│   ├── templates/
│   │   └── index.html                   # Dark-Glass Dashboard UI
│   └── static/
│       ├── css/style.css                # Glassmorphic Styling & Shield Activation Keyframes
│       ├── js/main.js                   # Chart.js Integration (4 Analytics Charts)
│       └── images/frontendbkg.jpg       # Theme Background Image
└── extension/                           # Chrome Browser Extension (Manifest V3)
    ├── manifest.json
    ├── popup.html
    ├── popup.css
    └── popup.js
```

---

## ⚙️ Model Architecture & Ensemble Formula

```
                   ┌───────────────────────────────┐
                   │          Input URL            │
                   └───────────────┬───────────────┘
                                   │
         ┌─────────────────────────┴─────────────────────────┐
         ▼                                                   ▼
┌──────────────────────────┐               ┌──────────────────────────────────┐
│  Lexical Feature Extractor│               │  Raw Character Tokenizer (1-200) │
│  (16 Mathematical Rules) │               │  (ASCII Vocabulary Embedding)    │
└────────┬─────────────────┘               └────────────────┬─────────────────┘
         │                                                  │
         ▼                                                  ▼
┌──────────────────────────┐               ┌──────────────────────────────────┐
│   ML Ensemble (RF + XGB) │               │   Character-Level 1D CNN         │
│   (Soft Probability)     │               │   (SpatialDropout + L2 Reg)      │
└────────┬─────────────────┘               └────────────────┬─────────────────┘
         │                                                  │
         │ (15% Weight)                                     │ (85% Weight)
         └─────────────────────────┬────────────────────────┘
                                   ▼
                   ┌───────────────────────────────┐
                   │  Hybrid Weighted Probability  │
                   │  P = (0.85 * CNN) + (0.15 * ML)│
                   └───────────────┬───────────────┘
                                   ▼
                   ┌───────────────────────────────┐
                   │  Verdict: SAFE / CRITICAL     │
                   └───────────────────────────────┘
```

---

## 💻 Installation & Local Usage

### 1. Prerequisites
- Python 3.10.11
- NVIDIA GPU with DirectX 12 support (Optional, for DirectML acceleration)

### 2. Environment Setup
```bash
# Clone Repository
git clone https://github.com/<your-username>/Malicious-URLs-Detection-using-Machine-Learning.git
cd Malicious-URLs-Detection-using-Machine-Learning

# Install Local Dependencies
pip install -r requirements.txt
```

### 3. Training
Open `Malicious_URLs_Detection.ipynb` in VS Code or Jupyter Notebook, select the Python 3.10 kernel, and click **Run All**. The notebook will:
1. Load 150,000 clean balanced URLs.
2. Train Random Forest, XGBoost, and Voting Ensemble.
3. Train GPU-Accelerated 1D CNN with EarlyStopping and ReduceLROnPlateau.
4. Save trained artifacts into `models/`.

### 4. Running Web Dashboard
```bash
python webapp/app.py
```
Open **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your browser.

---

## 🧩 Chrome Extension Setup

1. Open Google Chrome and navigate to `chrome://extensions`.
2. Enable **Developer mode** (toggle in top-right corner).
3. Click **Load unpacked** and select the `extension/` folder inside the project.
4. Pin **PhishAegis** to your Chrome toolbar.
5. Click the shield icon on any tab to scan in real time!

---

## 🌐 Deploying to Hugging Face Spaces (Free)

1. Create a free account at **[huggingface.co/spaces](https://huggingface.co/spaces)**.
2. Click **Create new Space**, select **Streamlit**, and choose **CPU basic (Free)**.
3. Upload `app_streamlit.py` (rename to `app.py`), `requirements_hf.txt` (rename to `requirements.txt`), `src/`, and `models/`.
4. Your live app will be hosted automatically at `https://huggingface.co/spaces/YOUR_USERNAME/PhishAegis`!

---

## 📜 License

This project is open-source and available under the MIT License.
