"""
ML Model Trainer for Phishing URL Detection
Uses PhiUSIIL dataset + PhishStorm (urlset.csv)
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    accuracy_score, precision_score, recall_score, f1_score
)
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
import warnings
warnings.filterwarnings('ignore')

try:
    import xgboost as xgb
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

try:
    import lightgbm as lgb
    HAS_LGB = True
except ImportError:
    HAS_LGB = False


# ========================================================================
# Configuration
# ========================================================================

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / 'data'
MODEL_DIR = BASE_DIR / 'models'

PHIUSIIL_PATH = Path(r"C:\Users\ADMIN\Downloads\phiusiil_extracted\PhiUSIIL_Phishing_URL_Dataset.csv")
URLSET_PATH   = Path(r"C:\Users\ADMIN\Downloads\urlset_extracted\urlset.csv")
PHISHTANK_PATH = Path(r"C:\Users\ADMIN\Downloads\verified_online.csv")

MODEL_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# PhiUSIIL feature columns used for training
PHIUSIIL_FEATURES = [
    'URLLength', 'DomainLength', 'IsDomainIP', 'TLD', 'URLSimilarityIndex',
    'CharContinuationRate', 'TLDLegitimateProb', 'URLCharProb', 'TLDLength',
    'NoOfSubDomain', 'HasObfuscation', 'NoOfObfuscatedChar', 'ObfuscationRatio',
    'NoOfLettersInURL', 'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL',
    'NoOfEqualsInURL', 'NoOfQMarkInURL', 'NoOfAmpersandInURL',
    'NoOfOtherSpecialCharsInURL', 'SpacialCharRatioInURL', 'IsHTTPS',
    'LineOfCode', 'LargestLineLength', 'HasTitle', 'DomainTitleMatchScore',
    'URLTitleMatchScore', 'HasFavicon', 'Robots', 'IsResponsive',
    'NoOfURLRedirect', 'NoOfSelfRedirect', 'HasDescription', 'NoOfPopup',
    'NoOfiFrame', 'HasExternalFormSubmit', 'HasSocialNet', 'HasSubmitButton',
    'HasHiddenFields', 'HasPasswordField', 'Bank', 'Pay', 'Crypto',
    'HasCopyrightInfo', 'NoOfImage', 'NoOfCSS', 'NoOfJS',
    'NoOfSelfRef', 'NoOfEmptyRef', 'NoOfExternalRef'
]


# ========================================================================
# Data Loading & Preprocessing
# ========================================================================

def load_phiusiil(path: Path, sample_frac: float = 1.0) -> pd.DataFrame:
    """Load and preprocess the PhiUSIIL dataset."""
    print(f"[*] Loading PhiUSIIL dataset from: {path}")
    df = pd.read_csv(path, low_memory=False, encoding='latin-1', on_bad_lines='skip')
    print(f"    Shape: {df.shape}")
    print(f"    Label distribution:\n{df['label'].value_counts()}")

    # label: 1 = legitimate, 0 = phishing → keep as-is
    available = [c for c in PHIUSIIL_FEATURES if c in df.columns]
    df = df[available + ['label']].copy()

    # Drop rows with all-NaN features
    df.dropna(how='all', subset=available, inplace=True)

    # Sample if needed
    if sample_frac < 1.0:
        df = df.sample(frac=sample_frac, random_state=42)

    df.rename(columns={'label': 'Label'}, inplace=True)
    df['source'] = 'phiusiil'
    return df


def load_urlset(path: Path) -> pd.DataFrame:
    """Load PhishStorm urlset.csv (label 1.0 = phishing)."""
    print(f"\n[*] Loading PhishStorm dataset from: {path}")
    df = pd.read_csv(path, low_memory=False, encoding='latin-1', on_bad_lines='skip')
    print(f"    Shape: {df.shape}")

    # Columns: domain, ranking, mld_res, mld.ps_res, card_rem, ratio_Rrem,
    #          ratio_Arem, jaccard_RR, jaccard_RA, jaccard_AR, jaccard_AA,
    #          jaccard_ARrd, jaccard_ARrem, label
    # label = 1.0 phishing, 0.0 legitimate
    df = df.copy()
    df['Label'] = df['label'].apply(lambda x: 0 if float(x) == 1.0 else 1)  # invert to match PhiUSIIL
    df['source'] = 'urlset'
    # Keep only numeric columns (deduplicated)
    numeric_cols = list(dict.fromkeys(df.select_dtypes(include=[np.number]).columns.tolist()))
    df = df[numeric_cols + ['Label', 'source']]
    df = df.loc[:, ~df.columns.duplicated()]
    return df


def build_combined_dataset(phiusiil_df: pd.DataFrame, urlset_df: pd.DataFrame) -> pd.DataFrame:
    """
    Merge common numeric columns from both datasets.
    PhiUSIIL is the primary (larger) dataset; urlset adds extra samples.
    """
    # Deduplicate columns in each df first (keep first occurrence)
    phiusiil_df = phiusiil_df.loc[:, ~phiusiil_df.columns.duplicated()]
    urlset_df   = urlset_df.loc[:, ~urlset_df.columns.duplicated()]

    # Find shared numeric columns (excluding Label and source)
    p_cols = set(phiusiil_df.select_dtypes(include=[np.number]).columns) - {'Label'}
    u_cols = set(urlset_df.select_dtypes(include=[np.number]).columns) - {'Label'}
    shared = list(p_cols & u_cols)

    df_p = phiusiil_df[shared + ['Label', 'source']].copy()
    df_u = urlset_df[shared + ['Label', 'source']].copy()

    combined = pd.concat([df_p, df_u], ignore_index=True)
    print(f"\n[*] Combined dataset shape: {combined.shape}")
    print(f"    Label distribution:\n{combined['Label'].value_counts()}")
    return combined, shared


# ========================================================================
# Training
# ========================================================================

def train_models(X_train, X_test, y_train, y_test, feature_names):
    """Train multiple classifiers and return the best one."""

    models = {
        'RandomForest': Pipeline([
            ('imputer', SimpleImputer(strategy='median')),
            ('clf', RandomForestClassifier(
                n_estimators=200, max_depth=20,
                min_samples_leaf=2, n_jobs=-1,
                random_state=42, class_weight='balanced'
            ))
        ]),
        'GradientBoosting': Pipeline([
            ('imputer', SimpleImputer(strategy='median')),
            ('clf', GradientBoostingClassifier(
                n_estimators=150, learning_rate=0.1,
                max_depth=6, random_state=42
            ))
        ]),
        'LogisticRegression': Pipeline([
            ('imputer', SimpleImputer(strategy='median')),
            ('scaler', StandardScaler()),
            ('clf', LogisticRegression(max_iter=1000, C=1.0, random_state=42))
        ]),
    }

    if HAS_XGB:
        models['XGBoost'] = Pipeline([
            ('imputer', SimpleImputer(strategy='median')),
            ('clf', xgb.XGBClassifier(
                n_estimators=200, learning_rate=0.1,
                max_depth=6, use_label_encoder=False,
                eval_metric='logloss', random_state=42,
                n_jobs=-1
            ))
        ])

    if HAS_LGB:
        models['LightGBM'] = Pipeline([
            ('imputer', SimpleImputer(strategy='median')),
            ('clf', lgb.LGBMClassifier(
                n_estimators=200, learning_rate=0.1,
                max_depth=6, random_state=42,
                n_jobs=-1, verbose=-1
            ))
        ])

    results = {}
    best_model = None
    best_f1 = -1

    print("\n" + "=" * 60)
    print("MODEL TRAINING RESULTS")
    print("=" * 60)

    for name, pipeline in models.items():
        print(f"\n[*] Training {name}...")
        pipeline.fit(X_train, y_train)
        y_pred = pipeline.predict(X_test)
        y_proba = pipeline.predict_proba(X_test)[:, 1] if hasattr(pipeline, 'predict_proba') else None

        acc  = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec  = recall_score(y_test, y_pred)
        f1   = f1_score(y_test, y_pred)
        auc  = roc_auc_score(y_test, y_proba) if y_proba is not None else None

        results[name] = {
            'accuracy': acc, 'precision': prec,
            'recall': rec, 'f1': f1, 'auc': auc
        }

        print(f"    Accuracy : {acc:.4f}")
        print(f"    Precision: {prec:.4f}")
        print(f"    Recall   : {rec:.4f}")
        print(f"    F1-Score : {f1:.4f}")
        if auc:
            print(f"    ROC-AUC  : {auc:.4f}")
        print(classification_report(y_test, y_pred, target_names=['Phishing', 'Legitimate']))

        if f1 > best_f1:
            best_f1 = f1
            best_model = (name, pipeline)

    print(f"\n[✓] Best model: {best_model[0]} (F1={best_f1:.4f})")
    return best_model, results


def save_artifacts(best_model_name, pipeline, feature_names, results, shared_cols):
    """Save the trained model and metadata."""
    model_path = MODEL_DIR / 'phishing_model.joblib'
    meta_path  = MODEL_DIR / 'model_metadata.json'

    joblib.dump(pipeline, model_path)

    metadata = {
        'best_model': best_model_name,
        'feature_names': feature_names,
        'shared_columns': shared_cols,
        'results': results,
        'trained_at': pd.Timestamp.now().isoformat()
    }
    with open(meta_path, 'w') as f:
        json.dump(metadata, f, indent=2)

    print(f"\n[✓] Model saved  → {model_path}")
    print(f"[✓] Metadata saved → {meta_path}")


# ========================================================================
# Main
# ========================================================================

def main():
    print("=" * 60)
    print("PHISHING URL DETECTION — MODEL TRAINING")
    print("=" * 60)

    # Load primary dataset (PhiUSIIL)
    phiusiil_df = load_phiusiil(PHIUSIIL_PATH)

    # Try to load and combine urlset if columns overlap
    combined = phiusiil_df.copy()
    shared_cols = None

    if URLSET_PATH.exists():
        try:
            urlset_df = load_urlset(URLSET_PATH)
            combined_try, shared = build_combined_dataset(phiusiil_df, urlset_df)
            if len(shared) > 0:
                combined = combined_try
                shared_cols = shared
                print(f"[✓] Merged datasets. Shared numeric features: {len(shared)}")
            else:
                print("[!] urlset.csv shares no numeric columns with PhiUSIIL — training on PhiUSIIL only.")
        except Exception as e:
            print(f"[!] Could not merge urlset: {e} — training on PhiUSIIL only.")

    combined.drop(columns=['source'], inplace=True, errors='ignore')

    # Feature columns: use PhiUSIIL features that exist in combined AND are numeric
    if shared_cols is not None:
        feature_cols = [c for c in shared_cols if c != 'Label']
    else:
        feature_cols = [c for c in PHIUSIIL_FEATURES if c in combined.columns]

    # Keep only truly numeric features (drop string columns like TLD)
    numeric_mask = combined[feature_cols].apply(
        lambda col: pd.to_numeric(col, errors='coerce').notna().mean() > 0.5
    )
    feature_cols = [c for c in feature_cols if numeric_mask[c]]

    X = combined[feature_cols].apply(pd.to_numeric, errors='coerce').values
    y = combined['Label'].values

    print(f"\n[*] Features used for training: {len(feature_cols)}")
    print(f"    Feature list: {feature_cols}")
    print(f"    Dataset size: {len(X):,} rows")

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\n[*] Train size: {len(X_train):,}  |  Test size: {len(X_test):,}")

    # Train
    (best_name, best_pipeline), all_results = train_models(
        X_train, X_test, y_train, y_test, feature_cols
    )

    # Save
    save_artifacts(best_name, best_pipeline, feature_cols, all_results,
                   feature_cols if shared_cols is None else shared_cols)

    print("\n[✓] Training complete!")
    return best_pipeline, feature_cols


if __name__ == '__main__':
    main()

