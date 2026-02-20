"""
Data preprocessing pipeline for UNSW-NB15 and CIC-IDS-2017 datasets.
Handles: loading, cleaning, encoding, scaling, balancing, and splitting.
"""

import os
import warnings
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
import joblib

warnings.filterwarnings("ignore")

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.config import (
    UNSW_TRAIN, UNSW_TEST, CIC_IDS_2017_DIR,
    UNSW_DROP_COLS, UNSW_CAT_COLS, UNSW_TARGET, CIC_TARGET,
    PROCESSED_DIR, MODELS_DIR, RANDOM_STATE, TEST_SIZE,
)


# ═══════════════════════════════════════════════════════════════
#  UNSW-NB15 Preprocessing
# ═══════════════════════════════════════════════════════════════

def load_unsw():
    """Load and concatenate UNSW-NB15 training + testing sets."""
    df_train = pd.read_csv(UNSW_TRAIN)
    df_test = pd.read_csv(UNSW_TEST)
    df = pd.concat([df_train, df_test], ignore_index=True)
    print(f"[UNSW-NB15] Loaded {len(df)} rows, {df.shape[1]} columns")
    return df


def clean_unsw(df: pd.DataFrame) -> pd.DataFrame:
    """Clean UNSW-NB15 data: drop cols, handle missing, remove inf."""
    df = df.drop(columns=UNSW_DROP_COLS, errors="ignore")

    # Replace inf/-inf with NaN then fill
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    # Fill numeric with median
    num_cols = df.select_dtypes(include=[np.number]).columns
    df[num_cols] = df[num_cols].fillna(df[num_cols].median())
    # Fill categorical with mode
    cat_cols = df.select_dtypes(include=["object"]).columns
    for c in cat_cols:
        df[c] = df[c].fillna(df[c].mode()[0])

    print(f"[UNSW-NB15] Cleaned → {df.shape}")
    return df


def encode_unsw(df: pd.DataFrame):
    """Label-encode categorical features. Returns df and encoders dict."""
    encoders = {}
    for col in UNSW_CAT_COLS:
        if col in df.columns:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            encoders[col] = le
    print(f"[UNSW-NB15] Encoded {len(encoders)} categorical columns")
    return df, encoders


def scale_features(X_train, X_test):
    """StandardScaler fit on train, transform both."""
    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc = scaler.transform(X_test)
    return X_train_sc, X_test_sc, scaler


def preprocess_unsw(apply_smote=True):
    """Full UNSW-NB15 preprocessing pipeline. Returns ready-to-train data."""
    df = load_unsw()
    df = clean_unsw(df)
    df, encoders = encode_unsw(df)

    X = df.drop(columns=[UNSW_TARGET])
    y = df[UNSW_TARGET]

    feature_names = list(X.columns)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    # Scale
    X_train_sc, X_test_sc, scaler = scale_features(X_train, X_test)

    # SMOTE for class imbalance
    if apply_smote:
        smote = SMOTE(random_state=RANDOM_STATE)
        X_train_sc, y_train = smote.fit_resample(X_train_sc, y_train)
        print(f"[UNSW-NB15] SMOTE applied → train {X_train_sc.shape[0]} samples")

    # Save artifacts
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler_unsw.pkl"))
    joblib.dump(encoders, os.path.join(MODELS_DIR, "encoders_unsw.pkl"))
    joblib.dump(feature_names, os.path.join(MODELS_DIR, "feature_names_unsw.pkl"))

    # Save processed arrays
    np.save(os.path.join(PROCESSED_DIR, "X_train_unsw.npy"), X_train_sc)
    np.save(os.path.join(PROCESSED_DIR, "X_test_unsw.npy"), X_test_sc)
    np.save(os.path.join(PROCESSED_DIR, "y_train_unsw.npy"), y_train)
    np.save(os.path.join(PROCESSED_DIR, "y_test_unsw.npy"), y_test)

    print(f"[UNSW-NB15] Saved processed data → {PROCESSED_DIR}")
    print(f"  Train: {X_train_sc.shape}, Test: {X_test_sc.shape}")
    return X_train_sc, X_test_sc, np.array(y_train), np.array(y_test), feature_names


# ═══════════════════════════════════════════════════════════════
#  CIC-IDS-2017 Preprocessing
# ═══════════════════════════════════════════════════════════════

def load_cic():
    """Load all CIC-IDS-2017 CSV files into a single DataFrame."""
    frames = []
    for fname in sorted(os.listdir(CIC_IDS_2017_DIR)):
        if fname.endswith(".csv"):
            fp = os.path.join(CIC_IDS_2017_DIR, fname)
            df = pd.read_csv(fp)
            frames.append(df)
            print(f"  Loaded {fname}: {len(df)} rows")
    df = pd.concat(frames, ignore_index=True)
    print(f"[CIC-IDS-2017] Total: {len(df)} rows, {df.shape[1]} columns")
    return df


def clean_cic(df: pd.DataFrame) -> pd.DataFrame:
    """Clean CIC-IDS-2017 data."""
    # Strip whitespace from column names
    df.columns = df.columns.str.strip()

    # Binary label: BENIGN=0, Attack=1
    df["Label_binary"] = (df["Label"] != "BENIGN").astype(int)

    # Drop non-numeric / problematic columns
    drop_cols = ["Flow ID", "Source IP", "Source Port",
                 "Destination IP", "Destination Port", "Timestamp", "Label"]
    df = df.drop(columns=[c for c in drop_cols if c in df.columns], errors="ignore")

    # Replace inf and NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    num_cols = df.select_dtypes(include=[np.number]).columns
    df[num_cols] = df[num_cols].fillna(df[num_cols].median())

    print(f"[CIC-IDS-2017] Cleaned → {df.shape}")
    return df


def preprocess_cic(sample_size=500_000, apply_smote=False):
    """Full CIC-IDS-2017 preprocessing pipeline."""
    df = load_cic()
    df = clean_cic(df)

    # Sample to keep memory manageable
    if sample_size and len(df) > sample_size:
        df = df.sample(n=sample_size, random_state=RANDOM_STATE)
        print(f"[CIC-IDS-2017] Sampled to {sample_size} rows")

    X = df.drop(columns=["Label_binary"])
    y = df["Label_binary"]
    feature_names = list(X.columns)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    X_train_sc, X_test_sc, scaler = scale_features(X_train, X_test)

    if apply_smote:
        smote = SMOTE(random_state=RANDOM_STATE)
        X_train_sc, y_train = smote.fit_resample(X_train_sc, y_train)
        print(f"[CIC-IDS-2017] SMOTE → train {X_train_sc.shape[0]} samples")

    os.makedirs(PROCESSED_DIR, exist_ok=True)
    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler_cic.pkl"))
    joblib.dump(feature_names, os.path.join(MODELS_DIR, "feature_names_cic.pkl"))

    np.save(os.path.join(PROCESSED_DIR, "X_train_cic.npy"), X_train_sc)
    np.save(os.path.join(PROCESSED_DIR, "X_test_cic.npy"), X_test_sc)
    np.save(os.path.join(PROCESSED_DIR, "y_train_cic.npy"), y_train)
    np.save(os.path.join(PROCESSED_DIR, "y_test_cic.npy"), y_test)

    print(f"[CIC-IDS-2017] Saved processed data → {PROCESSED_DIR}")
    return X_train_sc, X_test_sc, np.array(y_train), np.array(y_test), feature_names


# ═══════════════════════════════════════════════════════════════
#  Main entry point
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  PREPROCESSING UNSW-NB15")
    print("=" * 60)
    preprocess_unsw()

    print("\n" + "=" * 60)
    print("  PREPROCESSING CIC-IDS-2017")
    print("=" * 60)
    preprocess_cic()

    print("\n✅ All preprocessing complete!")
