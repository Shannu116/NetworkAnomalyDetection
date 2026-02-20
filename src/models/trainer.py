"""
Model training, evaluation, and comparison for Network Anomaly Detection.
Trains multiple ML models and selects the best one.
"""

import os
import sys
import json
import time
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import (
    RandomForestClassifier,
    GradientBoostingClassifier,
    IsolationForest,
    VotingClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
    roc_curve,
)
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
import joblib

warnings.filterwarnings("ignore")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.config import PROCESSED_DIR, MODELS_DIR, STATIC_DIR, RANDOM_STATE, N_JOBS


# ═══════════════════════════════════════════════════════════════
#  Model Definitions
# ═══════════════════════════════════════════════════════════════

def get_models():
    """Return a dict of model_name → model_instance."""
    return {
        "Random Forest": RandomForestClassifier(
            n_estimators=200, max_depth=20, random_state=RANDOM_STATE, n_jobs=N_JOBS
        ),
        "XGBoost": XGBClassifier(
            n_estimators=200, max_depth=8, learning_rate=0.1,
            random_state=RANDOM_STATE, n_jobs=N_JOBS,
            eval_metric="logloss", verbosity=0,
        ),
        "LightGBM": LGBMClassifier(
            n_estimators=200, max_depth=8, learning_rate=0.1,
            random_state=RANDOM_STATE, n_jobs=N_JOBS, verbose=-1,
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=15, random_state=RANDOM_STATE
        ),
        "KNN": KNeighborsClassifier(n_neighbors=5, n_jobs=N_JOBS),
        "Logistic Regression": LogisticRegression(
            max_iter=1000, random_state=RANDOM_STATE, n_jobs=N_JOBS
        ),
        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators=100, max_depth=5, learning_rate=0.1,
            random_state=RANDOM_STATE,
        ),
    }


# ═══════════════════════════════════════════════════════════════
#  Training & Evaluation
# ═══════════════════════════════════════════════════════════════

def evaluate_model(model, X_test, y_test, model_name="Model"):
    """Evaluate a trained model and return metrics dict."""
    y_pred = model.predict(X_test)

    try:
        y_prob = model.predict_proba(X_test)[:, 1]
        roc_auc = roc_auc_score(y_test, y_prob)
    except Exception:
        y_prob = None
        roc_auc = None

    metrics = {
        "model": model_name,
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1_score": round(f1_score(y_test, y_pred, zero_division=0), 4),
        "roc_auc": round(roc_auc, 4) if roc_auc else None,
    }
    return metrics, y_pred, y_prob


def train_and_evaluate_all(X_train, X_test, y_train, y_test, dataset_name="unsw"):
    """Train all models, evaluate, save results and plots."""
    models = get_models()
    results = []
    trained_models = {}
    plots_dir = os.path.join(STATIC_DIR, "plots")
    os.makedirs(plots_dir, exist_ok=True)

    print(f"\n{'='*70}")
    print(f"  TRAINING & EVALUATING MODELS ON {dataset_name.upper()}")
    print(f"{'='*70}")
    print(f"  Train: {X_train.shape}  |  Test: {X_test.shape}")
    print(f"{'='*70}\n")

    for name, model in models.items():
        print(f"▶ Training {name}...", end=" ", flush=True)
        start = time.time()

        model.fit(X_train, y_train)
        train_time = round(time.time() - start, 2)

        metrics, y_pred, y_prob = evaluate_model(model, X_test, y_test, name)
        metrics["train_time_sec"] = train_time

        results.append(metrics)
        trained_models[name] = model

        print(
            f"✓ ({train_time}s) | "
            f"Acc={metrics['accuracy']:.4f}  "
            f"F1={metrics['f1_score']:.4f}  "
            f"AUC={metrics['roc_auc'] if metrics['roc_auc'] else 'N/A'}"
        )

    # ── Select best model ────────────────────────────────────
    results_df = pd.DataFrame(results)
    best_row = results_df.loc[results_df["f1_score"].idxmax()]
    best_name = best_row["model"]
    best_model = trained_models[best_name]

    print(f"\n🏆 BEST MODEL: {best_name} (F1={best_row['f1_score']:.4f})")

    # ── Save best model ──────────────────────────────────────
    os.makedirs(MODELS_DIR, exist_ok=True)
    model_path = os.path.join(MODELS_DIR, f"best_model_{dataset_name}.pkl")
    joblib.dump(best_model, model_path)
    print(f"   Saved → {model_path}")

    # Save results JSON
    results_path = os.path.join(MODELS_DIR, f"results_{dataset_name}.json")
    results_df.to_json(results_path, orient="records", indent=2)

    # ── Generate visualisation plots ──────────────────────────
    _plot_comparison(results_df, dataset_name, plots_dir)
    _plot_confusion_matrix(best_model, X_test, y_test, best_name, dataset_name, plots_dir)
    _plot_roc_curves(trained_models, X_test, y_test, dataset_name, plots_dir)
    _plot_feature_importance(best_model, dataset_name, plots_dir)

    return best_model, results_df


# ═══════════════════════════════════════════════════════════════
#  Visualisation helpers
# ═══════════════════════════════════════════════════════════════

def _plot_comparison(results_df, dataset_name, plots_dir):
    """Bar chart comparing all models on key metrics."""
    fig, axes = plt.subplots(1, 4, figsize=(20, 5))
    metrics_to_plot = ["accuracy", "precision", "recall", "f1_score"]
    colors = sns.color_palette("viridis", len(results_df))

    for ax, metric in zip(axes, metrics_to_plot):
        bars = ax.barh(results_df["model"], results_df[metric], color=colors)
        ax.set_xlabel(metric.replace("_", " ").title())
        ax.set_xlim(0, 1.05)
        for bar, val in zip(bars, results_df[metric]):
            ax.text(val + 0.01, bar.get_y() + bar.get_height() / 2,
                    f"{val:.3f}", va="center", fontsize=8)

    plt.suptitle(f"Model Comparison — {dataset_name.upper()}", fontsize=14, weight="bold")
    plt.tight_layout()
    plt.savefig(os.path.join(plots_dir, f"comparison_{dataset_name}.png"), dpi=150)
    plt.close()
    print(f"   📊 Saved comparison plot")


def _plot_confusion_matrix(model, X_test, y_test, model_name, dataset_name, plots_dir):
    """Confusion matrix heatmap for the best model."""
    y_pred = model.predict(X_test)
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["Normal", "Anomaly"],
                yticklabels=["Normal", "Anomaly"], ax=ax)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(f"Confusion Matrix — {model_name}\n({dataset_name.upper()})")
    plt.tight_layout()
    plt.savefig(os.path.join(plots_dir, f"confusion_{dataset_name}.png"), dpi=150)
    plt.close()
    print(f"   📊 Saved confusion matrix")


def _plot_roc_curves(trained_models, X_test, y_test, dataset_name, plots_dir):
    """ROC curves for all models."""
    fig, ax = plt.subplots(figsize=(8, 6))
    for name, model in trained_models.items():
        try:
            y_prob = model.predict_proba(X_test)[:, 1]
            fpr, tpr, _ = roc_curve(y_test, y_prob)
            auc = roc_auc_score(y_test, y_prob)
            ax.plot(fpr, tpr, label=f"{name} (AUC={auc:.3f})")
        except Exception:
            pass
    ax.plot([0, 1], [0, 1], "k--", alpha=0.5)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title(f"ROC Curves — {dataset_name.upper()}")
    ax.legend(loc="lower right", fontsize=8)
    plt.tight_layout()
    plt.savefig(os.path.join(plots_dir, f"roc_{dataset_name}.png"), dpi=150)
    plt.close()
    print(f"   📊 Saved ROC curves")


def _plot_feature_importance(model, dataset_name, plots_dir):
    """Feature importance plot (for tree-based models)."""
    try:
        importances = model.feature_importances_
        feature_names = joblib.load(
            os.path.join(MODELS_DIR, f"feature_names_{dataset_name}.pkl")
        )
        idx = np.argsort(importances)[-20:]  # top 20
        fig, ax = plt.subplots(figsize=(8, 8))
        ax.barh(range(len(idx)), importances[idx], color=sns.color_palette("viridis", len(idx)))
        ax.set_yticks(range(len(idx)))
        ax.set_yticklabels([feature_names[i] for i in idx], fontsize=9)
        ax.set_xlabel("Importance")
        ax.set_title(f"Top 20 Feature Importances — {dataset_name.upper()}")
        plt.tight_layout()
        plt.savefig(os.path.join(plots_dir, f"features_{dataset_name}.png"), dpi=150)
        plt.close()
        print(f"   📊 Saved feature importance plot")
    except Exception as e:
        print(f"   ⚠ Feature importance not available: {e}")


# ═══════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════

def load_processed(dataset_name="unsw"):
    """Load preprocessed numpy arrays."""
    X_train = np.load(os.path.join(PROCESSED_DIR, f"X_train_{dataset_name}.npy"))
    X_test = np.load(os.path.join(PROCESSED_DIR, f"X_test_{dataset_name}.npy"))
    y_train = np.load(os.path.join(PROCESSED_DIR, f"y_train_{dataset_name}.npy"))
    y_test = np.load(os.path.join(PROCESSED_DIR, f"y_test_{dataset_name}.npy"))
    return X_train, X_test, y_train, y_test


if __name__ == "__main__":
    # ── UNSW-NB15 ─────────────────────────────────────────────
    print("Loading UNSW-NB15 processed data...")
    X_tr, X_te, y_tr, y_te = load_processed("unsw")
    best_unsw, results_unsw = train_and_evaluate_all(X_tr, X_te, y_tr, y_te, "unsw")

    # ── CIC-IDS-2017 ─────────────────────────────────────────
    print("\nLoading CIC-IDS-2017 processed data...")
    X_tr, X_te, y_tr, y_te = load_processed("cic")
    best_cic, results_cic = train_and_evaluate_all(X_tr, X_te, y_tr, y_te, "cic")

    print("\n" + "=" * 70)
    print("  ALL TRAINING COMPLETE!")
    print("=" * 70)
    print("\nUNSW-NB15 Results:")
    print(results_unsw.to_string(index=False))
    print("\nCIC-IDS-2017 Results:")
    print(results_cic.to_string(index=False))
