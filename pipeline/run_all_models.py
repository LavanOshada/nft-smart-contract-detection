"""
Run All ML Models — NFT Smart Contract Vulnerability Detection
==============================================================
Trains and evaluates all four classifiers in a single run and produces
a consolidated results table saved to results/all_models_results.csv.

Evaluation modes:
  --mode cv     : 5-fold stratified CV on synthetic contracts (controlled setting)
  --mode cross  : Train on synthetic, test on real on-chain contracts (default)
                  Requires output/nft_real_with_source.csv (run fetch_etherscan_source.py first)

Usage:
    python pipeline/run_all_models.py --mode cross

Output:
    results/all_models_results.csv     — summary table (all models)
    results/all_models_per_class.csv   — per-class F1 for each model
    results/cross_dataset_results.csv  — cross-dataset evaluation summary
"""

import sys
import argparse
import pathlib
import warnings
import json
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import (
    classification_report, f1_score, precision_score,
    recall_score, make_scorer
)
from sklearn.utils.class_weight import compute_sample_weight
import xgboost as xgb

warnings.filterwarnings("ignore")

# Add models directory to path for feature_extraction import
sys.path.insert(0, str(pathlib.Path(__file__).parent / "models"))
from feature_extraction import FeatureExtractor, NFT_CLASSES

HERE      = pathlib.Path(__file__).parent
ROOT      = HERE.parent
SYN_DATA  = ROOT / "output" / "nft_synthetic_with_source.csv"
REAL_DATA = ROOT / "output" / "nft_real_with_source.csv"
OUT       = ROOT / "results"
OUT.mkdir(exist_ok=True)


def load(path):
    df = pd.read_csv(path)
    df["vulnerability_class"] = df["vulnerability_class"].fillna("None")
    df = df[df["vulnerability_class"].isin(NFT_CLASSES)]
    df = df[df["source_code"].notna() & (df["source_code"].str.strip() != "")]
    return df.reset_index(drop=True)


CLASSIFIERS = {
    "Logistic Regression": LogisticRegression(
        C=1.0, class_weight="balanced", max_iter=1000,
        solver="lbfgs", random_state=42
    ),
    "SVM (Linear)": LinearSVC(
        C=0.5, class_weight="balanced", max_iter=2000, random_state=42
    ),
    "Random Forest": RandomForestClassifier(
        n_estimators=300, class_weight="balanced_subsample",
        max_features="sqrt", bootstrap=True, random_state=42, n_jobs=-1
    ),
    "XGBoost": xgb.XGBClassifier(
        n_estimators=300, learning_rate=0.05, max_depth=6,
        eval_metric="mlogloss", use_label_encoder=False,
        random_state=42, n_jobs=-1
    ),
}


def run_cross(le):
    """Cross-dataset evaluation: train on synthetic, test on real."""
    print("\n" + "="*72)
    print("CROSS-DATASET EVALUATION")
    print("Train: Synthetic NFT contracts (hand-authored, fully labelled)")
    print("Test:  Real on-chain NFT contracts (Etherscan-verified source)")
    print("="*72)

    df_train = load(SYN_DATA)
    df_test  = load(REAL_DATA)
    print(f"\nTrain set: {len(df_train)} contracts")
    print(df_train["vulnerability_class"].value_counts().to_string())
    print(f"\nTest set: {len(df_test)} contracts")
    print(df_test["vulnerability_class"].value_counts().to_string())

    extractor = FeatureExtractor()
    X_train = extractor.fit_transform(df_train["source_code"].tolist())
    X_test  = extractor.transform(df_test["source_code"].tolist())
    y_train = le.transform(df_train["vulnerability_class"])
    y_test  = le.transform(df_test["vulnerability_class"])
    sw      = compute_sample_weight("balanced", y_train)

    records      = []
    per_class_rows = []

    print(f"\n{'Model':<22} {'Macro F1':>9} {'Wt F1':>8} {'Precision':>10} {'Recall':>8}")
    print("-"*62)

    for name, clf in CLASSIFIERS.items():
        if isinstance(clf, xgb.XGBClassifier):
            clf.fit(X_train, y_train, sample_weight=sw)
        else:
            clf.fit(X_train, y_train)

        y_pred = clf.predict(X_test)

        mf1  = f1_score(y_test, y_pred, average="macro",    zero_division=0)
        wf1  = f1_score(y_test, y_pred, average="weighted", zero_division=0)
        prec = precision_score(y_test, y_pred, average="macro", zero_division=0)
        rec  = recall_score(y_test,  y_pred, average="macro",  zero_division=0)

        print(f"{name:<22} {mf1:>9.4f} {wf1:>8.4f} {prec:>10.4f} {rec:>8.4f}")

        records.append({
            "Model": name, "Macro F1": round(mf1,4),
            "Weighted F1": round(wf1,4), "Precision": round(prec,4),
            "Recall": round(rec,4), "Mode": "cross_dataset"
        })

        # Per-class F1
        for i, cls in enumerate(le.classes_):
            mask = (y_test == i)
            if mask.sum() > 0:
                cls_f1 = f1_score(y_test, y_pred, labels=[i], average="macro", zero_division=0)
                per_class_rows.append({"Model": name, "Class": cls, "F1": round(cls_f1, 4)})

    print("-"*62)

    # Per-class report for best model
    best_name = max(records, key=lambda r: r["Macro F1"])["Model"]
    best_clf  = CLASSIFIERS[best_name]
    y_pred    = best_clf.predict(X_test)
    print(f"\nDetailed report — {best_name} (best Macro F1):")
    print(classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0))

    return records, per_class_rows


def run_cv(le):
    """5-fold cross-validation on synthetic contracts."""
    print("\n" + "="*72)
    print("5-FOLD CROSS-VALIDATION (Synthetic contracts)")
    print("="*72)

    df = load(SYN_DATA)
    extractor = FeatureExtractor()
    X = extractor.fit_transform(df["source_code"].tolist())
    y = le.transform(df["vulnerability_class"])
    sw = compute_sample_weight("balanced", y)

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scoring = {
        "macro_f1":    make_scorer(f1_score, average="macro", zero_division=0),
        "weighted_f1": make_scorer(f1_score, average="weighted", zero_division=0),
        "macro_prec":  make_scorer(precision_score, average="macro", zero_division=0),
        "macro_rec":   make_scorer(recall_score, average="macro", zero_division=0),
    }

    records = []
    print(f"\n{'Model':<22} {'Macro F1':>9} {'±Std':>6} {'Wt F1':>8} {'Precision':>10} {'Recall':>8}")
    print("-"*68)

    for name, clf in CLASSIFIERS.items():
        fp = {"sample_weight": sw} if isinstance(clf, xgb.XGBClassifier) else {}
        scores = cross_validate(clf, X, y, cv=cv, scoring=scoring,
                                fit_params=fp, n_jobs=-1)
        mf1  = scores["test_macro_f1"].mean()
        std  = scores["test_macro_f1"].std()
        wf1  = scores["test_weighted_f1"].mean()
        prec = scores["test_macro_prec"].mean()
        rec  = scores["test_macro_rec"].mean()
        print(f"{name:<22} {mf1:>9.4f} {std:>6.4f} {wf1:>8.4f} {prec:>10.4f} {rec:>8.4f}")
        records.append({
            "Model": name, "Macro F1": round(mf1,4), "F1 Std": round(std,4),
            "Weighted F1": round(wf1,4), "Precision": round(prec,4),
            "Recall": round(rec,4), "Mode": "cv"
        })

    print("-"*68)
    return records, []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["cv", "cross"], default="cross")
    args = parser.parse_args()

    le = LabelEncoder()
    le.fit(NFT_CLASSES)

    if args.mode == "cross":
        if not REAL_DATA.exists():
            print("ERROR: output/nft_real_with_source.csv not found.")
            print("Run: python pipeline/fetch_etherscan_source.py --api-key YOUR_KEY")
            sys.exit(1)
        records, per_class = run_cross(le)
    else:
        records, per_class = run_cv(le)

    # Save results
    results_df = pd.DataFrame(records)
    results_path = OUT / f"all_models_{args.mode}_results.csv"
    results_df.to_csv(results_path, index=False)
    print(f"\nResults saved → {results_path}")

    if per_class:
        pc_df = pd.DataFrame(per_class).pivot(index="Class", columns="Model", values="F1")
        pc_path = OUT / "all_models_per_class_f1.csv"
        pc_df.to_csv(pc_path)
        print(f"Per-class F1  → {pc_path}")

    print("\nDone.")


if __name__ == "__main__":
    main()
