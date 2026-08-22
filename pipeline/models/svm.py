"""
Support Vector Machine Classifier for NFT Smart Contract Vulnerability Detection
================================================================================
Implements a Linear Support Vector Machine (SVM) classifier using a linear
kernel, which is well-suited to high-dimensional sparse text feature spaces
such as the combined HC + TF-IDF representation used here.

Model Construction
------------------
- Algorithm  : Linear SVM via coordinate descent (LibLinear)
- Kernel     : Linear (implicit — no explicit kernel computation)
- Regularisation : L2, C=0.5 (stronger regularisation than LR to reduce
                  overfitting on sparse minority-class features)
- Class weighting : "balanced" — mandatory for imbalanced NFT datasets
- Max iterations : 2,000
- Multi-class strategy : One-vs-Rest (OvR) — one binary SVM per class

Rationale for Linear Kernel
----------------------------
Kernel SVMs (RBF, polynomial) require dense feature matrices and do not
scale to our 1,521-dimensional sparse combined feature space. LinearSVC
implements the same maximum-margin objective using a primal formulation
that is O(n × d) rather than O(n²), making it practical on large sparse inputs.

Feature Input
-------------
Combined hand-crafted (21-dim) + TF-IDF (1,500-dim) = 1,521-dim sparse matrix.

Usage
-----
    python pipeline/models/svm.py --mode cross
"""

import argparse
import pathlib
import json
import pandas as pd
from sklearn.svm import LinearSVC
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import (
    classification_report, f1_score, precision_score,
    recall_score, make_scorer
)

from feature_extraction import FeatureExtractor, NFT_CLASSES

HERE      = pathlib.Path(__file__).parent
ROOT      = HERE.parent.parent
SYN_DATA  = ROOT / "output" / "nft_synthetic_with_source.csv"
REAL_DATA = ROOT / "output" / "nft_real_with_source.csv"
OUT       = ROOT / "results"
OUT.mkdir(exist_ok=True)

MODEL_NAME = "SVM_Linear"


def load(path):
    df = pd.read_csv(path)
    df["vulnerability_class"] = df["vulnerability_class"].fillna("None")
    df = df[df["vulnerability_class"].isin(NFT_CLASSES)]
    df = df[df["source_code"].notna() & (df["source_code"].str.strip() != "")]
    return df.reset_index(drop=True)


def build_model():
    """
    Construct LinearSVC with fixed hyperparameters.

    C=0.5: slightly stronger regularisation than LR (C=1.0) because SVM
    decision boundaries are more sensitive to outlier support vectors in
    sparse minority-class feature regions.
    """
    return LinearSVC(
        C=0.5,
        class_weight="balanced",
        max_iter=2000,
        random_state=42,
    )


def run_cv(X, y, le, n_splits=5):
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    scoring = {
        "macro_f1":    make_scorer(f1_score, average="macro", zero_division=0),
        "weighted_f1": make_scorer(f1_score, average="weighted", zero_division=0),
        "macro_prec":  make_scorer(precision_score, average="macro", zero_division=0),
        "macro_rec":   make_scorer(recall_score, average="macro", zero_division=0),
    }
    scores = cross_validate(build_model(), X, y, cv=cv, scoring=scoring)
    return {
        "model": MODEL_NAME, "mode": "cv",
        "macro_f1":    round(scores["test_macro_f1"].mean(), 4),
        "f1_std":      round(scores["test_macro_f1"].std(), 4),
        "weighted_f1": round(scores["test_weighted_f1"].mean(), 4),
        "precision":   round(scores["test_macro_prec"].mean(), 4),
        "recall":      round(scores["test_macro_rec"].mean(), 4),
    }


def run_cross_dataset(X_train, y_train, X_test, y_test, le):
    clf = build_model()
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print(f"\n{'='*60}\nModel: {MODEL_NAME}\n{'='*60}")
    print(classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0))
    return {
        "model": MODEL_NAME, "mode": "cross_dataset",
        "macro_f1":    round(f1_score(y_test, y_pred, average="macro", zero_division=0), 4),
        "weighted_f1": round(f1_score(y_test, y_pred, average="weighted", zero_division=0), 4),
        "precision":   round(precision_score(y_test, y_pred, average="macro", zero_division=0), 4),
        "recall":      round(recall_score(y_test, y_pred, average="macro", zero_division=0), 4),
        "f1_std":      0.0,
    }


def main():
    parser = argparse.ArgumentParser(description=f"{MODEL_NAME} for NFT vulnerability detection")
    parser.add_argument("--mode", choices=["cv", "cross"], default="cross")
    args = parser.parse_args()

    extractor = FeatureExtractor()
    le = LabelEncoder()
    le.fit(NFT_CLASSES)

    if args.mode == "cv":
        df = load(SYN_DATA)
        X  = extractor.fit_transform(df["source_code"].tolist())
        y  = le.transform(df["vulnerability_class"])
        result = run_cv(X, y, le)
    else:
        df_train = load(SYN_DATA)
        df_test  = load(REAL_DATA)
        X_train  = extractor.fit_transform(df_train["source_code"].tolist())
        X_test   = extractor.transform(df_test["source_code"].tolist())
        y_train  = le.transform(df_train["vulnerability_class"])
        y_test   = le.transform(df_test["vulnerability_class"])
        result   = run_cross_dataset(X_train, y_train, X_test, y_test, le)

    print(f"\nSummary: Macro F1 = {result['macro_f1']}  |  Weighted F1 = {result['weighted_f1']}")
    out_path = OUT / f"{MODEL_NAME.lower()}_{args.mode}_results.json"
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"Results saved → {out_path}")


if __name__ == "__main__":
    main()
