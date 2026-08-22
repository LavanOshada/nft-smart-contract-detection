"""
Logistic Regression Classifier for NFT Smart Contract Vulnerability Detection
=============================================================================
Implements a multinomial Logistic Regression (LR) classifier using L2
regularisation and balanced class weighting to handle the severe class
imbalance present in real on-chain NFT contract datasets.

Model Construction
------------------
- Algorithm  : Multinomial Logistic Regression via L-BFGS optimisation
- Regularisation : L2 (Ridge), C=1.0 (inverse of regularisation strength)
- Class weighting : "balanced" — sample weights inversely proportional to
                   class frequency, compensating for the ~93.4% clean-contract
                   majority in the real partition
- Max iterations : 1,000 (sufficient for convergence on sparse TF-IDF input)
- Multi-class strategy : One-vs-Rest (OvR) with softmax probability output

Feature Input
-------------
Combined hand-crafted (21-dim) + TF-IDF (1,500-dim) = 1,521-dim sparse matrix.
See pipeline/models/feature_extraction.py for feature construction details.

Usage
-----
    python pipeline/models/logistic_regression.py --mode cross
"""

import argparse
import pathlib
import json
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import (
    classification_report, f1_score, precision_score,
    recall_score, make_scorer
)

from feature_extraction import FeatureExtractor, NFT_CLASSES

# ── Paths ──────────────────────────────────────────────────────────────────
HERE      = pathlib.Path(__file__).parent
ROOT      = HERE.parent.parent
SYN_DATA  = ROOT / "output" / "nft_synthetic_with_source.csv"
REAL_DATA = ROOT / "output" / "nft_real_with_source.csv"
OUT       = ROOT / "results"
OUT.mkdir(exist_ok=True)

MODEL_NAME = "Logistic_Regression"


def load(path: pathlib.Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    df["vulnerability_class"] = df["vulnerability_class"].fillna("None")
    df = df[df["vulnerability_class"].isin(NFT_CLASSES)]
    df = df[df["source_code"].notna() & (df["source_code"].str.strip() != "")]
    return df.reset_index(drop=True)


def build_model() -> LogisticRegression:
    """
    Construct and return the Logistic Regression model with fixed hyperparameters.

    Hyperparameter justification:
        C=1.0     — standard L2 regularisation; stronger regularisation
                    (smaller C) was tested but reduced recall on minority classes.
        balanced  — mandatory for imbalanced datasets; without this, the model
                    predicts "None" for all inputs (accuracy 93%, F1 ~0).
        lbfgs     — memory-efficient quasi-Newton solver; converges well on
                    sparse high-dimensional input (our 1,521-dim feature space).
    """
    return LogisticRegression(
        C=1.0,
        class_weight="balanced",
        max_iter=1000,
        solver="lbfgs",
        multi_class="auto",
        random_state=42,
    )


def run_cv(X, y, label_encoder, n_splits: int = 5):
    """Run stratified k-fold cross-validation and print results."""
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    scoring = {
        "macro_f1":    make_scorer(f1_score, average="macro", zero_division=0),
        "weighted_f1": make_scorer(f1_score, average="weighted", zero_division=0),
        "macro_prec":  make_scorer(precision_score, average="macro", zero_division=0),
        "macro_rec":   make_scorer(recall_score, average="macro", zero_division=0),
    }
    scores = cross_validate(build_model(), X, y, cv=cv, scoring=scoring)
    return {
        "model":       MODEL_NAME,
        "mode":        "cv",
        "macro_f1":    round(scores["test_macro_f1"].mean(), 4),
        "f1_std":      round(scores["test_macro_f1"].std(), 4),
        "weighted_f1": round(scores["test_weighted_f1"].mean(), 4),
        "precision":   round(scores["test_macro_prec"].mean(), 4),
        "recall":      round(scores["test_macro_rec"].mean(), 4),
    }


def run_cross_dataset(X_train, y_train, X_test, y_test, label_encoder):
    """Train on synthetic, test on real contracts."""
    clf = build_model()
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    print(f"\n{'='*60}")
    print(f"Model: {MODEL_NAME}")
    print(f"{'='*60}")
    print(classification_report(
        y_test, y_pred,
        target_names=label_encoder.classes_,
        zero_division=0
    ))

    return {
        "model":       MODEL_NAME,
        "mode":        "cross_dataset",
        "macro_f1":    round(f1_score(y_test, y_pred, average="macro", zero_division=0), 4),
        "weighted_f1": round(f1_score(y_test, y_pred, average="weighted", zero_division=0), 4),
        "precision":   round(precision_score(y_test, y_pred, average="macro", zero_division=0), 4),
        "recall":      round(recall_score(y_test, y_pred, average="macro", zero_division=0), 4),
        "f1_std":      0.0,
    }


def main():
    parser = argparse.ArgumentParser(description=f"{MODEL_NAME} for NFT vulnerability detection")
    parser.add_argument("--mode", choices=["cv", "cross"], default="cross",
                        help="cv = 5-fold CV on synthetic | cross = train synthetic / test real")
    args = parser.parse_args()

    extractor = FeatureExtractor()
    le = LabelEncoder()
    le.fit(NFT_CLASSES)

    if args.mode == "cv":
        print(f"[{MODEL_NAME}] Mode: 5-fold cross-validation on synthetic data")
        df = load(SYN_DATA)
        print(f"  {len(df)} contracts | classes: {df['vulnerability_class'].value_counts().to_dict()}")
        X = extractor.fit_transform(df["source_code"].tolist())
        y = le.transform(df["vulnerability_class"])
        result = run_cv(X, y, le)

    else:  # cross
        print(f"[{MODEL_NAME}] Mode: cross-dataset (train=synthetic, test=real)")
        if not REAL_DATA.exists():
            raise FileNotFoundError("Run fetch_etherscan_source.py first to get real contract source.")
        df_train = load(SYN_DATA)
        df_test  = load(REAL_DATA)
        print(f"  Train: {len(df_train)} synthetic | Test: {len(df_test)} real")

        X_train = extractor.fit_transform(df_train["source_code"].tolist())
        X_test  = extractor.transform(df_test["source_code"].tolist())
        y_train = le.transform(df_train["vulnerability_class"])
        y_test  = le.transform(df_test["vulnerability_class"])
        result  = run_cross_dataset(X_train, y_train, X_test, y_test, le)

    print(f"\nSummary: Macro F1 = {result['macro_f1']}  |  Weighted F1 = {result['weighted_f1']}")
    out_path = OUT / f"{MODEL_NAME.lower()}_{args.mode}_results.json"
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"Results saved → {out_path}")


if __name__ == "__main__":
    main()
