"""
XGBoost Classifier for NFT Smart Contract Vulnerability Detection
=================================================================
Implements an XGBoost gradient boosted tree classifier optimised for
multi-class NFT vulnerability detection on imbalanced datasets.

Model Construction
------------------
- Algorithm  : XGBoost (eXtreme Gradient Boosting) — gradient boosted trees
- Trees      : 300 (n_estimators)
- Learning rate: 0.05 (eta) — conservative step size; reduces overfitting
               on small minority classes
- Max depth  : 6 — controls tree complexity; prevents overfitting on
               minority class patterns
- Subsample  : 1.0 (default) — can be reduced to 0.8 for additional
               regularisation if overfitting is observed
- Colsample by tree: 1.0 (uses all features per tree)
- Objective  : multi:softmax — multiclass classification with one-hot targets
- Eval metric: mlogloss (multiclass log loss)
- Imbalance handling: sample_weight computed as inverse class frequency
                      (equivalent to class_weight="balanced" in sklearn)

Rationale
---------
XGBoost's sequential tree construction focuses each new tree on the
residuals (hard-to-classify samples) of previous trees, which
theoretically helps with minority-class detection. However, the
sequential nature means that misclassified minority samples must
propagate through many rounds before receiving sufficient attention,
making it sensitive to the learning rate and number of estimators.

Feature Input
-------------
Combined hand-crafted (21-dim) + TF-IDF (1,500-dim) = 1,521-dim sparse matrix.

Usage
-----
    python pipeline/models/xgboost_model.py --mode cross
"""

import argparse
import pathlib
import json
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import (
    classification_report, f1_score, precision_score,
    recall_score, make_scorer
)
from sklearn.utils.class_weight import compute_sample_weight

from feature_extraction import FeatureExtractor, NFT_CLASSES

HERE      = pathlib.Path(__file__).parent
ROOT      = HERE.parent.parent
SYN_DATA  = ROOT / "output" / "nft_synthetic_with_source.csv"
REAL_DATA = ROOT / "output" / "nft_real_with_source.csv"
OUT       = ROOT / "results"
OUT.mkdir(exist_ok=True)

MODEL_NAME = "XGBoost"


def load(path):
    df = pd.read_csv(path)
    df["vulnerability_class"] = df["vulnerability_class"].fillna("None")
    df = df[df["vulnerability_class"].isin(NFT_CLASSES)]
    df = df[df["source_code"].notna() & (df["source_code"].str.strip() != "")]
    return df.reset_index(drop=True)


def build_model(num_classes: int = 6):
    """
    Construct XGBClassifier with fixed hyperparameters.

    learning_rate=0.05: conservative step to prevent the boosting process
    from over-committing to majority-class patterns in early rounds.

    max_depth=6: standard depth for tabular data; deeper trees risk memorising
    minority-class templates rather than learning generalisable patterns.

    num_class is set automatically by XGBoost from the label set; it is
    included here for documentation clarity.
    """
    return xgb.XGBClassifier(
        n_estimators=300,
        learning_rate=0.05,
        max_depth=6,
        subsample=1.0,
        colsample_bytree=1.0,
        eval_metric="mlogloss",
        use_label_encoder=False,
        random_state=42,
        n_jobs=-1,
    )


def run_cv(X, y, le, n_splits=5):
    """
    5-fold CV with per-fold sample weighting to handle class imbalance.
    XGBoost does not support class_weight= natively; sample_weight is
    computed inside each fold via cross_validate's fit_params.
    """
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    sample_weight = compute_sample_weight("balanced", y)

    scoring = {
        "macro_f1":    make_scorer(f1_score, average="macro", zero_division=0),
        "weighted_f1": make_scorer(f1_score, average="weighted", zero_division=0),
        "macro_prec":  make_scorer(precision_score, average="macro", zero_division=0),
        "macro_rec":   make_scorer(recall_score, average="macro", zero_division=0),
    }
    scores = cross_validate(
        build_model(), X, y, cv=cv, scoring=scoring,
        fit_params={"sample_weight": sample_weight},
    )
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
    sample_weight = compute_sample_weight("balanced", y_train)
    clf.fit(X_train, y_train, sample_weight=sample_weight)
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
