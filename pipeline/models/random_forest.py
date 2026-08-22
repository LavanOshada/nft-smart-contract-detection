"""
Random Forest Classifier for NFT Smart Contract Vulnerability Detection
=======================================================================
Implements a Random Forest (RF) ensemble classifier using 300 decision
trees with balanced class weighting and bootstrap sampling.

Model Construction
------------------
- Algorithm  : Random Forest (bagging ensemble of decision trees)
- Trees      : 300 (sufficient for stable OOB error estimation)
- Max features: sqrt(n_features) per split — standard for classification
- Bootstrap  : True — each tree trained on a bootstrap sample of the data
- Class weighting : "balanced_subsample" — class weights recomputed per
                   bootstrap sample, more robust than global "balanced"
                   for imbalanced datasets with variable sample sizes
- Max depth  : None (full trees) — regularised implicitly by min_samples_leaf
- Min samples leaf : 1 (default)
- Random state: 42 (reproducibility)
- Parallelism: n_jobs=-1 (all available CPU cores)

Rationale
---------
Random Forests are robust to high-dimensional sparse input because
each split considers only sqrt(d) features. The ensemble averaging
reduces variance from noisy minority-class patterns in the TF-IDF
representation. The "balanced_subsample" weighting is preferred over
"balanced" because it adapts to the class distribution in each bootstrap
sample, which varies due to the extreme imbalance (~93% clean contracts).

Feature Input
-------------
Combined hand-crafted (21-dim) + TF-IDF (1,500-dim) = 1,521-dim sparse matrix.

Usage
-----
    python pipeline/models/random_forest.py --mode cross
"""

import argparse
import pathlib
import json
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
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

MODEL_NAME = "Random_Forest"


def load(path):
    df = pd.read_csv(path)
    df["vulnerability_class"] = df["vulnerability_class"].fillna("None")
    df = df[df["vulnerability_class"].isin(NFT_CLASSES)]
    df = df[df["source_code"].notna() & (df["source_code"].str.strip() != "")]
    return df.reset_index(drop=True)


def build_model():
    """
    Construct RandomForestClassifier with fixed hyperparameters.

    n_estimators=300: more trees reduce variance; 300 is the point of
    diminishing returns on this dataset size.

    class_weight="balanced_subsample": recomputes weights per bootstrap
    sample — more appropriate than "balanced" when class imbalance is severe
    and bootstrap samples vary in class composition.
    """
    return RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced_subsample",
        max_features="sqrt",
        bootstrap=True,
        random_state=42,
        n_jobs=-1,
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

    # Feature importance for hand-crafted features (interpretability)
    hc_names = FeatureExtractor().hc_feature_names
    importances = clf.feature_importances_[:len(hc_names)]
    top = sorted(zip(hc_names, importances), key=lambda x: -x[1])[:5]
    print("Top 5 hand-crafted features by importance:")
    for name, imp in top:
        print(f"  {name:<30} {imp:.4f}")

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
