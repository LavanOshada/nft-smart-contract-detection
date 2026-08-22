"""
NFT Smart Contract Vulnerability Detection — ML Baseline
=========================================================
Trains and evaluates four classifiers on NFT smart contract source code.

Modes:
  --mode synthetic   Train + 5-fold CV on synthetic contracts only (default)
  --mode real        Train + 5-fold CV on real contracts (requires fetch first)
  --mode cross       Train on synthetic, test on real (cross-dataset evaluation)

Feature sets:
  1. Hand-crafted (HC)  — 28 binary/count features from regex patterns
  2. TF-IDF             — 1500-dim bag-of-tokens on Solidity source
  3. Combined (HC + TF-IDF)

Classifiers:
  - Logistic Regression (LR)
  - Support Vector Machine (SVM)
  - Random Forest (RF)
  - XGBoost (XGB)

Evaluation:
  - 5-fold stratified cross-validation
  - Macro F1, weighted F1, precision, recall
  - Per-class F1 saved to results/
"""

import re
import json
import argparse
import warnings
import pathlib
import pandas as pd
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import (
    classification_report, f1_score, precision_score,
    recall_score, make_scorer
)
from sklearn.utils.class_weight import compute_class_weight
from scipy.sparse import hstack, csr_matrix
import xgboost as xgb

warnings.filterwarnings("ignore")

# ── Args ───────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument("--mode", choices=["synthetic", "real", "cross"],
                    default="synthetic",
                    help="synthetic=CV on synthetic | real=CV on real | cross=train synthetic/test real")
args = parser.parse_args()

# ── Paths ──────────────────────────────────────────────────────────────────
HERE      = pathlib.Path(__file__).parent
SYN_DATA  = HERE.parent / "output" / "nft_synthetic_with_source.csv"
REAL_DATA = HERE.parent / "output" / "nft_real_with_source.csv"
OUT       = HERE.parent / "results"
OUT.mkdir(exist_ok=True)

# ── Load data ──────────────────────────────────────────────────────────────
NFT_CLASSES = [
    "ERC721_Reentrancy",
    "Unlimited_Minting",
    "Missing_Requirements",
    "Public_Burn",
    "Risky_Mutable_Proxy",
    "None",   # clean contracts
]

print(f"Loading dataset (mode={args.mode}) …")

def load_and_filter(path):
    d = pd.read_csv(path)
    d = d[d["vulnerability_class"].isin(NFT_CLASSES)].reset_index(drop=True)
    d = d[d["source_code"].notna() & (d["source_code"].str.strip() != "")]
    return d

if args.mode == "synthetic":
    df = load_and_filter(SYN_DATA)
    df_test = None
elif args.mode == "real":
    if not REAL_DATA.exists():
        raise FileNotFoundError("Real source not found. Run: python pipeline/fetch_etherscan_source.py --api-key YOUR_KEY")
    df = load_and_filter(REAL_DATA)
    df_test = None
else:  # cross
    if not REAL_DATA.exists():
        raise FileNotFoundError("Real source not found. Run: python pipeline/fetch_etherscan_source.py --api-key YOUR_KEY")
    df       = load_and_filter(SYN_DATA)   # train
    df_test  = load_and_filter(REAL_DATA)  # test

print(f"  Train: {len(df)} contracts | {df['vulnerability_class'].nunique()} classes")
print(f"  Class distribution:\n{df['vulnerability_class'].value_counts().to_string()}")
if df_test is not None:
    print(f"\n  Test (real): {len(df_test)} contracts")
    print(f"  {df_test['vulnerability_class'].value_counts().to_string()}")
print()

# ── Hand-crafted features ──────────────────────────────────────────────────
PATTERNS = {
    # Reentrancy indicators
    "has_safeMint":            r"_safeMint\s*\(",
    "has_safeTransferFrom":    r"safeTransferFrom\s*\(",
    "has_onERC721Received":    r"onERC721Received",
    "has_nonReentrant":        r"nonReentrant",
    "has_reentrancyGuard":     r"ReentrancyGuard",
    "state_after_external":    r"\.call\{.*?\}.*?\n.*?=\s*",   # rough CEI violation signal

    # Access control
    "has_onlyOwner":           r"onlyOwner",
    "has_require_owner":       r"require\s*\(.*?owner|msg\.sender.*?\)",
    "has_Ownable":             r"Ownable",
    "has_AccessControl":       r"AccessControl",

    # Minting / supply
    "has_maxSupply":           r"maxSupply|MAX_SUPPLY|_maxSupply",
    "has_totalSupply_check":   r"totalSupply\(\)\s*[<>]=?\s*",
    "has_tx_origin":           r"tx\.origin",

    # Burn
    "has_burn":                r"\bburn\b|\b_burn\b",
    "has_burn_ownerCheck":     r"burn.*?require|require.*?burn",

    # Proxy / delegatecall
    "has_delegatecall":        r"delegatecall",
    "has_upgradeTo":           r"upgradeTo|_upgradeTo",
    "has_timelock":            r"timelock|TimeLock",

    # Selfdestruct
    "has_selfdestruct":        r"selfdestruct|suicide\s*\(",

    # ETH transfer
    "has_call_value":          r"\.call\{value:",
    "has_transfer":            r"\.transfer\s*\(",
    "has_send":                r"\.send\s*\(",

    # Unchecked
    "has_unchecked_block":     r"\bunchecked\s*\{",

    # General quality
    "has_require":             r"\brequire\s*\(",
    "has_emit":                r"\bemit\s+\w+",
}

def extract_hc_features(source: str) -> dict:
    feats = {}
    for name, pat in PATTERNS.items():
        feats[name] = int(bool(re.search(pat, source, re.IGNORECASE | re.DOTALL)))
    # Count features
    feats["num_require"]   = len(re.findall(r"\brequire\s*\(", source))
    feats["num_functions"] = len(re.findall(r"\bfunction\s+\w+", source))
    feats["loc"]           = source.count("\n")
    return feats

print("Extracting hand-crafted features …")
hc_df = pd.DataFrame([extract_hc_features(s) for s in df["source_code"]])
print(f"  {hc_df.shape[1]} hand-crafted features extracted\n")

# ── Labels ─────────────────────────────────────────────────────────────────
le = LabelEncoder()
y = le.fit_transform(df["vulnerability_class"])
classes = le.classes_
print(f"Classes ({len(classes)}): {list(classes)}\n")

# ── Feature matrices ───────────────────────────────────────────────────────
# 1. HC
X_hc = csr_matrix(hc_df.values.astype(float))

# 2. TF-IDF on Solidity tokens
print("Building TF-IDF features …")
tfidf = TfidfVectorizer(
    token_pattern=r"[a-zA-Z_][a-zA-Z0-9_]*",
    max_features=1500,
    sublinear_tf=True,
    ngram_range=(1, 2),
)
X_tfidf = tfidf.fit_transform(df["source_code"])
print(f"  TF-IDF matrix: {X_tfidf.shape}\n")

# 3. Combined
X_combined = hstack([X_hc, X_tfidf])

FEATURE_SETS = {
    "Hand-crafted":    X_hc,
    "TF-IDF":          X_tfidf,
    "HC + TF-IDF":     X_combined,
}

# ── Classifiers ────────────────────────────────────────────────────────────
CLASSIFIERS = {
    "Logistic Regression": LogisticRegression(
        max_iter=1000, class_weight="balanced", C=1.0, random_state=42
    ),
    "SVM (Linear)": LinearSVC(
        max_iter=2000, class_weight="balanced", C=0.5, random_state=42
    ),
    "Random Forest": RandomForestClassifier(
        n_estimators=300, class_weight="balanced",
        random_state=42, n_jobs=-1
    ),
    "XGBoost": xgb.XGBClassifier(
        n_estimators=300, learning_rate=0.05, max_depth=6,
        use_label_encoder=False, eval_metric="mlogloss",
        random_state=42, n_jobs=-1,
        # Handle imbalance via scale_pos_weight not needed for multiclass;
        # use sample_weight in fit instead
    ),
}

# ── Cross-validation ───────────────────────────────────────────────────────
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

scoring = {
    "macro_f1":    make_scorer(f1_score, average="macro", zero_division=0),
    "weighted_f1": make_scorer(f1_score, average="weighted", zero_division=0),
    "macro_prec":  make_scorer(precision_score, average="macro", zero_division=0),
    "macro_rec":   make_scorer(recall_score, average="macro", zero_division=0),
}

records = []

if args.mode == "cross":
    # ── Cross-dataset: train on synthetic, test on real ────────────────────
    hc_test = pd.DataFrame([extract_hc_features(s) for s in df_test["source_code"]])
    X_hc_test      = csr_matrix(hc_test.values.astype(float))
    X_tfidf_test   = tfidf.transform(df_test["source_code"])
    X_combined_test = hstack([X_hc_test, X_tfidf_test])

    le_test = LabelEncoder().fit(NFT_CLASSES)
    y_test  = le_test.transform(df_test["vulnerability_class"])

    FEAT_SETS_TEST = {
        "Hand-crafted": (X_hc,       X_hc_test),
        "TF-IDF":       (X_tfidf,    X_tfidf_test),
        "HC + TF-IDF":  (X_combined, X_combined_test),
    }

    print("=" * 70)
    print("CROSS-DATASET: Train=Synthetic  Test=Real")
    print(f"{'Model':<22} {'Features':<16} {'Macro F1':>9} {'Wt F1':>8} {'Prec':>8} {'Rec':>8}")
    print("=" * 70)

    for feat_name, (X_tr, X_te) in FEAT_SETS_TEST.items():
        for clf_name, clf in CLASSIFIERS.items():
            clf.fit(X_tr, y)
            y_pred = clf.predict(X_te)

            mf1  = f1_score(y_test, y_pred, average="macro",    zero_division=0)
            wf1  = f1_score(y_test, y_pred, average="weighted", zero_division=0)
            prec = precision_score(y_test, y_pred, average="macro", zero_division=0)
            rec  = recall_score(y_test, y_pred, average="macro",  zero_division=0)

            print(f"{clf_name:<22} {feat_name:<16} {mf1:>9.4f} {wf1:>8.4f} {prec:>8.4f} {rec:>8.4f}")
            records.append({"model": clf_name, "features": feat_name,
                             "macro_f1": round(mf1,4), "weighted_f1": round(wf1,4),
                             "precision": round(prec,4), "recall": round(rec,4), "f1_std": 0.0})
    print("=" * 70)

else:
    # ── Standard cross-validation ──────────────────────────────────────────
    print("=" * 70)
    print(f"{'Model':<22} {'Features':<16} {'Macro F1':>9} {'Wt F1':>8} {'Prec':>8} {'Rec':>8}")
    print("=" * 70)

    for feat_name, X in FEATURE_SETS.items():
        for clf_name, clf in CLASSIFIERS.items():
            scores = cross_validate(clf, X, y, cv=cv, scoring=scoring, n_jobs=-1)

            mf1  = scores["test_macro_f1"].mean()
            wf1  = scores["test_weighted_f1"].mean()
            prec = scores["test_macro_prec"].mean()
            rec  = scores["test_macro_rec"].mean()

            print(f"{clf_name:<22} {feat_name:<16} {mf1:>9.4f} {wf1:>8.4f} {prec:>8.4f} {rec:>8.4f}")
            records.append({
                "model":       clf_name,
                "features":    feat_name,
                "macro_f1":    round(mf1, 4),
                "weighted_f1": round(wf1, 4),
                "precision":   round(prec, 4),
                "recall":      round(rec, 4),
                "f1_std":      round(scores["test_macro_f1"].std(), 4),
            })

    print("=" * 70)

# ── Save summary ───────────────────────────────────────────────────────────
results_df = pd.DataFrame(records).sort_values("macro_f1", ascending=False)
results_df.to_csv(OUT / "ml_baseline_results.csv", index=False)
print(f"\nResults saved → results/ml_baseline_results.csv")

# ── Per-class F1 for best model ────────────────────────────────────────────
best = results_df.iloc[0]
print(f"\nBest: {best['model']} with {best['features']} features  (Macro F1 = {best['macro_f1']})")
print("\nPer-class report (best model, final fold):")

best_clf_name = best["model"]
best_feat_name = best["features"]
X_best = FEATURE_SETS[best_feat_name]
best_clf = CLASSIFIERS[best_clf_name]

# Fit on full data for per-class breakdown
best_clf.fit(X_best, y)
y_pred = best_clf.predict(X_best)
report = classification_report(y, y_pred, target_names=classes, zero_division=0)
print(report)

# Save per-class report
with open(OUT / "ml_best_classification_report.txt", "w") as f:
    f.write(f"Best model: {best_clf_name} | Features: {best_feat_name}\n\n")
    f.write(report)

# Save per-class F1 JSON (for plotting later)
per_class = {}
for i, cls in enumerate(classes):
    mask = (y == i)
    per_class[cls] = round(f1_score(y, y_pred, labels=[i], average="macro", zero_division=0), 4)

with open(OUT / "ml_per_class_f1.json", "w") as f:
    json.dump(per_class, f, indent=2)

print(f"\nPer-class F1 saved → results/ml_per_class_f1.json")
print("Done.")
