# NFT Smart Contract Vulnerability Dataset — Instructions

## Overview

This repository contains the code and pipeline for the NFT Smart Contract Vulnerability Detection dataset, constructed to support machine learning and LLM-based vulnerability detection research on Ethereum NFT contracts.

The dataset comprises two components:
- **Synthetic dataset** — 150 hand-authored Solidity contracts with known vulnerability labels
- **Real dataset** — 16,527 real on-chain NFT contracts collected from Etherscan with verified source code

---

## Vulnerability Classes

The dataset covers five NFT-specific vulnerability classes plus a clean (None) class:

| Class | Description |
|---|---|
| `ERC721_Reentrancy` | Reentrancy attack via external calls in ERC721 transfer hooks (e.g., `onERC721Received`) before state updates |
| `Unlimited_Minting` | No cap on token supply; contract owner can mint arbitrarily large amounts |
| `Missing_Requirements` | Missing access control checks (`require`/`onlyOwner`) in sensitive functions |
| `Public_Burn` | Burn function is publicly callable — any address can destroy tokens they do not own |
| `Risky_Mutable_Proxy` | Proxy implementation address is changeable by owner post-deployment, enabling rug pulls |
| `None` | Clean contract with no detected vulnerability |

---

## Repository Structure

```
nft-smart-contract-detection/
├── pipeline/
│   ├── fetch_etherscan_source.py     # Fetch real contract source from Etherscan
│   ├── run_all_models.py             # Run all ML models (CV or cross-dataset)
│   └── models/
│       ├── feature_extraction.py     # Shared feature extractor (HC + TF-IDF)
│       ├── logistic_regression.py    # Logistic Regression classifier
│       ├── svm.py                    # Linear SVM classifier
│       ├── random_forest.py          # Random Forest classifier
│       └── xgboost_model.py          # XGBoost classifier
├── output/
│   ├── nft_synthetic_with_source.csv # Synthetic dataset (150 contracts)
│   └── nft_vulnerability_dataset.csv # Full vulnerability label dataset
├── results/
│   ├── all_models_cross_results.csv  # Cross-dataset evaluation results
│   ├── all_models_per_class_f1.csv   # Per-class F1 scores
│   └── ml_best_classification_report.txt
├── generate_dataset.py               # Generate synthetic contracts
├── requirements.txt                  # Python dependencies
└── DATASET_INSTRUCTIONS.md          # This file
```

---

## Setup

### Requirements

Python 3.8+ is required. Install dependencies:

```bash
pip install -r requirements.txt
```

### Dependencies

- scikit-learn
- xgboost
- pandas
- numpy
- requests

---

## Step 1 — Generate Synthetic Dataset

The synthetic dataset contains 150 hand-authored Solidity contracts (20–30 per class) with injected vulnerability patterns.

```bash
python generate_dataset.py
```

Output: `output/nft_synthetic_with_source.csv`

This file is already included in the repository.

---

## Step 2 — Collect Real On-Chain Contracts

Real NFT contract source code is fetched from the Etherscan API. You need a free Etherscan API key from [etherscan.io](https://etherscan.io/myapikey).

```bash
python pipeline/fetch_etherscan_source.py --api-key YOUR_ETHERSCAN_API_KEY
```

This will:
- Fetch Solidity source for 16,527 real on-chain NFT contracts
- Save progress every 50 contracts (resume-safe if interrupted)
- Take approximately 60–90 minutes to complete

Output: `output/nft_real_with_source.csv`

**Note:** The real dataset CSV is not included in this repository due to its size (743 MB). It must be generated locally using the fetch script.

### Real Dataset Class Distribution

| Class | Count |
|---|---|
| None (clean) | 15,196 |
| Unlimited_Minting | 708 |
| ERC721_Reentrancy | 503 |
| Missing_Requirements | 73 |
| Public_Burn | 37 |
| Risky_Mutable_Proxy | 10 |
| **Total** | **16,527** |

---

## Step 3 — Run ML Models

### Cross-Dataset Evaluation (recommended)

Trains on synthetic contracts, tests on real on-chain contracts:

```bash
python pipeline/run_all_models.py --mode cross
```

### 5-Fold Cross-Validation (controlled setting)

Runs on synthetic contracts only:

```bash
python pipeline/run_all_models.py --mode cv
```

### Run Individual Models

Each model can also be run independently:

```bash
python pipeline/models/logistic_regression.py --mode cross
python pipeline/models/svm.py --mode cross
python pipeline/models/random_forest.py --mode cross
python pipeline/models/xgboost_model.py --mode cross
```

---

## Results

### Cross-Dataset Evaluation (train: 150 synthetic, test: 16,527 real)

| Model | Macro F1 | Weighted F1 | Precision | Recall |
|---|---|---|---|---|
| Logistic Regression | 0.1562 | 0.8582 | 0.1534 | 0.1605 |
| Random Forest | 0.1461 | 0.7760 | 0.1563 | 0.1452 |
| XGBoost | 0.0020 | 0.0067 | 0.1674 | 0.1554 |
| SVM (Linear) | 0.0007 | 0.0027 | 0.1668 | 0.1669 |

**Key finding:** All ML models score 0.00 F1 on individual vulnerability classes in real production contracts, demonstrating a significant generalisation gap between synthetic templates and real-world code. This motivates LLM-based approaches for NFT vulnerability detection.

### Controlled Setting (5-fold CV on synthetic contracts)

All models achieve Macro F1 = 1.00 on the synthetic dataset due to the distinctive hand-crafted patterns, confirming the labels are clean and unambiguous.

---

## Feature Extraction

The shared feature extractor (`pipeline/models/feature_extraction.py`) produces a 1,521-dimensional feature vector per contract:

- **21 hand-crafted features** — binary regex flags and count features targeting NFT-specific patterns (reentrancy guards, minting caps, access control, burn permissions, proxy patterns)
- **1,500 TF-IDF features** — unigram and bigram token frequencies with sublinear TF scaling

---

## Citation

If you use this dataset or pipeline in your research, please cite:

```
@dataset{nft_vulnerability_dataset_2024,
  title  = {NFT Smart Contract Vulnerability Dataset},
  author = {Oshada, Lavan},
  year   = {2024},
  url    = {https://github.com/LavanOshada/nft-smart-contract-detection}
}
```

---

## Notes

- The Etherscan V2 API is required (`https://api.etherscan.io/v2/api` with `chainid=1`). The V1 API is deprecated and returns no results.
- Rate limiting is handled automatically (0.22s delay between requests, ~4.5 req/s).
- The fetch script is resume-safe — if interrupted, delete `output/_fetch_progress.csv` only after the script finishes, not during.
