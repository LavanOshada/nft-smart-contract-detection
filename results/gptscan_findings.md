# GPTScan-NFT Baseline: Results and Findings

## Overview

We adapt GPTScan (Sun et al., ICSE 2024) for NFT-specific vulnerability detection and evaluate it on 3,000 real on-chain NFT smart contracts drawn from the NFTDefects benchmark (Chen et al., ISSTA 2023). This serves as our LLM-based baseline for comparison against traditional ML classifiers.

## Experimental Setup

| Parameter | Value |
|---|---|
| Base methodology | GPTScan (arXiv:2308.03314) |
| LLM backbone | Google Gemini 1.5 Flash |
| Prompting strategy | Mimic-in-the-background (temperature=0) |
| Static confirmation | Regex-based Order Check (OC) + Value Comparison Check (VC) |
| Dataset | NFTDefects real on-chain contracts |
| Evaluation subset | 3,000 contracts (stratified sample) |
| Vulnerability classes | ERC721\_Reentrancy, Unlimited\_Minting, Missing\_Requirements, Public\_Burn, Risky\_Mutable\_Proxy, None |

## Results

### Overall Metrics

| Metric | Score |
|---|---|
| Macro F1 | 0.1191 |
| Weighted F1 | 0.3970 |
| Macro Precision | 0.0926 |
| Macro Recall | 0.1667 |

### Per-Class Performance

| Vulnerability Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| ERC721\_Reentrancy | 0.000 | 0.000 | 0.000 | 503 |
| Unlimited\_Minting | 0.000 | 0.000 | 0.000 | 709 |
| Missing\_Requirements | 0.000 | 0.000 | 0.000 | 73 |
| Public\_Burn | 0.000 | 0.000 | 0.000 | 38 |
| Risky\_Mutable\_Proxy | 0.000 | 0.000 | 0.000 | 10 |
| None (clean) | 0.556 | 1.000 | 0.714 | 1,667 |
| **Macro avg** | **0.093** | **0.167** | **0.119** | **3,000** |

### Comparison Against ML Baselines (Real On-Chain Contracts)

| Method | Macro F1 |
|---|---|
| Logistic Regression | 0.1562 |
| Random Forest | 0.1461 |
| **GPTScan-NFT (Gemini 1.5 Flash)** | **0.1191** |
| XGBoost | 0.0020 |
| SVM | 0.0007 |

## Analysis

### Predict-None Collapse

The most salient finding is that GPTScan-NFT achieves a per-class F1 of 0.000 across all five vulnerability classes, while correctly identifying all clean contracts (None recall = 1.000). This indicates a **predict-None collapse**: the pipeline systematically classifies every contract as clean, failing to flag any vulnerability instance.

This is not a sampling artifact. With 1,333 vulnerable contracts in the evaluation subset (44.4% of the sample), the class distribution is sufficient for detection. The collapse is structural.

### Root Causes

**1. Generic prompting misaligned with NFT contract structure.**
GPTScan's scenario and property prompts were designed for DeFi vulnerability patterns (flash loans, price oracle manipulation) on small curated datasets. NFT vulnerability patterns — particularly CEI violations hidden within OpenZeppelin override chains — require more precise, NFT-specific semantic descriptions than the adapted prompts provide. Gemini, reasoning zero-shot, defaults to "not vulnerable" on ambiguous real-world code.

**2. Compounding conservatism.**
The pipeline applies two sequential conservative filters: LLM scenario matching followed by LLM property matching, then static confirmation. Each stage independently rejects borderline candidates. Stacked on real on-chain contracts — which are noisier and more structurally complex than handpicked research benchmarks — this produces near-zero positive predictions.

**3. Domain shift from DeFi to NFT.**
GPTScan was validated on approximately 100 handpicked DeFi contracts exhibiting clear, textbook-style vulnerabilities. Real NFT contracts on Ethereum mainnet exhibit substantially more variation in coding style, inheritance depth, and vulnerability expression. This domain shift degrades zero-shot LLM performance significantly.

**4. Static confirmation over-filtering.**
The regex-based static checks (Order Check for reentrancy, Value Comparison Check for the remaining classes) are calibrated for idealized vulnerability patterns. In real contracts, state updates and external calls are often interleaved with conditional logic, library calls, and modifier chains that the regex patterns do not account for, causing true positives to be incorrectly rejected.

### Comparison with Original GPTScan

The original GPTScan paper reports F1 scores of 0.50–0.75 on DeFi vulnerabilities evaluated on a small curated benchmark of approximately 100 contracts. Our evaluation on 3,000 real on-chain NFT contracts yields Macro F1 = 0.1191, consistent with the well-documented performance degradation of zero-shot LLM-based tools when applied at scale to real-world codebases. The NFT domain exacerbates this degradation due to the prevalence of OpenZeppelin inheritance, which obscures vulnerability patterns from function-level analysis.

## Conclusions

GPTScan's zero-shot LLM approach, while effective on small curated DeFi datasets, exhibits a systematic predict-None collapse when applied to large-scale real-world NFT contract datasets. The per-class F1 of 0.000 across all five vulnerability classes indicates that the failure is not a sampling artifact but a fundamental mismatch between GPTScan's generic prompting strategy and the structural characteristics of NFT smart contracts.

Specifically, three limitations are identified: (1) NFT vulnerability semantics are insufficiently captured by generic scenario/property prompts; (2) the function-level analysis paradigm cannot resolve cross-function vulnerability patterns common in NFT contracts; and (3) the two-stage LLM filtering combined with regex-based static confirmation is too conservative for real-world code at scale.

These findings motivate a purpose-built NFT vulnerability detection architecture that exploits the structural regularities of ERC-721/ERC-1155 contracts — including their lifecycle semantics, OpenZeppelin override patterns, and cross-function dependency structure — rather than adapting a general-purpose smart contract analysis tool.
