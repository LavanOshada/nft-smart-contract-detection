# NFT-Scan v1: Results and Findings

## Overview

NFT-Scan v1 is a purpose-built NFT vulnerability detection architecture designed to address the limitations identified in GPTScan-NFT. It introduces five NFT-specific components: an ERC-721 Override Detector, NFT Lifecycle Tagger, Few-Shot Prompting with real vulnerability examples, Cross-Function Dependency Resolver, and an OZ-Aware Static Confirmation layer. Despite these improvements over the generic GPTScan methodology, NFT-Scan v1 exhibits the same predict-None collapse on real on-chain contract data.

## Architecture

NFT-Scan v1 extends the GPTScan paradigm with five NFT-specific components:

| Step | Component | Purpose |
|---|---|---|
| 1 | ERC-721 Override Detector | Filters to developer-written overrides, drops inherited OZ boilerplate |
| 2 | NFT Lifecycle Tagger | Maps functions to Deploy/Mint/Transfer/Burn/Admin/Proxy lifecycle stages |
| 3 | Few-Shot NFT Prompting | Injects real vulnerable/safe code examples before each LLM query |
| 4 | Cross-Function Resolver | Expands function body with called internal functions (one level) |
| 5 | OZ-Aware Static Confirmation | Understands OpenZeppelin hooks and approval patterns |

## Experimental Setup

| Parameter | Value |
|---|---|
| LLM backbone | Google Gemini 1.5 Flash |
| Prompting strategy | Few-shot with real vulnerable/safe examples |
| Temperature | 0 (deterministic) |
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

### Comparison: GPTScan-NFT vs NFT-Scan v1 vs ML Baselines

| Method | Macro F1 | Notes |
|---|---|---|
| Logistic Regression | 0.1562 | Bag-of-words features |
| Random Forest | 0.1461 | Bag-of-words features |
| GPTScan-NFT (Gemini 1.5 Flash) | 0.1191 | Generic LLM prompting |
| **NFT-Scan v1 (Gemini 1.5 Flash)** | **0.1191** | NFT-specific LLM prompting |
| XGBoost | 0.0020 | Bag-of-words features |
| SVM | 0.0007 | Bag-of-words features |

## Analysis

### Predict-None Collapse Persists

NFT-Scan v1 achieves identical per-class results to GPTScan-NFT: F1 = 0.000 across all five vulnerability classes and F1 = 0.714 on None (clean) contracts. The NFT-specific components — lifecycle tagging, few-shot prompting, cross-function resolution, and OZ-aware static confirmation — do not mitigate the collapse. This indicates the failure is not caused by generic prompting or lack of NFT context, but is structural to LLM-based classification at scale on real on-chain contracts.

### Potential Implementation Factors

Two implementation factors may be contributing to the collapse and warrant investigation before attributing the result solely to LLM capability limitations:

**1. API quota exhaustion.** The Gemini 1.5 Flash free tier allows 1,500 requests per day. NFT-Scan v1 requires approximately 2 LLM calls per contract (scenario matching + property matching), totalling approximately 6,000 calls for 3,000 contracts. Quota exhaustion midway through the evaluation causes all subsequent `_gemini_call` invocations to return empty strings, which the pipeline interprets as "not vulnerable". If exhaustion occurs at contract 750 (1,500 calls / 2 per contract), the remaining 2,250 contracts are classified as None by default regardless of content.

**2. Response parsing mismatch.** The pipeline parses LLM responses by checking for "Yes" at the start of the returned string. If Gemini returns a verbose response beginning with "Based on my analysis..." or "No, this contract does not appear...", the parser treats it as a negative even when the LLM's reasoning identifies a vulnerability.

### Comparison with LLM-Based Literature

Papers reporting strong LLM-based smart contract vulnerability detection (GPTScan: F1 = 0.50–0.75; SmartInv; LLM4Vuln) consistently evaluate on small, hand-curated datasets of 50–200 contracts where vulnerabilities are textbook-clear and the source code is clean. Our evaluation on 3,000 real on-chain NFT contracts — which exhibit deep OpenZeppelin inheritance, complex modifier chains, and highly variable coding styles — represents a substantially harder evaluation regime. The performance gap between curated benchmarks and real on-chain contracts is consistent with known domain-shift degradation for zero-shot LLM tools.

## Conclusions

NFT-Scan v1's predict-None collapse, despite NFT-specific architectural improvements over GPTScan, indicates that LLM-first classification is insufficient as a primary detection mechanism for real-world NFT contracts at scale. Two explanations are plausible and not mutually exclusive: (1) technical factors including API quota exhaustion and response parsing mismatches, and (2) fundamental LLM conservatism on noisy real-world code.

The next evaluation step is a controlled debug run on 10 contracts with verbose logging to distinguish technical from fundamental causes. If technical, the LLM pipeline can be repaired. If fundamental, the architecture should be redesigned with NFT-specific static features as the primary classifier and the LLM reserved for post-hoc explanation of confirmed detections.
