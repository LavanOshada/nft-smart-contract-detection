"""
Feature Extraction for NFT Smart Contract Vulnerability Detection
=================================================================
Provides two complementary feature representations for Solidity source code:

1. Hand-Crafted (HC) Features — 21 binary/count signals derived from
   security-relevant regex patterns identified through manual analysis
   of the NFTDefects vulnerability taxonomy.

2. TF-IDF Features — 1,500-dimensional sparse bag-of-tokens representation
   using unigram and bigram Solidity token sequences with sublinear TF
   scaling to reduce the dominance of high-frequency keywords.

Both feature sets are concatenated into a 1,521-dimensional combined
representation used as the primary input to all classifiers.

Usage:
    from pipeline.models.feature_extraction import FeatureExtractor
    extractor = FeatureExtractor()
    X_train = extractor.fit_transform(train_source_list)
    X_test  = extractor.transform(test_source_list)
"""

import re
import pandas as pd
import numpy as np
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer


# ── NFT vulnerability classes (5 NFT-specific + clean) ────────────────────
NFT_CLASSES = [
    "ERC721_Reentrancy",
    "Unlimited_Minting",
    "Missing_Requirements",
    "Public_Burn",
    "Risky_Mutable_Proxy",
    "None",
]

# ── Hand-crafted feature patterns ─────────────────────────────────────────
# Each entry is (feature_name, regex_pattern).
# Patterns target the key code constructs that distinguish each vulnerability
# class in the NFTDefects taxonomy.
HC_PATTERNS = {
    # --- ERC721_Reentrancy signals ---
    # _safeMint and safeTransferFrom trigger onERC721Received callback
    "has_safeMint":          r"_safeMint\s*\(",
    "has_safeTransferFrom":  r"safeTransferFrom\s*\(",
    "has_onERC721Received":  r"onERC721Received",
    "has_nonReentrant":      r"nonReentrant",
    "has_reentrancyGuard":   r"ReentrancyGuard",

    # --- Access control signals (Unlimited_Minting, Public_Burn, Proxy) ---
    "has_onlyOwner":         r"onlyOwner",
    "has_Ownable":           r"Ownable",
    "has_AccessControl":     r"AccessControl",

    # --- Unlimited_Minting signals ---
    "has_maxSupply":         r"maxSupply|MAX_SUPPLY|_maxSupply",
    "has_totalSupply_check": r"totalSupply\(\)\s*[<>]=?\s*",
    "has_tx_origin":         r"tx\.origin",          # per-wallet limit bypass

    # --- Public_Burn signals ---
    "has_burn":              r"\bburn\b|\b_burn\b",

    # --- Risky_Mutable_Proxy signals ---
    "has_delegatecall":      r"delegatecall",
    "has_upgradeTo":         r"upgradeTo|_upgradeTo",
    "has_timelock":          r"timelock|TimeLock",

    # --- General security signals ---
    "has_selfdestruct":      r"selfdestruct|suicide\s*\(",
    "has_call_value":        r"\.call\{value:",
    "has_unchecked":         r"\bunchecked\s*\{",
    "has_require":           r"\brequire\s*\(",
    "has_emit":              r"\bemit\s+\w+",
}


def extract_hc_features(source: str) -> dict:
    """
    Extract hand-crafted binary and count features from Solidity source code.

    Parameters
    ----------
    source : str
        Raw Solidity source code string.

    Returns
    -------
    dict
        Dictionary mapping feature name → integer value.
        Binary features: 0 or 1.
        Count features: non-negative integer.
    """
    features = {}

    # Binary pattern features
    for name, pattern in HC_PATTERNS.items():
        features[name] = int(bool(re.search(pattern, source, re.IGNORECASE | re.DOTALL)))

    # Count features
    features["num_require"]   = len(re.findall(r"\brequire\s*\(", source))
    features["num_functions"] = len(re.findall(r"\bfunction\s+\w+", source))
    features["loc"]           = source.count("\n")

    return features


class FeatureExtractor:
    """
    Combined hand-crafted + TF-IDF feature extractor for Solidity contracts.

    Attributes
    ----------
    tfidf : TfidfVectorizer
        Fitted TF-IDF vectorizer (available after fit_transform).
    feature_dim : int
        Total feature dimension (HC + TF-IDF).
    """

    def __init__(self, tfidf_max_features: int = 1500, ngram_range: tuple = (1, 2)):
        """
        Parameters
        ----------
        tfidf_max_features : int
            Maximum vocabulary size for TF-IDF (default 1500).
        ngram_range : tuple
            N-gram range for TF-IDF (default (1, 2) for unigrams + bigrams).
        """
        self.tfidf = TfidfVectorizer(
            token_pattern=r"[a-zA-Z_][a-zA-Z0-9_]*",
            max_features=tfidf_max_features,
            sublinear_tf=True,
            ngram_range=ngram_range,
        )
        self.feature_dim = None

    def fit_transform(self, sources: list) -> csr_matrix:
        """
        Fit on training sources and return combined feature matrix.

        Parameters
        ----------
        sources : list of str
            List of Solidity source code strings (training set).

        Returns
        -------
        scipy.sparse.csr_matrix
            Combined HC + TF-IDF feature matrix, shape (n_samples, 1521).
        """
        X_hc    = self._hc_matrix(sources)
        X_tfidf = self.tfidf.fit_transform(sources)
        combined = hstack([X_hc, X_tfidf])
        self.feature_dim = combined.shape[1]
        return combined

    def transform(self, sources: list) -> csr_matrix:
        """
        Transform new sources using the fitted extractor.

        Parameters
        ----------
        sources : list of str
            List of Solidity source code strings (test set).

        Returns
        -------
        scipy.sparse.csr_matrix
            Combined HC + TF-IDF feature matrix, shape (n_samples, 1521).
        """
        X_hc    = self._hc_matrix(sources)
        X_tfidf = self.tfidf.transform(sources)
        return hstack([X_hc, X_tfidf])

    def _hc_matrix(self, sources: list) -> csr_matrix:
        rows = [extract_hc_features(s) for s in sources]
        return csr_matrix(pd.DataFrame(rows).values.astype(float))

    @property
    def hc_feature_names(self) -> list:
        """Names of all hand-crafted features (in order)."""
        names = list(HC_PATTERNS.keys()) + ["num_require", "num_functions", "loc"]
        return names
