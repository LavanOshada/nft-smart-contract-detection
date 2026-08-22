# NFT Smart Contract Vulnerability Dataset

## Overview

A labeled dataset of NFT smart contracts annotated with vulnerability classes, designed for LLM-based vulnerability detection research and compatible with static analysis tools such as [Slither](https://github.com/crytic/slither).

| Property | Value |
|---|---|
| Total samples | 16,791 |
| Vulnerable contracts | 1,564 |
| Clean contracts | 15,227 |
| Vulnerability classes | 11 (5 NFT-specific + 6 general) |
| NFT standards covered | ERC-721, ERC-1155, Custom |
| Sources | NFTDefects (real on-chain), synthetic |

---

## Dataset Sources

### 1. NFTDefects (Real On-Chain Contracts)
- **Paper**: "Definition and Detection of Defects in NFT Smart Contracts" (ISSTA 2023)
- **Reference**: https://github.com/NFTDefects/nftdefects
- **Contracts**: 16,531 verified ERC-721 contracts on Ethereum Mainnet
- **Labels**: 5 NFT-specific defect types, manually and tool-verified
- **Source code**: Contract addresses are provided; source code can be fetched from Etherscan using the `contract_address` column

### 2. Synthetic Contracts (Solidity source included)
- **Count**: 260 contracts with full Solidity source code
- **Method**: Hand-crafted templates parameterised over 10 contract name/symbol variants
- **Coverage**: 11 vulnerability classes × multiple templates per class
- **Usability**: Immediately runnable through Slither without any API key

---

## Vulnerability Classes

### NFT-Specific (NFTDefects Taxonomy)

| Class | Count (real) | Count (synthetic) | Severity | Slither Detector |
|---|---|---|---|---|
| ERC721_Reentrancy | 503 | 30 | High | reentrancy-no-eth |
| Unlimited_Minting | 708 | 30 | High–Medium | access-control |
| Missing_Requirements | 73 | 20 | Medium–High | missing-zero-check |
| Public_Burn | 37 | 20 | High–Medium | access-control |
| Risky_Mutable_Proxy | 10 | 20 | Critical–High | access-control |

**ERC721_Reentrancy**: The `onERC721Received` callback (triggered by `_safeMint` or `safeTransferFrom`) executes before state variables are updated, enabling re-entrant calls that bypass mint limits or drain funds.

**Unlimited_Minting**: No on-chain maximum supply cap, or cap check is bypassable (e.g., via `tx.origin`), allowing infinite token creation and destroying scarcity guarantees.

**Missing_Requirements**: Critical `require` checks are absent — e.g., no sale-active guard, no balance check before withdrawal, or price settable to zero.

**Public_Burn**: The `burn` or `_burn` function lacks an ownership/approval check, allowing any address to destroy tokens they do not own.

**Risky_Mutable_Proxy**: The proxy upgrade function (pointing to a new implementation via `delegatecall`) lacks access control or a timelock, enabling unauthorised contract replacement.

### General (Slither-Detectable in NFT Context)

| Class | Count (synthetic) | Severity | Slither Detector |
|---|---|---|---|
| Access_Control | 20 | Critical–High | access-control |
| Reentrancy_ETH | 20 | Critical | reentrancy-eth |
| Unchecked_Transfer | 20 | High–Medium | unchecked-transfer |
| Integer_Overflow | 20 | High–Medium | taint-analysis |
| TX_Origin_Auth | 10 | High | tx-origin |
| Unprotected_Selfdestruct | 20 | Critical–High | suicidal |

---

## Schema

| Column | Type | Description |
|---|---|---|
| `id` | string | Unique sample identifier (NFT-SYN-xxxx or NFT-REAL-xxxxx) |
| `source` | string | `synthetic`, `NFTDefects (real on-chain)`, or `NFTDefects evaluation sample (real .sol)` |
| `contract_name` | string | Contract name (empty for real contracts without source) |
| `nft_standard` | string | ERC-721 / ERC-1155 / Custom |
| `solidity_version` | string | Pragma version string |
| `vulnerability_class` | string | Primary vulnerability class (or `None`) |
| `nftdefects_label` | string | NFTDefects taxonomy label |
| `severity` | string | Critical / High / Medium / None |
| `is_vulnerable` | int | 1 = vulnerable, 0 = clean |
| `slither_detector` | string | Relevant Slither detector name |
| `vulnerability_description` | string | Human-readable description of the vulnerability |
| `label_risky_mutable_proxy` | int | NFTDefects multi-label: Risky Mutable Proxy (0/1) |
| `label_erc721_reentrancy` | int | NFTDefects multi-label: ERC-721 Re-entrancy (0/1) |
| `label_unlimited_minting` | int | NFTDefects multi-label: Unlimited Minting (0/1) |
| `label_missing_requirements` | int | NFTDefects multi-label: Missing Requirements (0/1) |
| `label_public_burn` | int | NFTDefects multi-label: Public Burn (0/1) |
| `contract_address` | string | Ethereum address (real contracts only) |
| `source_code` | string | Full Solidity source (synthetic + .sol files); Etherscan link for real contracts |

---

## Files

| File | Description |
|---|---|
| `nft_vulnerability_dataset.csv` | Full dataset (16,791 rows) — all sources |
| `nft_vulnerability_dataset.jsonl` | Same, JSONL format |
| `nft_synthetic_with_source.csv` | Synthetic-only subset (260 rows, full Solidity source) |
| `nft_synthetic_with_source.jsonl` | Same, JSONL format |
| `dataset_card.md` | This file |

---

## Using with Slither

To run Slither on the synthetic contracts:

```bash
# Extract a contract to file
python3 -c "
import pandas as pd, pathlib
df = pd.read_csv('nft_synthetic_with_source.csv')
for _, row in df[df['source']=='synthetic'].iterrows():
    p = pathlib.Path(f'contracts/{row[\"id\"]}.sol')
    p.parent.mkdir(exist_ok=True)
    p.write_text(row['source_code'])
print(f'Wrote {len(df)} contracts to contracts/')
"

# Run Slither on all
for f in contracts/*.sol; do
    slither "$f" --json slither_output/$(basename "$f" .sol).json 2>/dev/null
done
```

To fetch source code for real contracts (requires Etherscan API key):

```python
import pandas as pd, requests, time

df = pd.read_csv('nft_vulnerability_dataset.csv')
real = df[df['source'] == 'NFTDefects (real on-chain)']

API_KEY = "YOUR_ETHERSCAN_API_KEY"

for _, row in real.iterrows():
    addr = row['contract_address']
    r = requests.get(
        "https://api.etherscan.io/api",
        params={
            "module": "contract",
            "action": "getsourcecode",
            "address": addr,
            "apikey": API_KEY,
        }
    )
    source = r.json()["result"][0]["SourceCode"]
    # ... save or process
    time.sleep(0.25)  # respect rate limit
```

---

## Citation

If you use this dataset, please cite:

```bibtex
@inproceedings{nftdefects2023,
  title     = {Definition and Detection of Defects in NFT Smart Contracts},
  author    = {Chen, Shuo and others},
  booktitle = {Proceedings of the 32nd ACM SIGSOFT International Symposium on Software Testing and Analysis (ISSTA)},
  year      = {2023},
  doi       = {10.1145/3597926.3598063}
}
```

---

## Licence

Synthetic contracts: MIT  
NFTDefects labels: see https://github.com/NFTDefects/nftdefects (MIT)
