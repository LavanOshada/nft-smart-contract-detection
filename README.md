# NFT Smart Contract Vulnerability Dataset

A labeled dataset of NFT smart contracts annotated with vulnerability classes, designed for LLM-based vulnerability detection research and compatible with [Slither](https://github.com/crytic/slither).

## Dataset Summary

| Property | Value |
|---|---|
| Total samples | 16,791 |
| Vulnerable contracts | 1,564 |
| Clean contracts | 15,227 |
| Vulnerability classes | 11 (5 NFT-specific + 6 general) |
| NFT standards | ERC-721, ERC-1155, Custom |
| Sources | NFTDefects (real on-chain) + synthetic |

## Quick Start

### Regenerate the dataset

```bash
pip install pandas
python generate_dataset.py
# Output written to output/
```

### Regenerate the paper document

```bash
npm install docx
node build_paper_doc.js
# Output: output/NFT_Dataset_Description.docx
```

### Run Slither on synthetic contracts

```bash
# Extract all synthetic contracts to .sol files
python3 -c "
import pandas as pd, pathlib
df = pd.read_csv('output/nft_synthetic_with_source.csv')
for _, row in df.iterrows():
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

## Files

| File | Description |
|---|---|
| `output/nft_vulnerability_dataset.csv` | Full dataset (16,791 rows) |
| `output/nft_vulnerability_dataset.jsonl` | Same, JSONL format |
| `output/nft_synthetic_with_source.csv` | Synthetic subset (260 rows, full Solidity source) |
| `output/nft_synthetic_with_source.jsonl` | Same, JSONL format |
| `output/dataset_card.md` | Schema, usage guide, citation |
| `output/NFT_Dataset_Description.docx` | Full paper-ready dataset description (IEEE style) |
| `generate_dataset.py` | Script to regenerate the full dataset |
| `build_paper_doc.js` | Script to regenerate the Word document |

## Vulnerability Classes

### NFT-Specific (from NFTDefects taxonomy)

| Class | Real | Synthetic | Severity |
|---|---|---|---|
| ERC721_Reentrancy | 503 | 30 | High |
| Unlimited_Minting | 708 | 30 | High–Medium |
| Missing_Requirements | 73 | 20 | Medium–High |
| Public_Burn | 37 | 20 | High–Medium |
| Risky_Mutable_Proxy | 10 | 20 | Critical |

### General Slither-Detectable

| Class | Synthetic | Severity |
|---|---|---|
| Access_Control | 20 | Critical–High |
| Reentrancy_ETH | 20 | Critical |
| Unchecked_Transfer | 20 | High–Medium |
| Integer_Overflow | 20 | High–Medium |
| TX_Origin_Auth | 10 | High |
| Unprotected_Selfdestruct | 20 | Critical–High |

## Data Sources

- **NFTDefects** — 16,527 verified ERC-721 contracts from Ethereum Mainnet, labeled with 5 NFT-specific defect types. Paper: [ISSTA 2023](https://doi.org/10.1145/3597926.3598063). Repo: https://github.com/NFTDefects/nftdefects
- **Synthetic** — 260 hand-authored Solidity contracts with deliberate, isolated defects, covering all 11 vulnerability classes with full source code.

## Citation

```bibtex
@inproceedings{nftdefects2023,
  title     = {Definition and Detection of Defects in NFT Smart Contracts},
  author    = {Chen, Shuo and others},
  booktitle = {Proceedings of the 32nd ACM SIGSOFT International Symposium on Software Testing and Analysis (ISSTA)},
  year      = {2023},
  doi       = {10.1145/3597926.3598063}
}
```

## Licence

- Synthetic contracts: MIT  
- NFTDefects labels: MIT (see https://github.com/NFTDefects/nftdefects)
