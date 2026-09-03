"""
make_uncompilable_experiment.py
================================
Experiment 4: Uncompilable Contracts.

Takes contracts from eval_sample_400.jsonl (already labelled by NFTGuard),
replaces the pragma solidity line with "^0.6.0" so that solc 0.8.16 rejects them,
and saves the modified contracts as the experiment set.

The vulnerability is in business logic — not the pragma — so the LLM result
on the pragma-modified version is equivalent to the original. Ground truth
labels come from the original NFTGuard run.

NFTGuard result on these: 0 contracts analysed (compilation failure)
LLM result on these:      X% F1 (detects vulnerabilities despite no compilation)

Output:
  output/exp4_uncompilable.jsonl      — pragma-modified contracts (for LLM)
  output/exp4_uncompilable_meta.csv   — original labels + pragma info
"""

import json
import re
import random
import pathlib
import pandas as pd

random.seed(42)

INPUT   = pathlib.Path("output/eval_sample_400.jsonl")
OUT_JSONL = pathlib.Path("output/exp4_uncompilable.jsonl")
OUT_CSV   = pathlib.Path("output/exp4_uncompilable_meta.csv")

# Target sample size per class
SAMPLES_PER_CLASS = {
    "ERC721_Reentrancy":    8,
    "Unlimited_Minting":    8,
    "Missing_Requirements": 8,
    "Public_Burn":          8,
    "Risky_Mutable_Proxy":  8,   # only 10 exist, take 8
    "None":                 10,  # benign contracts
}

TARGET_PRAGMA = "^0.6.0"

# ── Load ──────────────────────────────────────────────────────────────────────

rows = []
with open(INPUT) as f:
    for line in f:
        line = line.strip()
        if line:
            rows.append(json.loads(line))

print(f"Loaded {len(rows)} contracts")

# ── Split by class ────────────────────────────────────────────────────────────

by_class: dict[str, list] = {}
for row in rows:
    label = str(row.get("vulnerability_class", row.get("label", "None")))
    by_class.setdefault(label, []).append(row)

print("\nAvailable per class:")
for cls, items in sorted(by_class.items(), key=lambda x: -len(x[1])):
    print(f"  {cls:<30} {len(items):>4}")

# ── Sample ────────────────────────────────────────────────────────────────────

selected = []
for cls, n in SAMPLES_PER_CLASS.items():
    pool = by_class.get(cls, [])
    take = min(n, len(pool))
    selected.extend(random.sample(pool, take))
    print(f"  Sampled {take}/{len(pool)} from {cls}")

print(f"\nTotal selected: {len(selected)} contracts")

# ── Modify pragma ─────────────────────────────────────────────────────────────

def replace_pragma(source: str, new_pragma: str) -> tuple[str, str]:
    """Replace first pragma solidity line. Returns (modified_source, original_pragma)."""
    pattern = r'(pragma\s+solidity\s+)([^;]+)(;)'
    m = re.search(pattern, source)
    if m:
        original = m.group(2).strip()
        modified = re.sub(pattern, rf'\g<1>{new_pragma}\g<3>', source, count=1)
        return modified, original
    return source, "not found"

modified_rows = []
meta_rows = []

for row in selected:
    contract_id = str(row.get("contract_address", row.get("contract_id", row.get("id", ""))))
    true_label  = str(row.get("vulnerability_class", row.get("label", "None")))
    source      = str(row.get("source_code", row.get("source", "")))

    modified_source, original_pragma = replace_pragma(source, TARGET_PRAGMA)

    # Build modified row — same structure as original JSONL
    mod_row = dict(row)
    mod_row["source_code"]     = modified_source
    mod_row["original_pragma"] = original_pragma
    mod_row["modified_pragma"] = TARGET_PRAGMA

    modified_rows.append(mod_row)
    meta_rows.append({
        "contract_id":      contract_id,
        "true_label":       true_label,
        "original_pragma":  original_pragma,
        "modified_pragma":  TARGET_PRAGMA,
        "pragma_changed":   original_pragma != "not found",
        "source_len":       len(modified_source),
    })

# ── Save ──────────────────────────────────────────────────────────────────────

OUT_JSONL.parent.mkdir(parents=True, exist_ok=True)

with open(OUT_JSONL, "w") as f:
    for row in modified_rows:
        f.write(json.dumps(row) + "\n")

df = pd.DataFrame(meta_rows)
df.to_csv(OUT_CSV, index=False)

# ── Report ────────────────────────────────────────────────────────────────────

print(f"\nLabel distribution in experiment set:")
print(df["true_label"].value_counts().to_string())

print(f"\nPragma changes:")
print(f"  Successfully modified: {df['pragma_changed'].sum()}/{len(df)}")
print(f"  No pragma found (kept as-is): {(~df['pragma_changed']).sum()}")

print(f"\nOriginal pragma versions:")
print(df["original_pragma"].value_counts().head(15).to_string())

print(f"\nSaved {len(modified_rows)} contracts → {OUT_JSONL}")
print(f"Metadata → {OUT_CSV}")

print(f"""
═══════════════════════════════════════════════════════════
EXPERIMENT 4 SETUP COMPLETE
═══════════════════════════════════════════════════════════

Step 1 — Verify NFTGuard fails on these contracts:
  (Optional) Try compiling one with solc 0.8.16 to confirm rejection.

Step 2 — Run LLM on uncompilable contracts:
  python pipeline/nft_ruleguided.py \\
      --openai-key sk-or-v1-... \\
      --model deepseek/deepseek-chat \\
      --data output/exp4_uncompilable.jsonl \\
      --out results/exp4_uncompilable_results.csv \\
      --workers 3

Step 3 — Compare:
  NFTGuard: 0 contracts analysed (compilation failure)
  LLM:      X Macro F1 on {len(modified_rows)} contracts
═══════════════════════════════════════════════════════════
""")
