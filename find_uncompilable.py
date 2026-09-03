"""
find_uncompilable.py
====================
Scans eval_sample_400.jsonl to find contracts that would fail to compile
with solc 0.8.16 — the version NFTGuard requires.

Identifies:
  1. Contracts with pragma < 0.8.x (version mismatch)
  2. Contracts with ^0.x.x or >=0.x.x that don't cover 0.8.16
  3. Contracts using assembly features deprecated in 0.8.x

Outputs:
  - Console summary with candidate list
  - output/uncompilable_candidates.jsonl  (contracts likely to fail)
  - output/uncompilable_candidates.csv    (summary for review)
"""

import json
import re
import pathlib
import pandas as pd

INPUT  = pathlib.Path("output/eval_sample_400.jsonl")
OUT_JSONL = pathlib.Path("output/uncompilable_candidates.jsonl")
OUT_CSV   = pathlib.Path("output/uncompilable_candidates.csv")

# ── Pragma parser ─────────────────────────────────────────────────────────────

def extract_pragma(source: str) -> str:
    """Return the first pragma solidity version string found."""
    m = re.search(r'pragma\s+solidity\s+([^;]+);', source)
    if m:
        return m.group(1).strip()
    return ""

def is_incompatible_with_0816(pragma_str: str) -> tuple[bool, str]:
    """
    Returns (is_incompatible, reason).
    Checks whether the pragma version constraint EXCLUDES 0.8.16.
    """
    if not pragma_str:
        return False, "no pragma found"

    p = pragma_str.strip()

    # Extract all version numbers mentioned
    versions = re.findall(r'(\d+)\.(\d+)\.(\d+)', p)

    # Exact version pinned below 0.8.0
    if re.match(r'^=?\s*0\.[0-7]\.', p):
        return True, f"pinned to old version: {p}"

    # ^0.x.y where x < 8  (caret allows patch updates only within minor)
    m = re.match(r'^\^0\.([0-7])\.', p)
    if m:
        return True, f"caret range excludes 0.8: {p}"

    # >=0.x.y <0.8.0  or  >=0.x.y <=0.7.z
    if re.search(r'<\s*0\.8\b', p):
        return True, f"upper bound below 0.8: {p}"
    if re.search(r'<=\s*0\.[0-7]\.', p):
        return True, f"upper bound below 0.8: {p}"

    # >=0.x.y <0.9.0 style — compatible if x<=8
    # Anything that explicitly pins to 0.4-0.7
    for major, minor, patch in versions:
        if int(major) == 0 and int(minor) < 8:
            # Could still be compatible if it's a lower bound, check context
            # If it's the ONLY version mentioned and no upper bound
            if len(versions) == 1 and not re.search(r'[<>]=?\s*0\.8', p):
                # e.g. ">=0.6.0" — 0.8.16 satisfies this
                if re.match(r'>=', p):
                    return False, f"lower bound only, compatible: {p}"
                # e.g. "0.6.12" pinned exactly
                if re.match(r'^=?\s*0\.', p) and '>' not in p and '<' not in p:
                    return True, f"pinned to old version: {p}"

    return False, f"likely compatible: {p}"

def has_old_assembly(source: str) -> bool:
    """Check for assembly patterns that break in 0.8.x."""
    # suicide() removed in 0.8
    if re.search(r'\bsuicide\s*\(', source):
        return True
    # sha3() removed in 0.8
    if re.search(r'\bsha3\s*\(', source):
        return True
    # throw statement removed in 0.8
    if re.search(r'\bthrow\s*;', source):
        return True
    return False

# ── Main ──────────────────────────────────────────────────────────────────────

rows = []
with open(INPUT) as f:
    for line in f:
        line = line.strip()
        if line:
            rows.append(json.loads(line))

print(f"Loaded {len(rows)} contracts\n")

candidates = []
summary_rows = []

for row in rows:
    contract_id = str(row.get("contract_address", row.get("contract_id", row.get("id", ""))))
    true_label  = str(row.get("vulnerability_class", row.get("label", "None")))
    source      = str(row.get("source_code", row.get("source", "")))

    pragma_str = extract_pragma(source)
    incompatible, reason = is_incompatible_with_0816(pragma_str)
    old_asm = has_old_assembly(source)

    if incompatible or old_asm:
        full_reason = reason
        if old_asm:
            full_reason += " + deprecated syntax (suicide/sha3/throw)"

        candidates.append(row)
        summary_rows.append({
            "contract_id":  contract_id,
            "true_label":   true_label,
            "pragma":       pragma_str,
            "reason":       full_reason,
            "source_len":   len(source),
        })

# ── Report ────────────────────────────────────────────────────────────────────

df = pd.DataFrame(summary_rows)

print(f"Found {len(candidates)} likely-uncompilable contracts out of {len(rows)}\n")

if len(df):
    print("Label distribution of candidates:")
    print(df["true_label"].value_counts().to_string())
    print()

    print("Pragma version breakdown:")
    print(df["pragma"].value_counts().head(20).to_string())
    print()

    print("First 20 candidates:")
    print(df[["contract_id", "true_label", "pragma", "reason"]].head(20).to_string(index=False))

# ── Save ──────────────────────────────────────────────────────────────────────

OUT_JSONL.parent.mkdir(parents=True, exist_ok=True)

with open(OUT_JSONL, "w") as f:
    for row in candidates:
        f.write(json.dumps(row) + "\n")

df.to_csv(OUT_CSV, index=False)

print(f"\nSaved {len(candidates)} candidates → {OUT_JSONL}")
print(f"Summary CSV → {OUT_CSV}")
print("\nNext step: pick ~20 diverse candidates (mix of vulnerability classes),")
print("fix pragma/imports only, run NFTGuard on fixed versions for ground truth.")
