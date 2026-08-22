"""
Fetch Solidity source code for real on-chain NFT contracts via Etherscan API
=============================================================================
Usage:
    python pipeline/fetch_etherscan_source.py --api-key YOUR_KEY

What it does:
  - Reads output/nft_vulnerability_dataset.csv
  - For each real on-chain contract (source == "NFTDefects (real on-chain)")
    that doesn't yet have source code, fetches it from Etherscan
  - Saves progress incrementally to output/nft_real_with_source.csv
    (safe to interrupt and resume — already-fetched contracts are skipped)
  - Prints a live progress summary

Rate limit: 5 req/s on free Etherscan tier (script respects this automatically)
Estimated time: ~1 hour for all 16,527 contracts on free tier
                ~10 min for first 1,000 (enough to start ML experiments)
"""

import argparse
import time
import pathlib
import requests
import pandas as pd
from datetime import datetime

# ── Paths ──────────────────────────────────────────────────────────────────
HERE    = pathlib.Path(__file__).parent
FULL    = HERE.parent / "output" / "nft_vulnerability_dataset.csv"
OUT     = HERE.parent / "output" / "nft_real_with_source.csv"
PROGRESS= HERE.parent / "output" / "_fetch_progress.csv"

ETHERSCAN_URL = "https://api.etherscan.io/v2/api"
RATE_DELAY    = 0.22   # ~4.5 req/s, safely under the 5/s limit

def fetch_source(address: str, api_key: str) -> str | None:
    """Return Solidity source string or None if unavailable."""
    try:
        r = requests.get(
            ETHERSCAN_URL,
            params={
                "chainid": "1",
                "module":  "contract",
                "action":  "getsourcecode",
                "address": address,
                "apikey":  api_key,
            },
            timeout=10,
        )
        data = r.json()
        if data.get("status") == "1" and data["result"]:
            src = data["result"][0]["SourceCode"].strip()
            if src and src != "0x":
                return src
    except Exception:
        pass
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-key", required=True, help="Etherscan API key")
    parser.add_argument("--limit",   type=int, default=None,
                        help="Stop after fetching this many contracts (for testing)")
    args = parser.parse_args()

    # ── Load full dataset ──────────────────────────────────────────────────
    print(f"[{datetime.now():%H:%M:%S}] Loading dataset …")
    df = pd.read_csv(FULL)
    real = df[df["source"] == "NFTDefects (real on-chain)"].copy()
    print(f"  {len(real):,} real on-chain contracts")

    # ── Load existing progress ─────────────────────────────────────────────
    if PROGRESS.exists():
        done = pd.read_csv(PROGRESS, index_col="contract_address")
        print(f"  {len(done):,} already fetched — resuming …")
    else:
        done = pd.DataFrame(columns=["contract_address", "source_code", "verified"])
        done = done.set_index("contract_address")

    # ── Fetch loop ─────────────────────────────────────────────────────────
    fetched = 0
    failed  = 0
    todo    = real[~real["contract_address"].isin(done.index)]

    if args.limit:
        todo = todo.head(args.limit)

    print(f"  {len(todo):,} remaining to fetch\n")

    for i, (_, row) in enumerate(todo.iterrows(), 1):
        addr = row["contract_address"]
        src  = fetch_source(addr, args.api_key)

        if src:
            done.loc[addr] = {"source_code": src, "verified": True}
            fetched += 1
        else:
            done.loc[addr] = {"source_code": "", "verified": False}
            failed += 1

        # Save progress every 50 contracts
        if i % 50 == 0:
            done.to_csv(PROGRESS)
            pct = 100 * fetched / (fetched + failed) if (fetched + failed) else 0
            print(f"  [{datetime.now():%H:%M:%S}] {i:>5}/{len(todo):,} | "
                  f"verified: {fetched:,} ({pct:.0f}%) | unverified: {failed:,}")

        time.sleep(RATE_DELAY)

    # Final save of progress
    done.to_csv(PROGRESS)

    # ── Merge back and save ────────────────────────────────────────────────
    print(f"\n[{datetime.now():%H:%M:%S}] Merging results …")
    real = real.copy()
    real["source_code"] = real["contract_address"].map(
        done["source_code"].where(done["verified"], other=None)
    )
    real["is_verified"] = real["contract_address"].map(done["verified"]).fillna(False)

    # Keep only verified contracts (those with source)
    verified = real[real["is_verified"]].copy()
    print(f"  {len(verified):,} contracts with verified source code")
    print(f"  Class distribution:\n{verified['vulnerability_class'].value_counts().to_string()}")

    verified.to_csv(OUT, index=False)
    print(f"\n  Saved → output/nft_real_with_source.csv")
    print(f"\nDone! Next step: run  python pipeline/ml_baseline.py --use-real")


if __name__ == "__main__":
    main()
