"""
slither_ablation.py — Slither-only ablation baseline for NFT vulnerability detection.

Runs Slither on each contract in eval_sample_400.jsonl and maps its findings
to the 6 NFTDefects vulnerability classes using a rule-based mapping.

Key fixes over v1:
  - Version-aware compilation: detects pragma solidity and installs correct solc
  - Contract written to repo root (not tempdir) so @openzeppelin imports resolve
  - Handles caret/tilde/range pragma expressions

Expected result:
  - Detects ERC721_Reentrancy on contracts with unguarded safeTransferFrom calls
  - Zero detection on NFT-specific classes (Unlimited_Minting, Missing_Requirements,
    Public_Burn, Risky_Mutable_Proxy) — Slither has no domain rules for these
  - Confirms that static analysis alone cannot replace LLM-based NFT vulnerability detection

Usage:
    python pipeline/slither_ablation.py \
        --data output/eval_sample_400.jsonl \
        --out results/slither_ablation_results.csv \
        [--timeout 90]

Requirements:
    pip install slither-analyzer solc-select
    npm install @openzeppelin/contracts   (already done)
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Solc version resolution
# ---------------------------------------------------------------------------

# Map (major, minor) → latest stable patch version
SOLC_VERSION_MAP = {
    (0, 4): "0.4.26",
    (0, 5): "0.5.17",
    (0, 6): "0.6.12",
    (0, 7): "0.7.6",
    (0, 8): "0.8.20",
}
DEFAULT_SOLC = "0.8.20"

_installed_versions = set()
_active_version = None


def detect_solc_version(source_code: str) -> str:
    """
    Parse pragma solidity from source and return the best matching stable solc version.
    Handles: ^0.8.0, >=0.7.0 <0.8.0, 0.6.12, ~0.8.4, >=0.6.0, etc.
    """
    match = re.search(r'pragma\s+solidity\s+([^;]+);', source_code)
    if not match:
        return DEFAULT_SOLC

    pragma = match.group(1).strip()

    # Exact version (no operator): "0.8.7"
    exact = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)', pragma)
    if exact:
        maj, min_, pat = int(exact.group(1)), int(exact.group(2)), int(exact.group(3))
        # Use the stable version for that minor series
        stable = SOLC_VERSION_MAP.get((maj, min_))
        if stable:
            sv_patch = int(stable.split(".")[2])
            # If exact patch is <= stable, use stable; else use exact
            return stable if pat <= sv_patch else stable
        return f"{maj}.{min_}.{pat}"

    # Extract all version numbers mentioned, pick the first one to determine minor series
    all_versions = re.findall(r'(\d+)\.(\d+)\.(\d+)', pragma)
    if all_versions:
        maj, min_ = int(all_versions[0][0]), int(all_versions[0][1])
        return SOLC_VERSION_MAP.get((maj, min_), DEFAULT_SOLC)

    # Fallback: look for major.minor only
    mm = re.search(r'(\d+)\.(\d+)', pragma)
    if mm:
        maj, min_ = int(mm.group(1)), int(mm.group(2))
        return SOLC_VERSION_MAP.get((maj, min_), DEFAULT_SOLC)

    return DEFAULT_SOLC


def ensure_solc(version: str, timeout: int = 120) -> bool:
    """Install solc version if needed, then activate it. Returns True on success."""
    global _active_version

    if version == _active_version:
        return True  # already active

    if version not in _installed_versions:
        try:
            result = subprocess.run(
                ["solc-select", "install", version],
                capture_output=True, text=True, timeout=timeout
            )
            if result.returncode != 0 and "already installed" not in result.stdout:
                print(f"  [solc-select install {version}] failed: {result.stderr[:200]}")
                return False
            _installed_versions.add(version)
        except Exception as e:
            print(f"  [solc-select install] exception: {e}")
            return False

    try:
        result = subprocess.run(
            ["solc-select", "use", version],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            _active_version = version
            return True
        print(f"  [solc-select use {version}] failed: {result.stderr[:200]}")
        return False
    except Exception as e:
        print(f"  [solc-select use] exception: {e}")
        return False


# ---------------------------------------------------------------------------
# Slither detector → NFTDefects class mapping
# ---------------------------------------------------------------------------

REENTRANCY_DETECTORS = {
    "reentrancy-eth",
    "reentrancy-no-eth",
    "reentrancy-benign",
    "reentrancy-unlimited-gas",
    "reentrancy-events",
}

ALL_CLASSES = [
    "ERC721_Reentrancy",
    "Unlimited_Minting",
    "Missing_Requirements",
    "Public_Burn",
    "Risky_Mutable_Proxy",
    "None",
]

# Temp file placed in repo root so node_modules/@openzeppelin is reachable
TEMP_CONTRACT_NAME = "_slither_ablation_tmp.sol"


def run_slither(sol_path: str, repo_root: str, timeout: int, debug: bool = False) -> dict:
    """Run Slither on a .sol file from repo_root, return parsed JSON output."""
    # Use forward slashes for remapping path (solc requires POSIX-style paths even on Windows)
    oz_path = os.path.join(repo_root, 'node_modules', '@openzeppelin').replace('\\', '/') + '/'
    cmd = [
        "slither",
        sol_path,
        "--json", "-",
        "--solc-remaps", f"@openzeppelin/={oz_path}",
        "--disable-color",
        "--exclude-informational",
        "--exclude-low",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=repo_root,
        )
        if debug:
            print(f"  [slither] returncode={result.returncode}")
        # On Windows, Slither exits with -1 (4294967295) even on success.
        # Always try to parse stdout first — valid JSON trumps returncode.
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                if debug:
                    print(f"  [slither] parsed JSON ok, success={data.get('success')}, "
                          f"detectors={len(data.get('results',{}).get('detectors',[]))}")
                return data
            except json.JSONDecodeError:
                pass
        # No parseable stdout → real error
        err_msg = (result.stderr or result.stdout or "no output")[:600]
        if debug:
            print(f"  [slither error] {err_msg[:200]}")
        return {"error": err_msg}
    except subprocess.TimeoutExpired:
        return {"error": f"timeout_{timeout}s"}
    except FileNotFoundError:
        print("ERROR: 'slither' not found. Run: pip install slither-analyzer", file=sys.stderr)
        sys.exit(1)


def map_to_class(slither_output: dict) -> str:
    """
    Map Slither detector output to one of the 6 NFTDefects classes.
    Slither can only detect reentrancy; all other classes → None.

    Slither JSON format: {"success": true/false, "error": null/str, "results": {"detectors": [...]}}
    Our error format:    {"error": "stderr text"}  (no "success" key)
    """
    # Our custom error dict (compilation/subprocess failure) — no "success" key
    if "success" not in slither_output:
        return "None"
    # Slither reported its own failure
    if slither_output.get("success") is False:
        return "None"
    # Valid output — check detectors
    detectors = slither_output.get("results", {}).get("detectors", [])
    fired = {d.get("check", "") for d in detectors}
    if fired & REENTRANCY_DETECTORS:
        return "ERC721_Reentrancy"
    return "None"


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate(predictions: list, labels: list) -> dict:
    from collections import defaultdict
    tp, fp, fn = defaultdict(int), defaultdict(int), defaultdict(int)
    for pred, label in zip(predictions, labels):
        if pred == label:
            tp[label] += 1
        else:
            fp[pred] += 1
            fn[label] += 1

    per_class = {}
    f1_scores = []
    for cls in ALL_CLASSES:
        p = tp[cls] / (tp[cls] + fp[cls]) if (tp[cls] + fp[cls]) > 0 else 0.0
        r = tp[cls] / (tp[cls] + fn[cls]) if (tp[cls] + fn[cls]) > 0 else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        per_class[cls] = {
            "precision": round(p, 4), "recall": round(r, 4),
            "f1": round(f1, 4), "support": labels.count(cls)
        }
        f1_scores.append(f1)

    return {
        "macro_f1": round(sum(f1_scores) / len(f1_scores), 4),
        "accuracy": round(sum(p == l for p, l in zip(predictions, labels)) / len(labels), 4),
        "per_class": per_class,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Slither-only ablation baseline (v2 — version-aware)")
    parser.add_argument("--data", required=True, help="Path to eval_sample_400.jsonl")
    parser.add_argument("--out", required=True, help="Output CSV path")
    parser.add_argument("--timeout", type=int, default=90,
                        help="Per-contract Slither timeout in seconds (default 90)")
    args = parser.parse_args()

    data_path = Path(args.data)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Repo root = parent of the data file's parent (data is in output/, repo root is up one)
    repo_root = str(data_path.parent.parent.resolve())
    tmp_sol = os.path.join(repo_root, TEMP_CONTRACT_NAME)

    print(f"Slither Ablation v2 (version-aware)")
    print(f"Repo root : {repo_root}")
    print(f"Temp file : {tmp_sol}")
    print(f"Timeout   : {args.timeout}s per contract")
    print(f"Output    : {out_path}")
    print()

    # Pre-install common solc versions to avoid install delay during run
    print("Pre-installing common solc versions...")
    for ver in SOLC_VERSION_MAP.values():
        result = subprocess.run(
            ["solc-select", "install", ver],
            capture_output=True, text=True, timeout=120
        )
        status = "ok" if result.returncode == 0 or "already" in result.stdout else "failed"
        print(f"  {ver}: {status}")
        _installed_versions.add(ver)
    print()

    # Load dataset
    contracts = []
    with open(data_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                contracts.append(json.loads(line))
    print(f"Loaded {len(contracts)} contracts\n")

    predictions, labels, rows = [], [], []
    errors = 0
    reentrancy_detected = 0
    start = time.time()

    for i, contract in enumerate(contracts):
        contract_id = contract.get("contract_address", f"contract_{i}")
        source_code = contract.get("source_code", "")
        true_label = contract.get("vulnerability_class", "None")

        # Detect and activate correct solc version
        solc_ver = detect_solc_version(source_code)
        ver_ok = ensure_solc(solc_ver)

        if not ver_ok:
            # Fall back to default
            ensure_solc(DEFAULT_SOLC)
            solc_ver = DEFAULT_SOLC

        # Write contract to repo root (so @openzeppelin imports resolve)
        with open(tmp_sol, "w", encoding="utf-8") as f:
            f.write(source_code)

        # Run Slither — print debug info for first 3 contracts to diagnose errors
        debug = (i < 3)
        slither_out = run_slither(tmp_sol, repo_root, args.timeout, debug=debug)
        predicted = map_to_class(slither_out)

        had_error = "success" not in slither_out or slither_out.get("success") is False
        if had_error:
            errors += 1
            if i < 3:
                print(f"  [error detail] {str(slither_out.get('error', ''))[:300]}")
        if predicted == "ERC721_Reentrancy":
            reentrancy_detected += 1

        detectors_fired = []
        if not had_error:
            detectors_fired = [
                d.get("check", "")
                for d in slither_out.get("results", {}).get("detectors", [])
            ]

        predictions.append(predicted)
        labels.append(true_label)
        rows.append({
            "contract_id": contract_id,
            "true_label": true_label,
            "predicted": predicted,
            "correct": predicted == true_label,
            "solc_version": solc_ver,
            "slither_error": had_error,
            "error_msg": str(slither_out.get("error") or "")[:200] if had_error else "",
            "detectors_fired": "|".join(detectors_fired),
        })

        elapsed = time.time() - start
        eta = (len(contracts) - i - 1) / (i + 1) * elapsed / 60
        if (i + 1) % 10 == 0 or i == 0:
            print(f"[{i+1:3d}/{len(contracts)}] solc={solc_ver} | "
                  f"true={true_label:25s} pred={predicted:20s} | "
                  f"errors={errors} reentrancy_found={reentrancy_detected} ETA={eta:.1f}min")

    # Clean up temp file
    try:
        os.remove(tmp_sol)
    except Exception:
        pass

    # Write CSV
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    metrics = evaluate(predictions, labels)
    elapsed_min = (time.time() - start) / 60

    print("\n" + "=" * 64)
    print("SLITHER-ONLY ABLATION RESULTS (v2 — version-aware)")
    print("=" * 64)
    print(f"Macro F1:  {metrics['macro_f1']:.4f}")
    print(f"Accuracy:  {metrics['accuracy']:.4f}")
    print()
    print(f"{'Class':<28} {'F1':>6} {'Prec':>6} {'Rec':>6} {'Support':>8}")
    print("-" * 64)
    for cls in ALL_CLASSES:
        pc = metrics["per_class"][cls]
        print(f"{cls:<28} {pc['f1']:>6.3f} {pc['precision']:>6.3f} "
              f"{pc['recall']:>6.3f} {pc['support']:>8d}")
    print("=" * 64)
    print(f"Slither errors : {errors}/{len(contracts)}")
    print(f"Reentrancy found: {reentrancy_detected}")
    print(f"Total time : {elapsed_min:.1f} min")

    summary_path = out_path.parent / "slither_ablation_summary.json"
    summary = {
        "method": "Slither-only",
        "model": "none",
        "version": "v2-version-aware",
        "n_contracts": len(contracts),
        "slither_errors": errors,
        "reentrancy_detected": reentrancy_detected,
        "elapsed_minutes": round(elapsed_min, 1),
        **metrics,
    }
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Summary → {summary_path}")


if __name__ == "__main__":
    main()
