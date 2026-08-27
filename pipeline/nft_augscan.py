"""
nft_augscan.py — NFT-AugScan: AST-Augmented LLM Pipeline for NFT Vulnerability Detection

Architecture:
  Step 0: Structural feature extraction (regex/pattern-based, no compilation, 100% success rate)
  Step 1: Contextualized contract overview (LLM + structural features)
  Step 2: Targeted per-class vulnerability analysis (LLM guided by class-specific signals)
  Step 3: Cross-verification (LLM checks findings against structural signals)
  Step 4: Final classification (LLM aggregates all signals into one label)

Improvements over GPTScan:
  - Structural features ground each LLM phase in deterministic code signals
  - ERC721_Reentrancy specifically targeted using callback/guard pattern detection
  - ~8 API calls/contract vs ~16 for GPTScan

Improvements over NFT-Scan:
  - Independent phases avoid error propagation
  - No compilation dependency (unlike Slither-based hybrid)
  - Structural signals replace sequential chain dependency

Usage:
    python pipeline/nft_augscan.py \
        --openai-key sk-or-... \
        --model deepseek/deepseek-chat \
        --data output/eval_sample_400.jsonl \
        --out results/augscan_results.csv
"""

import argparse
import csv
import json
import re
import sys
import time
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TARGET_RPM = 50
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MAX_RETRIES = 6
RETRY_BASE = 5

VULNERABILITY_CLASSES = [
    "ERC721_Reentrancy",
    "Unlimited_Minting",
    "Missing_Requirements",
    "Public_Burn",
    "Risky_Mutable_Proxy",
    "None",
]

VULNERABILITY_DESCRIPTIONS = {
    "ERC721_Reentrancy": (
        "ERC721 Reentrancy: safeTransferFrom/_safeTransfer triggers the recipient's onERC721Received "
        "callback before state (balances, ownership mappings) is updated, allowing re-entry. "
        "The checks-effects-interactions pattern must be followed. "
        "Key signals: external transfer call before state update, missing nonReentrant guard, "
        "onERC721Received hook present."
    ),
    "Unlimited_Minting": (
        "Unlimited Minting: a public/external minting function has no supply cap or per-wallet limit, "
        "allowing anyone to mint an unbounded number of tokens. "
        "Key signals: _mint/_safeMint without require(totalSupply() < maxSupply), "
        "public mint function with no quantity restriction."
    ),
    "Missing_Requirements": (
        "Missing Requirements: sensitive operations (transfers, configuration, minting) lack proper "
        "require() checks for caller authorization or contract state validation. "
        "Key signals: public/external functions missing onlyOwner, msg.sender checks, or state guards."
    ),
    "Public_Burn": (
        "Public Burn: a burn function is callable by anyone including non-owners, allowing "
        "arbitrary destruction of tokens the caller does not own. "
        "Key signals: burn/burnFrom without require(ownerOf(tokenId)==msg.sender) or "
        "_isApprovedOrOwner check."
    ),
    "Risky_Mutable_Proxy": (
        "Risky Mutable Proxy: an upgradeable proxy pattern allows implementation replacement "
        "without adequate access control, or contains storage layout conflicts. "
        "Key signals: delegatecall, UUPS/TransparentProxy patterns, initialize() without "
        "initializer modifier, selfdestruct in implementation."
    ),
}


# ---------------------------------------------------------------------------
# Step 0: Structural Feature Extraction (no API, no compilation)
# ---------------------------------------------------------------------------

def extract_structural_features(source_code: str) -> dict:
    """
    Extract vulnerability-relevant structural features via regex/pattern matching.
    Works on raw Solidity source — no solc, no imports, no node_modules needed.
    """
    src = source_code

    # Reentrancy
    has_safe_transfer = bool(re.search(
        r'\bsafeTransferFrom\b|\b_safeTransfer\b|\bsafeTransfer\b', src))
    has_reentrancy_guard = bool(re.search(
        r'\bnonReentrant\b|\bReentrancyGuard\b', src))
    has_on_erc721_received = bool(re.search(r'\bonERC721Received\b', src))
    has_external_call = bool(re.search(
        r'\.(call|delegatecall|transfer|send)\s*[({]', src))
    # CEI violation heuristic: state variable assignment after a transfer call
    # (rough: look for transfer call in a function, then a storage write)
    cei_suspect = bool(re.search(
        r'(safeTransferFrom|\.transfer|\.call)[^}]{0,300}=\s*[^=]', src, re.DOTALL))

    # Minting
    has_mint = bool(re.search(r'\b_mint\s*\(|\b_safeMint\s*\(', src))
    has_supply_cap = bool(re.search(
        r'totalSupply\(\)\s*[<>+]|maxSupply|MAX_SUPPLY|_maxSupply|'
        r'require\s*\(.*[Ss]upply|require\s*\(.*[Mm]ax', src))
    mint_functions_public = re.findall(
        r'function\s+(\w*[Mm]int\w*)\s*\([^)]*\)\s*(?:public|external)', src)

    # Access control
    has_only_owner = bool(re.search(r'\bonlyOwner\b', src))
    has_ownable = bool(re.search(r'\bOwnable\b', src))
    require_count = len(re.findall(r'\brequire\s*\(', src))
    has_access_control = bool(re.search(
        r'\bAccessControl\b|\bRole\b|\bonlyRole\b', src))

    # Burn
    has_burn = bool(re.search(r'\b_burn\s*\(|\bburn\s*\(', src))
    burn_functions_public = re.findall(
        r'function\s+(\w*[Bb]urn\w*)\s*\([^)]*\)\s*(?:public|external)', src)
    burn_has_ownership_check = bool(re.search(
        r'function\s+\w*[Bb]urn\w*[^}]*'
        r'(?:ownerOf|_isApprovedOrOwner|msg\.sender\s*==)[^}]*}',
        src, re.DOTALL))

    # Proxy / upgradeable
    has_delegatecall = bool(re.search(r'\bdelegatecall\b', src))
    has_selfdestruct = bool(re.search(r'\bselfdestruct\b', src))
    has_upgradeable = bool(re.search(
        r'\bUpgradeable\b|\bTransparentUpgradeableProxy\b|\bUUPS\b|'
        r'\bProxyAdmin\b|\binitializer\b', src))
    has_initialize = bool(re.search(r'\bfunction\s+initialize\b', src))

    # General
    has_erc721 = bool(re.search(r'\bERC721\b|\bIERC721\b', src))
    pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', src)
    pragma = pragma_match.group(1).strip() if pragma_match else "unknown"

    return {
        "has_safe_transfer": has_safe_transfer,
        "has_reentrancy_guard": has_reentrancy_guard,
        "has_on_erc721_received": has_on_erc721_received,
        "has_external_call": has_external_call,
        "cei_suspect": cei_suspect,
        "has_mint": has_mint,
        "has_supply_cap": has_supply_cap,
        "mint_functions_public": mint_functions_public,
        "has_only_owner": has_only_owner,
        "has_ownable": has_ownable,
        "require_count": require_count,
        "has_access_control": has_access_control,
        "has_burn": has_burn,
        "burn_functions_public": burn_functions_public,
        "burn_has_ownership_check": burn_has_ownership_check,
        "has_delegatecall": has_delegatecall,
        "has_selfdestruct": has_selfdestruct,
        "has_upgradeable": has_upgradeable,
        "has_initialize": has_initialize,
        "has_erc721": has_erc721,
        "pragma": pragma,
    }


def format_features(f: dict) -> str:
    """Format structural features as a readable block for LLM prompts."""
    mints = f["mint_functions_public"] or ["none detected"]
    burns = f["burn_functions_public"] or ["none detected"]

    return f"""=== STRUCTURAL ANALYSIS (deterministic, compilation-free) ===
Pragma: {f['pragma']} | ERC721: {'YES' if f['has_erc721'] else 'NO'}

[Reentrancy]
  safeTransferFrom / _safeTransfer present : {'YES ⚠' if f['has_safe_transfer'] else 'no'}
  onERC721Received callback present        : {'YES ⚠' if f['has_on_erc721_received'] else 'no'}
  nonReentrant / ReentrancyGuard present   : {'YES ✓' if f['has_reentrancy_guard'] else 'NO — unprotected'}
  External .call/.transfer patterns        : {'YES' if f['has_external_call'] else 'no'}
  Possible CEI violation (state after call): {'SUSPECT ⚠' if f['cei_suspect'] else 'not detected'}

[Minting]
  _mint / _safeMint present                : {'YES' if f['has_mint'] else 'no'}
  Public/external mint functions           : {mints}
  Supply cap (MAX_SUPPLY / require check)  : {'YES ✓' if f['has_supply_cap'] else 'NOT DETECTED ⚠'}

[Access Control]
  onlyOwner modifier                       : {'YES ✓' if f['has_only_owner'] else 'NO ⚠'}
  Ownable inheritance                      : {'YES' if f['has_ownable'] else 'no'}
  require() count                          : {f['require_count']}
  AccessControl / role-based               : {'YES' if f['has_access_control'] else 'no'}

[Burn]
  burn / _burn present                     : {'YES' if f['has_burn'] else 'no'}
  Public/external burn functions           : {burns}
  Ownership check in burn                  : {'YES ✓' if f['burn_has_ownership_check'] else 'NOT DETECTED ⚠'}

[Proxy / Upgrade]
  delegatecall                             : {'YES ⚠' if f['has_delegatecall'] else 'no'}
  selfdestruct                             : {'YES ⚠' if f['has_selfdestruct'] else 'no'}
  Upgradeable proxy pattern                : {'DETECTED ⚠' if f['has_upgradeable'] else 'no'}
  initialize() function                    : {'YES' if f['has_initialize'] else 'no'}
============================================================="""


# ---------------------------------------------------------------------------
# LLM API
# ---------------------------------------------------------------------------

def call_llm(messages: list, model: str, api_key: str, max_tokens: int = 400) -> str:
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {"model": model, "messages": messages, "max_tokens": max_tokens, "temperature": 0}

    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=120)
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"].strip()
            elif resp.status_code in (429, 503, 504):
                wait = RETRY_BASE * (2 ** attempt)
                print(f"  [rate limit {resp.status_code}] sleeping {wait}s")
                time.sleep(wait)
            else:
                print(f"  [API error {resp.status_code}] {resp.text[:200]}")
                return ""
        except Exception as e:
            time.sleep(RETRY_BASE)
    return ""


# ---------------------------------------------------------------------------
# Pipeline Phases
# ---------------------------------------------------------------------------

SYSTEM = (
    "You are a smart contract security auditor specialising in NFT (ERC-721) vulnerabilities. "
    "You are given Solidity source code AND a pre-computed structural analysis. "
    "Use BOTH the structural signals and the source code in your reasoning. "
    "Be precise and cite specific code evidence."
)


def phase1_overview(src: str, feat_text: str, model: str, key: str) -> str:
    return call_llm([
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": (
            f"{feat_text}\n\n"
            f"=== SOURCE CODE (first 5000 chars) ===\n{src[:5000]}\n\n"
            "Briefly summarise (max 150 words):\n"
            "1. What this NFT contract does\n"
            "2. Which structural signals look most suspicious\n"
            "3. Which vulnerability classes are worth deeper investigation"
        )}
    ], model, key, max_tokens=250)


def phase2_class_analysis(src: str, feat_text: str, vuln_class: str,
                           model: str, key: str) -> str:
    desc = VULNERABILITY_DESCRIPTIONS[vuln_class]
    return call_llm([
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": (
            f"{feat_text}\n\n"
            f"=== SOURCE CODE (first 5000 chars) ===\n{src[:5000]}\n\n"
            f"=== TARGET VULNERABILITY: {vuln_class} ===\n{desc}\n\n"
            f"The structural signals above are relevant to {vuln_class}. "
            "Examine the source code carefully for this specific vulnerability.\n\n"
            "Respond exactly in this format:\n"
            "FINDING: VULNERABLE | SAFE\n"
            "EVIDENCE: [quote the specific code or pattern]\n"
            "CONFIDENCE: HIGH | MEDIUM | LOW"
        )}
    ], model, key, max_tokens=250)


def phase3_verification(src: str, feat_text: str, p2: dict, model: str, key: str) -> str:
    vulnerable = {cls: r for cls, r in p2.items() if "VULNERABLE" in r}
    if not vulnerable:
        return "No vulnerabilities flagged in Phase 2 — no verification needed."

    flagged = "\n".join(f"  {cls}: {r[:200]}" for cls, r in vulnerable.items())
    return call_llm([
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": (
            f"{feat_text}\n\n"
            f"=== PHASE 2 FLAGGED FINDINGS ===\n{flagged}\n\n"
            f"=== SOURCE CODE (first 4000 chars) ===\n{src[:4000]}\n\n"
            "Cross-verify each flagged finding against the structural signals and source code.\n"
            "For each: does the evidence hold up, or is this a false positive?\n"
            "Format each line as:\n"
            "CONFIRMED: ClassName — [reason]\n"
            "REJECTED: ClassName — [reason why it is a false positive]"
        )}
    ], model, key, max_tokens=300)


def phase4_final(p1: str, p2: dict, p3: str, features: dict, model: str, key: str) -> str:
    p2_summary = "\n".join(
        f"  {cls}: {'VULNERABLE' if 'VULNERABLE' in r else 'SAFE'}"
        for cls, r in p2.items()
    )
    # Build deterministic risk flags from structural features
    flags = []
    if features["has_safe_transfer"] and not features["has_reentrancy_guard"]:
        flags.append("ERC721_Reentrancy risk: safeTransfer present, no guard")
    if features["cei_suspect"] and not features["has_reentrancy_guard"]:
        flags.append("ERC721_Reentrancy risk: possible CEI violation detected")
    if features["has_mint"] and not features["has_supply_cap"]:
        flags.append("Unlimited_Minting risk: no supply cap detected")
    if features["burn_functions_public"] and not features["burn_has_ownership_check"]:
        flags.append("Public_Burn risk: public burn without ownership check")
    if features["has_upgradeable"] or features["has_delegatecall"]:
        flags.append("Risky_Mutable_Proxy risk: proxy/delegatecall pattern detected")
    if features["require_count"] < 2:
        flags.append("Missing_Requirements risk: very few require() statements")

    flag_text = "\n".join(f"  - {f}" for f in flags) if flags else "  None"
    classes_str = ", ".join(VULNERABILITY_CLASSES)

    return call_llm([
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": (
            f"=== PHASE 1 OVERVIEW ===\n{p1[:250]}\n\n"
            f"=== PHASE 2 FINDINGS ===\n{p2_summary}\n\n"
            f"=== PHASE 3 VERIFICATION ===\n{p3[:350]}\n\n"
            f"=== STRUCTURAL RISK FLAGS ===\n{flag_text}\n\n"
            f"Choose the single most accurate label for this contract from:\n"
            f"{classes_str}\n\n"
            "Rules:\n"
            "- Choose the most severe confirmed vulnerability\n"
            "- If no vulnerability is confirmed by both Phase 2 and Phase 3, choose: None\n"
            "- Respond with ONLY the class name, nothing else"
        )}
    ], model, key, max_tokens=15)


def parse_label(raw: str) -> str:
    raw = raw.strip()
    for cls in VULNERABILITY_CLASSES:
        if cls.lower() in raw.lower():
            return cls
    return "None"


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate(predictions, labels):
    from collections import defaultdict
    tp, fp, fn = defaultdict(int), defaultdict(int), defaultdict(int)
    for pred, label in zip(predictions, labels):
        if pred == label:
            tp[label] += 1
        else:
            fp[pred] += 1
            fn[label] += 1

    per_class = {}
    f1s = []
    for cls in VULNERABILITY_CLASSES:
        p = tp[cls] / (tp[cls] + fp[cls]) if (tp[cls] + fp[cls]) > 0 else 0.0
        r = tp[cls] / (tp[cls] + fn[cls]) if (tp[cls] + fn[cls]) > 0 else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        per_class[cls] = {
            "f1": round(f1, 4), "precision": round(p, 4),
            "recall": round(r, 4), "support": labels.count(cls)
        }
        f1s.append(f1)

    n = len(labels)
    wf1 = sum(per_class[c]["f1"] * per_class[c]["support"] / n for c in VULNERABILITY_CLASSES)
    return {
        "macro_f1": round(sum(f1s) / len(f1s), 4),
        "weighted_f1": round(wf1, 4),
        "accuracy": round(sum(p == l for p, l in zip(predictions, labels)) / n, 4),
        "per_class": per_class,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="NFT-AugScan")
    parser.add_argument("--openai-key", required=True)
    parser.add_argument("--model", default="deepseek/deepseek-chat")
    parser.add_argument("--data", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--limit", type=int, default=None,
                        help="Process only first N contracts (smoke test)")
    args = parser.parse_args()

    data_path = Path(args.data)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    contracts = []
    with open(data_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                contracts.append(json.loads(line))
    if args.limit:
        contracts = contracts[:args.limit]

    print(f"NFT-AugScan | model={args.model} | n={len(contracts)}")
    print(f"API calls per contract: ~8 (1 overview + 5 class + 1 verify + 1 final)")
    print(f"Estimated total API calls: ~{len(contracts)*8}")
    print(f"Output: {out_path}\n")

    predictions, labels, rows = [], [], []
    api_calls = 0
    call_times = []
    start = time.time()

    def throttled_call(messages, max_tokens=300):
        nonlocal api_calls
        now = time.time()
        call_times[:] = [t for t in call_times if now - t < 60]
        if len(call_times) >= TARGET_RPM:
            wait = 60 - (now - call_times[0]) + 1
            if wait > 0:
                time.sleep(wait)
        result = call_llm(messages, args.model, args.openai_key, max_tokens)
        call_times.append(time.time())
        api_calls += 1
        return result

    # Patch call_llm to use throttling via wrapper
    # (we call each phase function manually with throttle)

    for i, contract in enumerate(contracts):
        cid = contract.get("contract_address", f"contract_{i}")
        src = contract.get("source_code", "")
        true_label = contract.get("vulnerability_class", "None")

        # Step 0: Free structural analysis
        features = extract_structural_features(src)
        feat_text = format_features(features)

        # Step 1: Overview
        msgs1 = [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": (
                f"{feat_text}\n\n=== SOURCE CODE (first 5000 chars) ===\n{src[:5000]}\n\n"
                "Briefly summarise (max 150 words):\n"
                "1. What this NFT contract does\n"
                "2. Which structural signals look most suspicious\n"
                "3. Which vulnerability classes are worth deeper investigation"
            )}
        ]
        p1 = throttled_call(msgs1, 250)

        # Step 2: Per-class analysis (5 calls)
        p2 = {}
        for vcls in VULNERABILITY_CLASSES[:-1]:
            desc = VULNERABILITY_DESCRIPTIONS[vcls]
            msgs2 = [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": (
                    f"{feat_text}\n\n=== SOURCE CODE (first 5000 chars) ===\n{src[:5000]}\n\n"
                    f"=== TARGET VULNERABILITY: {vcls} ===\n{desc}\n\n"
                    f"The structural signals above are relevant to {vcls}. "
                    "Examine the source code carefully for this specific vulnerability.\n\n"
                    "Respond exactly:\n"
                    "FINDING: VULNERABLE | SAFE\n"
                    "EVIDENCE: [specific code or pattern]\n"
                    "CONFIDENCE: HIGH | MEDIUM | LOW"
                )}
            ]
            p2[vcls] = throttled_call(msgs2, 250)

        # Step 3: Verification
        vulnerable = {c: r for c, r in p2.items() if "VULNERABLE" in r}
        if vulnerable:
            flagged = "\n".join(f"  {c}: {r[:200]}" for c, r in vulnerable.items())
            msgs3 = [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": (
                    f"{feat_text}\n\n=== FLAGGED FINDINGS ===\n{flagged}\n\n"
                    f"=== SOURCE CODE (first 4000 chars) ===\n{src[:4000]}\n\n"
                    "Cross-verify each finding against structural signals and source code.\n"
                    "Format:\nCONFIRMED: ClassName — reason\nREJECTED: ClassName — reason"
                )}
            ]
            p3 = throttled_call(msgs3, 300)
        else:
            p3 = "No vulnerabilities flagged — no verification needed."

        # Step 4: Final classification
        p2_summary = "\n".join(
            f"  {c}: {'VULNERABLE' if 'VULNERABLE' in r else 'SAFE'}" for c, r in p2.items()
        )
        flags = []
        if features["has_safe_transfer"] and not features["has_reentrancy_guard"]:
            flags.append("ERC721_Reentrancy: safeTransfer present, no guard")
        if features["cei_suspect"] and not features["has_reentrancy_guard"]:
            flags.append("ERC721_Reentrancy: possible CEI violation")
        if features["has_mint"] and not features["has_supply_cap"]:
            flags.append("Unlimited_Minting: no supply cap")
        if features["burn_functions_public"] and not features["burn_has_ownership_check"]:
            flags.append("Public_Burn: public burn without ownership check")
        if features["has_upgradeable"] or features["has_delegatecall"]:
            flags.append("Risky_Mutable_Proxy: proxy/delegatecall detected")
        if features["require_count"] < 2:
            flags.append("Missing_Requirements: very few require() statements")
        flag_text = "\n".join(f"  - {f}" for f in flags) if flags else "  None"

        msgs4 = [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": (
                f"=== PHASE 1 ===\n{p1[:250]}\n\n"
                f"=== PHASE 2 ===\n{p2_summary}\n\n"
                f"=== PHASE 3 ===\n{p3[:350]}\n\n"
                f"=== STRUCTURAL FLAGS ===\n{flag_text}\n\n"
                f"Choose ONE label: {', '.join(VULNERABILITY_CLASSES)}\n"
                "- Most severe confirmed vulnerability, or None if nothing confirmed.\n"
                "- Respond with ONLY the class name."
            )}
        ]
        p4_raw = throttled_call(msgs4, 15)
        predicted = parse_label(p4_raw)

        predictions.append(predicted)
        labels.append(true_label)
        rows.append({
            "contract_id": cid,
            "true_label": true_label,
            "predicted": predicted,
            "correct": predicted == true_label,
            "p4_raw": p4_raw,
            "ast_reentrancy_risk": features["has_safe_transfer"] and not features["has_reentrancy_guard"],
            "ast_mint_risk": features["has_mint"] and not features["has_supply_cap"],
            "ast_burn_risk": bool(features["burn_functions_public"]) and not features["burn_has_ownership_check"],
            "ast_proxy_risk": features["has_upgradeable"] or features["has_delegatecall"],
            "require_count": features["require_count"],
        })

        elapsed = time.time() - start
        eta = (len(contracts) - i - 1) / (i + 1) * elapsed / 60
        if (i + 1) % 5 == 0 or i == 0:
            acc_so_far = sum(r["correct"] for r in rows) / len(rows)
            print(f"[{i+1:3d}/{len(contracts)}] true={true_label:25s} pred={predicted:25s} | "
                  f"acc={acc_so_far:.2f} api={api_calls} ETA={eta:.1f}min")

    # Write CSV
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    # Metrics
    metrics = evaluate(predictions, labels)
    elapsed_min = (time.time() - start) / 60

    print("\n" + "=" * 62)
    print("NFT-AugScan FINAL RESULTS")
    print("=" * 62)
    print(f"Macro F1:    {metrics['macro_f1']:.4f}")
    print(f"Weighted F1: {metrics['weighted_f1']:.4f}")
    print(f"Accuracy:    {metrics['accuracy']:.4f}")
    print()
    print(f"{'Class':<28} {'F1':>6} {'Prec':>6} {'Rec':>6} {'Support':>8}")
    print("-" * 62)
    for cls in VULNERABILITY_CLASSES:
        pc = metrics["per_class"][cls]
        print(f"{cls:<28} {pc['f1']:>6.3f} {pc['precision']:>6.3f} "
              f"{pc['recall']:>6.3f} {pc['support']:>8d}")
    print("=" * 62)
    print(f"Total API calls: {api_calls} | Time: {elapsed_min:.1f} min")

    summary = {
        "method": "NFT-AugScan",
        "model": args.model,
        "n_contracts": len(contracts),
        "api_calls": api_calls,
        "elapsed_minutes": round(elapsed_min, 1),
        **metrics,
    }
    summary_path = out_path.parent / "augscan_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Summary → {summary_path}")


if __name__ == "__main__":
    main()
