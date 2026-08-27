"""
nft_augscan_v2.py — NFT-AugScan v2: Slither-Oracle Augmented LLM Pipeline

Architecture:
  Step 0a: Structural feature extraction (regex/pattern-based, always succeeds)
  Step 0b: Slither expert analysis — full detector output, grouped by NFT class relevance.
           Gracefully skipped if Slither fails; LLM then falls back to regex features only.
  Step 1:  LLM contract overview  (structural + Slither context)
  Step 2:  LLM per-class analysis ×5  (guided by combined expert signals)
  Step 3:  LLM cross-verification  (confirms/rejects Phase 2 findings)
  Step 4:  LLM final classification

Key improvements over NFT-AugScan v1:
  - Slither's full detector output fed as a structured "expert report" to every LLM phase
  - LLM sees specific function names, impact levels, and detector descriptions
  - Reentrancy signal is explicit ("reentrancy-no-eth in mint()") not inferred from text
  - constable-states / immutable-states on supply variables → Unlimited_Minting signal
  - arbitrary-send-eth / tx-origin → Missing_Requirements signal
  - unprotected-upgrade / controlled-delegatecall → Risky_Mutable_Proxy signal
  - No reentrancy fires → negative evidence fed to LLM (reduces false positives)
  - Progress checkpointing: saves every 10 contracts; --resume skips already-done rows
  - Same ~8 API calls/contract as v1; Slither adds ~3-5s per contract (not LLM-bound)

Usage:
    python pipeline/nft_augscan_v2.py \\
        --openai-key sk-or-... \\
        --model deepseek/deepseek-chat \\
        --data output/eval_sample_400.jsonl \\
        --out results/augscan_v2_results.csv \\
        [--repo-root .] \\
        [--slither-timeout 90] \\
        [--skip-slither] \\
        [--resume] \\
        [--limit 10]

Requirements:
    pip install slither-analyzer solc-select requests
    npm install @openzeppelin/contracts   (in repo root)
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TARGET_RPM = 50
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MAX_RETRIES = 6
RETRY_BASE = 5
TEMP_CONTRACT_NAME = "_augscan_v2_tmp.sol"

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
        "ERC721 Reentrancy: safeTransferFrom/_safeTransfer triggers the recipient's "
        "onERC721Received callback before state (balances, ownership mappings) is updated, "
        "allowing re-entry. The checks-effects-interactions (CEI) pattern must be followed. "
        "Key signals: external transfer call before state update, missing nonReentrant guard, "
        "onERC721Received hook present in a recipient contract."
    ),
    "Unlimited_Minting": (
        "Unlimited Minting: a public/external minting function has no supply cap or per-wallet "
        "limit, allowing anyone to mint an unbounded number of tokens. "
        "Key signals: _mint/_safeMint without require(totalSupply() < maxSupply), "
        "public mint function with no quantity restriction."
    ),
    "Missing_Requirements": (
        "Missing Requirements: sensitive operations (transfers, configuration, minting) lack "
        "proper require() checks for caller authorization or contract state validation. "
        "Key signals: public/external functions missing onlyOwner, msg.sender checks, or "
        "state guards; ETH sent to arbitrary addresses; tx.origin used for auth."
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
        "Key signals: delegatecall, UUPS/TransparentProxy, initialize() without initializer "
        "modifier, selfdestruct in implementation, unprotected upgrade function."
    ),
}

# ---------------------------------------------------------------------------
# Slither detector → NFT class relevance mapping
# ---------------------------------------------------------------------------

REENTRANCY_DETECTORS = {
    "reentrancy-eth",
    "reentrancy-no-eth",
    "reentrancy-benign",
    "reentrancy-unlimited-gas",
    "reentrancy-events",
}

# Detectors that signal access control / Missing_Requirements
ACCESS_CONTROL_DETECTORS = {
    "arbitrary-send-eth",       # ETH sent without proper access control
    "suicidal",                 # selfdestruct callable by anyone
    "tx-origin",                # tx.origin used for authentication
    "missing-zero-check",       # zero address not validated
    "incorrect-equality",       # dangerous strict == on uints/addresses
    "unchecked-transfer",       # ERC20 transfer return ignored (wrong context but signals lax checks)
    "locked-ether",             # ETH locked with no withdrawal
}

# Detectors that signal Risky_Mutable_Proxy
PROXY_DETECTORS = {
    "controlled-delegatecall",  # delegatecall to user-controlled address
    "unprotected-upgrade",      # UUPS upgrade without access control
}

# Detectors that signal Unlimited_Minting (supply variable never set/enforced)
SUPPLY_DETECTORS = {
    "constable-states",         # state var could be constant → if it's a supply cap, it's static
    "immutable-states",         # state var could be immutable
}

# All other detectors — still reported but labelled as general quality
GENERAL_DETECTORS = {
    "unused-return",
    "uninitialized-local",
    "divide-before-multiply",
    "tautology",
    "cache-array-length",
    "encode-packed-collision",
    "weak-prng",
    "msg-value-loop",
    "delegatecall-loop",
    "variable-scope",
    "shadowing-local",
    "shadowing-state",
    "shadowing-abstract",
    "shadowing-builtin",
    "calls-loop",
    "reentrancy-benign",
}

# ---------------------------------------------------------------------------
# Solc version resolution (identical to slither_ablation.py)
# ---------------------------------------------------------------------------

SOLC_VERSION_MAP = {
    (0, 4): "0.4.26",
    (0, 5): "0.5.17",
    (0, 6): "0.6.12",
    (0, 7): "0.7.6",
    (0, 8): "0.8.20",
}
DEFAULT_SOLC = "0.8.20"

_installed_versions: set = set()
_active_version: str | None = None


def detect_solc_version(source_code: str) -> str:
    match = re.search(r'pragma\s+solidity\s+([^;]+);', source_code)
    if not match:
        return DEFAULT_SOLC
    pragma = match.group(1).strip()

    exact = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)', pragma)
    if exact:
        maj, min_ = int(exact.group(1)), int(exact.group(2))
        return SOLC_VERSION_MAP.get((maj, min_), DEFAULT_SOLC)

    all_versions = re.findall(r'(\d+)\.(\d+)\.(\d+)', pragma)
    if all_versions:
        maj, min_ = int(all_versions[0][0]), int(all_versions[0][1])
        return SOLC_VERSION_MAP.get((maj, min_), DEFAULT_SOLC)

    mm = re.search(r'(\d+)\.(\d+)', pragma)
    if mm:
        maj, min_ = int(mm.group(1)), int(mm.group(2))
        return SOLC_VERSION_MAP.get((maj, min_), DEFAULT_SOLC)

    return DEFAULT_SOLC


def ensure_solc(version: str, timeout: int = 120) -> bool:
    """Install and activate a solc version. Returns True on success."""
    global _active_version

    if version == _active_version:
        return True

    if version not in _installed_versions:
        try:
            r = subprocess.run(
                ["solc-select", "install", version],
                capture_output=True, text=True, timeout=timeout
            )
            if r.returncode != 0 and "already installed" not in r.stdout:
                print(f"  [solc-select install {version}] FAILED: {r.stderr[:150]}")
                return False
            _installed_versions.add(version)
        except Exception as e:
            print(f"  [solc-select install] exception: {e}")
            return False

    try:
        r = subprocess.run(
            ["solc-select", "use", version],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode == 0:
            _active_version = version
            return True
        print(f"  [solc-select use {version}] FAILED: {r.stderr[:150]}")
        return False
    except Exception as e:
        print(f"  [solc-select use] exception: {e}")
        return False


def run_slither(sol_path: str, repo_root: str, timeout: int) -> dict:
    """
    Run Slither and return parsed JSON output.
    Always tries to parse stdout first — Windows returns -1 even on success.
    Returns {"error": "reason"} on failure (no "success" key).
    """
    oz_path = (
        os.path.join(repo_root, "node_modules", "@openzeppelin")
        .replace("\\", "/") + "/"
    )
    cmd = [
        "slither", sol_path,
        "--json", "-",
        "--solc-remaps", f"@openzeppelin/={oz_path}",
        "--disable-color",
        "--exclude-informational",
        "--exclude-low",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, cwd=repo_root
        )
        if result.stdout.strip():
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        err = (result.stderr or result.stdout or "no output")[:400]
        return {"error": err}
    except subprocess.TimeoutExpired:
        return {"error": f"timeout_{timeout}s"}
    except FileNotFoundError:
        print("ERROR: 'slither' not found. Run: pip install slither-analyzer", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Slither output → structured expert report for LLM
# ---------------------------------------------------------------------------

def _finding_summary(d: dict, max_desc: int = 110) -> str:
    """Format one Slither finding as a single readable line."""
    check = d.get("check", "unknown")
    impact = d.get("impact", "?")
    confidence = d.get("confidence", "?")
    desc = d.get("description", "").replace("\n", " ").strip()[:max_desc]

    # Extract the most useful element name (function or variable)
    elements = d.get("elements", [])
    names = []
    for el in elements[:3]:
        name = el.get("name", "")
        etype = el.get("type", "")
        if name and etype in ("function", "variable", "contract"):
            names.append(f"{etype} `{name}`")
        elif name:
            names.append(f"`{name}`")
    loc = ", ".join(names) if names else ""

    line = f"  [{impact}/{confidence}] {check}"
    if loc:
        line += f"  in {loc}"
    line += f"\n    {desc}"
    return line


def format_slither_report(slither_output: dict, solc_ver: str) -> str:
    """
    Format Slither's full detector output as a structured expert report for the LLM.

    Groups findings by NFT vulnerability class relevance so the LLM can immediately
    see which signals are most pertinent to each class.
    """
    # Slither failed entirely (our error dict — no "success" key)
    if "success" not in slither_output:
        err = slither_output.get("error", "unknown error")[:200]
        return (
            f"=== SLITHER ANALYSIS (solc {solc_ver}) ===\n"
            f"STATUS: FAILED — {err}\n"
            "NOTE: No static analysis signals available; rely on structural features only.\n"
            "=" * 56
        )

    # Slither ran but reported its own failure (compilation error, parse error)
    if slither_output.get("success") is False:
        err_msg = slither_output.get("error") or "unknown"
        err_msg = str(err_msg)[:200]
        return (
            f"=== SLITHER ANALYSIS (solc {solc_ver}) ===\n"
            f"STATUS: COMPILATION FAILED — {err_msg}\n"
            "NOTE: Contract could not be compiled by Slither; rely on structural features only.\n"
            "=" * 56
        )

    detectors = slither_output.get("results", {}).get("detectors", [])

    if not detectors:
        return (
            f"=== SLITHER ANALYSIS (solc {solc_ver}) | 0 findings ===\n"
            "STATUS: CLEAN — No medium/high severity issues detected by Slither.\n"
            "  → No reentrancy detectors fired (ERC721_Reentrancy less likely)\n"
            "  → No access control issues detected (Missing_Requirements less likely)\n"
            "  → No upgrade/proxy issues detected (Risky_Mutable_Proxy less likely)\n"
            "=" * 56
        )

    # Bucket each finding
    re_findings = []
    ac_findings = []
    proxy_findings = []
    supply_findings = []
    other_findings = []

    for d in detectors:
        check = d.get("check", "")
        summary = _finding_summary(d)
        if check in REENTRANCY_DETECTORS:
            re_findings.append(summary)
        elif check in PROXY_DETECTORS:
            proxy_findings.append(summary)
        elif check in ACCESS_CONTROL_DETECTORS:
            ac_findings.append(summary)
        elif check in SUPPLY_DETECTORS:
            supply_findings.append(summary)
        else:
            other_findings.append(summary)

    lines = [
        f"=== SLITHER STATIC ANALYSIS (solc {solc_ver}) | {len(detectors)} findings ==="
    ]

    # --- Reentrancy ---
    if re_findings:
        lines.append(
            f"\n[REENTRANCY DETECTORS ⚠  →  ERC721_Reentrancy]  ({len(re_findings)} finding(s))"
        )
        lines.extend(re_findings)
    else:
        lines.append(
            "\n[REENTRANCY]  No reentrancy detectors fired."
            "\n  → Negative evidence: ERC721_Reentrancy is LESS LIKELY unless code review says otherwise."
        )

    # --- Access control / Missing_Requirements ---
    if ac_findings:
        lines.append(
            f"\n[ACCESS CONTROL ⚠  →  Missing_Requirements]  ({len(ac_findings)} finding(s))"
        )
        lines.extend(ac_findings)

    # --- Proxy / Risky_Mutable_Proxy ---
    if proxy_findings:
        lines.append(
            f"\n[PROXY / UPGRADE ⚠  →  Risky_Mutable_Proxy]  ({len(proxy_findings)} finding(s))"
        )
        lines.extend(proxy_findings)

    # --- Supply / Unlimited_Minting signal ---
    if supply_findings:
        # Cap to 6 to avoid flooding context with constable-states noise
        shown = supply_findings[:6]
        rest = len(supply_findings) - len(shown)
        lines.append(
            f"\n[STATE VARIABLES  →  Unlimited_Minting signal]  ({len(supply_findings)} finding(s))"
        )
        lines.append(
            "  NOTE: constable-states/immutable-states on supply variables may indicate"
            " the cap is hard-coded (not dynamic), which is relevant to Unlimited_Minting."
        )
        lines.extend(shown)
        if rest > 0:
            lines.append(f"  ... and {rest} more constable-states/immutable-states findings")

    # --- Other findings (capped to avoid prompt bloat) ---
    if other_findings:
        shown = other_findings[:5]
        rest = len(other_findings) - len(shown)
        lines.append(f"\n[OTHER FINDINGS]  ({len(other_findings)} total)")
        lines.extend(shown)
        if rest > 0:
            lines.append(f"  ... and {rest} more")

    lines.append("=" * 56)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Step 0a: Structural feature extraction (regex, no compilation)
# ---------------------------------------------------------------------------

def extract_structural_features(source_code: str) -> dict:
    src = source_code

    # Reentrancy
    has_safe_transfer = bool(re.search(
        r'\bsafeTransferFrom\b|\b_safeTransfer\b|\bsafeTransfer\b', src))
    has_reentrancy_guard = bool(re.search(
        r'\bnonReentrant\b|\bReentrancyGuard\b', src))
    has_on_erc721_received = bool(re.search(r'\bonERC721Received\b', src))
    has_external_call = bool(re.search(
        r'\.(call|delegatecall|transfer|send)\s*[({]', src))
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
    mints = f["mint_functions_public"] or ["none detected"]
    burns = f["burn_functions_public"] or ["none detected"]
    return f"""=== STRUCTURAL ANALYSIS (regex/pattern, compilation-free) ===
Pragma: {f['pragma']} | ERC721: {'YES' if f['has_erc721'] else 'NO'}

[Reentrancy]
  safeTransferFrom / _safeTransfer present : {'YES ⚠' if f['has_safe_transfer'] else 'no'}
  onERC721Received callback present        : {'YES ⚠' if f['has_on_erc721_received'] else 'no'}
  nonReentrant / ReentrancyGuard present   : {'YES ✓' if f['has_reentrancy_guard'] else 'NO — unprotected'}
  External .call/.transfer/.send patterns  : {'YES' if f['has_external_call'] else 'no'}
  Possible CEI violation (state after call): {'SUSPECT ⚠' if f['cei_suspect'] else 'not detected'}

[Minting]
  _mint / _safeMint present                : {'YES' if f['has_mint'] else 'no'}
  Public/external mint functions           : {mints}
  Supply cap detected (MAX_SUPPLY/require) : {'YES ✓' if f['has_supply_cap'] else 'NOT DETECTED ⚠'}

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
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": 0,
    }
    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.post(
                OPENROUTER_URL, headers=headers, json=payload, timeout=120
            )
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
            print(f"  [request exception] {e}")
            time.sleep(RETRY_BASE)
    return ""


# ---------------------------------------------------------------------------
# Pipeline phases
# ---------------------------------------------------------------------------

SYSTEM = (
    "You are a smart contract security auditor specialising in NFT (ERC-721) vulnerabilities. "
    "You are given Solidity source code, a pre-computed structural analysis (regex-based), "
    "AND a Slither static analysis report. "
    "Use ALL three sources of evidence in your reasoning. "
    "The Slither report names specific functions and variables — prioritise these concrete signals. "
    "Be precise and cite specific code evidence."
)


def _build_context(feat_text: str, slither_report: str) -> str:
    """Combine regex features + Slither report into one context block."""
    return f"{feat_text}\n\n{slither_report}"


def phase1_overview(src: str, context: str, model: str, key: str) -> str:
    return call_llm([
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": (
            f"{context}\n\n"
            f"=== SOURCE CODE (first 5000 chars) ===\n{src[:5000]}\n\n"
            "Summarise in ≤150 words:\n"
            "1. What this NFT contract does\n"
            "2. Which structural/Slither signals look most suspicious\n"
            "3. Which vulnerability classes are worth deeper investigation"
        )}
    ], model, key, max_tokens=250)


def phase2_class_analysis(
    src: str, context: str, vuln_class: str, model: str, key: str
) -> str:
    desc = VULNERABILITY_DESCRIPTIONS[vuln_class]
    return call_llm([
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": (
            f"{context}\n\n"
            f"=== SOURCE CODE (first 5000 chars) ===\n{src[:5000]}\n\n"
            f"=== TARGET VULNERABILITY: {vuln_class} ===\n{desc}\n\n"
            f"Using the structural analysis AND Slither report above as guidance, "
            f"examine the source code for {vuln_class}.\n\n"
            "Respond EXACTLY in this format:\n"
            "FINDING: VULNERABLE | SAFE\n"
            "EVIDENCE: [quote the specific code or Slither signal]\n"
            "CONFIDENCE: HIGH | MEDIUM | LOW"
        )}
    ], model, key, max_tokens=250)


def phase3_verification(
    src: str, context: str, p2: dict, model: str, key: str
) -> str:
    vulnerable = {cls: r for cls, r in p2.items() if "VULNERABLE" in r}
    if not vulnerable:
        return "No vulnerabilities flagged in Phase 2 — no verification needed."

    flagged = "\n".join(f"  {cls}: {r[:200]}" for cls, r in vulnerable.items())
    return call_llm([
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": (
            f"{context}\n\n"
            f"=== PHASE 2 FLAGGED FINDINGS ===\n{flagged}\n\n"
            f"=== SOURCE CODE (first 4000 chars) ===\n{src[:4000]}\n\n"
            "Cross-verify each flagged finding against the Slither report, structural signals, "
            "and source code. Does the evidence hold up or is this a false positive?\n\n"
            "For each finding:\n"
            "CONFIRMED: ClassName — [specific reason, cite Slither or code]\n"
            "REJECTED: ClassName — [specific reason it is a false positive]"
        )}
    ], model, key, max_tokens=300)


def phase4_final(
    p1: str, p2: dict, p3: str, features: dict,
    slither_re_fired: bool, model: str, key: str
) -> str:
    p2_summary = "\n".join(
        f"  {cls}: {'VULNERABLE' if 'VULNERABLE' in r else 'SAFE'}"
        for cls, r in p2.items()
    )

    # Structural risk flags (deterministic)
    flags = []
    if features["has_safe_transfer"] and not features["has_reentrancy_guard"]:
        flags.append("ERC721_Reentrancy: safeTransfer present, no reentrancy guard")
    if features["cei_suspect"] and not features["has_reentrancy_guard"]:
        flags.append("ERC721_Reentrancy: possible CEI violation (state written after call)")
    if slither_re_fired:
        flags.append("ERC721_Reentrancy: Slither reentrancy detector fired ⚠")
    if not slither_re_fired and not features["has_safe_transfer"]:
        flags.append("ERC721_Reentrancy: LOW RISK — no Slither reentrancy signal and no safeTransfer")
    if features["has_mint"] and not features["has_supply_cap"]:
        flags.append("Unlimited_Minting: no supply cap detected")
    if features["burn_functions_public"] and not features["burn_has_ownership_check"]:
        flags.append("Public_Burn: public burn without ownership check")
    if features["has_upgradeable"] or features["has_delegatecall"]:
        flags.append("Risky_Mutable_Proxy: proxy/delegatecall pattern detected")
    if features["require_count"] < 2:
        flags.append("Missing_Requirements: very few require() statements")

    flag_text = "\n".join(f"  - {f}" for f in flags) if flags else "  None"
    classes_str = ", ".join(VULNERABILITY_CLASSES)

    return call_llm([
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": (
            f"=== PHASE 1 OVERVIEW ===\n{p1[:250]}\n\n"
            f"=== PHASE 2 FINDINGS ===\n{p2_summary}\n\n"
            f"=== PHASE 3 VERIFICATION ===\n{p3[:350]}\n\n"
            f"=== DETERMINISTIC RISK FLAGS ===\n{flag_text}\n\n"
            f"Choose the single most accurate label from:\n{classes_str}\n\n"
            "Rules:\n"
            "- Choose the most severe vulnerability confirmed by BOTH Phase 2 AND Phase 3\n"
            "- If a Slither reentrancy flag appears in the risk flags, weight it heavily\n"
            "- If no vulnerability is confirmed by both phases, choose: None\n"
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

def evaluate(predictions: list, labels: list) -> dict:
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
            "recall": round(r, 4), "support": labels.count(cls),
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
# Checkpointing helpers
# ---------------------------------------------------------------------------

def load_checkpoint(out_path: Path) -> set:
    """Return set of contract_ids already processed (from partial CSV)."""
    done = set()
    if out_path.exists():
        try:
            with open(out_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    done.add(row["contract_id"])
            print(f"[resume] Found {len(done)} already-processed contracts in {out_path}")
        except Exception as e:
            print(f"[resume] Could not read checkpoint: {e}")
    return done


def append_rows(out_path: Path, rows: list, fieldnames: list):
    """Append rows to CSV (create with header if new file)."""
    write_header = not out_path.exists()
    with open(out_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

CSV_FIELDS = [
    "contract_id", "true_label", "predicted", "correct",
    "p4_raw", "slither_ok", "slither_re_fired", "slither_n_findings",
    "solc_version",
    "ast_reentrancy_risk", "ast_mint_risk", "ast_burn_risk", "ast_proxy_risk",
    "require_count",
]


def main():
    parser = argparse.ArgumentParser(
        description="NFT-AugScan v2 — Slither-Oracle Augmented LLM Pipeline"
    )
    parser.add_argument("--openai-key", required=True, help="OpenRouter API key")
    parser.add_argument("--model", default="deepseek/deepseek-chat")
    parser.add_argument("--data", required=True, help="Path to eval_sample_400.jsonl")
    parser.add_argument("--out", required=True, help="Output CSV path")
    parser.add_argument(
        "--repo-root", default=None,
        help="Repo root where node_modules/@openzeppelin is. "
             "Defaults to parent of data file's parent directory."
    )
    parser.add_argument(
        "--slither-timeout", type=int, default=90,
        help="Per-contract Slither timeout in seconds (default 90)"
    )
    parser.add_argument(
        "--skip-slither", action="store_true",
        help="Skip Slither entirely (run as pure NFT-AugScan v1 for ablation comparison)"
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Skip contracts already in the output CSV (resume interrupted run)"
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Process only first N contracts (smoke test)"
    )
    args = parser.parse_args()

    data_path = Path(args.data)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Determine repo root (where @openzeppelin node_modules lives)
    if args.repo_root:
        repo_root = str(Path(args.repo_root).resolve())
    else:
        repo_root = str(data_path.parent.parent.resolve())
    tmp_sol = os.path.join(repo_root, TEMP_CONTRACT_NAME)

    print("=" * 62)
    print("NFT-AugScan v2  —  Slither-Oracle Augmented LLM Pipeline")
    print("=" * 62)
    print(f"Model           : {args.model}")
    print(f"Data            : {data_path}")
    print(f"Output          : {out_path}")
    print(f"Repo root       : {repo_root}")
    print(f"Slither         : {'DISABLED (--skip-slither)' if args.skip_slither else f'ENABLED (timeout={args.slither_timeout}s)'}")
    print(f"Resume          : {args.resume}")
    print()

    # Pre-install solc versions
    if not args.skip_slither:
        print("Pre-installing solc versions...")
        for ver in SOLC_VERSION_MAP.values():
            r = subprocess.run(
                ["solc-select", "install", ver],
                capture_output=True, text=True, timeout=120
            )
            status = "ok" if r.returncode == 0 or "already" in r.stdout else "failed"
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
    if args.limit:
        contracts = contracts[: args.limit]
    print(f"Loaded {len(contracts)} contracts")

    # Resume: find already-done contract IDs
    done_ids: set = set()
    if args.resume:
        done_ids = load_checkpoint(out_path)

    # Collect already-processed rows for final metrics
    all_predictions: list = []
    all_labels: list = []

    if args.resume and out_path.exists():
        try:
            with open(out_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    all_predictions.append(row["predicted"])
                    all_labels.append(row["true_label"])
        except Exception:
            pass

    api_calls = 0
    call_times: list = []
    slither_errors = 0
    slither_re_count = 0
    batch: list = []
    start = time.time()

    def throttled_call(messages: list, max_tokens: int = 300) -> str:
        nonlocal api_calls
        now = time.time()
        call_times[:] = [t for t in call_times if now - t < 60]
        if len(call_times) >= TARGET_RPM:
            wait = 60 - (now - call_times[0]) + 1
            if wait > 0:
                print(f"  [throttle] sleeping {wait:.1f}s (RPM limit)")
                time.sleep(wait)
        result = call_llm(messages, args.model, args.openai_key, max_tokens)
        call_times.append(time.time())
        api_calls += 1
        return result

    total = len(contracts)
    processed = 0

    for i, contract in enumerate(contracts):
        cid = contract.get("contract_address", f"contract_{i}")
        src = contract.get("source_code", "")
        true_label = contract.get("vulnerability_class", "None")

        # Skip already-processed contracts when resuming
        if cid in done_ids:
            continue

        processed += 1

        # ── Step 0a: Regex structural features ───────────────────────────────
        features = extract_structural_features(src)
        feat_text = format_features(features)

        # ── Step 0b: Slither expert analysis ─────────────────────────────────
        slither_ok = False
        slither_re_fired = False
        slither_n_findings = 0
        solc_ver = DEFAULT_SOLC

        if not args.skip_slither:
            solc_ver = detect_solc_version(src)
            if not ensure_solc(solc_ver):
                ensure_solc(DEFAULT_SOLC)
                solc_ver = DEFAULT_SOLC

            try:
                with open(tmp_sol, "w", encoding="utf-8") as f_sol:
                    f_sol.write(src)
            except Exception as e:
                print(f"  [write tmp] failed: {e}")

            slither_out = run_slither(tmp_sol, repo_root, args.slither_timeout)
            slither_ok = (
                "success" in slither_out and slither_out.get("success") is not False
            )

            if slither_ok:
                detectors = slither_out.get("results", {}).get("detectors", [])
                slither_n_findings = len(detectors)
                fired_checks = {d.get("check", "") for d in detectors}
                slither_re_fired = bool(fired_checks & REENTRANCY_DETECTORS)
                if slither_re_fired:
                    slither_re_count += 1
            else:
                slither_errors += 1

            slither_report = format_slither_report(slither_out, solc_ver)
        else:
            slither_report = "=== SLITHER ANALYSIS === SKIPPED (--skip-slither flag)"
            slither_ok = False

        # Combined context for all LLM phases
        context = _build_context(feat_text, slither_report)

        # ── Step 1: Overview ─────────────────────────────────────────────────
        msgs1 = [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": (
                f"{context}\n\n"
                f"=== SOURCE CODE (first 5000 chars) ===\n{src[:5000]}\n\n"
                "Summarise in ≤150 words:\n"
                "1. What this NFT contract does\n"
                "2. Which structural/Slither signals look most suspicious\n"
                "3. Which vulnerability classes are worth deeper investigation"
            )},
        ]
        p1 = throttled_call(msgs1, 250)

        # ── Step 2: Per-class analysis (5 calls) ─────────────────────────────
        p2: dict = {}
        for vcls in VULNERABILITY_CLASSES[:-1]:  # exclude "None"
            desc = VULNERABILITY_DESCRIPTIONS[vcls]
            msgs2 = [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": (
                    f"{context}\n\n"
                    f"=== SOURCE CODE (first 5000 chars) ===\n{src[:5000]}\n\n"
                    f"=== TARGET VULNERABILITY: {vcls} ===\n{desc}\n\n"
                    f"Using the structural analysis AND Slither report above as guidance, "
                    f"examine the source code for {vcls}.\n\n"
                    "Respond EXACTLY:\n"
                    "FINDING: VULNERABLE | SAFE\n"
                    "EVIDENCE: [specific code or Slither signal]\n"
                    "CONFIDENCE: HIGH | MEDIUM | LOW"
                )},
            ]
            p2[vcls] = throttled_call(msgs2, 250)

        # ── Step 3: Cross-verification ────────────────────────────────────────
        vulnerable = {c: r for c, r in p2.items() if "VULNERABLE" in r}
        if vulnerable:
            flagged = "\n".join(f"  {c}: {r[:200]}" for c, r in vulnerable.items())
            msgs3 = [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": (
                    f"{context}\n\n"
                    f"=== PHASE 2 FLAGGED FINDINGS ===\n{flagged}\n\n"
                    f"=== SOURCE CODE (first 4000 chars) ===\n{src[:4000]}\n\n"
                    "Cross-verify each finding against the Slither report, structural signals, "
                    "and source code.\n"
                    "Format:\n"
                    "CONFIRMED: ClassName — reason (cite Slither or code)\n"
                    "REJECTED: ClassName — reason it is a false positive"
                )},
            ]
            p3 = throttled_call(msgs3, 300)
        else:
            p3 = "No vulnerabilities flagged in Phase 2 — no verification needed."
            api_calls  # no increment, no call

        # ── Step 4: Final classification ──────────────────────────────────────
        p2_summary = "\n".join(
            f"  {c}: {'VULNERABLE' if 'VULNERABLE' in r else 'SAFE'}"
            for c, r in p2.items()
        )

        # Deterministic risk flags (structural + Slither combined)
        flags = []
        if features["has_safe_transfer"] and not features["has_reentrancy_guard"]:
            flags.append("ERC721_Reentrancy: safeTransfer present, no reentrancy guard")
        if features["cei_suspect"] and not features["has_reentrancy_guard"]:
            flags.append("ERC721_Reentrancy: possible CEI violation")
        if slither_re_fired:
            flags.append("ERC721_Reentrancy: Slither reentrancy detector FIRED ⚠")
        if not slither_re_fired and slither_ok and not features["has_safe_transfer"]:
            flags.append("ERC721_Reentrancy: LOW RISK — no Slither signal, no safeTransfer")
        if features["has_mint"] and not features["has_supply_cap"]:
            flags.append("Unlimited_Minting: no supply cap detected")
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
                f"=== DETERMINISTIC FLAGS ===\n{flag_text}\n\n"
                f"Choose ONE label: {', '.join(VULNERABILITY_CLASSES)}\n"
                "- Most severe vulnerability confirmed by both Phase 2 and Phase 3.\n"
                "- Weight Slither reentrancy signals heavily if present.\n"
                "- If nothing confirmed, choose: None\n"
                "- Respond with ONLY the class name."
            )},
        ]
        p4_raw = throttled_call(msgs4, 15)
        predicted = parse_label(p4_raw)

        all_predictions.append(predicted)
        all_labels.append(true_label)

        row = {
            "contract_id": cid,
            "true_label": true_label,
            "predicted": predicted,
            "correct": predicted == true_label,
            "p4_raw": p4_raw,
            "slither_ok": slither_ok,
            "slither_re_fired": slither_re_fired,
            "slither_n_findings": slither_n_findings,
            "solc_version": solc_ver,
            "ast_reentrancy_risk": (
                features["has_safe_transfer"] and not features["has_reentrancy_guard"]
            ),
            "ast_mint_risk": features["has_mint"] and not features["has_supply_cap"],
            "ast_burn_risk": (
                bool(features["burn_functions_public"])
                and not features["burn_has_ownership_check"]
            ),
            "ast_proxy_risk": features["has_upgradeable"] or features["has_delegatecall"],
            "require_count": features["require_count"],
        }
        batch.append(row)

        # Checkpoint every 10 contracts
        if len(batch) >= 10:
            append_rows(out_path, batch, CSV_FIELDS)
            batch.clear()

        elapsed = time.time() - start
        done_count = len(done_ids) + processed
        remaining = total - done_count
        eta = remaining / processed * elapsed / 60 if processed > 0 else 0

        if processed % 5 == 0 or processed == 1:
            acc = sum(
                p == l for p, l in zip(all_predictions[-processed:], all_labels[-processed:])
            ) / processed if processed > 0 else 0
            print(
                f"[{done_count:3d}/{total}] true={true_label:25s} pred={predicted:20s} | "
                f"slither={'OK' if slither_ok else 'FAIL'} re={slither_re_fired} | "
                f"api={api_calls} acc={acc:.2f} ETA={eta:.1f}min"
            )

    # Flush remaining batch
    if batch:
        append_rows(out_path, batch, CSV_FIELDS)

    # Clean up temp file
    try:
        os.remove(tmp_sol)
    except Exception:
        pass

    # Final metrics
    metrics = evaluate(all_predictions, all_labels)
    elapsed_min = (time.time() - start) / 60

    print("\n" + "=" * 62)
    print("NFT-AugScan v2  FINAL RESULTS")
    print("=" * 62)
    print(f"Macro F1:    {metrics['macro_f1']:.4f}")
    print(f"Weighted F1: {metrics['weighted_f1']:.4f}")
    print(f"Accuracy:    {metrics['accuracy']:.4f}")
    print()
    print(f"{'Class':<28} {'F1':>6} {'Prec':>6} {'Rec':>6} {'Support':>8}")
    print("-" * 62)
    for cls in VULNERABILITY_CLASSES:
        pc = metrics["per_class"][cls]
        print(
            f"{cls:<28} {pc['f1']:>6.3f} {pc['precision']:>6.3f} "
            f"{pc['recall']:>6.3f} {pc['support']:>8d}"
        )
    print("=" * 62)
    print(f"Total API calls   : {api_calls}")
    print(f"Slither errors    : {slither_errors}/{total}")
    print(f"Reentrancy fired  : {slither_re_count}")
    print(f"Total time        : {elapsed_min:.1f} min")

    summary = {
        "method": "NFT-AugScan-v2",
        "model": args.model,
        "slither_enabled": not args.skip_slither,
        "n_contracts": total,
        "api_calls": api_calls,
        "slither_errors": slither_errors,
        "slither_reentrancy_fired": slither_re_count,
        "elapsed_minutes": round(elapsed_min, 1),
        **metrics,
    }
    summary_path = out_path.parent / "augscan_v2_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Summary → {summary_path}")


if __name__ == "__main__":
    main()
