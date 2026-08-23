"""
Rare Class Augmentation for NFT Vulnerability Dataset
======================================================
Generates additional synthetic Solidity contracts for underrepresented
vulnerability classes (Public_Burn and Risky_Mutable_Proxy) to address
severe class imbalance in the NFTDefects real-world dataset.

Real dataset counts:
  Public_Burn          38 samples
  Risky_Mutable_Proxy  10 samples

This script generates 200 additional synthetic contracts per class,
appending them to the existing nft_synthetic_with_source.csv.

Usage:
  python pipeline/augment_rare_classes.py
"""

import pandas as pd
import pathlib
import itertools

HERE      = pathlib.Path(__file__).parent
REPO_ROOT = HERE.parent
OUT_DIR   = REPO_ROOT / "output"
SYNTH_CSV = OUT_DIR / "nft_synthetic_with_source.csv"
AUG_CSV   = OUT_DIR / "nft_synthetic_augmented.csv"

# ─────────────────────────────────────────────────────────────────────────────
# CONTRACT NAME VARIANTS (more diverse than original 10)
# ─────────────────────────────────────────────────────────────────────────────

VARIANTS = [
    {"name": "CryptoBeasts",    "symbol": "CBST",  "max_supply": 8888,  "price": "0.08"},
    {"name": "PixelPunks",      "symbol": "PPNK",  "max_supply": 5000,  "price": "0.05"},
    {"name": "NeonApes",        "symbol": "NAPE",  "max_supply": 10000, "price": "0.07"},
    {"name": "EtherBots",       "symbol": "EBOT",  "max_supply": 3333,  "price": "0.12"},
    {"name": "SpaceWhales",     "symbol": "SPWH",  "max_supply": 7777,  "price": "0.06"},
    {"name": "MetaRovers",      "symbol": "MRVR",  "max_supply": 4444,  "price": "0.09"},
    {"name": "CyberKitties",    "symbol": "CKTY",  "max_supply": 6666,  "price": "0.04"},
    {"name": "QuantumDragons",  "symbol": "QDGN",  "max_supply": 2222,  "price": "0.15"},
    {"name": "GalacticOwls",    "symbol": "GOWL",  "max_supply": 9999,  "price": "0.03"},
    {"name": "DeepSeaSharks",   "symbol": "DSSK",  "max_supply": 1111,  "price": "0.20"},
    {"name": "StellarPandas",   "symbol": "STPD",  "max_supply": 4200,  "price": "0.06"},
    {"name": "FrostWolves",     "symbol": "FRWF",  "max_supply": 3000,  "price": "0.10"},
    {"name": "LunarFoxes",      "symbol": "LUNF",  "max_supply": 6000,  "price": "0.055"},
    {"name": "CosmicTigers",    "symbol": "CTIG",  "max_supply": 7500,  "price": "0.08"},
    {"name": "NebulaCats",      "symbol": "NBCT",  "max_supply": 2500,  "price": "0.18"},
    {"name": "ArcadeHeroes",    "symbol": "ARCH",  "max_supply": 5555,  "price": "0.07"},
    {"name": "VoxelKnights",    "symbol": "VXKN",  "max_supply": 4321,  "price": "0.11"},
    {"name": "DigitalDemons",   "symbol": "DGDM",  "max_supply": 6660,  "price": "0.066"},
    {"name": "ChromaDucks",     "symbol": "CHDK",  "max_supply": 9000,  "price": "0.04"},
    {"name": "PlasmaLions",     "symbol": "PLSL",  "max_supply": 1234,  "price": "0.25"},
]

# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC BURN TEMPLATES
# 10 diverse templates covering different vulnerability patterns
# ─────────────────────────────────────────────────────────────────────────────

PUBLIC_BURN_TEMPLATES = [

    # 1. Completely open burn — no check at all
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name}
/// @notice Vulnerable: burn function callable by anyone with no authorization
contract {name} is ERC721 {{
    uint256 private _id;
    uint256 public price = {price} ether;

    constructor() ERC721("{name}", "{symbol}") {{}}

    function mint() external payable {{
        require(msg.value >= price, "Insufficient ETH");
        _mint(msg.sender, _id++);
    }}

    // VULNERABLE: no require(ownerOf(tokenId) == msg.sender)
    // Any address can destroy any token they do not own
    function burn(uint256 tokenId) external {{
        _burn(tokenId);
    }}
}}""",

    # 2. Owner-only burn — owner can burn holder tokens
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title {name}
/// @notice Vulnerable: centralised burn — owner can destroy any holder's token
contract {name} is ERC721, Ownable {{
    uint256 private _id;

    constructor() ERC721("{name}", "{symbol}") {{}}

    function mint(address to) external payable {{
        _mint(to, _id++);
    }}

    // VULNERABLE: owner can burn tokens held by any user without their consent
    function adminBurn(uint256 tokenId) external onlyOwner {{
        _burn(tokenId);
    }}
}}""",

    # 3. Batch burn — loop over tokenIds, no auth check per token
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name}
/// @notice Vulnerable: batch burn with no per-token ownership check
contract {name} is ERC721 {{
    uint256 private _id;

    constructor() ERC721("{name}", "{symbol}") {{}}

    function mint(uint256 qty) external payable {{
        require(msg.value >= {price} ether * qty);
        for (uint i = 0; i < qty; i++) _mint(msg.sender, _id++);
    }}

    // VULNERABLE: loops through tokenIds and burns all with no ownership check
    function batchBurn(uint256[] calldata tokenIds) external {{
        for (uint i = 0; i < tokenIds.length; i++) {{
            _burn(tokenIds[i]);   // no require(ownerOf(tokenIds[i]) == msg.sender)
        }}
    }}
}}""",

    # 4. Burn with wrong authorization — checks contract owner not token owner
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name}
/// @notice Vulnerable: burn checks contract deployer, not token owner
contract {name} is ERC721 {{
    address public deployer;
    uint256 private _id;

    constructor() ERC721("{name}", "{symbol}") {{
        deployer = msg.sender;
    }}

    function mint(address to) external {{
        _mint(to, _id++);
    }}

    // VULNERABLE: checks deployer (contract-level) not token ownership
    // Any token holder other than deployer cannot burn their own tokens
    // but deployer can burn any token — wrong authorization model
    function burn(uint256 tokenId) external {{
        require(msg.sender == deployer, "Only deployer");
        _burn(tokenId);
    }}
}}""",

    # 5. Burn with try/catch ignoring ownership — token gets burned on error too
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title {name}
/// @notice Vulnerable: approval check is bypassable — _burn called regardless
contract {name} is ERC721, Ownable {{
    uint256 private _id;
    mapping(address => bool) public burners;

    constructor() ERC721("{name}", "{symbol}") {{}}

    function mint(address to) external {{
        _mint(to, _id++);
    }}

    function addBurner(address b) external onlyOwner {{
        burners[b] = true;
    }}

    // VULNERABLE: any address in burners mapping can burn any token
    // burners list is meant for operators but grants blanket burn rights
    function burn(uint256 tokenId) external {{
        require(burners[msg.sender], "Not a burner");
        _burn(tokenId);   // no per-token ownership check
    }}
}}""",

    # 6. Redeem-and-burn — no check that redeemer owns the token
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name} Redeemable NFT
/// @notice Vulnerable: redeem burns token without checking caller owns it
contract {name} is ERC721 {{
    uint256 private _id;
    uint256 public constant MAX_SUPPLY = {max_supply};
    mapping(uint256 => bool) public redeemed;

    constructor() ERC721("{name}", "{symbol}") {{}}

    function mint() external payable {{
        require(msg.value >= {price} ether);
        require(_id < MAX_SUPPLY, "Sold out");
        _mint(msg.sender, _id++);
    }}

    // VULNERABLE: anyone can redeem (burn) any token for its redeemable value
    // should check ownerOf(tokenId) == msg.sender first
    function redeem(uint256 tokenId) external {{
        require(!redeemed[tokenId], "Already redeemed");
        redeemed[tokenId] = true;
        _burn(tokenId);  // no ownership check
        payable(msg.sender).transfer(0.01 ether);
    }}
}}""",

    # 7. Governance burn — any token holder can burn others' tokens via vote bypass
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name} Governance NFT
/// @notice Vulnerable: community burn requires no quorum check — single caller suffices
contract {name} is ERC721 {{
    uint256 private _id;
    mapping(uint256 => uint256) public burnVotes;

    constructor() ERC721("{name}", "{symbol}") {{}}

    function mint() external payable {{
        require(msg.value >= {price} ether);
        _mint(msg.sender, _id++);
    }}

    function voteToBurn(uint256 tokenId) external {{
        burnVotes[tokenId]++;
    }}

    // VULNERABLE: quorum check is missing — 1 vote is enough to burn any token
    function executeBurn(uint256 tokenId) external {{
        require(burnVotes[tokenId] > 0, "No votes");
        // Missing: require(burnVotes[tokenId] >= QUORUM)
        _burn(tokenId);
    }}
}}""",

    # 8. Emergency burn with no access control
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title {name}
/// @notice Vulnerable: emergency burn function open to all
contract {name} is ERC721, Ownable {{
    uint256 private _id;
    bool public emergencyMode;

    constructor() ERC721("{name}", "{symbol}") {{}}

    function mint() external payable {{
        require(msg.value >= {price} ether);
        _mint(msg.sender, _id++);
    }}

    function setEmergency(bool v) external onlyOwner {{
        emergencyMode = v;
    }}

    // VULNERABLE: in emergency mode any address can burn any token
    function emergencyBurn(uint256 tokenId) external {{
        require(emergencyMode, "Not emergency");
        // Missing: require(ownerOf(tokenId) == msg.sender)
        _burn(tokenId);
    }}
}}""",

    # 9. Staking contract burn — unstake burns without ownership check
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name} Stakeable NFT
/// @notice Vulnerable: unstake/burn path has no staker validation
contract {name} is ERC721 {{
    uint256 private _id;
    mapping(uint256 => address) public staker;
    mapping(uint256 => uint256) public stakedAt;

    constructor() ERC721("{name}", "{symbol}") {{}}

    function mint() external payable {{
        require(msg.value >= {price} ether);
        _mint(msg.sender, _id++);
    }}

    function stake(uint256 tokenId) external {{
        require(ownerOf(tokenId) == msg.sender, "Not owner");
        transferFrom(msg.sender, address(this), tokenId);
        staker[tokenId] = msg.sender;
        stakedAt[tokenId] = block.timestamp;
    }}

    // VULNERABLE: anyone can call burnStaked for any tokenId
    // should require msg.sender == staker[tokenId]
    function burnStaked(uint256 tokenId) external {{
        require(staker[tokenId] != address(0), "Not staked");
        delete staker[tokenId];
        _burn(tokenId);  // no check that caller is the staker
    }}
}}""",

    # 10. Cross-contract burn — external contract can burn without token ownership
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title {name}
/// @notice Vulnerable: approved burner contract can burn any token
contract {name} is ERC721, Ownable {{
    uint256 private _id;
    address public burnerContract;

    constructor() ERC721("{name}", "{symbol}") {{}}

    function mint(address to) external payable {{
        require(msg.value >= {price} ether);
        _mint(to, _id++);
    }}

    function setBurnerContract(address b) external onlyOwner {{
        burnerContract = b;
    }}

    // VULNERABLE: any call from burnerContract can burn any token
    // burnerContract itself may have no ownership check
    function burnFrom(uint256 tokenId) external {{
        require(msg.sender == burnerContract, "Not burner contract");
        _burn(tokenId);  // no ownership validation at this level
    }}
}}""",
]

# ─────────────────────────────────────────────────────────────────────────────
# RISKY MUTABLE PROXY TEMPLATES
# 10 diverse templates covering different proxy vulnerability patterns
# ─────────────────────────────────────────────────────────────────────────────

RISKY_PROXY_TEMPLATES = [

    # 1. Classic unprotected upgrade — no access control at all
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title {name} Proxy
/// @notice Vulnerable: implementation slot changeable by anyone
contract {name}Proxy {{
    address public implementation;
    address public admin;

    constructor(address _impl) {{
        implementation = _impl;
        admin = msg.sender;
    }}

    // VULNERABLE: no onlyAdmin modifier — any address can point proxy to malicious impl
    function upgrade(address newImpl) external {{
        implementation = newImpl;
    }}

    fallback() external payable {{
        address impl = implementation;
        assembly {{
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {{ revert(0, returndatasize()) }}
            default {{ return(0, returndatasize()) }}
        }}
    }}
}}""",

    # 2. EIP-1967 proxy with unprotected upgradeTo
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title {name} EIP-1967 Proxy
/// @notice Vulnerable: EIP-1967 implementation slot writable by any caller
contract {name}Proxy {{
    bytes32 private constant IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address _impl) {{
        assembly {{ sstore(IMPL_SLOT, _impl) }}
    }}

    // VULNERABLE: no access control — anyone can call upgradeTo
    function upgradeTo(address newImpl) external {{
        assembly {{ sstore(IMPL_SLOT, newImpl) }}
    }}

    fallback() external payable {{
        assembly {{
            let impl := sload(IMPL_SLOT)
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {{ revert(0, returndatasize()) }}
            default {{ return(0, returndatasize()) }}
        }}
    }}
}}""",

    # 3. Approved list upgrade — any approved address can upgrade immediately
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title {name} Multi-approved Proxy
/// @notice Vulnerable: any approved address can upgrade with no timelock
contract {name}Proxy {{
    address public implementation;
    address public proxyOwner;
    mapping(address => bool) public approved;

    constructor(address _impl) {{
        implementation = _impl;
        proxyOwner = msg.sender;
    }}

    function approve(address addr) external {{
        require(msg.sender == proxyOwner, "Not owner");
        approved[addr] = true;
    }}

    // VULNERABLE: any approved address → no timelock, no multi-sig
    function upgradeTo(address newImpl) external {{
        require(approved[msg.sender] || msg.sender == proxyOwner, "Not authorized");
        implementation = newImpl;  // immediate — no delay
    }}

    fallback() external payable {{
        address impl = implementation;
        assembly {{
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {{ revert(0, returndatasize()) }}
            default {{ return(0, returndatasize()) }}
        }}
    }}
}}""",

    # 4. UUPS with weak initializer check
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title {name} UUPS-style Proxy
/// @notice Vulnerable: upgradeTo in logic contract has no onlyOwner
contract {name}Logic {{
    address public owner;
    address public implementation;
    bool public initialized;

    function initialize(address _owner) external {{
        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
    }}

    // VULNERABLE: anyone can call upgradeTo since there is no onlyOwner
    function upgradeTo(address newImpl) external {{
        // Missing: require(msg.sender == owner, "Not owner");
        implementation = newImpl;
    }}
}}

contract {name}Proxy {{
    address public implementation;

    constructor(address _impl) {{
        implementation = _impl;
    }}

    fallback() external payable {{
        address impl = implementation;
        assembly {{
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {{ revert(0, returndatasize()) }}
            default {{ return(0, returndatasize()) }}
        }}
    }}
}}""",

    # 5. Beacon proxy with unprotected beacon update
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title {name} Beacon
/// @notice Vulnerable: beacon implementation changeable without access control
contract {name}Beacon {{
    address public implementation;
    address public owner;

    constructor(address _impl) {{
        implementation = _impl;
        owner = msg.sender;
    }}

    // VULNERABLE: no onlyOwner — any address can update the beacon
    // All proxies pointing to this beacon are affected simultaneously
    function update(address newImpl) external {{
        implementation = newImpl;
    }}
}}

contract {name}BeaconProxy {{
    address public beacon;

    constructor(address _beacon) {{
        beacon = _beacon;
    }}

    fallback() external payable {{
        address impl = {name}Beacon(beacon).implementation();
        assembly {{
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {{ revert(0, returndatasize()) }}
            default {{ return(0, returndatasize()) }}
        }}
    }}
}}""",

    # 6. Diamond proxy with unprotected facet addition
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title {name} Diamond Proxy
/// @notice Vulnerable: facet can be added or replaced by any caller
contract {name}Diamond {{
    mapping(bytes4 => address) public facets;
    address public owner;

    constructor() {{
        owner = msg.sender;
    }}

    // VULNERABLE: no access control — anyone can add/replace facets
    function setFacet(bytes4 selector, address facet) external {{
        // Missing: require(msg.sender == owner, "Not owner");
        facets[selector] = facet;
    }}

    fallback() external payable {{
        address facet = facets[msg.sig];
        require(facet != address(0), "Function not found");
        assembly {{
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {{ revert(0, returndatasize()) }}
            default {{ return(0, returndatasize()) }}
        }}
    }}
}}""",

    # 7. Minimal proxy factory with changeable master
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title {name} Minimal Proxy Factory
/// @notice Vulnerable: master implementation changeable by owner alone (no multisig)
contract {name}Factory {{
    address public master;
    address public owner;

    constructor(address _master) {{
        master = _master;
        owner = msg.sender;
    }}

    // VULNERABLE: single owner can change master without timelock
    // All minimal proxy clones immediately delegate to new master
    function setMaster(address newMaster) external {{
        require(msg.sender == owner, "Not owner");
        // Missing: timelock or multi-sig requirement
        master = newMaster;
    }}

    function createClone() external returns (address clone) {{
        address impl = master;
        assembly {{
            let ptr := mload(0x40)
            mstore(ptr, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(ptr, 0x14), shl(0x60, impl))
            mstore(add(ptr, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            clone := create(0, ptr, 0x37)
        }}
    }}
}}""",

    # 8. Transparent proxy with exploitable admin fallthrough
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title {name} Transparent Proxy
/// @notice Vulnerable: admin check uses tx.origin — phishing attack possible
contract {name}TransparentProxy {{
    address public implementation;
    address public admin;

    constructor(address _impl, address _admin) {{
        implementation = _impl;
        admin = _admin;
    }}

    // VULNERABLE: uses tx.origin instead of msg.sender for admin check
    // A phishing contract can trick admin into triggering an upgrade
    function upgradeTo(address newImpl) external {{
        require(tx.origin == admin, "Not admin");
        implementation = newImpl;
    }}

    fallback() external payable {{
        address impl = implementation;
        assembly {{
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {{ revert(0, returndatasize()) }}
            default {{ return(0, returndatasize()) }}
        }}
    }}
}}""",

    # 9. Storage slot proxy — implementation slot readable and writable by anyone
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title {name} Storage Proxy
/// @notice Vulnerable: arbitrary storage slot write with no access control
contract {name}StorageProxy {{
    // Uses raw storage slot for implementation — no access control on setter
    bytes32 constant IMPL_SLOT = keccak256("proxy.implementation");
    bytes32 constant ADMIN_SLOT = keccak256("proxy.admin");

    constructor(address _impl) {{
        bytes32 slot = IMPL_SLOT;
        assembly {{ sstore(slot, _impl) }}
        bytes32 aslot = ADMIN_SLOT;
        address sender = msg.sender;
        assembly {{ sstore(aslot, sender) }}
    }}

    function getImplementation() public view returns (address impl) {{
        bytes32 slot = IMPL_SLOT;
        assembly {{ impl := sload(slot) }}
    }}

    // VULNERABLE: no access control on setImplementation
    function setImplementation(address newImpl) external {{
        // Missing: address admin; assembly {{ admin := sload(ADMIN_SLOT) }}
        // Missing: require(msg.sender == admin, "Not admin");
        bytes32 slot = IMPL_SLOT;
        assembly {{ sstore(slot, newImpl) }}
    }}

    fallback() external payable {{
        address impl = getImplementation();
        assembly {{
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {{ revert(0, returndatasize()) }}
            default {{ return(0, returndatasize()) }}
        }}
    }}
}}""",

    # 10. NFT-specific upgradeable proxy — upgrade with weak guard
    """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title {name} Upgradeable NFT Proxy
/// @notice Vulnerable: upgrade callable by any NFT holder
contract {name}UpgradeableProxy {{
    address public implementation;
    address public nftContract;
    address public owner;

    constructor(address _impl, address _nft) {{
        implementation = _impl;
        nftContract = _nft;
        owner = msg.sender;
    }}

    // VULNERABLE: any NFT holder can upgrade the proxy
    // Intended: only owner should upgrade
    function upgradeTo(address newImpl) external {{
        // Weak check: any holder of the NFT collection can upgrade
        // Missing: require(msg.sender == owner, "Not owner");
        require(
            IERC721(nftContract).balanceOf(msg.sender) > 0,
            "Not an NFT holder"
        );
        implementation = newImpl;
    }}

    fallback() external payable {{
        address impl = implementation;
        assembly {{
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {{ revert(0, returndatasize()) }}
            default {{ return(0, returndatasize()) }}
        }}
    }}
}}

interface IERC721 {{
    function balanceOf(address owner) external view returns (uint256);
}}""",
]


# ─────────────────────────────────────────────────────────────────────────────
# GENERATION
# ─────────────────────────────────────────────────────────────────────────────

def generate_rows(templates: list[str], vuln_class: str, start_id: int) -> list[dict]:
    rows = []
    sample_id = start_id

    for template, variant in itertools.product(templates, VARIANTS):
        try:
            source = template.format(**variant)
        except KeyError:
            # Some templates don't use all variant keys — fill missing with defaults
            safe_variant = {**variant}
            source = template.format(**safe_variant)

        rows.append({
            "id":                        f"NFT-AUG-{sample_id:05d}",
            "source":                    "synthetic_augmented",
            "contract_name":             variant["name"],
            "nft_standard":              "ERC-721",
            "solidity_version":          "^0.8.0",
            "source_code":               source,
            "vulnerability_class":       vuln_class,
            "nftdefects_label":          vuln_class,
            "severity":                  "High",
            "is_vulnerable":             1,
            "slither_detector":          "access-control",
            "vulnerability_description": f"Augmented synthetic {vuln_class} contract",
            "label_risky_mutable_proxy": 1 if vuln_class == "Risky_Mutable_Proxy" else 0,
            "label_erc721_reentrancy":   0,
            "label_unlimited_minting":   0,
            "label_missing_requirements":0,
            "label_public_burn":         1 if vuln_class == "Public_Burn" else 0,
            "contract_address":          "",
        })
        sample_id += 1

    return rows, sample_id


def main():
    print("Loading existing synthetic dataset …")
    if SYNTH_CSV.exists():
        existing = pd.read_csv(SYNTH_CSV)
        print(f"  Existing rows: {len(existing)}")
        print(existing["vulnerability_class"].value_counts().to_string())
        start_id = len(existing)
    else:
        existing = pd.DataFrame()
        start_id = 0

    print(f"\nGenerating augmented contracts …")

    pb_rows, start_id = generate_rows(PUBLIC_BURN_TEMPLATES, "Public_Burn", start_id)
    rp_rows, start_id = generate_rows(RISKY_PROXY_TEMPLATES, "Risky_Mutable_Proxy", start_id)

    print(f"  Public_Burn generated      : {len(pb_rows)}")
    print(f"  Risky_Mutable_Proxy generated: {len(rp_rows)}")

    new_rows = pd.DataFrame(pb_rows + rp_rows)

    # Align columns with existing dataset
    if not existing.empty:
        for col in existing.columns:
            if col not in new_rows.columns:
                new_rows[col] = ""
        new_rows = new_rows[existing.columns]

    augmented = pd.concat([existing, new_rows], ignore_index=True)

    augmented.to_csv(AUG_CSV, index=False)
    print(f"\n✅ Augmented dataset saved → {AUG_CSV}")
    print(f"   Total rows: {len(augmented)}")
    print("\n   Vulnerability class distribution:")
    print(augmented["vulnerability_class"].value_counts().to_string())


if __name__ == "__main__":
    main()
