"""
NFT Smart Contract Vulnerability Dataset Generator
===================================================
Combines:
  1. NFTDefects labeled contract addresses (real on-chain NFTs)
  2. Synthetic Solidity NFT contracts covering all vulnerability classes
  3. Real sample contracts from the NFTDefects evaluation set

Vulnerability classes:
  NFT-specific (NFTDefects taxonomy):
    - ERC721_Reentrancy
    - Unlimited_Minting
    - Missing_Requirements
    - Public_Burn
    - Risky_Mutable_Proxy

  General (Slither-detectable in NFT context):
    - Access_Control
    - Reentrancy_ETH
    - Unchecked_Transfer
    - Integer_Overflow
    - TX_Origin_Auth
    - Unprotected_Selfdestruct

Output:
  - nft_vulnerability_dataset.csv
  - nft_vulnerability_dataset.jsonl
  - dataset_card.md
"""

import pandas as pd
import json
import os
import re
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# 1.  NFT-SPECIFIC SYNTHETIC CONTRACTS (20 per vulnerability type)
# ─────────────────────────────────────────────────────────────────────────────

CONTRACTS = []

# ── ERC-721 Reentrancy ──────────────────────────────────────────────────────
# Vulnerability: onERC721Received callback fires before state update → reentrancy

erc721_reentrant_templates = [
    # Template A – basic safeTransferFrom reentrancy
    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title {name} NFT
/// @notice Vulnerable: state updated AFTER external call in mint
contract {name} is ERC721, Ownable {{
    uint256 public totalSupply;
    uint256 public maxSupply = {max_supply};
    uint256 public price = {price} ether;

    mapping(address => uint256) public pendingWithdrawals;

    constructor() ERC721("{name}", "{symbol}") {{}}

    // VULNERABLE: checks totalSupply before minting, but safeTransferFrom
    // triggers onERC721Received on recipient BEFORE updating totalSupply.
    function mint(uint256 quantity) external payable {{
        require(msg.value >= price * quantity, "Insufficient ETH");
        for (uint256 i = 0; i < quantity; i++) {{
            uint256 tokenId = totalSupply;        // read before state change
            _safeMint(msg.sender, tokenId);       // external call here ← reentrancy
            totalSupply++;                        // state update after external call
        }}
    }}

    function withdraw() external onlyOwner {{
        payable(owner()).transfer(address(this).balance);
    }}
}}""", "ERC721_Reentrancy", "High", "ERC721_Re-entrancy",
     "State variable `totalSupply` is incremented AFTER `_safeMint`, which triggers "
     "`onERC721Received` on the recipient. A malicious receiver can re-enter `mint` "
     "before `totalSupply` is updated, minting extra tokens at the same index."),

    # Template B – claim + callback reentrancy
    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name}
/// @notice Vulnerable: free-claim function with reentrancy via onERC721Received
contract {name} is ERC721 {{
    uint256 private _nextId = 1;
    mapping(address => bool) public hasClaimed;

    constructor() ERC721("{name}", "{symbol}") {{}}

    // VULNERABLE: hasClaimed set AFTER _safeMint external call
    function claim() external {{
        require(!hasClaimed[msg.sender], "Already claimed");
        uint256 id = _nextId++;
        _safeMint(msg.sender, id);          // ← external call before state change
        hasClaimed[msg.sender] = true;      // ← state change too late
    }}
}}""", "ERC721_Reentrancy", "High", "ERC721_Re-entrancy",
     "Claim guard `hasClaimed[msg.sender]` is set AFTER `_safeMint`. A contract "
     "recipient can re-enter `claim()` inside `onERC721Received`, bypassing the guard "
     "and claiming multiple tokens."),

    # Template C – Checks-Effects-Interactions violation in auction settle
    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name} Auction
/// @notice Vulnerable: auction settlement sends NFT before recording winner
contract {name} is ERC721 {{
    address public highBidder;
    uint256 public highBid;
    uint256 public tokenId;
    bool public settled;

    constructor() ERC721("{name}", "{symbol}") {{
        _mint(address(this), 1);
        tokenId = 1;
    }}

    function bid() external payable {{
        require(msg.value > highBid, "Bid too low");
        if (highBidder != address(0)) {{
            payable(highBidder).transfer(highBid);   // refund previous
        }}
        highBidder = msg.sender;
        highBid = msg.value;
    }}

    // VULNERABLE: _safeTransferFrom triggers onERC721Received before settled=true
    function settle() external {{
        require(!settled, "Already settled");
        require(msg.sender == highBidder, "Not winner");
        _safeTransfer(address(this), highBidder, tokenId, "");  // ← external call
        settled = true;                                          // ← too late
    }}
}}""", "ERC721_Reentrancy", "High", "ERC721_Re-entrancy",
     "`settled` flag is written AFTER `_safeTransfer` fires `onERC721Received`. "
     "A winning bidder with a malicious receiver contract can call `settle()` again "
     "inside the callback and receive duplicate settlement benefits."),
]

# ── Unlimited Minting ────────────────────────────────────────────────────────
unlimited_minting_templates = [
    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name}
/// @notice Vulnerable: mint has no supply cap and no access control
contract {name} is ERC721 {{
    uint256 private _tokenId;

    constructor() ERC721("{name}", "{symbol}") {{}}

    // VULNERABLE: anyone can call; no max supply enforced
    function mint(address to) external {{
        _mint(to, _tokenId++);
    }}
}}""", "Unlimited_Minting", "High", "Unlimited_Minting",
     "The `mint` function has no `onlyOwner` modifier and no maximum supply check. "
     "Any address can mint an unlimited number of tokens, destroying scarcity."),

    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title {name}
/// @notice Vulnerable: owner-only mint but no supply cap — owner can mint infinitely
contract {name} is ERC721, Ownable {{
    uint256 public minted;
    // Missing: uint256 public constant MAX_SUPPLY = {max_supply};

    constructor() ERC721("{name}", "{symbol}") {{}}

    // VULNERABLE: onlyOwner but no cap
    function ownerMint(address to, uint256 quantity) external onlyOwner {{
        for (uint256 i = 0; i < quantity; i++) {{
            _mint(to, minted++);
        }}
    }}
}}""", "Unlimited_Minting", "Medium", "Unlimited_Minting",
     "Owner can mint an unbounded quantity because there is no `MAX_SUPPLY` constant "
     "or supply-cap check. Collectors have no on-chain guarantee of scarcity."),

    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title {name}
/// @notice Vulnerable: per-wallet limit ignored because check uses tx.origin
contract {name} is ERC721, Ownable {{
    uint256 public totalMinted;
    uint256 public constant MAX_SUPPLY = {max_supply};
    uint256 public constant MAX_PER_WALLET = 5;
    mapping(address => uint256) public minted;
    uint256 public price = {price} ether;

    constructor() ERC721("{name}", "{symbol}") {{}}

    // VULNERABLE: uses tx.origin instead of msg.sender → per-wallet limit bypass
    function mint(uint256 qty) external payable {{
        require(totalMinted + qty <= MAX_SUPPLY, "Sold out");
        require(msg.value >= price * qty, "Bad value");
        // Bug: tx.origin lets intermediary contracts bypass wallet limit
        require(minted[tx.origin] + qty <= MAX_PER_WALLET, "Limit exceeded");
        minted[tx.origin] += qty;
        for (uint256 i = 0; i < qty; i++) {{
            _mint(msg.sender, totalMinted++);
        }}
    }}
}}""", "Unlimited_Minting", "Medium", "Unlimited_Minting",
     "Per-wallet limit is tracked via `tx.origin` rather than `msg.sender`. "
     "A router/forwarder contract can be used to bypass the limit and mint "
     "unbounded tokens on behalf of different `msg.sender` addresses sharing the same `tx.origin`."),
]

# ── Public Burn ──────────────────────────────────────────────────────────────
public_burn_templates = [
    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name}
/// @notice Vulnerable: burn function has no caller check — anyone can destroy any token
contract {name} is ERC721 {{
    uint256 private _id;

    constructor() ERC721("{name}", "{symbol}") {{}}

    function mint(address to) external {{
        _mint(to, _id++);
    }}

    // VULNERABLE: no require(ownerOf(tokenId) == msg.sender || isApproved)
    function burn(uint256 tokenId) external {{
        _burn(tokenId);   // ← no authorization check
    }}
}}""", "Public_Burn", "High", "Public_Burn",
     "The `burn` function calls `_burn` without verifying that `msg.sender` is the "
     "token owner or an approved operator. Any address can destroy any token."),

    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title {name}
/// @notice Vulnerable: owner-only burn allows owner to destroy holder tokens
contract {name} is ERC721, Ownable {{
    uint256 private _id;

    constructor() ERC721("{name}", "{symbol}") {{}}

    function mint(address to) external payable {{
        _mint(to, _id++);
    }}

    // VULNERABLE: owner can burn tokens held by other users
    function adminBurn(uint256 tokenId) external onlyOwner {{
        _burn(tokenId);
    }}
}}""", "Public_Burn", "Medium", "Public_Burn",
     "Centralised burn: the contract owner can destroy tokens held by any user "
     "without their consent, violating NFT ownership guarantees."),
]

# ── Missing Requirements ─────────────────────────────────────────────────────
missing_req_templates = [
    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title {name}
/// @notice Vulnerable: withdraw sends to caller, not owner; no balance check
contract {name} is ERC721, Ownable {{
    uint256 public price = {price} ether;
    uint256 private _id;

    constructor() ERC721("{name}", "{symbol}") {{}}

    function mint() external payable {{
        require(msg.value >= price, "Low ETH");
        _mint(msg.sender, _id++);
    }}

    // VULNERABLE: missing require(address(this).balance > 0) and sends to msg.sender
    function withdraw() external onlyOwner {{
        // No balance check; anyone who becomes owner gets all funds
        payable(msg.sender).transfer(address(this).balance);
    }}

    // VULNERABLE: setPrice missing require(newPrice > 0)
    function setPrice(uint256 newPrice) external onlyOwner {{
        price = newPrice;   // can be set to 0, enabling free minting
    }}
}}""", "Missing_Requirements", "Medium", "Missing_Requirements",
     "Two missing requirements: (1) `withdraw` has no balance check, and "
     "(2) `setPrice` allows price to be set to zero, enabling free unlimited minting."),

    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name}
/// @notice Vulnerable: transfer helpers missing critical require checks
contract {name} is ERC721 {{
    uint256 private _id;
    bool public saleActive;

    constructor() ERC721("{name}", "{symbol}") {{}}

    // VULNERABLE: missing require(saleActive) guard
    function mint(address to) external payable {{
        // Should check: require(saleActive, "Sale not active");
        require(msg.value >= 0.05 ether, "Low value");
        _mint(to, _id++);
    }}

    function setSaleActive(bool active) external {{
        // VULNERABLE: no onlyOwner — anyone can toggle sale
        saleActive = active;
    }}
}}""", "Missing_Requirements", "High", "Missing_Requirements",
     "Missing requirements: (1) `mint` does not check `saleActive` flag, "
     "allowing minting before the sale begins; (2) `setSaleActive` has no "
     "access control, so any address can start or stop the sale."),
]

# ── Risky Mutable Proxy ──────────────────────────────────────────────────────
risky_proxy_templates = [
    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title {name} Proxy
/// @notice Vulnerable: implementation slot can be changed by anyone
contract {name}Proxy {{
    address public implementation;
    address public admin;

    constructor(address _impl) {{
        implementation = _impl;
        admin = msg.sender;
    }}

    // VULNERABLE: no onlyAdmin check — anyone can point proxy to malicious impl
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
}}""", "Risky_Mutable_Proxy", "Critical", "Risky_Mutable_Proxy",
     "The `upgrade` function has no access control. Any external caller can redirect "
     "the proxy's `delegatecall` to a malicious implementation, gaining full control "
     "over all state and funds in the proxy's storage."),

    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title {name} Upgradeable NFT Proxy
/// @notice Vulnerable: implementation updatable by any approved address with no timelock
contract {name}Proxy {{
    bytes32 private constant IMPL_SLOT = keccak256("eip1967.proxy.implementation");
    address public proxyOwner;
    mapping(address => bool) public approved;

    constructor(address _impl) {{
        proxyOwner = msg.sender;
        _setImplementation(_impl);
    }}

    function _setImplementation(address impl) internal {{
        bytes32 slot = IMPL_SLOT;
        assembly {{ sstore(slot, impl) }}
    }}

    function _getImplementation() internal view returns (address impl) {{
        bytes32 slot = IMPL_SLOT;
        assembly {{ impl := sload(slot) }}
    }}

    // VULNERABLE: any approved address can upgrade; no timelock or multisig
    function upgradeTo(address newImpl) external {{
        require(approved[msg.sender] || msg.sender == proxyOwner, "Not authorized");
        _setImplementation(newImpl);  // immediate effect, no delay
    }}

    function approve(address addr) external {{
        require(msg.sender == proxyOwner, "Not owner");
        approved[addr] = true;
    }}

    fallback() external payable {{
        address impl = _getImplementation();
        assembly {{
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {{ revert(0, returndatasize()) }}
            default {{ return(0, returndatasize()) }}
        }}
    }}
}}""", "Risky_Mutable_Proxy", "High", "Risky_Mutable_Proxy",
     "Any `approved` address can upgrade the proxy immediately without a timelock. "
     "A compromised approved address (or social-engineering attack) can silently "
     "replace the implementation with malicious code affecting all NFT holders."),
]

# ── Access Control ───────────────────────────────────────────────────────────
access_control_templates = [
    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name}
/// @notice Vulnerable: admin functions lack access control modifiers
contract {name} is ERC721 {{
    address public owner;
    uint256 public price = {price} ether;
    bool public revealed;
    string private _baseTokenURI;
    uint256 private _id;

    constructor() ERC721("{name}", "{symbol}") {{
        owner = msg.sender;
    }}

    function mint() external payable {{
        require(msg.value >= price, "Insufficient ETH");
        _mint(msg.sender, _id++);
    }}

    // VULNERABLE: anyone can change base URI (metadata rug-pull)
    function setBaseURI(string calldata uri) external {{
        _baseTokenURI = uri;
    }}

    // VULNERABLE: anyone can change the mint price
    function setPrice(uint256 newPrice) external {{
        price = newPrice;
    }}

    // VULNERABLE: anyone can withdraw contract funds
    function withdraw() external {{
        payable(msg.sender).transfer(address(this).balance);
    }}

    function _baseURI() internal view override returns (string memory) {{
        return _baseTokenURI;
    }}
}}""", "Access_Control", "Critical", "Access_Control",
     "Three unprotected admin functions: `setBaseURI` (metadata rug-pull), "
     "`setPrice` (price manipulation), and `withdraw` (fund theft). None have "
     "`onlyOwner` or equivalent guards."),

    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name} Whitelist Sale
/// @notice Vulnerable: whitelist management has no access control
contract {name} is ERC721 {{
    mapping(address => bool) public whitelist;
    uint256 private _id;
    address private _owner;

    constructor() ERC721("{name}", "{symbol}") {{
        _owner = msg.sender;
    }}

    // VULNERABLE: any address can add itself or others to the whitelist
    function addToWhitelist(address addr) external {{
        whitelist[addr] = true;
    }}

    function whitelistMint() external {{
        require(whitelist[msg.sender], "Not whitelisted");
        _mint(msg.sender, _id++);
    }}
}}""", "Access_Control", "High", "Access_Control",
     "`addToWhitelist` has no `onlyOwner` guard. Any user can whitelist themselves "
     "or others, completely bypassing the intended allowlist gating mechanism."),
]

# ── Reentrancy ETH (withdrawal pattern) ─────────────────────────────────────
reentrancy_eth_templates = [
    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name} Auction
/// @notice Vulnerable: classic reentrancy in ETH refund
contract {name} is ERC721 {{
    mapping(address => uint256) public balances;
    uint256 private _id;

    constructor() ERC721("{name}", "{symbol}") {{}}

    function deposit() external payable {{
        balances[msg.sender] += msg.value;
    }}

    function mintWithDeposit() external {{
        require(balances[msg.sender] >= 0.1 ether, "Insufficient");
        balances[msg.sender] -= 0.1 ether;
        _mint(msg.sender, _id++);
    }}

    // VULNERABLE: classic reentrancy — sends ETH before zeroing balance
    function withdraw() external {{
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");
        (bool ok,) = msg.sender.call{{value: amount}}("");  // ← external call first
        require(ok, "Transfer failed");
        balances[msg.sender] = 0;                           // ← state zeroed after
    }}
}}""", "Reentrancy_ETH", "Critical", "Reentrancy_ETH",
     "Classic reentrancy: `withdraw` sends ETH via `call` before zeroing "
     "`balances[msg.sender]`. A malicious fallback can re-enter `withdraw` "
     "and drain the contract repeatedly."),

    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name} Royalty Distributor
/// @notice Vulnerable: royalty payout reentrancy
contract {name} is ERC721 {{
    mapping(uint256 => address) public creators;
    mapping(address => uint256) public royalties;
    uint256 private _id;

    constructor() ERC721("{name}", "{symbol}") {{}}

    function mint() external {{
        uint256 id = _id++;
        creators[id] = msg.sender;
        _mint(msg.sender, id);
    }}

    function accrue(address creator) external payable {{
        royalties[creator] += msg.value;
    }}

    // VULNERABLE: pays before zeroing; creator can re-enter
    function claimRoyalties() external {{
        uint256 amount = royalties[msg.sender];
        require(amount > 0, "No royalties");
        (bool ok,) = msg.sender.call{{value: amount}}("");
        require(ok);
        royalties[msg.sender] = 0;   // ← too late
    }}
}}""", "Reentrancy_ETH", "Critical", "Reentrancy_ETH",
     "Royalty payout sends ETH before resetting the creator's balance. "
     "A malicious creator contract can re-enter `claimRoyalties` and drain "
     "all accumulated royalties."),
]

# ── Unchecked Transfer Return Value ─────────────────────────────────────────
unchecked_transfer_templates = [
    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title {name} ERC20-payment NFT
/// @notice Vulnerable: ERC20 transfer return value not checked
contract {name} is ERC721 {{
    IERC20 public paymentToken;
    uint256 public price;
    uint256 private _id;
    address public treasury;

    constructor(address token, uint256 _price, address _treasury)
        ERC721("{name}", "{symbol}") {{
        paymentToken = IERC20(token);
        price = _price;
        treasury = _treasury;
    }}

    // VULNERABLE: transfer() return value ignored — USDT returns false on fail
    function mint() external {{
        paymentToken.transfer(treasury, price);   // ← return value unchecked
        _mint(msg.sender, _id++);
    }}
}}""", "Unchecked_Transfer", "High", "Unchecked_Transfer",
     "`paymentToken.transfer()` return value is not checked. Non-standard ERC20 "
     "tokens (e.g. USDT) return `false` on failure instead of reverting. "
     "A failed payment would still result in an NFT being minted."),

    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name}
/// @notice Vulnerable: low-level ETH send result ignored
contract {name} is ERC721 {{
    address payable public royaltyReceiver;
    uint256 public royaltyBps = 500; // 5%
    uint256 private _id;

    constructor(address payable receiver) ERC721("{name}", "{symbol}") {{
        royaltyReceiver = receiver;
    }}

    function mint() external payable {{
        require(msg.value >= 0.08 ether, "Low value");
        uint256 royalty = (msg.value * royaltyBps) / 10000;
        royaltyReceiver.send(royalty);   // VULNERABLE: send return value ignored
        _mint(msg.sender, _id++);
    }}
}}""", "Unchecked_Transfer", "Medium", "Unchecked_Transfer",
     "`royaltyReceiver.send()` silently returns `false` if the receiver is a "
     "contract that consumes more than 2300 gas. Royalties are silently lost "
     "with no revert or event emitted."),
]

# ── Integer Overflow (pre-0.8 Solidity) ─────────────────────────────────────
integer_overflow_templates = [
    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name}
/// @notice Vulnerable: integer overflow in pre-0.8 Solidity without SafeMath
contract {name} is ERC721 {{
    uint8 public maxPerWallet = 5;
    mapping(address => uint8) public minted;
    uint256 private _id;

    constructor() ERC721("{name}", "{symbol}") {{}}

    // VULNERABLE: minted[msg.sender] is uint8 — wraps from 255 to 0 on overflow
    function mint(uint8 quantity) external payable {{
        require(msg.value >= 0.05 ether * quantity, "Bad value");
        // Overflow: if minted[msg.sender] = 255, adding 1 wraps to 0
        require(minted[msg.sender] + quantity <= maxPerWallet, "Limit exceeded");
        minted[msg.sender] += quantity;
        for (uint8 i = 0; i < quantity; i++) {{
            _mint(msg.sender, _id++);
        }}
    }}
}}""", "Integer_Overflow", "High", "Integer_Overflow",
     "`minted[msg.sender]` is `uint8`. In Solidity <0.8, arithmetic wraps silently. "
     "A user at the limit (255 mints) can overflow back to 0, bypassing per-wallet "
     "limits and minting unlimited tokens."),

    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name} Auction House
/// @notice Vulnerable: bid underflow check absent in pre-0.8
contract {name} is ERC721 {{
    mapping(uint256 => uint256) public highBid;
    mapping(uint256 => address) public highBidder;
    uint256 private _id;

    constructor() ERC721("{name}", "{symbol}") {{}}

    function createAuction() external returns (uint256) {{
        uint256 id = _id++;
        _mint(address(this), id);
        return id;
    }}

    // VULNERABLE: refund subtraction can underflow if bid manipulated
    function bid(uint256 tokenId) external payable {{
        require(msg.value > highBid[tokenId], "Low bid");
        uint256 prev = highBid[tokenId];
        address prevBidder = highBidder[tokenId];
        highBid[tokenId] = msg.value;
        highBidder[tokenId] = msg.sender;
        if (prevBidder != address(0)) {{
            // VULNERABLE: no SafeMath — underflow possible if state corrupted
            payable(prevBidder).transfer(prev);
        }}
    }}
}}""", "Integer_Overflow", "Medium", "Integer_Overflow",
     "Pre-0.8 Solidity without SafeMath. While this specific function is unlikely "
     "to underflow in isolation, the absence of SafeMath across the contract means "
     "any arithmetic is a potential overflow/underflow point, as flagged by Slither."),
]

# ── tx.origin Authentication ─────────────────────────────────────────────────
txorigin_templates = [
    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name}
/// @notice Vulnerable: uses tx.origin for owner authentication
contract {name} is ERC721 {{
    address public owner;
    uint256 private _id;
    uint256 public price = {price} ether;

    constructor() ERC721("{name}", "{symbol}") {{
        owner = msg.sender;
    }}

    function mint() external payable {{
        require(msg.value >= price, "Insufficient ETH");
        _mint(msg.sender, _id++);
    }}

    // VULNERABLE: tx.origin can be tricked via phishing contract
    function withdraw() external {{
        require(tx.origin == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }}

    // VULNERABLE: tx.origin check in admin function
    function setPrice(uint256 newPrice) external {{
        require(tx.origin == owner, "Not owner");
        price = newPrice;
    }}
}}""", "TX_Origin_Auth", "High", "TX_Origin_Auth",
     "`tx.origin` is used for owner authentication in `withdraw` and `setPrice`. "
     "A phishing contract can trick the owner into calling it, then forward a call "
     "to this NFT contract — `tx.origin` will still be the owner, granting access."),
]

# ── Unprotected Selfdestruct ─────────────────────────────────────────────────
selfdestruct_templates = [
    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name}
/// @notice Vulnerable: selfdestruct with no or weak access control
contract {name} is ERC721 {{
    address public owner;
    uint256 private _id;

    constructor() ERC721("{name}", "{symbol}") {{
        owner = msg.sender;
    }}

    function mint() external payable {{
        require(msg.value >= 0.05 ether);
        _mint(msg.sender, _id++);
    }}

    // VULNERABLE: anyone can destroy the contract and steal ETH balance
    function kill() external {{
        selfdestruct(payable(msg.sender));
    }}
}}""", "Unprotected_Selfdestruct", "Critical", "Unprotected_Selfdestruct",
     "`selfdestruct` is callable by any address. An attacker can destroy the "
     "NFT contract and redirect its entire ETH balance to themselves, leaving "
     "holders with non-functional tokens."),

    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title {name} Emergency NFT
/// @notice Vulnerable: emergency kill switch has no multisig requirement
contract {name} is ERC721 {{
    address public owner;
    mapping(address => bool) public guardians;
    uint256 private _id;

    constructor() ERC721("{name}", "{symbol}") {{
        owner = msg.sender;
    }}

    function mint() external payable {{
        _mint(msg.sender, _id++);
    }}

    function addGuardian(address g) external {{
        require(msg.sender == owner, "Not owner");
        guardians[g] = true;
    }}

    // VULNERABLE: single guardian can selfdestruct (should require 2-of-N)
    function emergencyKill() external {{
        require(guardians[msg.sender] || msg.sender == owner, "Not authorized");
        selfdestruct(payable(owner));
    }}
}}""", "Unprotected_Selfdestruct", "High", "Unprotected_Selfdestruct",
     "Emergency selfdestruct requires only a single guardian signature. "
     "A compromised guardian key is sufficient to destroy the contract, "
     "violating the implied multi-party trust model."),
]

# ── Clean / Non-Vulnerable Contracts ────────────────────────────────────────
clean_templates = [
    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

/// @title {name} (Clean)
/// @notice Non-vulnerable ERC-721 NFT with best-practice mitigations
contract {name} is ERC721, Ownable, ReentrancyGuard {{
    using Counters for Counters.Counter;

    Counters.Counter private _tokenIds;
    uint256 public constant MAX_SUPPLY = {max_supply};
    uint256 public constant MAX_PER_WALLET = 5;
    uint256 public price = {price} ether;
    bool public saleActive;
    string private _baseTokenURI;

    mapping(address => uint256) public minted;

    constructor(string memory baseURI)
        ERC721("{name}", "{symbol}") {{
        _baseTokenURI = baseURI;
    }}

    // ── Mint ───────────────────────────────────────────────────────────────
    function mint(uint256 quantity) external payable nonReentrant {{
        require(saleActive, "Sale not active");
        require(quantity > 0 && quantity <= 10, "Bad quantity");
        require(_tokenIds.current() + quantity <= MAX_SUPPLY, "Sold out");
        require(minted[msg.sender] + quantity <= MAX_PER_WALLET, "Wallet limit");
        require(msg.value >= price * quantity, "Insufficient ETH");

        minted[msg.sender] += quantity;
        for (uint256 i = 0; i < quantity; i++) {{
            _tokenIds.increment();
            _safeMint(msg.sender, _tokenIds.current());
        }}
    }}

    // ── Admin ──────────────────────────────────────────────────────────────
    function setSaleActive(bool active) external onlyOwner {{
        saleActive = active;
    }}

    function setPrice(uint256 newPrice) external onlyOwner {{
        require(newPrice > 0, "Price must be > 0");
        price = newPrice;
    }}

    function setBaseURI(string calldata uri) external onlyOwner {{
        _baseTokenURI = uri;
    }}

    function withdraw() external onlyOwner nonReentrant {{
        uint256 balance = address(this).balance;
        require(balance > 0, "No funds");
        (bool ok,) = payable(owner()).call{{value: balance}}("");
        require(ok, "Transfer failed");
    }}

    function _baseURI() internal view override returns (string memory) {{
        return _baseTokenURI;
    }}
}}""", "None", "None", "None",
     "Well-structured ERC-721 with ReentrancyGuard, Counters, onlyOwner guards on "
     "all admin functions, supply cap, per-wallet limit, and CEI-compliant withdraw."),

    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/// @title {name} Whitelist Sale (Clean)
/// @notice Merkle-proof whitelist with full CEI and access controls
contract {name} is ERC721Enumerable, Ownable, ReentrancyGuard {{
    bytes32 public merkleRoot;
    uint256 public constant MAX_SUPPLY = {max_supply};
    uint256 public whitelistPrice = 0.05 ether;
    uint256 public publicPrice = 0.08 ether;
    bool public whitelistActive;
    bool public publicActive;
    string private _baseTokenURI;

    mapping(address => uint256) public whitelistMinted;

    constructor(string memory baseURI, bytes32 root)
        ERC721("{name}", "{symbol}") {{
        _baseTokenURI = baseURI;
        merkleRoot = root;
    }}

    function whitelistMint(bytes32[] calldata proof) external payable nonReentrant {{
        require(whitelistActive, "Whitelist inactive");
        require(msg.value >= whitelistPrice, "Insufficient ETH");
        require(totalSupply() < MAX_SUPPLY, "Sold out");
        require(whitelistMinted[msg.sender] == 0, "Already minted");

        bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "Not whitelisted");

        whitelistMinted[msg.sender] = 1;               // CEI: state first
        _safeMint(msg.sender, totalSupply() + 1);       // then external call
    }}

    function publicMint(uint256 qty) external payable nonReentrant {{
        require(publicActive, "Public sale inactive");
        require(qty > 0 && qty <= 5, "Bad quantity");
        require(totalSupply() + qty <= MAX_SUPPLY, "Sold out");
        require(msg.value >= publicPrice * qty, "Insufficient ETH");

        for (uint256 i = 0; i < qty; i++) {{
            _safeMint(msg.sender, totalSupply() + 1);
        }}
    }}

    function setMerkleRoot(bytes32 root) external onlyOwner {{
        merkleRoot = root;
    }}

    function setWhitelistActive(bool v) external onlyOwner {{ whitelistActive = v; }}
    function setPublicActive(bool v) external onlyOwner {{ publicActive = v; }}

    function withdraw() external onlyOwner nonReentrant {{
        require(address(this).balance > 0, "No funds");
        (bool ok,) = payable(owner()).call{{value: address(this).balance}}("");
        require(ok, "Transfer failed");
    }}

    function _baseURI() internal view override returns (string memory) {{
        return _baseTokenURI;
    }}
}}""", "None", "None", "None",
     "Merkle-proof whitelist sale following CEI pattern, nonReentrant, onlyOwner "
     "admin functions, proper event emission via OZ base. No vulnerabilities."),

    ("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/// @title {name} ERC-1155 Multi-token (Clean)
/// @notice Non-vulnerable ERC-1155 with per-token supply caps
contract {name} is ERC1155, Ownable, ReentrancyGuard {{
    uint256 public constant COMMON   = 0;
    uint256 public constant RARE     = 1;
    uint256 public constant LEGENDARY = 2;

    mapping(uint256 => uint256) public maxSupply;
    mapping(uint256 => uint256) public totalMinted;
    mapping(uint256 => uint256) public price;
    bool public saleActive;

    constructor() ERC1155("ipfs://QmExample/{{id}}.json") {{
        maxSupply[COMMON]    = 5000;
        maxSupply[RARE]      = 1000;
        maxSupply[LEGENDARY] = 100;

        price[COMMON]    = 0.02 ether;
        price[RARE]      = 0.1 ether;
        price[LEGENDARY] = 0.5 ether;
    }}

    function mint(uint256 tokenId, uint256 amount) external payable nonReentrant {{
        require(saleActive, "Sale inactive");
        require(maxSupply[tokenId] > 0, "Invalid token");
        require(totalMinted[tokenId] + amount <= maxSupply[tokenId], "Exceeds cap");
        require(msg.value >= price[tokenId] * amount, "Insufficient ETH");

        totalMinted[tokenId] += amount;   // state update before mint
        _mint(msg.sender, tokenId, amount, "");
    }}

    function setSaleActive(bool v) external onlyOwner {{ saleActive = v; }}

    function withdraw() external onlyOwner nonReentrant {{
        require(address(this).balance > 0, "No funds");
        (bool ok,) = payable(owner()).call{{value: address(this).balance}}("");
        require(ok, "Transfer failed");
    }}
}}""", "None", "None", "None",
     "ERC-1155 multi-token with per-type supply caps, CEI-compliant mint, "
     "nonReentrant guard, and owner-only admin functions. No vulnerabilities."),
]

# ─────────────────────────────────────────────────────────────────────────────
# 2.  ASSEMBLE ALL TEMPLATE GROUPS
# ─────────────────────────────────────────────────────────────────────────────

ALL_TEMPLATE_GROUPS = [
    (erc721_reentrant_templates,   "ERC721_Reentrancy"),
    (unlimited_minting_templates,  "Unlimited_Minting"),
    (public_burn_templates,        "Public_Burn"),
    (missing_req_templates,        "Missing_Requirements"),
    (risky_proxy_templates,        "Risky_Mutable_Proxy"),
    (access_control_templates,     "Access_Control"),
    (reentrancy_eth_templates,     "Reentrancy_ETH"),
    (unchecked_transfer_templates, "Unchecked_Transfer"),
    (integer_overflow_templates,   "Integer_Overflow"),
    (txorigin_templates,           "TX_Origin_Auth"),
    (selfdestruct_templates,       "Unprotected_Selfdestruct"),
    (clean_templates,              "None"),
]

# Contract name / symbol variations for parameterisation
CONTRACT_VARIANTS = [
    {"name": "CryptoBeasts",  "symbol": "CBST", "max_supply": 8888, "price": "0.08"},
    {"name": "PixelPunks",    "symbol": "PPNK", "max_supply": 5000, "price": "0.05"},
    {"name": "NeonApes",      "symbol": "NAPE", "max_supply": 10000,"price": "0.07"},
    {"name": "EtherBots",     "symbol": "EBOT", "max_supply": 3333, "price": "0.12"},
    {"name": "SpaceWhales",   "symbol": "SPWH", "max_supply": 7777, "price": "0.06"},
    {"name": "MetaRovers",    "symbol": "MRVR", "max_supply": 4444, "price": "0.09"},
    {"name": "CyberKitties",  "symbol": "CKTY", "max_supply": 6666, "price": "0.04"},
    {"name": "QuantumDragons","symbol": "QDGN", "max_supply": 2222, "price": "0.15"},
    {"name": "GalacticOwls",  "symbol": "GOWL", "max_supply": 9999, "price": "0.03"},
    {"name": "DeepSeaSharks", "symbol": "DSSK", "max_supply": 1111, "price": "0.20"},
]

# ─────────────────────────────────────────────────────────────────────────────
# 3.  GENERATE DATASET ROWS
# ─────────────────────────────────────────────────────────────────────────────

rows = []
sample_id = 0

for template_group, vuln_class in ALL_TEMPLATE_GROUPS:
    for t_idx, (template, vuln_type, severity, nftdefects_label, description) in enumerate(template_group):
        for v_idx, variant in enumerate(CONTRACT_VARIANTS):
            source = template.format(**variant)

            # Build multi-label boolean columns (NFTDefects taxonomy)
            label_risky_proxy    = 1 if nftdefects_label == "Risky_Mutable_Proxy" else 0
            label_erc721_re      = 1 if nftdefects_label == "ERC721_Re-entrancy"  else 0
            label_unlimited_mint = 1 if nftdefects_label == "Unlimited_Minting"   else 0
            label_missing_req    = 1 if nftdefects_label == "Missing_Requirements" else 0
            label_public_burn    = 1 if nftdefects_label == "Public_Burn"          else 0

            # Infer NFT standard from source
            if "ERC721" in source or "ERC-721" in source:
                nft_standard = "ERC-721"
            elif "ERC1155" in source or "ERC-1155" in source:
                nft_standard = "ERC-1155"
            else:
                nft_standard = "Custom"

            # Suggested Slither detector
            slither_map = {
                "ERC721_Reentrancy":        "reentrancy-no-eth",
                "Reentrancy_ETH":           "reentrancy-eth",
                "Unlimited_Minting":        "access-control",
                "Public_Burn":              "access-control",
                "Missing_Requirements":     "missing-zero-check",
                "Risky_Mutable_Proxy":      "access-control",
                "Access_Control":           "access-control",
                "Unchecked_Transfer":       "unchecked-transfer",
                "Integer_Overflow":         "taint-analysis",
                "TX_Origin_Auth":           "tx-origin",
                "Unprotected_Selfdestruct": "suicidal",
                "None":                     "N/A",
            }

            rows.append({
                "id":                     f"NFT-SYN-{sample_id:04d}",
                "source":                 "synthetic",
                "contract_name":          variant["name"],
                "nft_standard":           nft_standard,
                "solidity_version":       re.search(r"pragma solidity ([^;]+);", source).group(1).strip(),
                "source_code":            source,
                "vulnerability_class":    vuln_type,
                "nftdefects_label":       nftdefects_label,
                "severity":               severity,
                "is_vulnerable":          0 if vuln_type == "None" else 1,
                "slither_detector":       slither_map.get(vuln_type, "N/A"),
                "vulnerability_description": description,
                # NFTDefects multi-label columns (aligned with their dataset)
                "label_risky_mutable_proxy":  label_risky_proxy,
                "label_erc721_reentrancy":    label_erc721_re,
                "label_unlimited_minting":    label_unlimited_mint,
                "label_missing_requirements": label_missing_req,
                "label_public_burn":          label_public_burn,
            })
            sample_id += 1

synthetic_df = pd.DataFrame(rows)
print(f"Synthetic contracts generated: {len(synthetic_df)}")
print(synthetic_df["vulnerability_class"].value_counts())

# ─────────────────────────────────────────────────────────────────────────────
# 4.  INTEGRATE NFTDEFECTS REAL CONTRACT LABELS
# ─────────────────────────────────────────────────────────────────────────────

nftdefects_df = pd.read_csv("/tmp/nftdefects/experiment/NFTContractDefects.csv")
nftdefects_df.columns = [
    "contract_address",
    "label_risky_mutable_proxy",
    "label_erc721_reentrancy",
    "label_unlimited_minting",
    "label_missing_requirements",
    "label_public_burn",
]

defect_cols = [
    "label_risky_mutable_proxy",
    "label_erc721_reentrancy",
    "label_unlimited_minting",
    "label_missing_requirements",
    "label_public_burn",
]

def infer_vuln_class(row):
    if row["label_erc721_reentrancy"]:     return "ERC721_Reentrancy"
    if row["label_unlimited_minting"]:     return "Unlimited_Minting"
    if row["label_public_burn"]:           return "Public_Burn"
    if row["label_missing_requirements"]:  return "Missing_Requirements"
    if row["label_risky_mutable_proxy"]:   return "Risky_Mutable_Proxy"
    return "None"

nftdefects_df["vulnerability_class"] = nftdefects_df.apply(infer_vuln_class, axis=1)
nftdefects_df["is_vulnerable"] = (nftdefects_df[defect_cols].sum(axis=1) > 0).astype(int)
nftdefects_df["severity"] = nftdefects_df.apply(
    lambda r: "High" if r["is_vulnerable"] else "None", axis=1
)

# Map to full schema (source code not available without Etherscan key)
real_rows = []
for i, row in nftdefects_df.iterrows():
    real_rows.append({
        "id":                     f"NFT-REAL-{i:05d}",
        "source":                 "NFTDefects (real on-chain)",
        "contract_name":          "",
        "nft_standard":           "ERC-721",
        "solidity_version":       "unknown",
        "source_code":            f"[Source at https://etherscan.io/address/{row['contract_address']}]",
        "vulnerability_class":    row["vulnerability_class"],
        "nftdefects_label":       row["vulnerability_class"],
        "severity":               row["severity"],
        "is_vulnerable":          row["is_vulnerable"],
        "slither_detector":       "N/A",
        "vulnerability_description": "",
        "label_risky_mutable_proxy":  row["label_risky_mutable_proxy"],
        "label_erc721_reentrancy":    row["label_erc721_reentrancy"],
        "label_unlimited_minting":    row["label_unlimited_minting"],
        "label_missing_requirements": row["label_missing_requirements"],
        "label_public_burn":          row["label_public_burn"],
        "contract_address":           row["contract_address"],
    })

real_df = pd.DataFrame(real_rows)
print(f"\nReal NFTDefects contracts: {len(real_df)}")
print(real_df["vulnerability_class"].value_counts())

# ─────────────────────────────────────────────────────────────────────────────
# 5.  ALSO ADD THE FEW REAL .SOL FILES FROM NFTDEFECTS
# ─────────────────────────────────────────────────────────────────────────────

sol_rows = []
sol_paths = list(Path("/tmp/nftdefects/experiment/evaluation").rglob("*.sol"))

for sol_path in sol_paths:
    source_code = sol_path.read_text(errors="replace")
    # Infer vuln from parent folder name
    parent = sol_path.parent.name
    addr = sol_path.stem.lower()

    # Look up label in NFTDefects CSV
    match = nftdefects_df[nftdefects_df["contract_address"].str.lower() == addr]
    if not match.empty:
        row = match.iloc[0]
        vc = row["vulnerability_class"]
        is_v = row["is_vulnerable"]
        sev  = row["severity"]
        lrmp = row["label_risky_mutable_proxy"]
        ler  = row["label_erc721_reentrancy"]
        lum  = row["label_unlimited_minting"]
        lmr  = row["label_missing_requirements"]
        lpb  = row["label_public_burn"]
    else:
        vc   = "Missing_Requirements" if "false_negatives" in str(sol_path) else "None"
        is_v = 1 if "false_negatives" in str(sol_path) else 0
        sev  = "High" if is_v else "None"
        lrmp = lum = lmr = lpb = ler = 0

    ver_match = re.search(r"pragma solidity ([^;]+);", source_code)
    sol_version = ver_match.group(1).strip() if ver_match else "unknown"

    sol_rows.append({
        "id":                     f"NFT-REAL-SOL-{len(sol_rows):03d}",
        "source":                 "NFTDefects evaluation sample (real .sol)",
        "contract_name":          sol_path.stem,
        "nft_standard":           "ERC-721",
        "solidity_version":       sol_version,
        "source_code":            source_code,
        "vulnerability_class":    vc,
        "nftdefects_label":       vc,
        "severity":               sev,
        "is_vulnerable":          is_v,
        "slither_detector":       "N/A",
        "vulnerability_description": f"Real contract from NFTDefects evaluation set ({parent})",
        "label_risky_mutable_proxy":  lrmp,
        "label_erc721_reentrancy":    ler,
        "label_unlimited_minting":    lum,
        "label_missing_requirements": lmr,
        "label_public_burn":          lpb,
        "contract_address":           addr,
    })

sol_df = pd.DataFrame(sol_rows) if sol_rows else pd.DataFrame()
print(f"\nReal Solidity source files: {len(sol_df)}")

# ─────────────────────────────────────────────────────────────────────────────
# 6.  MERGE & EXPORT
# ─────────────────────────────────────────────────────────────────────────────

frames = [synthetic_df, real_df]
if not sol_df.empty:
    frames.append(sol_df)

final_df = pd.concat(frames, ignore_index=True)

# Ensure consistent column order
cols = [
    "id", "source", "contract_name", "nft_standard", "solidity_version",
    "vulnerability_class", "nftdefects_label", "severity", "is_vulnerable",
    "slither_detector", "vulnerability_description",
    "label_risky_mutable_proxy", "label_erc721_reentrancy",
    "label_unlimited_minting", "label_missing_requirements", "label_public_burn",
    "contract_address", "source_code",
]
# Add any missing columns with empty strings
for c in cols:
    if c not in final_df.columns:
        final_df[c] = ""

final_df = final_df[cols]

os.makedirs("/root/nft_dataset/output", exist_ok=True)

# CSV
final_df.to_csv("/root/nft_dataset/output/nft_vulnerability_dataset.csv", index=False)
# JSONL (drop source_code in index file; keep it in full JSONL)
final_df.to_json("/root/nft_dataset/output/nft_vulnerability_dataset.jsonl",
                 orient="records", lines=True)

# Subset: only synthetic (has full source code)
syn_only = final_df[final_df["source"] == "synthetic"]
syn_only.to_csv("/root/nft_dataset/output/nft_synthetic_with_source.csv", index=False)
syn_only.to_json("/root/nft_dataset/output/nft_synthetic_with_source.jsonl",
                 orient="records", lines=True)

print(f"\n✅ Dataset saved.")
print(f"   Total rows:            {len(final_df)}")
print(f"   Synthetic (w/ source): {len(synthetic_df)}")
print(f"   Real NFTDefects refs:  {len(real_df)}")
print(f"   Real .sol files:       {len(sol_df)}")
print(f"\n   Vulnerability distribution (full dataset):")
print(final_df["vulnerability_class"].value_counts().to_string())
print(f"\n   Vulnerable vs Clean:")
print(final_df["is_vulnerable"].value_counts().to_string())
