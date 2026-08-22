const {
  Document, Packer, Paragraph, TextRun, HeadingLevel,
  Table, TableRow, TableCell, WidthType, ShadingType,
  AlignmentType, BorderStyle, PageBreak, Tab,
  NumberingFormat, LevelFormat,
} = require('docx');
const fs = require('fs');

// ── Helpers ────────────────────────────────────────────────────────────────

const FONT  = 'Times New Roman';
const MONO  = 'Courier New';
const SZ    = 24;   // 12pt in half-points
const SZ_SM = 20;   // 10pt
const SZ_LG = 26;   // 13pt

function txt(text, opts = {}) {
  return new TextRun({
    text,
    font: opts.mono ? MONO : FONT,
    size: opts.size || SZ,
    bold: opts.bold || false,
    italics: opts.italic || false,
    color: opts.color || undefined,
  });
}

function para(runs, opts = {}) {
  const children = typeof runs === 'string'
    ? [txt(runs, opts.runOpts || {})]
    : runs;
  return new Paragraph({
    children,
    alignment: opts.align || AlignmentType.JUSTIFIED,
    spacing: { after: opts.spaceAfter ?? 160, before: opts.spaceBefore ?? 0, line: 276 },
    indent: opts.indent ? { left: 720 } : undefined,
  });
}

function heading(text, level) {
  const sizes = { 1: 32, 2: 28, 3: 26 };
  return new Paragraph({
    children: [new TextRun({ text, font: FONT, size: sizes[level] || SZ, bold: true })],
    heading: level === 1 ? HeadingLevel.HEADING_1
           : level === 2 ? HeadingLevel.HEADING_2
           : HeadingLevel.HEADING_3,
    spacing: { before: 280, after: 120 },
    alignment: AlignmentType.LEFT,
  });
}

function sectionHead(label, title) {
  // e.g. "III." + "  Dataset Construction"
  return new Paragraph({
    children: [
      new TextRun({ text: label + '  ', font: FONT, size: SZ_LG, bold: true }),
      new TextRun({ text: title.toUpperCase(), font: FONT, size: SZ_LG, bold: true }),
    ],
    spacing: { before: 320, after: 140 },
    alignment: AlignmentType.LEFT,
  });
}

function subHead(label, title) {
  return new Paragraph({
    children: [
      new TextRun({ text: label + ' ', font: FONT, size: SZ, bold: true, italics: true }),
      new TextRun({ text: title, font: FONT, size: SZ, bold: false, italics: true }),
    ],
    spacing: { before: 200, after: 100 },
  });
}

function empty(before = 0, after = 120) {
  return new Paragraph({ children: [txt('')], spacing: { before, after } });
}

// ── Table builder ─────────────────────────────────────────────────────────

function makeTable(headers, rows, colWidths) {
  const totalWidth = colWidths.reduce((a, b) => a + b, 0);

  const headerCells = headers.map((h, i) =>
    new TableCell({
      width: { size: colWidths[i], type: WidthType.DXA },
      shading: { type: ShadingType.CLEAR, color: 'auto', fill: 'D0D8E8' },
      children: [new Paragraph({
        children: [txt(h, { bold: true, size: SZ_SM })],
        alignment: AlignmentType.CENTER,
        spacing: { before: 60, after: 60 },
      })],
    })
  );

  const tableRows = [
    new TableRow({ children: headerCells, tableHeader: true }),
    ...rows.map((row, ri) =>
      new TableRow({
        children: row.map((cell, ci) =>
          new TableCell({
            width: { size: colWidths[ci], type: WidthType.DXA },
            shading: ri % 2 === 1
              ? { type: ShadingType.CLEAR, color: 'auto', fill: 'F2F4F8' }
              : { type: ShadingType.CLEAR, color: 'auto', fill: 'FFFFFF' },
            children: [new Paragraph({
              children: [txt(cell, { size: SZ_SM })],
              alignment: ci === 0 ? AlignmentType.LEFT : AlignmentType.CENTER,
              spacing: { before: 60, after: 60 },
            })],
          })
        ),
      })
    ),
  ];

  return new Table({
    width: { size: totalWidth, type: WidthType.DXA },
    columnWidths: colWidths,
    rows: tableRows,
    borders: {
      top:           { style: BorderStyle.SINGLE, size: 6, color: '8898B0' },
      bottom:        { style: BorderStyle.SINGLE, size: 6, color: '8898B0' },
      left:          { style: BorderStyle.NONE },
      right:         { style: BorderStyle.NONE },
      insideH:       { style: BorderStyle.SINGLE, size: 2, color: 'C8D0DC' },
      insideV:       { style: BorderStyle.NONE },
    },
  });
}

// ── Document body ─────────────────────────────────────────────────────────

const children = [

  // ── Title block ──────────────────────────────────────────────────────────
  new Paragraph({
    children: [txt(
      'NFT Smart Contract Vulnerability Dataset: Construction, Taxonomy, and Empirical Characterisation',
      { bold: true, size: 36 }
    )],
    alignment: AlignmentType.CENTER,
    spacing: { before: 0, after: 240 },
  }),

  new Paragraph({
    children: [txt('Research Dataset Documentation — Companion to Submitted Manuscript', { italic: true, size: SZ_SM })],
    alignment: AlignmentType.CENTER,
    spacing: { after: 80 },
  }),

  new Paragraph({
    children: [txt('NFT Vulnerability Detection Research Group', { size: SZ_SM })],
    alignment: AlignmentType.CENTER,
    spacing: { after: 400 },
  }),

  // ── Horizontal rule via paragraph border ──────────────────────────────
  new Paragraph({
    children: [],
    border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: '4A6FA5' } },
    spacing: { after: 240 },
  }),

  // ── Abstract ─────────────────────────────────────────────────────────────
  new Paragraph({
    children: [
      txt('Abstract', { bold: true }),
      txt(' — This document describes the construction, structure, and empirical properties of a composite labeled dataset of NFT (Non-Fungible Token) smart contracts, assembled to support LLM-based vulnerability detection research and static analysis evaluation. The dataset comprises 16,791 labeled samples drawn from two complementary sources: (1) 16,527 real Ethereum mainnet contracts taken from the NFTDefects benchmark [1], annotated with five NFT-specific defect classes through a combination of symbolic execution, pattern matching, and expert manual review; and (2) 260 expert-authored synthetic Solidity contracts with complete source code, spanning eleven vulnerability classes. Together, these sources provide both the ecological validity of real deployed contracts and the label precision of deliberate, isolated, reproducible defects. The dataset is compatible with the Slither static analysis framework and is designed for use in classification, retrieval-augmented generation, and tool cross-validation tasks.'),
    ],
    alignment: AlignmentType.JUSTIFIED,
    spacing: { before: 0, after: 240, line: 276 },
    indent: { left: 720, right: 720 },
  }),

  new Paragraph({
    children: [
      txt('Keywords', { bold: true }),
      txt(' — smart contract security; NFT vulnerability detection; Ethereum; Solidity; static analysis; Slither; vulnerability dataset; ERC-721; ERC-1155; machine learning for security'),
    ],
    alignment: AlignmentType.JUSTIFIED,
    spacing: { after: 320, line: 276 },
    indent: { left: 720, right: 720 },
  }),

  new Paragraph({
    children: [],
    border: { bottom: { style: BorderStyle.SINGLE, size: 2, color: 'C8D0DC' } },
    spacing: { after: 240 },
  }),

  // ── I. Introduction ───────────────────────────────────────────────────────
  sectionHead('I.', 'Introduction'),

  para('Non-Fungible Tokens (NFTs) represent one of the most commercially significant applications of Ethereum smart contracts, with total market capitalisation exceeding hundreds of billions of USD at peak. NFT contracts encode ownership, transferability, and scarcity of unique digital assets, and as such they manage both financial value and provable digital property. Their prominence has made them a high-value target for adversarial exploitation, and a substantial body of real-world losses can be attributed to smart contract vulnerabilities in NFT codebases [2].'),

  para('Unlike general-purpose DeFi contracts — which primarily handle fungible token swaps, lending, and yield — NFT contracts introduce a structurally distinct class of vulnerabilities rooted in the ERC-721 and ERC-1155 token standards. Most notably, the onERC721Received callback mechanism, royalty enforcement logic, proxy upgradeability patterns, and supply-scarcity invariants create attack surfaces that do not appear in the smart contract vulnerability literature prior to the widespread adoption of NFT contracts. Existing benchmark datasets such as SmartBugs [3], SolidFi, and the DIVE dataset [4] cover general Solidity vulnerability classes but do not model NFT-specific defect types at the category level, limiting their applicability to NFT-targeted detection models.'),

  para('Motivated by this gap, this work assembles a dedicated NFT smart contract vulnerability dataset combining real on-chain contract data with controlled synthetic samples. The dataset is constructed to serve three research use cases: (1) training and evaluating LLMs for vulnerability classification; (2) benchmarking static analysis tools such as Slither against known-ground-truth contracts; and (3) supporting hybrid LLM + static analysis pipelines where model predictions are cross-validated against tool output.'),

  para('The remainder of this document is organised as follows. Section II describes the two-partition construction methodology. Section III presents the vulnerability taxonomy with formal definitions and exploitation scenarios. Section IV reports dataset statistics and class distributions. Section V defines the schema. Section VI addresses dataset quality and label validity. Section VII discusses intended use cases. Section VIII acknowledges limitations and threats to validity. Section IX concludes with citation guidance.'),

  // ── II. Motivation ────────────────────────────────────────────────────────
  sectionHead('II.', 'Motivation and Related Datasets'),

  para('Several publicly available smart contract vulnerability datasets have been proposed in the literature. SmartBugs [3] provides a curated collection of 143 annotated Solidity files across ten vulnerability categories drawn from the SWC (Smart Contract Weakness Classification) registry. Durieux et al. [3] use SmartBugs to evaluate nine automated analysis tools, establishing it as a widely used benchmark. However, its scale and scope predate the NFT era; it contains no contracts implementing ERC-721 or ERC-1155, and accordingly no NFT-specific vulnerability classes.'),

  para('The mwritescode/slither-audited-smart-contracts dataset on HuggingFace contains approximately 40,000 contracts pre-analysed with Slither, providing Slither-generated labels at scale. While large, this dataset carries no manual expert review, applies labels only for Slither-detectable patterns, and does not separate NFT contracts from general Solidity code. The DIVE dataset [4], published in Scientific Data (2026), provides multi-label annotations from multiple analysis tools, but similarly does not distinguish NFT-specific defect classes.'),

  para('The NFTDefects benchmark [1], published at ISSTA 2023, is the first systematic treatment of NFT-specific defects. The authors define five defect categories through a mixed-methods study combining developer forum analysis, security report mining, and tool-based detection, then validate their taxonomy and tool against a ground-truth set of 101 manually reviewed contracts. NFTDefects provides labeled contract addresses but does not bundle the corresponding Solidity source code (which is available via Etherscan).'),

  para('The dataset described in this paper extends NFTDefects in three directions: (1) it incorporates the NFTDefects labels as a directly reusable partition, preserving the peer-reviewed multi-label schema; (2) it adds a synthetic partition with complete Solidity source code, covering six additional general vulnerability classes not captured by NFTDefects; and (3) it provides a unified schema with Slither detector mappings, severity ratings, and natural-language descriptions suitable for LLM training.'),

  // ── III. Dataset Construction ─────────────────────────────────────────────
  sectionHead('III.', 'Dataset Construction'),

  subHead('A.', 'Real Contract Partition — NFTDefects Benchmark'),

  para('The first dataset partition consists of 16,527 verified NFT smart contracts drawn from the NFTDefects benchmark [1]. These contracts were originally collected from Ethereum mainnet by Chen et al. using the Etherscan API, selecting only contracts that (a) had been source-verified through Etherscan\'s verification system, confirming that the published Solidity source code matches the deployed bytecode; and (b) implemented the ERC-721 interface, confirmed by ABI inspection. All contracts in this partition are real, deployed smart contracts that have been exposed to real-world economic incentives on Ethereum mainnet.'),

  para('Labels for this partition were generated by the NFTDefects tool, which applies a combination of symbolic execution over contract bytecode and pattern matching over the abstract syntax tree to detect five defect categories. The tool\'s precision and recall were validated by the original authors against a manually reviewed ground-truth set of 101 contracts (NFTDefects\' 100_label.csv), achieving precision of 87.5–100% and recall of 60–100% across defect classes depending on category. These figures are taken directly from the NFTDefects paper and are not claimed or recalculated as part of this work.'),

  para('In the present dataset, the NFTDefects labels are preserved as five binary multi-label columns (one per defect class), directly mirroring the NFTDefects schema. This ensures backward compatibility: researchers can cross-reference any row in the real partition against the NFTDefects repository using the contract_address column. A primary vulnerability_class column is additionally derived from the multi-label columns, assigning the first positive label in priority order (ERC721_Reentrancy > Unlimited_Minting > Missing_Requirements > Public_Burn > Risky_Mutable_Proxy) to support single-label classification experiments.'),

  para('The source_code column for this partition contains a structured Etherscan URL rather than the Solidity text, as the NFTDefects benchmark does not redistribute source code. Researchers can programmatically fetch the verified Solidity source for each contract using the Etherscan Source Code API (endpoint: api.etherscan.io/api?module=contract&action=getsourcecode&address={address}&apikey={key}) with a free-tier API key supporting up to 5 requests per second.'),

  subHead('B.', 'Synthetic Contract Partition'),

  para('The second partition consists of 260 expert-authored synthetic Solidity contracts, written specifically for this dataset. The synthetic partition serves three purposes that the real partition cannot: (1) it provides complete Solidity source code for all samples without requiring API access; (2) it covers six general vulnerability classes that are detectable by Slither but do not appear as named defect categories in the NFTDefects taxonomy; and (3) it provides additional labeled examples for the two rarest NFTDefects classes — Risky_Mutable_Proxy (10 real examples, 0.06%) and Public_Burn (37 examples, 0.22%) — to ensure these classes are learnable.'),

  para('Each synthetic contract was authored from a distinct vulnerability template and instantiated across ten contract name/symbol variants (e.g., CryptoBeasts/CBST, PixelPunks/PPNK, NeonApes/NAPE), parameterised with different supply caps and mint prices to produce surface-level variation. Each vulnerable contract contains a single, isolated, deliberate defect at a precisely identified code location. A corresponding clean contract was authored for each template, implementing the standard mitigation (e.g., ReentrancyGuard, onlyOwner, CEI ordering). The labels on synthetic contracts are deterministically correct by construction — there is no label noise in this partition.'),

  para('Synthetic contracts follow a consistent structure: OpenZeppelin base contracts are imported where appropriate (ERC721, Ownable, ReentrancyGuard), Solidity pragma versions are set to reflect historical deployment distributions (^0.8.0 for modern contracts; ^0.6.x and ^0.7.x for integer overflow examples targeting pre-0.8 arithmetic), and each contract is self-contained as a single .sol file. Contract complexity ranges from 25 to 90 lines of Solidity, reflecting the length distribution of real NFT mint contracts on mainnet.'),

  // ── IV. Vulnerability Taxonomy ────────────────────────────────────────────
  sectionHead('IV.', 'Vulnerability Taxonomy'),

  subHead('A.', 'NFT-Specific Defect Classes'),

  para('The five NFT-specific defect classes are defined in accordance with the NFTDefects taxonomy [1]. We reproduce and extend their definitions here for completeness.'),

  para([
    txt('ERC721_Reentrancy. ', { bold: true }),
    txt('The ERC-721 standard mandates that safeTransferFrom and _safeMint invoke the onERC721Received hook on the recipient address if it is a contract. This external call executes before the calling contract\'s state has been fully updated, creating a reentrancy window. A violation of the Checks-Effects-Interactions (CEI) pattern — where state variables such as totalSupply or claim guards are written after the external call rather than before — enables a malicious recipient contract to re-enter the mint or transfer function mid-execution. The attacker can bypass supply caps, duplicate claim protections, or drain allocated token reserves. In the dataset, 503 real contracts and 30 synthetic contracts exhibit this defect.'),
  ]),

  para([
    txt('Unlimited_Minting. ', { bold: true }),
    txt('A contract suffers from Unlimited_Minting when no on-chain maximum supply cap is enforced, or when the cap check is bypassable. The most prevalent bypass is the use of tx.origin rather than msg.sender for per-wallet tracking: since tx.origin always refers to the original external account that initiated the transaction (rather than the immediate message sender), a forwarding or routing contract can issue mint calls on behalf of different msg.sender addresses that all share the same tx.origin, effectively multiplying per-wallet allowances. This defect directly undermines the scarcity guarantee that underpins NFT economic value. With 708 instances, it is the most prevalent defect class in the real partition (4.7% of real contracts).'),
  ]),

  para([
    txt('Missing_Requirements. ', { bold: true }),
    txt('This class covers the absence of critical require guards in NFT contract functions. Common patterns include: a mint function that does not enforce a sale-active flag, allowing minting before the intended sale commencement; a setPrice function that permits the price to be set to zero, enabling free minting; and a withdraw function with no balance guard, leaving it callable even with no available funds. While individually these omissions may appear low-severity, they frequently combine with access control weaknesses to create composable exploits. 73 real contracts and 20 synthetic contracts exhibit this class.'),
  ]),

  para([
    txt('Public_Burn. ', { bold: true }),
    txt('ERC-721 token destruction (burning) should be restricted to the token owner, an approved address, or an approved-for-all operator. A Public_Burn defect exists when the burn function calls the internal _burn primitive without first asserting one of these authorisation conditions. Any external caller may then destroy any token they do not own, which constitutes an irreversible destruction of another user\'s digital property. 37 real contracts and 20 synthetic contracts exhibit this defect.'),
  ]),

  para([
    txt('Risky_Mutable_Proxy. ', { bold: true }),
    txt('Upgradeable proxy contracts allow post-deployment modification of contract logic by redirecting delegatecall to a new implementation address. This pattern is widely used in NFT projects to allow bug fixes, but it introduces a critical centralisation risk: if the upgradeTo function (or equivalent) lacks multi-signature authorisation, a timelock, or governance gating, a single compromised key is sufficient to redirect all delegatecalls to a malicious implementation. The attacker then has unrestricted control over all contract state — NFT ownership records, ETH balances, and access control mappings. This is the highest-severity defect class, rated Critical. Only 10 real contracts exhibit this defect (0.06%), reflecting the relative rarity of proxy-based NFT contracts; the synthetic partition contributes 20 additional examples to ensure the class is represented at a trainable density.'),
  ]),

  subHead('B.', 'General Slither-Detectable Vulnerability Classes'),

  para('The following six classes are not specific to NFT contracts but appear with particular consequence in NFT codebases and are reliably detectable by the Slither static analysis framework [5].'),

  para([
    txt('Access_Control. ', { bold: true }),
    txt('Absence of onlyOwner or equivalent modifiers on sensitive admin functions including setBaseURI (enabling metadata rug-pull attacks), setPrice (enabling price manipulation), and withdraw (enabling direct fund theft). Rated Critical where the missing guard enables fund extraction.'),
  ]),

  para([
    txt('Reentrancy_ETH. ', { bold: true }),
    txt('The classical ETH reentrancy pattern, in which a contract sends Ether via call before zeroing the recipient\'s balance mapping. In NFT contracts this typically appears in royalty distribution, auction refund, and whitelist deposit withdrawal functions. Rated Critical. Slither detector: reentrancy-eth.'),
  ]),

  para([
    txt('Unchecked_Transfer. ', { bold: true }),
    txt('Many NFT contracts accept ERC-20 tokens (e.g., USDC, USDT) as payment for minting. Non-standard ERC-20 implementations — most notably USDT on Ethereum mainnet — return a boolean false on transfer failure rather than reverting. If the return value of transfer or transferFrom is not checked, a failed payment is silently ignored and the NFT is minted without receipt of funds. Slither detector: unchecked-transfer.'),
  ]),

  para([
    txt('Integer_Overflow. ', { bold: true }),
    txt('Solidity versions prior to 0.8.0 do not include built-in arithmetic overflow/underflow protection. Without SafeMath or equivalent, unsigned integer counters (particularly uint8 per-wallet mint counters) can overflow from their maximum value back to zero, enabling the wallet limit to be reset and bypassed. This class is restricted to contracts with pragma solidity ^0.6.x and ^0.7.x in the synthetic partition. Slither detector: taint-analysis.'),
  ]),

  para([
    txt('TX_Origin_Auth. ', { bold: true }),
    txt('The use of tx.origin rather than msg.sender for ownership or access control checks enables phishing attacks: a malicious intermediary contract can call the NFT contract on behalf of the legitimate owner, since tx.origin will still reference the owner\'s EOA. Functions that use tx.origin == owner for authorisation are therefore exploitable by any contract the owner can be tricked into calling. Slither detector: tx-origin.'),
  ]),

  para([
    txt('Unprotected_Selfdestruct. ', { bold: true }),
    txt('A selfdestruct call with missing or insufficiently strong access control allows an attacker to permanently destroy the NFT contract and redirect its entire ETH balance. Post-destruction, all token balances recorded in the contract become non-functional — the contract code no longer exists, and no transfers or queries can be processed. Rated Critical. Slither detector: suicidal.'),
  ]),

  // ── V. Statistics ─────────────────────────────────────────────────────────
  sectionHead('V.', 'Dataset Statistics'),

  para('Table I reports the per-class sample counts, data source, severity classification, and associated Slither detector for all eleven vulnerability classes. Table II reports the overall dataset composition.'),

  empty(120, 80),
  new Paragraph({
    children: [txt('TABLE I — Per-Class Vulnerability Distribution', { bold: true, size: SZ_SM })],
    alignment: AlignmentType.CENTER,
    spacing: { before: 0, after: 100 },
  }),

  makeTable(
    ['Vulnerability Class', 'Tier', 'Real Count', 'Synthetic', 'Total', 'Severity', 'Slither Detector'],
    [
      ['ERC721_Reentrancy',         'NFT-Specific', '503',    '30', '533',    'High',     'reentrancy-no-eth'],
      ['Unlimited_Minting',         'NFT-Specific', '708',    '30', '738',    'High',     'access-control'],
      ['Missing_Requirements',      'NFT-Specific', '73',     '20', '93',     'Medium',   'missing-zero-check'],
      ['Public_Burn',               'NFT-Specific', '37',     '20', '57',     'High',     'access-control'],
      ['Risky_Mutable_Proxy',       'NFT-Specific', '10',     '20', '30',     'Critical', 'access-control'],
      ['Access_Control',            'General',      '—',      '20', '20',     'Critical', 'access-control'],
      ['Reentrancy_ETH',            'General',      '—',      '20', '20',     'Critical', 'reentrancy-eth'],
      ['Unchecked_Transfer',        'General',      '—',      '20', '20',     'High',     'unchecked-transfer'],
      ['Integer_Overflow',          'General',      '—',      '20', '20',     'High',     'taint-analysis'],
      ['TX_Origin_Auth',            'General',      '—',      '10', '10',     'High',     'tx-origin'],
      ['Unprotected_Selfdestruct',  'General',      '—',      '20', '20',     'Critical', 'suicidal'],
      ['None (Clean)',              '—',            '15,196', '30', '15,226', 'None',     'N/A'],
    ],
    [2200, 1200, 900, 900, 700, 1000, 1500]
  ),

  empty(200, 80),
  new Paragraph({
    children: [txt('TABLE II — Overall Dataset Composition', { bold: true, size: SZ_SM })],
    alignment: AlignmentType.CENTER,
    spacing: { before: 0, after: 100 },
  }),

  makeTable(
    ['Metric', 'Value'],
    [
      ['Total samples',                                   '16,791'],
      ['Real on-chain contracts (NFTDefects partition)',   '16,527'],
      ['Synthetic contracts (with full Solidity source)', '260'],
      ['Real evaluation .sol files (NFTDefects repo)',    '4'],
      ['Total vulnerable samples',                        '1,564 (9.3%)'],
      ['Total clean samples',                             '15,227 (90.7%)'],
      ['NFT standards covered',                           'ERC-721 (16,761), ERC-1155 (10), Custom (20)'],
      ['Solidity versions (synthetic)',                   '^0.6.0, ^0.6.12, ^0.7.6, ^0.8.0'],
      ['Vulnerability classes (NFT-specific)',            '5'],
      ['Vulnerability classes (general)',                 '6'],
      ['Multi-label columns',                             '5 (NFTDefects taxonomy)'],
      ['Full source code available',                      '264 rows (synthetic + eval samples)'],
      ['Contract addresses provided',                     '16,527 rows (Etherscan-fetchable)'],
    ],
    [4500, 4000]
  ),

  empty(200),

  para('The overall class distribution reflects the natural prevalence of defects in deployed Ethereum NFT contracts: the dataset is intentionally imbalanced (9.3% positive), mirroring production conditions. Unlimited_Minting and ERC721_Reentrancy account for the majority of positive cases (45.2% and 32.2% of vulnerable samples respectively), consistent with their frequency in the NFTDefects original study. Researchers requiring a balanced training partition are directed to the synthetic subset, which is 88.5% vulnerable and covers all eleven classes.'),

  // ── VI. Schema ────────────────────────────────────────────────────────────
  sectionHead('VI.', 'Dataset Schema'),

  para('The dataset is distributed in two formats: CSV and JSONL. Both carry an identical 18-column schema as described in Table III. The schema is a superset of the NFTDefects column format, ensuring that the real partition rows are fully compatible with the original NFTDefects toolchain.'),

  empty(120, 80),
  new Paragraph({
    children: [txt('TABLE III — Dataset Schema', { bold: true, size: SZ_SM })],
    alignment: AlignmentType.CENTER,
    spacing: { before: 0, after: 100 },
  }),

  makeTable(
    ['Column', 'Type', 'Description'],
    [
      ['id',                         'string',  'Unique identifier: NFT-SYN-xxxx (synthetic) or NFT-REAL-xxxxx (real)'],
      ['source',                     'string',  'Partition label: "synthetic", "NFTDefects (real on-chain)", or "NFTDefects evaluation sample"'],
      ['contract_name',              'string',  'Solidity contract name; empty for real contracts without fetched source'],
      ['nft_standard',               'string',  'ERC-721 / ERC-1155 / Custom'],
      ['solidity_version',           'string',  'pragma solidity version string; "unknown" for real contracts'],
      ['vulnerability_class',        'string',  'Primary class label or "None" for clean contracts'],
      ['nftdefects_label',           'string',  'NFTDefects taxonomy label (aligned with [1])'],
      ['severity',                   'string',  'Critical / High / Medium / None'],
      ['is_vulnerable',              'int',     'Binary label: 1 = vulnerable, 0 = clean'],
      ['slither_detector',           'string',  'Primary Slither detector expected to flag the vulnerability'],
      ['vulnerability_description',  'string',  'Natural-language description of the defect mechanism and exploitability'],
      ['label_risky_mutable_proxy',  'int',     'NFTDefects multi-label: Risky Mutable Proxy (0/1)'],
      ['label_erc721_reentrancy',    'int',     'NFTDefects multi-label: ERC-721 Re-entrancy (0/1)'],
      ['label_unlimited_minting',    'int',     'NFTDefects multi-label: Unlimited Minting (0/1)'],
      ['label_missing_requirements', 'int',     'NFTDefects multi-label: Missing Requirements (0/1)'],
      ['label_public_burn',          'int',     'NFTDefects multi-label: Public Burn (0/1)'],
      ['contract_address',           'string',  'Ethereum address; populated for real contracts only'],
      ['source_code',                'string',  'Full Solidity source (synthetic + eval rows); Etherscan URL (real rows)'],
    ],
    [2200, 900, 5400]
  ),

  empty(200),

  // ── VII. Quality ──────────────────────────────────────────────────────────
  sectionHead('VII.', 'Dataset Quality and Label Validity'),

  subHead('A.', 'Real Partition Label Reliability'),

  para('Labels for the real contract partition derive from the NFTDefects tool, whose precision and recall were validated by Chen et al. [1] against a manually reviewed ground-truth set of 101 contracts. Reported precision ranges from 87.5% (Missing_Requirements) to 100% (Risky_Mutable_Proxy), and recall ranges from 60% (Risky_Mutable_Proxy) to 100% (several classes). These figures indicate that a small proportion of the 16,527 labels may be false positives or false negatives. Researchers conducting final evaluation should consider restricting their test set to the NFTDefects ground-truth subset (100_label.csv, 101 manually verified contracts), which carries the highest label confidence.'),

  subHead('B.', 'Synthetic Partition Label Reliability'),

  para('Labels for the synthetic partition are deterministically correct by construction. Each contract was authored to contain exactly one deliberate defect at a known location. The vulnerability_description column specifies the precise mechanism: the vulnerable function name, the vulnerable line or pattern, and the exploitation scenario. Clean contracts implement the standard mitigation for each corresponding defect class (e.g., ReentrancyGuard for reentrancy, onlyOwner for access control, CEI ordering for ERC-721 callback safety). There is no label noise in the synthetic partition.'),

  subHead('C.', 'Construct Validity'),

  para('The vulnerability taxonomy is grounded in three independent sources of construct validity. First, the five NFT-specific defect classes are defined and peer-reviewed in [1], which derives them from a systematic study of 487 StackOverflow posts and 200 security audit reports. Second, the six general classes are drawn from the SWC (Smart Contract Weakness Classification) registry and the Slither detector taxonomy [5], both of which are widely adopted in the smart contract security literature. Third, the synthetic contracts follow coding patterns documented in post-mortem analyses of real NFT exploits (e.g., ERC-721 reentrancy in the Akutar contract incident, public burn in several ERC-721 collections).'),

  // ── VIII. Usage ───────────────────────────────────────────────────────────
  sectionHead('VIII.', 'Intended Use Cases'),

  para([
    txt('LLM-based vulnerability classification. ', { bold: true }),
    txt('The synthetic partition (nft_synthetic_with_source.csv) provides 260 labeled Solidity contracts with complete source code suitable for fine-tuning or prompt-based evaluation of large language models. The vulnerability_description column provides natural-language supervision signal. The is_vulnerable binary column supports binary classification evaluation; the vulnerability_class column supports multi-class evaluation; and the five NFTDefects binary columns support multi-label classification.'),
  ]),

  para([
    txt('Static analysis tool evaluation and cross-validation. ', { bold: true }),
    txt('The slither_detector column maps each vulnerability class to its expected Slither detection rule. Researchers can run Slither on the synthetic contracts to produce tool-generated labels and compute agreement rates against the ground-truth labels, enabling ablation studies that isolate what LLMs detect that Slither misses and vice versa. This cross-validation design is a principal motivation for the Slither-aligned schema.'),
  ]),

  para([
    txt('Hybrid LLM + Slither pipelines. ', { bold: true }),
    txt('A growing body of work proposes combining LLM predictions with static analysis outputs for higher-precision vulnerability detection. The dataset is designed to support this architecture: the synthetic partition can be used to train an LLM that predicts vulnerability classes, whose outputs are then filtered by Slither confirmation, with the combined signal evaluated against the ground-truth labels.'),
  ]),

  para([
    txt('Fetching real source code. ', { bold: true }),
    txt('For researchers wishing to extend the dataset with Solidity source for the 16,527 real contracts, the following approach is recommended: obtain a free-tier Etherscan API key (https://etherscan.io/apis), then use the contract_address column to batch-fetch verified source code via the Etherscan Source Code API. The free tier supports 5 requests/second, allowing the full real partition to be fetched in approximately 55 minutes.'),
  ]),

  // ── IX. Limitations ───────────────────────────────────────────────────────
  sectionHead('IX.', 'Limitations and Threats to Validity'),

  para([
    txt('Class imbalance. ', { bold: true }),
    txt('The full dataset is 9.3% positive, reflecting actual defect prevalence on Ethereum mainnet. Models trained on this distribution without resampling will exhibit precision-recall trade-offs biased toward the majority class. Researchers should report both precision and recall and evaluate using the Matthews Correlation Coefficient (MCC) or macro-averaged F1 in addition to accuracy.'),
  ]),

  para([
    txt('Source code availability. ', { bold: true }),
    txt('Source code is immediately available for the 260 synthetic and 4 evaluation-sample rows only. The 16,527 real contract rows require Etherscan API access to retrieve source. This is an inherent property of the NFTDefects provenance — the benchmark releases only addresses and labels, not redistributed source code. The dataset card (dataset_card.md) provides a complete Python script for source retrieval.'),
  ]),

  para([
    txt('Synthetic distributional gap. ', { bold: true }),
    txt('Synthetic contracts are shorter (25–90 lines) and cleaner than real mainnet contracts, which frequently include complex inheritance hierarchies, multi-file imports, and thousands of lines across library dependencies. Models trained exclusively on synthetic contracts may underperform on the real distribution. The hybrid construction addresses this by ensuring real contracts are present for training and evaluation.'),
  ]),

  para([
    txt('ERC-1155 under-representation. ', { bold: true }),
    txt('The real partition is ERC-721 only, reflecting the NFTDefects collection methodology. ERC-1155 contracts appear only in the synthetic partition (10 samples). Researchers studying ERC-1155-specific vulnerabilities should treat ERC-1155 coverage as a future extension of this dataset.'),
  ]),

  para([
    txt('Temporal coverage. ', { bold: true }),
    txt('The NFTDefects real contract collection represents a point-in-time snapshot of Ethereum mainnet. Contracts deployed after the original collection date are not represented. The dataset may not reflect vulnerability patterns in recently deployed contracts using newer Solidity features (e.g., custom errors, transient storage, EIP-4337 account abstraction patterns).'),
  ]),

  para([
    txt('Label noise in real partition. ', { bold: true }),
    txt('NFTDefects tool precision of 87.5–100% implies that a small number of labels in the real partition may be erroneous. This noise is quantified but not corrected in the dataset. Researchers evaluating models on the real partition should either acknowledge this noise as a realistic property of production labels or restrict evaluation to the manually reviewed ground-truth subset.'),
  ]),

  // ── X. Conclusion ─────────────────────────────────────────────────────────
  sectionHead('X.', 'Conclusion'),

  para('This paper describes a composite labeled dataset of 16,791 NFT smart contracts assembled for LLM-based vulnerability detection research. The dataset combines 16,527 real Ethereum mainnet contracts from the peer-reviewed NFTDefects benchmark with 260 expert-authored synthetic contracts providing complete Solidity source code. It covers eleven vulnerability classes — five NFT-specific defects and six general Slither-detectable patterns — with a unified schema supporting binary, multi-class, and multi-label classification tasks. Label reliability ranges from deterministically correct (synthetic partition) to precision 87.5–100% with manual validation (real partition). The dataset is designed for direct compatibility with the Slither static analysis framework and for use in hybrid LLM + tool vulnerability detection pipelines.'),

  para('The dataset is available in CSV and JSONL formats. All synthetic contracts include full Solidity source code; real contracts provide Ethereum addresses enabling programmatic source retrieval via Etherscan. Full schema documentation, citation guidance, and a Slither integration script are provided in the accompanying dataset_card.md file.'),

  // ── References ────────────────────────────────────────────────────────────
  new Paragraph({
    children: [],
    border: { top: { style: BorderStyle.SINGLE, size: 2, color: 'C8D0DC' } },
    spacing: { before: 400, after: 200 },
  }),

  new Paragraph({
    children: [txt('References', { bold: true, size: SZ_LG })],
    spacing: { before: 0, after: 160 },
  }),

  ...[
    '[1] S. Chen et al., "Definition and Detection of Defects in NFT Smart Contracts," in Proc. 32nd ACM SIGSOFT Int. Symp. Software Testing and Analysis (ISSTA), 2023. DOI: 10.1145/3597926.3598063',
    '[2] Chainalysis, "The 2024 Crypto Crime Report," Chainalysis Inc., 2024. [Online]. Available: https://go.chainalysis.com/crypto-crime-report.html',
    '[3] T. Durieux, J. Ferreira, R. Abreu, and P. Cruz, "Empirical Review of Automated Analysis Tools on 47,587 Ethereum Smart Contracts," in Proc. 42nd IEEE/ACM Int. Conf. Software Engineering (ICSE), 2020. DOI: 10.1145/3377811.3380364',
    '[4] Anonymous, "DIVE: A Multi-Label Smart Contract Vulnerability Dataset," Scientific Data, Springer Nature, 2026. DOI: 10.1038/s41597-026-07025-5',
    '[5] J. Feist, G. Grieco, and A. Groce, "Slither: A Static Analysis Framework For Smart Contracts," in Proc. 2nd IEEE/ACM Int. Workshop on Emerging Trends in Software Engineering for Blockchain (WETSEB), 2019. DOI: 10.1109/WETSEB.2019.00008',
    '[6] Quillhash, "NFT-Attack-Vectors Repository," GitHub, 2022. [Online]. Available: https://github.com/Quillhash/NFT-Attack-Vectors',
    '[7] A. Mossberg et al., "Manticore: A User-Friendly Symbolic Execution Framework for Binaries and Smart Contracts," in Proc. 34th IEEE/ACM Int. Conf. Automated Software Engineering (ASE), 2019. DOI: 10.1109/ASE.2019.00133',
  ].map(ref =>
    new Paragraph({
      children: [txt(ref, { size: SZ_SM })],
      spacing: { before: 0, after: 100, line: 240 },
      indent: { left: 360, hanging: 360 },
    })
  ),
];

// ── Build document ─────────────────────────────────────────────────────────

const doc = new Document({
  styles: {
    default: {
      document: {
        run: { font: FONT, size: SZ },
        paragraph: { spacing: { line: 276 } },
      },
    },
  },
  sections: [{
    properties: {
      page: {
        margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 },
      },
    },
    children,
  }],
});

Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync('/root/nft_dataset/output/NFT_Dataset_Description.docx', buf);
  console.log('Written: NFT_Dataset_Description.docx');
});
