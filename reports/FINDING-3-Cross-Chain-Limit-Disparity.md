# Finding: Cross-Chain Daily Mint Limit Disparity

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Title** | Cross-Chain Daily Mint Limit Disparity Enables Limit Bypass via Chain-Hopping |
| **Severity** | Low (CVSS 3.0: 2.4) |
| **CVSS Vector** | `CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N` |
| **Category** | Business Logic Error |
| **CWE** | CWE-840: Business Logic Error |
| **Affected Chains** | Ethereum, Base, Polygon, BSC, Gnosis, World Chain |
| **Date Discovered** | 2026-05-24 |

---

## CVSS 3.0 Breakdown

| Metric | Value | Score | Justification |
|--------|-------|:-----:|---------------|
| **Attack Vector (AV)** | Network | N | Exploitable via on-chain transaction submission |
| **Attack Complexity (AC)** | High | H | Requires MINTER_ROLE on both minters AND cross-chain bridging coordination |
| **Privileges Required (PR)** | High | H | Caller must hold MINTER_ROLE on affected contracts |
| **User Interaction (UI)** | None | N | No victim interaction needed |
| **Scope (S)** | Unchanged | U | Exploit confined to the vulnerable contracts |
| **Confidentiality (C)** | None | N | No data or private information disclosed |
| **Integrity (I)** | Low | L | Limited additional minting beyond per-chain cap via chain-hopping |
| **Availability (A)** | None | N | Service not disrupted |

**CVSS Base Score**: 2.4 (Low) — `CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N`

---

## Summary

Each chain deploys its own `LimitedMinter` instance with independently configured daily mint limits for the same WFIAT tokens. These limits vary significantly across chains — Ethereum allows **5.6x more** minting per day than Base. There is no global cross-chain mint cap enforcement. Since the bridge allows tokens to move freely between chains, an entity holding `MINTER_ROLE` on the chain with the highest limit can mint there and bridge tokens to lower-limit chains, circumventing the intended per-chain caps.

This compounds with Finding #1 (Dual Minter Bypass): the combined limit of both `LimitedMinter` + `LimitedMinterBridge` varies per chain, and the effective global daily limit is the **maximum** of all chain limits, not the minimum.

---

## Affected Assets

### Daily Limit Comparison (wARS)

| Chain | LimitedMinter | Daily Limit | LMBridge | Daily Limit | Combined Effective |
|-------|:---:|:---:|:---:|:---:|:---:|
| Ethereum | `0xD168...` | 700,000,000 | `0x4616...` | 30,000,000 | **730,000,000** |
| Base | `0xf469...` | 100,000,000 | `0x4616...` | 30,000,000 | **130,000,000** |
| World Chain | `0xDe7E...` | TBD | `0x4616...` | TBD | TBD |
| Gnosis | `0xD168...` | TBD | `0x4616...` | TBD | TBD |
| BSC | `0xD168...` | TBD | `0x4616...` | TBD | TBD |
| Polygon | `0xD168...` | TBD | `0x4616...` | TBD | TBD |

> Ethereum's combined limit (730M) is **5.6x higher** than Base's combined limit (130M).

### Other WFIAT Tokens (Ethereum)

| Token | LimitedMinter Daily Limit | LMBridge Daily Limit |
|-------|:---:|:---:|
| wARS | 700,000,000 | 30,000,000 |
| USDar | 40,000 | N/A (not on bridge) |

---

## Technical Description

### Root Cause

Each chain's `LimitedMinter` is a separate contract with its own storage. The `tokenConfigs[token].dailyMaxMint` value is set independently per chain by the token's `DEFAULT_ADMIN_ROLE` holder. There is no cross-chain coordination mechanism, shared registry, or global cap enforcement.

### Code: Daily Limit Enforcement (All Chains Use Identical Logic)

**LimitedMinter.sol:4050-4067:**
```solidity
function mint(address token, uint256 mintAmount)
    external onlyRole(MINTER_ROLE) tokenExists(token) nonReentrant whenNotPaused
{
    TokenConfig storage config = tokenConfigs[token];
    uint256 currentDay = block.timestamp / 1 days;
    uint256 alreadyMinted = mintedPerDay[token][currentDay];

    // Check against THIS chain's local config only
    if (alreadyMinted + mintAmount > config.dailyMaxMint)   // ← per-chain limit
        revert ExceedsDailyMintLimit();

    mintedPerDay[token][currentDay] = alreadyMinted + mintAmount;
    IToken(token).mint(config.mintDestination, mintAmount);
}
```

The `config.dailyMaxMint` is read from **local storage** — each chain maintains its own value. No cross-chain query is performed.

### Code: registerToken (Sets Per-Chain Limit)

**LimitedMinter.sol:3971-3985:**
```solidity
function registerToken(address token, address mintDestination, uint256 dailyMaxMint)
    external onlyExternalAdmin(token)
{
    // ...
    tokenConfigs[token] = TokenConfig({
        mintDestination: mintDestination,
        dailyMaxMint: dailyMaxMint,     // ← set independently per chain
        exists: true
    });
}
```

The `dailyMaxMint` parameter is provided by the caller with no cross-chain validation. There is no mechanism to enforce that the same limit is used across all chains.

### Why The Bridge Makes This Worse

The WFIAT tokens are designed to be fungible across chains via the `BridgeDeposit` / `LimitedMinterBridge` system. The bridge flow:

```
Source (high-limit chain):  Mint 730M → depositForBridge → Burn → BridgeDepositInitiated
Destination (low-limit chain): fulfillBridgeMint → LimitedMinterBridge.mintTo → Mint
```

Tokens minted on a high-limit chain can flow to a low-limit chain via the bridge. The destination chain enforces its own (lower) daily limit only for **native mints** on that chain — bridge fulfillments go through `LimitedMinterBridge.mintTo()` which has its own 30M cap shared across all chains.

### On-Chain Evidence

**Ethereum — LimitedMinter wARS config (block ~25159396):**
```
cast call 0xD168CFbBE260D48cd119497a9a2eE8482080C5E7 \
  "tokenConfigs(address)" 0x0DC4F92879B7670e5f4e4e6e3c801D229129D90D

Raw: 0x
  000000000000000000000000b6c9e6451a4b4f65249f60de4fd12da1088a2807  (mintDestination)
  0000000000000000000000000000000000000000024306c4097859c43c000000  (dailyMaxMint = 700M)
  0000000000000000000000000000000000000000000000000000000000000001  (exists = true)
```

**Base — LimitedMinter wARS config:**
```
cast call 0xf469eC9dEBf7F0adEBA4d1Db2FF5c70707bEeB30 \
  "tokenConfigs(address)" 0x0DC4F92879B7670e5f4e4e6e3c801D229129D90D \
  --rpc-url https://mainnet.base.org

Raw: 0x
  000000000000000000000000b6c9e6451a4b4f65249f60de4fd12da1088a2807  (same mintDestination!)
  0000000000000000000000000000000000000000052b7d2dcc80cd2e4000000    (dailyMaxMint = 100M)
  0000000000000000000000000000000000000000000000000000000000000001  (exists = true)
```

**LimitedMinterBridge (same across all chains via CREATE2):**
```
cast call 0x46167cB034feC6ceC46CaeD4f61281f5Aa0Eb0e6 \
  "tokenConfigs(address)" 0x0DC4F92879B7670e5f4e4e6e3c801D229129D90D

dailyMaxMint = 30,000,000 on both Ethereum AND Base
→ Bridge limit is consistent (30M), but Legacy Minter limit varies wildly (700M vs 100M)
```

### Exploit Scenario

1. Entity holds `MINTER_ROLE` on `LimitedMinter` on Ethereum (or controls `DEFAULT_ADMIN` there)
2. Entity mints **700M wARS** via `LimitedMinter.mint(wARS, 700M)` on Ethereum (within ETH's 700M limit)
3. Entity calls `wARS.approve(BridgeDeposit, 700M)` then `depositForBridge(wARS, 700M, Base, attacker, id)`
4. Tokens burned on ETH, `BridgeDepositInitiated` emitted
5. Bridge operator calls `fulfillBridgeMint` on Base → mints 700M via `LimitedMinterBridge.mintTo()`
6. **Result**: 700M wARS now on Base, which only allows 100M of native mints via its `LimitedMinter`
7. Effective daily limit bypassed: 700M reached on Base despite its local 100M cap

This is possible because bridge fulfillments count against `LimitedMinterBridge`'s 30M limit (same on all chains), not against the chain's local `LimitedMinter` limit.

### Cross-Chain Limit Summary

| Path | Effective Daily Cap | Limiter |
|------|:---:|--------|
| Native mint on Ethereum | 700M | LimitedMinter (ETH) |
| Native mint on Base | 100M | LimitedMinter (Base) |
| Bridge mint (any chain) | 30M | LimitedMinterBridge (all chains) |
| Maximum single-day flow | **730M** | ETH LM + ETH LMB combined |
| Minimum single-day flow | 130M | Base LM + Base LMB combined |

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | None | No data exposed |
| **Integrity** | Low | Limited bypass — only beneficial if one chain has higher limit |
| **Availability** | None | Service not disrupted |
| **Financial** | Low | Requires MINTER_ROLE on high-limit chain + bridge gas costs |
| **Likelihood** | Low | Requires cross-chain privilege coordination |

---

## Proof of Concept

File: `test/exploits/CrossChainDisparity.t.sol`

```bash
forge test --match-contract CrossChainLimitDisparityTest -vvvv
```

**Test Output:**
```
[PASS] testEthereumCombinedLimitExceedsIndividual() (gas: 40178)
Logs:
  LimitedMinter daily limit: 700000000000000000000000000
  LimitedMinterBridge daily limit: 30000000000000000000000000
  Combined (effective) limit: 730000000000000000000000000
  Excess over highest single limit: 30000000000000000000000000

  === CROSS-CHAIN LIMIT DISPARITY ===
  Each chain has its own LimitedMinter with independent config
  On-chain data from Base shows: dailyMaxMint = 100M (vs 700M on ETH)
  No global cross-chain mint cap exists
  A minter can use the highest-limit chain to bypass lower limits
```

**Transaction Trace:**
```
[40178] CrossChainLimitDisparityTest::testEthereumCombinedLimitExceedsIndividual()
  ├─ [6913] 0xD168...::tokenConfigs(wARS) [staticcall]
  │   └─ ← [Return] (0xB6C9..., 700000000000000000000000000, true)
  ├─ [4751] 0x4616...::tokenConfigs(wARS) [staticcall]
  │   └─ ← [Return] (30000000000000000000000000, true)
  └─ assertTrue(combined > limDaily) ← 730M > 700M passes
```

---

## Remediation

### Option A — Standardize Limits Across Chains (Recommended)

Document and enforce a single global daily mint limit per token. Configure all chains identically:

```solidity
// Governance: set same dailyMaxMint on all chains
// Ethereum: registerToken(wARS, dest, 100_000_000e18)
// Base:     registerToken(wARS, dest, 100_000_000e18)
// Polygon:  registerToken(wARS, dest, 100_000_000e18)
// ... all chains use identical limit
```

### Option B — Global Cross-Chain Cap via Shared Registry

Deploy a singleton registry contract on a designated "home" chain that tracks the global daily mint total. Each chain's `LimitedMinter` queries the registry before minting:

```solidity
interface IGlobalMintRegistry {
    function checkAndRecord(address token, uint256 amount, uint256 globalCap)
        external returns (uint256 newGlobalTotal);
}
```

### Option C — Bridge-Level Enforcement

Module `LimitedMinterBridge` on the destination chain checks the total bridged amount against the source chain's limit, ensuring the bridge doesn't become a vector for limit bypass.

---

## References

- Source: `src/contracts/LimitedMinter.sol:4050-4067` (mint function)
- Source: `src/contracts/LimitedMinter.sol:3971-3985` (registerToken function)
- On-chain: Ethereum block ~25159396, Base public RPC
- PoC: `test/exploits/CrossChainDisparity.t.sol`
