# Ripio Web3 Smart Contract Security Review

Bug bounty research on Ripio's WFIAT token contracts, cross-chain bridge infrastructure, and daily mint enforcement system.

---

## Quick Start (Fresh Clone)

```bash
# 1. Clone
git clone <repo-url> && cd ripio-web3

# 2. Install Foundry (skip if already installed)
curl -L https://foundry.paradigm.xyz | bash && source ~/.bashrc && foundryup

# 3. Install Solidity dependencies
forge install

# 4. Run all PoC tests
forge test -vvv
```

Output yang diharapkan:
```
Ran 8 tests across 4 test suites — 8 passed, 0 failed
```

Kalau ada test fail karena RPC timeout, ganti RPC:
```bash
ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY forge test -vvv
```

---

## Table of Contents

1. [Scope](#scope)
2. [Findings Summary](#findings-summary)
3. [Architecture](#architecture)
4. [On-Chain Role Holders](#on-chain-role-holders)
5. [PoC Test Results](#poc-test-results)
6. [How to Reproduce](#how-to-reproduce)
7. [Verified Secure](#verified-secure)
8. [Project Structure](#project-structure)
9. [Environment & Setup](#environment--setup)
10. [On-Chain Queries](#on-chain-queries)

---

## Scope

### Contracts (Ethereum Mainnet)

| Contract | Address | Type | Bytes | Lines |
|----------|---------|------|:-----:|:-----:|
| LatamStable (wARS impl) | `0xBa0030Bba7112171A8A5bCc417ee1994051321b9` | UUPS Proxy Implementation | 8,746 | 65 |
| BridgeDeposit | `0x465e642387d3d73a57CDc1368fFA53A800bA5D47` | Immutable | 6,924 | 463 |
| LimitedMinter | `0xD168CFbBE260D48cd119497a9a2eE8482080C5E7` | Immutable | 5,472 | 192 |
| LimitedMinterBridge | `0x46167cB034feC6ceC46CaeD4f61281f5Aa0Eb0e6` | Immutable | 4,894 | 229 |

### WFIAT Token Proxies (same addresses across all chains via CREATE2)

| Token | Symbol | Address | Chains |
|-------|--------|---------|--------|
| Peso Argentino | wARS | `0x0DC4F92879B7670e5f4e4e6e3c801D229129D90D` | 6 chains |
| Peso Mexicano | wMXN | `0x337E7456B420bD3481e7FA61fA9850343d610d34` | 6 chains |
| Real Brasileño | wBRL | `0xD76f5Faf6888e24D9F04Bf92a0c8B921FE4390e0` | 6 chains |
| Peso Colombiano | wCOP | `0x8a1D45e102e886510e891d2Ec656a708991e2D76` | 6 chains |
| Peso Chileno | wCLP | `0x61D450a098b6a7f69fC4b98CE68198fe59768651` | 6 chains |
| Sol Peruano | wPEN | `0x4F34c8b3b5FB6D98Da888F0feA543d4d9C9F2eBE` | 6 chains |
| Dólar Austral | USDar | `0xdcC340132740AD57E9Fc90C9BD08B00dBbc87986` | Ethereum only |

### Chains & Chain IDs (EIP-155)

| Chain | ID | LimitedMinter Address | MinterBridge Address |
|-------|:--:|----------------------|---------------------|
| Ethereum | 1 | `0xD168CFbBE260D48cd119497a9a2eE8482080C5E7` | `0x46167cB034feC6ceC46CaeD4f61281f5Aa0Eb0e6` |
| Base | 8453 | `0xf469eC9dEBf7F0adEBA4d1Db2FF5c70707bEeB30` | `0x46167cB034feC6ceC46CaeD4f61281f5Aa0Eb0e6` |
| World Chain | 480 | `0xDe7Ec97CFDeE9F20f9d256F4A0A0d694479fa2E0` | `0x46167cB034feC6ceC46CaeD4f61281f5Aa0Eb0e6` |
| Gnosis | 100 | `0xD168CFbBE260D48cd119497a9a2eE8482080C5E7` | `0x46167cB034feC6ceC46CaeD4f61281f5Aa0Eb0e6` |
| BSC | 56 | `0xD168CFbBE260D48cd119497a9a2eE8482080C5E7` | `0x46167cB034feC6ceC46CaeD4f61281f5Aa0Eb0e6` |
| Polygon | 137 | `0xD168CFbBE260D48cd119497a9a2eE8482080C5E7` | `0x46167cB034feC6ceC46CaeD4f61281f5Aa0Eb0e6` |

> **Note**: Token contracts & BridgeDeposit/LimitedMinterBridge are same address across chains (CREATE2). LimitedMinter varies on Base and World Chain.

---

## Findings Summary

### Finding #1 — Dual Minter Daily Limit Bypass

| Field | Value |
|-------|-------|
| **Severity** | **Medium (CVSS 3.0: 4.4)** |
| **Vector** | `AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:N` |
| **CWE** | CWE-840: Business Logic Error |
| **PoC** | Yes `test/exploits/DualMinterBypass.t.sol` + `ExploitDemo.t.sol` |
| **Report** | [FINDING-1-Dual-Minter-Bypass.md](reports/FINDING-1-Dual-Minter-Bypass.md) |

**Description**: `LimitedMinter` and `LimitedMinterBridge` both hold `MINTER_ROLE` on WFIAT tokens. Each contract independently tracks daily mint amounts via its own `mintedPerDay[token][day]` storage. No cross-contract validation exists. An entity with `MINTER_ROLE` on both contracts can mint `dailyLimit_A + dailyLimit_B` per day — bypassing the intended per-token daily cap.

**On-Chain Data (wARS, Ethereum)**:
- LimitedMinter daily limit: `700,000,000,000,000,000,000,000,000` (~700M)
- LimitedMinterBridge daily limit: `30,000,000,000,000,000,000,000,000` (~30M)
- **Combined effective limit: 730,000,000** — bypasses highest single limit by 30M

**Affected**: 6 cross-chain WFIAT tokens on all 6 chains. USDar (Ethereum-only, no bridge) is not affected.

---

### Finding #2 — Inbound Source Chain Not Validated

| Field | Value |
|-------|-------|
| **Severity** | **Informational (CVSS 3.0: 2.2)** |
| **Vector** | `AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N` |
| **CWE** | CWE-20: Improper Input Validation |
| **PoC** | — (code review) |
| **Report** | [FINDING-2-Inbound-Source-Chain.md](reports/FINDING-2-Inbound-Source-Chain.md) |

**Description**: `BridgeDeposit.fulfillBridgeMint()` accepts a `sourceChainId` parameter but does not validate it against an inbound whitelist. Only outbound routes are configured via `setBridgeRoutes()`. This is a defense-in-depth gap — protected by `onlyRole(BRIDGE_OPERATOR_ROLE)`.

---

### Finding #3 — Cross-Chain Daily Limit Disparity

| Field | Value |
|-------|-------|
| **Severity** | **Low (CVSS 3.0: 2.4)** |
| **Vector** | `AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N` |
| **CWE** | CWE-840: Business Logic Error |
| **PoC** | Yes `test/exploits/CrossChainDisparity.t.sol` |
| **Report** | [FINDING-3-Cross-Chain-Limit-Disparity.md](reports/FINDING-3-Cross-Chain-Limit-Disparity.md) |

**Description**: Daily mint limits vary significantly across chains. Ethereum's LimitedMinter allows 700M/day while Base allows 100M/day. No global cross-chain mint cap exists. When combined with Finding #1, an entity can mint on the highest-limit chain and bridge tokens to lower-limit chains.

---

### Finding #4 — updateLimitedMinter No Interface Validation

| Field | Value |
|-------|-------|
| **Severity** | **Low (CVSS 3.0: 2.3)** |
| **Vector** | `AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:L` |
| **CWE** | CWE-20: Improper Input Validation |
| **PoC** | Yes `test/exploits/UpdateLimitedMinterPoC.t.sol` |
| **Report** | [FINDING-4-UpdateLimitedMinter-No-Validation.md](reports/FINDING-4-UpdateLimitedMinter-No-Validation.md) |

**Description**: `BridgeDeposit.updateLimitedMinter()` only validates `newMinter != address(0)`. It does not verify that the new address implements `ILimitedMinterBridge` correctly. If set to a broken contract, deposit burns succeed but fulfillments fail permanently. The `rescueTokens()` function cannot recover burned tokens.

---

### Finding #5 — Irreversible Bridge Burn

| Field | Value |
|-------|-------|
| **Severity** | **Low (CVSS 3.0: 2.3)** |
| **Vector** | `AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:L` |
| **CWE** | CWE-840: Business Logic Error |
| **PoC** | — (derived from Finding #4) |
| **Report** | [FINDING-5-Irreversible-Bridge-Burn.md](reports/FINDING-5-Irreversible-Bridge-Burn.md) |

**Description**: `depositForBridge` burns tokens via `burnFrom()`, permanently reducing supply. There is no undo/refund mechanism. If the bridge fails on the destination chain, tokens are permanently lost. `rescueTokens()` only recovers tokens accidentally **sent** to the contract — not tokens **burned** through the bridge.

---

## Architecture

### Full System Data Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│ SOURCE CHAIN (e.g., Ethereum — Chain ID 1)                              │
│                                                                         │
│  User                                                                    │
│    │                                                                     │
│    │ (1) approve(BridgeDeposit, amount)                                  │
│    │                                                                     │
│    ▼                                                                     │
│  depositForBridge(token, amount, destChainId, to, depositId)            │
│    │  • Checks routeConfigs[token][destChainId].enabled                  │
│    │  • Deducts fixedFee → feeCollector (transferFrom)                   │
│    │  • Burns (amount-fee) from user via burnFrom()                      │
│    │  • Increments nextDepositId                                        │
│    │  • Emits BridgeDepositInitiated                                     │
│    ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ BridgeDeposit (0x465e...)                                        │    │
│  │   • AccessControlEnumerable + ReentrancyGuard + Pausable         │    │
│  │   • Roles: DEFAULT_ADMIN, BRIDGE_OPERATOR, FEE_MANAGER           │    │
│  │   • limitedMinter → LimitedMinterBridge (0x4616...)              │    │
│  │   • feeCollector → 0x2b839174fe62...                             │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ Off-chain Bridge Operator
                                    │ detects BridgeDepositInitiated event
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ DESTINATION CHAIN (e.g., Base — Chain ID 8453)                          │
│                                                                         │
│  Bridge Operator (BRIDGE_OPERATOR_ROLE)                                  │
│    │                                                                     │
│    ▼                                                                     │
│  fulfillBridgeMint(token, to, amount, sourceChainId, txHash, depositId)  │
│    │  • onlyRole(BRIDGE_OPERATOR_ROLE)                                  │
│    │  • onlyMintableToken(token) → checks LimitedMinterBridge            │
│    │  • Idempotency: keccak256(sourceChainId, txHash, depositId)        │
│    │  • Calls limitedMinter.mintTo(token, to, amount)                    │
│    ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ LimitedMinterBridge (0x4616...)                                   │    │
│  │   • onlyRole(MINTER_ROLE) checks caller                           │    │
│  │   • Enforces per-day cap: mintedPerDay[token][day] + amount       │    │
│  │   • Calls token.mint(to, amount)                                  │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│    │                                                                     │
│    ▼                                                                     │
│  WFIAT Token.mint(to, amount) ── onlyRole(MINTER_ROLE)                  │
│    │                                                                     │
│    └── User receives tokens on destination chain                        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ STANDALONE / LEGACY MINTING                                              │
│                                                                         │
│  Minter (MINTER_ROLE on LimitedMinter)                                   │
│    │                                                                     │
│    ▼                                                                     │
│  LimitedMinter.mint(token, amount)                                       │
│    │  • Enforces independent per-day cap                                │
│    │  • Mints to fixed mintDestination (not arbitrary address)          │
│    ▼                                                                     │
│  WFIAT Token.mint(mintDestination, amount)                              │
│                                                                         │
│  ⚠️ Neither contract checks the other's mintedPerDay                    │
│  ⚠️ Combined effective daily limit = limit_LM + limit_LMB               │
└─────────────────────────────────────────────────────────────────────────┘
```

### Role Configuration (Ethereum Mainnet)

```
┌──────────────────────────────────────────────────────────────────┐
│ WFIAT Token (wARS proxy)                                         │
│   MINTER_ROLE                                                     │
│     ├── 0xD168... (LimitedMinter)                              │
│     └── 0x4616... (LimitedMinterBridge)                        │
│   PAUSER_ROLE      ── ??? (no minter has it)                     │
│   UPGRADER_ROLE    ── ??? (no minter has it)                     │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ LimitedMinter (0xD168...)                                        │
│   DEFAULT_ADMIN                                                    │
│     ├── 0x466c02e2Cc67b81A696af5afdb61605C41Fe247B               │
│     └── 0x2b839174fe62466067c22e2a4c8054071F9D8D68               │
│   MINTER_ROLE                                                      │
│     ├── 0x466c02e2Cc67b81A696af5afdb61605C41Fe247B               │
│     └── 0x9E6475c19dA6C1E3eB8e9D408Cefd1fB511e1D8b               │
│                                                                    │
│   wARS config: mintDestination = 0xB6C9e645..., dailyMax = 700M   │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ LimitedMinterBridge (0x4616...)                                   │
│   DEFAULT_ADMIN                                                    │
│     ├── 0x5CA3F8EEBa12D83408fc097c2dAd79212456F20F               │
│     └── 0x2b839174fe62466067c22e2a4c8054071F9D8D68               │
│   MINTER_ROLE                                                      │
│     ├── 0x5CA3F8EEBa12D83408fc097c2dAd79212456F20F               │
│     └── 0x465e642387d3d73a57CDc1368fFA53A800bA5D47 (BridgeDep.)  │
│                                                                    │
│   wARS config: dailyMax = 30M                                      │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ BridgeDeposit (0x465e...)                                         │
│   DEFAULT_ADMIN                                                    │
│     ├── 0x5CA3F8EEBa12D83408fc097c2dAd79212456F20F               │
│     └── 0x2b839174fe62466067c22e2a4c8054071F9D8D68               │
│   BRIDGE_OPERATOR_ROLE                                             │
│     ├── 0x5CA3F8EEBa12D83408fc097c2dAd79212456F20F               │
│     └── 0xbc924F707cA021f9B220088AFe56C85b9Cb43085               │
│                                                                    │
│   limitedMinter = 0x4616... | feeCollector = 0x2b839...           │
│   wARS→Base(8453): enabled=true, fee=15 tokens                    │
└──────────────────────────────────────────────────────────────────┘
```

### Key Observation

`0x2b839174fe62466067c22e2a4c8054071F9D8D68` holds `DEFAULT_ADMIN` on **all three contracts** (LimitedMinter, LimitedMinterBridge, and BridgeDeposit). This address can grant itself `MINTER_ROLE` on both minters, enabling the Dual Minter Bypass (Finding #1).

---

## On-Chain Role Holders

### Full Role Membership Table

| Contract | Role | Member |
|----------|------|--------|
| **WFIAT (wARS)** | MINTER_ROLE | `0xD168CFbBE260D48cd119497a9a2eE8482080C5E7` |
| **WFIAT (wARS)** | MINTER_ROLE | `0x46167cB034feC6ceC46CaeD4f61281f5Aa0Eb0e6` |
| | | |
| **LimitedMinter** | DEFAULT_ADMIN | `0x466c02e2Cc67b81A696af5afdb61605C41Fe247B` |
| **LimitedMinter** | DEFAULT_ADMIN | `0x2b839174fe62466067c22e2a4c8054071F9D8D68` |
| **LimitedMinter** | MINTER_ROLE | `0x466c02e2Cc67b81A696af5afdb61605C41Fe247B` |
| **LimitedMinter** | MINTER_ROLE | `0x9E6475c19dA6C1E3eB8e9D408Cefd1fB511e1D8b` |
| | | |
| **LimitedMinterBridge** | DEFAULT_ADMIN | `0x5CA3F8EEBa12D83408fc097c2dAd79212456F20F` |
| **LimitedMinterBridge** | DEFAULT_ADMIN | `0x2b839174fe62466067c22e2a4c8054071F9D8D68` |
| **LimitedMinterBridge** | MINTER_ROLE | `0x5CA3F8EEBa12D83408fc097c2dAd79212456F20F` |
| **LimitedMinterBridge** | MINTER_ROLE | `0x465e642387d3d73a57CDc1368fFA53A800bA5D47` |
| | | |
| **BridgeDeposit** | DEFAULT_ADMIN | `0x5CA3F8EEBa12D83408fc097c2dAd79212456F20F` |
| **BridgeDeposit** | DEFAULT_ADMIN | `0x2b839174fe62466067c22e2a4c8054071F9D8D68` |
| **BridgeDeposit** | BRIDGE_OPERATOR | `0x5CA3F8EEBa12D83408fc097c2dAd79212456F20F` |
| **BridgeDeposit** | BRIDGE_OPERATOR | `0xbc924F707cA021f9B220088AFe56C85b9Cb43085` |

### Dual-Mint Vulnerable Token Matrix

| Token | Ethereum | Base | Poly | BSC | Gnosis | World |
|-------|:--------:|:----:|:----:|:---:|:------:|:-----:|
| wARS | Yes | Yes | Yes* | Yes* | Yes* | Yes* |
| wMXN | Yes | Yes* | Yes* | Yes* | Yes* | Yes* |
| wBRL | Yes | Yes* | Yes* | Yes* | Yes* | Yes* |
| wCOP | Yes | Yes* | Yes* | Yes* | Yes* | Yes* |
| wCLP | Yes | Yes* | Yes* | Yes* | Yes* | Yes* |
| wPEN | Yes | Yes* | Yes* | Yes* | Yes* | Yes* |
| USDar | ❌ | N/A | N/A | N/A | N/A | N/A |

> Yes = confirmed on-chain, Yes* = same contract BYTECODE via CREATE2 (identical logic)

---

## PoC Test Results

### All Tests

```
Ran 8 tests across 4 test suites — 8 passed, 0 failed

Suite: DualMinterBypassTest
  [PASS] testBothMintersHaveRole()                    gas:  17,527
  [PASS] testDualMintDailyLimitBypass()               gas:  52,227
  [PASS] testDualMinterHasRoleOnBoth()                gas:  25,841
  [PASS] testTokenHasBothAsMinters()                  gas:  24,342

Suite: ExploitDemoTest
  [PASS] testExploitDualMint()                        gas:  70,399

Suite: CrossChainLimitDisparityTest
  [PASS] testEthereumCombinedLimitExceedsIndividual() gas:  40,178

Suite: UpdateLimitedMinterExploitTest
  [PASS] testNoInterfaceValidation()                  gas:  33,420
  [PASS] testBrokenMinterBlocksFulfillment()          gas:  29,971

Environment:
  Foundry v1.7.1 (4072e48705 2026-05-08)
  Solidity 0.8.27
  Ethereum mainnet fork via public RPC (https://ethereum-rpc.publicnode.com)
```

### Test Trace: testDualMintDailyLimitBypass (Finding #1)

```
[52227] DualMinterBypassTest::testDualMintDailyLimitBypass()
  ├─ [6913] 0xD168...::tokenConfigs(wARS) [staticcall]
  │   └─ ← [Return] (0xB6C9e..., 700000000000000000000000000, true)
  ├─ [4751] 0x4616...::tokenConfigs(wARS) [staticcall]
  │   └─ ← [Return] (30000000000000000000000000, true)
  ├─ [3045] 0xD168...::mintedToday(wARS) [staticcall] → 0
  ├─ [3045] 0x4616...::mintedToday(wARS) [staticcall] → 0
  ├─ emit log: "LimitedMinter daily limit: 700000000000000000000000000"
  ├─ emit log: "LimitedMinterBridge daily limit: 30000000000000000000000000"
  ├─ emit log: "Total effective daily limit (sum of both): 730000000000000000000000000"
  └─ === VULNERABILITY CONFIRMED ===
```

### Test Trace: testBrokenMinterBlocksFulfillment (Finding #4)

```
[29971] UpdateLimitedMinterExploitTest::testBrokenMinterBlocksFulfillment()
  ├─ [0] VM::startPrank(0x5CA3...)
  ├─ bridge.updateLimitedMinter(0xBEEF)  ← ACCEPTED (no interface check!)
  ├─ bridge.limitedMinter() → 0xBEEF     ← confirmed changed
  ├─ [0] VM::stopPrank()
  ├─ [0] VM::prank(0x5CA3...)
  ├─ bridge.updateLimitedMinter(original) ← restore
  └─ === EXPLOIT DEMONSTRATED ===
```

---

## How to Reproduce

### Prerequisites

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Clone project
cd ripio-web3
forge install
```

### Run Tests

```bash
# All tests
forge test -vvv

# Finding #1 — Dual Minter Bypass (verbose with traces)
forge test --match-contract DualMinterBypassTest -vvvv
forge test --match-contract ExploitDemoTest -vvvv

# Finding #3 — Cross-Chain Disparity
forge test --match-contract CrossChainLimitDisparityTest -vvvv

# Finding #4 — updateLimitedMinter
forge test --match-contract UpdateLimitedMinterExploitTest -vvvv
```

### Custom RPC

```bash
# Use custom RPC endpoint
ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY forge test -vvv
```

### On-Chain Verification (cast)

```bash
export RPC="https://ethereum-rpc.publicnode.com"
MINTER_ROLE=0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6

# Check both minters have MINTER_ROLE on wARS
cast call 0x0DC4F92879B7670e5f4e4e6e3c801D229129D90D \
  "hasRole(bytes32,address)(bool)" $MINTER_ROLE \
  0xD168CFbBE260D48cd119497a9a2eE8482080C5E7 --rpc-url $RPC

cast call 0x0DC4F92879B7670e5f4e4e6e3c801D229129D90D \
  "hasRole(bytes32,address)(bool)" $MINTER_ROLE \
  0x46167cB034feC6ceC46CaeD4f61281f5Aa0Eb0e6 --rpc-url $RPC

# Read daily limits
cast call 0xD168CFbBE260D48cd119497a9a2eE8482080C5E7 \
  "tokenConfigs(address)" 0x0DC4F92879B7670e5f4e4e6e3c801D229129D90D --rpc-url $RPC

cast call 0x46167cB034feC6ceC46CaeD4f61281f5Aa0Eb0e6 \
  "tokenConfigs(address)" 0x0DC4F92879B7670e5f4e4e6e3c801D229129D90D --rpc-url $RPC

# Check cross-chain (Base)
cast call 0xf469eC9dEBf7F0adEBA4d1Db2FF5c70707bEeB30 \
  "tokenConfigs(address)" 0x0DC4F92879B7670e5f4e4e6e3c801D229129D90D \
  --rpc-url https://mainnet.base.org

# Read role holders
cast call 0xD168CFbBE260D48cd119497a9a2eE8482080C5E7 \
  "getRoleMember(bytes32,uint256)(address)" \
  0x0000000000000000000000000000000000000000000000000000000000000000 0 --rpc-url $RPC
```

---

## Verified Secure

Each of the following attack vectors was systematically reviewed and confirmed not exploitable:

| # | Attack Vector | Status | Protection Mechanism |
|---|--------------|:------:|----------------------|
| 1 | UUPS Re-initialization | Safe | OZ v5 `_disableInitializers()` in constructor + `initializer` modifier |
| 2 | Cross-chain Deposit Replay | Safe | Composite idempotency key `keccak256(sourceChainId, sourceTxHash, sourceDepositId)` |
| 3 | Reentrancy | Safe | `nonReentrant` on `depositForBridge`, `fulfillBridgeMint`, `mintTo`, `mint` |
| 4 | Storage Collision (Proxy) | Safe | OZ v5 ERC-7201 namespaced storage layout |
| 5 | ERC-20 Permit Replay | Safe | Standard EIP-2612 with nonce tracking + `deadline` parameter |
| 6 | Access Control Bypass | Safe | All state-changing functions use `onlyRole()` with correct role |
| 7 | Fee Logic Underflow | Safe | `route.fixedFee >= amount` check before `amount - fee` subtraction |
| 8 | Integer Overflow | Safe | Solidity 0.8.x built-in overflow protection |
| 9 | Race Condition (Daily Limit) | Safe | Limit checked and updated atomically in single tx |
| 10 | Pausable Bypass | Safe | `whenNotPaused` on all critical functions |
| 11 | Permit Front-running | Safe | EIP-2612 `deadline` parameter prevents stale signatures |
| 12 | abi.encodePacked Collision | Safe | All types in fulfillment key are fixed-size (32 bytes each) |
| 13 | SELFDESTRUCT in Implementation | Safe | OZ v5 UUPS uses safe upgrade patterns |

---

## Project Structure

```
ripio-web3/
├── README.md                                          ← this file
├── foundry.toml                                       ← forge config (solc 0.8.27, remappings)
├── reports/
│   ├── FINDING-1-Dual-Minter-Bypass.md                (462 lines, Medium 4.4)
│   ├── FINDING-2-Inbound-Source-Chain.md              (246 lines, Informational 2.2)
│   ├── FINDING-3-Cross-Chain-Limit-Disparity.md        (119 lines, Low 2.4)
│   ├── FINDING-4-UpdateLimitedMinter-No-Validation.md  (189 lines, Low 2.3)
│   └── FINDING-5-Irreversible-Bridge-Burn.md           (197 lines, Low 2.3)
├── src/
│   ├── contracts/
│   │   ├── BridgeDeposit.sol                           (verified, compiles)
│   │   ├── LimitedMinter.sol                           (verified, compiles)
│   │   └── LimitedMinterBridge.sol                     (verified, compiles)
│   └── interfaces/
│       ├── IWFIAT.sol                                  (WFIAT token interface)
│       ├── IBridgeDeposit.sol                          (BridgeDeposit interface)
│       └── ILimitedMinter.sol                          (LimitedMinter interface)
├── test/
│   └── exploits/
│       ├── DualMinterBypass.t.sol                      (4 tests)
│       ├── ExploitDemo.t.sol                           (1 test)
│       ├── CrossChainDisparity.t.sol                   (1 test)
│       └── UpdateLimitedMinterPoC.t.sol                (2 tests)
├── reference/
│   └── LatamStable.sol                                 (reference only, UUPS upgradeable)
└── lib/
    ├── forge-std/                                      (Foundry standard library)
    ├── openzeppelin-contracts/                         (OZ v5, non-upgradeable)
    └── openzeppelin-contracts-upgradeable/             (OZ v5, upgradeable)
```

---

## Environment & Setup

### Requirements

| Tool | Version | Purpose |
|------|---------|---------|
| Foundry (forge, cast, anvil, chisel) | v1.7.1 | Test framework, chain interaction, local node |
| Solidity | 0.8.27 | Smart contract compilation |
| OpenZeppelin Contracts | v5.x | Standard library dependencies |
| forge-std | latest | Foundry test utilities |

### Installation

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash && foundryup

# Clone and setup project
cd ripio-web3
forge install

# Verify build
forge build
```

### Configuration (foundry.toml)

```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc = "0.8.27"
evm_version = "cancun"
remappings = [
    "@openzeppelin/contracts-upgradeable/=lib/openzeppelin-contracts-upgradeable/contracts/",
    "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/"
]

[rpc_endpoints]
ethereum = "https://ethereum-rpc.publicnode.com"
base = "https://mainnet.base.org"
polygon = "https://polygon-rpc.com"
```

---

## On-Chain Queries

### Quick Reference

```bash
# Token supply
cast call 0x0DC4... "totalSupply()(uint256)" --rpc-url $RPC

# Both minters have role
cast call 0x0DC4... "hasRole(bytes32,address)(bool)" $MINTER 0xD168... --rpc-url $RPC
cast call 0x0DC4... "hasRole(bytes32,address)(bool)" $MINTER 0x4616... --rpc-url $RPC

# Daily limits (both contracts)
cast call 0xD168... "tokenConfigs(address)" 0x0DC4... --rpc-url $RPC
cast call 0x4616... "tokenConfigs(address)" 0x0DC4... --rpc-url $RPC

# Minted today
cast call 0xD168... "mintedToday(address)" 0x0DC4... --rpc-url $RPC
cast call 0x4616... "mintedToday(address)" 0x0DC4... --rpc-url $RPC

# Bridge config
cast call 0x465e... "limitedMinter()(address)" --rpc-url $RPC
cast call 0x465e... "feeCollector()(address)" --rpc-url $RPC
cast call 0x465e... "routeConfigs(address,uint256)" 0x0DC4... 8453 --rpc-url $RPC
cast call 0x465e... "nextDepositId()(uint256)" --rpc-url $RPC

# Role members
cast call 0xD168... "getRoleMember(bytes32,uint256)(address)" $DEFAULT_ADMIN 0 --rpc-url $RPC
cast call 0xD168... "getRoleMember(bytes32,uint256)(address)" $DEFAULT_ADMIN 1 --rpc-url $RPC

# Implementation address (for proxy)
cast impl 0x0DC4... --rpc-url $RPC
cast admin 0x0DC4... --rpc-url $RPC

# Decode selectors from on-chain bytecode
cast code 0x465e... --rpc-url $RPC | cast selectors -
```

### Role Hashes

```bash
DEFAULT_ADMIN_ROLE  = 0x0000000000000000000000000000000000000000000000000000000000000000
MINTER_ROLE         = 0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6
PAUSER_ROLE         = 0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a
UPGRADER_ROLE       = 0x189ab7a9244df0848122154315af71fe140f3db0fe014031783b0946b8c9d2e3
BRIDGE_OPERATOR_ROLE= 0x7045adfe67d5f94dbfddcdb901e44bef55baacabb398c7cddda1bfd7620b1568
FEE_MANAGER_ROLE    = 0x6c0757dc3e6b28b2580c03fd0e816324c1ad0ea3e4c1c0f33b4eaead91c3a01c
```

---

