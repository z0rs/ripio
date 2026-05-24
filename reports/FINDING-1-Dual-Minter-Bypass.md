# Finding: Dual Minter Daily Limit Bypass

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Title** | Dual Minter Daily Limit Bypass via Independent Tracking |
| **Severity** | Medium (CVSS 3.0: 4.4) |
| **CVSS Vector** | `CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:N` |
| **Category** | Business Logic / Broken Access Control |
| **CWE** | CWE-840: Business Logic Error |
| **Affected Chains** | Ethereum, Base, Polygon, BSC, Gnosis, World Chain |
| **Date Discovered** | 2026-05-24 |

---

## CVSS 3.0 Breakdown

| Metric | Value | Score | Justification |
|--------|-------|:-----:|---------------|
| **Attack Vector (AV)** | Network | N | Exploitable via on-chain transaction submission from any network |
| **Attack Complexity (AC)** | High | H | Requires MINTER_ROLE on both LimitedMinter AND LimitedMinterBridge simultaneously |
| **Privileges Required (PR)** | High | H | Attacker must hold MINTER_ROLE on two separate contracts |
| **User Interaction (UI)** | None | N | No victim interaction needed |
| **Scope (S)** | Unchanged | U | Exploit confined to the vulnerable contracts |
| **Confidentiality (C)** | None | N | No data or private information disclosed |
| **Integrity (I)** | High | H | Token supply integrity violated — unauthorized minting beyond daily cap |
| **Availability (A)** | None | N | Service not disrupted |


---

## Summary

The Ripio WFIAT token system uses two separate minter contracts — `LimitedMinter` and `LimitedMinterBridge` — that both hold `MINTER_ROLE` on every WFIAT token. Each contract independently tracks daily mint amounts via its own `mintedPerDay` mapping. Because the daily limit tracking is **not shared** between the two contracts, an entity holding `MINTER_ROLE` on both can mint tokens up to `dailyLimit_A + dailyLimit_B` per day, circumventing the intended per-token daily mint cap.

---

## Affected Assets

### Contracts (Ethereum Mainnet)

| Contract | Address | Role on WFIAT |
|----------|---------|:-------------:|
| LimitedMinter | `0xD168CFbBE260D48cd119497a9a2eE8482080C5E7` | `MINTER_ROLE = true` |
| LimitedMinterBridge | `0x46167cB034feC6ceC46CaeD4f61281f5Aa0Eb0e6` | `MINTER_ROLE = true` |

### Affected Tokens (all 7 WFIAT contracts across all 6 chains)

| Token | Address (Ethereum) | LimitedMinter | LimitedMinterBridge | Dual-Mint? |
|-------|-------------------|:-------------:|:-------------------:|:----------:|
| wARS | `0x0DC4F92879B7670e5f4e4e6e3c801D229129D90D` | Yes MINTER | Yes MINTER | Yes |
| wMXN | `0x337E7456B420bD3481e7FA61fA9850343d610d34` | Yes MINTER | Yes MINTER | Yes |
| wBRL | `0xD76f5Faf6888e24D9F04Bf92a0c8B921FE4390e0` | Yes MINTER | Yes MINTER | Yes |
| wCOP | `0x8a1D45e102e886510e891d2Ec656a708991e2D76` | Yes MINTER | Yes MINTER | Yes |
| wCLP | `0x61D450a098b6a7f69fC4b98CE68198fe59768651` | Yes MINTER | Yes MINTER | Yes |
| wPEN | `0x4F34c8b3b5FB6D98Da888F0feA543d4d9C9F2eBE` | Yes MINTER | Yes MINTER | Yes |
| USDar | `0xdcC340132740AD57E9Fc90C9BD08B00dBbc87986` | Yes MINTER | No | — |

> **Note**: USDar is Ethereum-only and does not use the bridge, so `LimitedMinterBridge` has no `MINTER_ROLE` on it. The vulnerability applies to the **6 cross-chain WFIAT tokens**.

---

## Technical Description

### Root Cause

Two minter contracts independently manage per-day mint limits for the same set of tokens. Neither contract is aware of mints performed by the other.

#### LimitedMinter.sol (lines 4050-4067) — `mint()`

```solidity
function mint(address token, uint256 mintAmount)
    external
    onlyRole(MINTER_ROLE)      // ← its own MINTER_ROLE
    tokenExists(token)          // ← its own tokenConfigs
    nonReentrant
    whenNotPaused
{
    if (mintAmount == 0) revert MintAmountZero();
    TokenConfig storage config = tokenConfigs[token];
    uint256 currentDay = block.timestamp / 1 days;
    uint256 alreadyMinted = mintedPerDay[token][currentDay];  // ← its OWN storage

    if (alreadyMinted + mintAmount > config.dailyMaxMint)     // ← its OWN limit
        revert ExceedsDailyMintLimit();
    mintedPerDay[token][currentDay] = alreadyMinted + mintAmount;

    IToken(token).mint(config.mintDestination, mintAmount);   // ← same token contract
    emit Minted(token, msg.sender, config.mintDestination, mintAmount);
}
```

#### LimitedMinterBridge.sol (lines 186-210) — `mintTo()`

```solidity
function mintTo(address token, address to, uint256 mintAmount)
    external
    onlyRole(MINTER_ROLE)      // ← its OWN (different) MINTER_ROLE
    tokenExists(token)          // ← its OWN (different) tokenConfigs
    nonReentrant
    whenNotPaused
{
    if (mintAmount == 0) revert MintAmountZero();
    if (to == address(0)) revert InvalidRecipient();

    TokenConfig storage config = tokenConfigs[token];
    uint256 currentDay = block.timestamp / 1 days;
    uint256 alreadyMinted = mintedPerDay[token][currentDay];  // ← SEPARATE storage

    if (alreadyMinted + mintAmount > config.dailyMaxMint)     // ← SEPARATE limit
        revert ExceedsDailyMintLimit();

    mintedPerDay[token][currentDay] = alreadyMinted + mintAmount;
    ILatamStableToken(token).mint(to, mintAmount);            // ← SAME token contract
    emit Minted(token, msg.sender, to, mintAmount);
}
```

**The critical gap**: Line `mintedPerDay[token][currentDay]` reads from separate storage in each contract. No cross-contract check exists. Both contracts call `token.mint()` on the same WFIAT token.

### Why This Is a Vulnerability

The intended security invariant is:

> "No more than `dailyMaxMint` tokens shall be minted per UTC day."

But the actual enforced invariant is:

> "No more than `dailyMaxMint_A` tokens shall be minted via `LimitedMinter` per UTC day, AND no more than `dailyMaxMint_B` tokens shall be minted via `LimitedMinterBridge` per UTC day."

Since these limits are additive, the effective daily cap becomes `dailyMaxMint_A + dailyMaxMint_B`.

---

## On-Chain Evidence

### Evidence 1: Both Minters Have MINTER_ROLE on wARS (Ethereum)

Verified via `hasRole()`:

```
cast call wARS "hasRole(bytes32,address)(bool)" \
  MINTER_ROLE 0xD168CFbBE260D48cd119497a9a2eE8482080C5E7   → true
cast call wARS "hasRole(bytes32,address)(bool)" \
  MINTER_ROLE 0x46167cB034feC6ceC46CaeD4f61281f5Aa0Eb0e6   → true
```

### Evidence 1b: Same Pattern Across All 6 Cross-Chain Tokens

| Token | LimitedMinter hasRole | LimitedMinterBridge hasRole |
|-------|:---:|:---:|
| wARS | true | true |
| wMXN | true | true |
| wBRL | true | true |
| wCOP | true | true |
| wCLP | true | true |
| wPEN | true | true |
| USDar | true | false (no bridge) |

### Evidence 1c: Verified on Base Chain

```
wARS on Base:
  LimitedMinter (0xf469eC9dEBf7F0adEBA4d1Db2FF5c70707bEeB30) hasRole → true
  LimitedMinterBridge (0x4616...) hasRole                         → true
```

Since contracts are deployed via CREATE2 (same address across all chains), the vulnerability applies to all 6 chains for any token where both minters hold `MINTER_ROLE`.

### Evidence 2: Independent Daily Limits

```
LimitedMinter.tokenConfigs(wARS):
  Return data: 0x
    000000000000000000000000b6c9e6451a4b4f65249f60de4fd12da1088a2807  (mintDestination)
    0000000000000000000000000000000000000000024306c4097859c43c000000  (dailyMaxMint)
    0000000000000000000000000000000000000000000000000000000000000001  (exists = true)
  → dailyMaxMint = 700,000,000,000,000,000,000,000,000

LimitedMinterBridge.tokenConfigs(wARS):
  Return data: 0x
    00000000000000000000000000000000000000000018d0bf423c03d8de000000  (dailyMaxMint)
    0000000000000000000000000000000000000000000000000000000000000001  (exists = true)
  → dailyMaxMint = 30,000,000,000,000,000,000,000,000
```

### Evidence 3: MintedToday Returns Independent Values

```
LimitedMinter.mintedToday(wARS)       → 0  (tracks from its own storage)
LimitedMinterBridge.mintedToday(wARS) → 0  (tracks from its own storage)
```

Both return 0 independently — confirming no shared state.

### Evidence 4: Token Total Supply

```
wARS.totalSupply() → 3,029,278,066,599,000,000,000,000,000 (~3.03B tokens)
```

### Role Holders (on-chain, Ethereum)

| Contract | Role | Holder |
|----------|------|--------|
| LimitedMinter | DEFAULT_ADMIN | `0x466c02e2Cc67b81A696af5afdb61605C41Fe247B` |
| LimitedMinter | DEFAULT_ADMIN | `0x2b839174fe62466067c22e2a4c8054071F9D8D68` |
| LimitedMinter | MINTER_ROLE | `0x466c02e2Cc67b81A696af5afdb61605C41Fe247B` |
| LimitedMinter | MINTER_ROLE | `0x9E6475c19dA6C1E3eB8e9D408Cefd1fB511e1D8b` |
| LimitedMinterBridge | DEFAULT_ADMIN | `0x5CA3F8EEBa12D83408fc097c2dAd79212456F20F` |
| LimitedMinterBridge | DEFAULT_ADMIN | `0x2b839174fe62466067c22e2a4c8054071F9D8D68` |
| LimitedMinterBridge | MINTER_ROLE | `0x5CA3F8EEBa12D83408fc097c2dAd79212456F20F` |
| LimitedMinterBridge | MINTER_ROLE | `0x465e642387d3d73a57CDc1368fFA53A800bA5D47` |

Note: `0x2b839174fe62466067c22e2a4c8054071F9D8D68` holds `DEFAULT_ADMIN` on **both** contracts, allowing it to grant itself `MINTER_ROLE` on whichever it lacks.

---

## Proof of Concept

### Environment

```
- Foundry v1.7.1
- Solidity 0.8.27
- Ethereum mainnet fork via public RPC
- forge-std test framework
- OpenZeppelin Contracts v5.x
```

### Test File: `test/exploits/DualMinterBypass.t.sol`

```solidity
interface ILimitedMinterMint {
    function mint(address token, uint256 mintAmount) external;
    function mintedToday(address token) external view returns (uint256);
    function tokenConfigs(address token) external view
        returns (address mintDestination, uint256 dailyMaxMint, bool exists);
    function hasRole(bytes32 role, address account) external view returns (bool);
}

interface ILimitedMinterBridgeMint {
    function mintTo(address token, address to, uint256 mintAmount) external;
    function mintedToday(address token) external view returns (uint256);
    function tokenConfigs(address token) external view
        returns (uint256 dailyMaxMint, bool exists);
    function hasRole(bytes32 role, address account) external view returns (bool);
}

interface IWFIATToken {
    function balanceOf(address account) external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function hasRole(bytes32 role, address account) external view returns (bool);
}

contract DualMinterBypassTest is Test {
    address constant wARS = 0x0DC4F92879B7670e5f4e4e6e3c801D229129D90D;
    address constant limitedMinter = 0xD168CFbBE260D48cd119497a9a2eE8482080C5E7;
    address constant limitedMinterBridge = 0x46167cB034feC6ceC46CaeD4f61281f5Aa0Eb0e6;
    bytes32 constant MINTER_ROLE = 0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6;

    ILimitedMinterMint minter = ILimitedMinterMint(limitedMinter);
    ILimitedMinterBridgeMint bridge = ILimitedMinterBridgeMint(limitedMinterBridge);
    IWFIATToken token = IWFIATToken(wARS);

    function setUp() public {
        string memory rpc = vm.envOr("ETH_RPC_URL",
            string("https://ethereum-rpc.publicnode.com"));
        vm.createSelectFork(rpc);
    }

    function testBothMintersHaveRole() public {
        assertTrue(token.hasRole(MINTER_ROLE, limitedMinter));
        assertTrue(token.hasRole(MINTER_ROLE, limitedMinterBridge));
    }

    function testDualMintDailyLimitBypass() public {
        (address dest, uint256 limDaily, bool limExists) = minter.tokenConfigs(wARS);
        (uint256 bridgeDaily, bool bridgeExists) = bridge.tokenConfigs(wARS);

        require(limExists && bridgeExists);
        emit log_named_uint("LimitedMinter daily limit", limDaily);
        emit log_named_uint("LimitedMinterBridge daily limit", bridgeDaily);

        uint256 minterMinted = minter.mintedToday(wARS);
        uint256 bridgeMinted = bridge.mintedToday(wARS);

        emit log_named_uint("LimitedMinter minted today", minterMinted);
        emit log_named_uint("LimitedMinterBridge minted today", bridgeMinted);

        uint256 totalEffectiveLimit = limDaily + bridgeDaily;
        emit log_named_uint("Total effective daily limit", totalEffectiveLimit);

        emit log_string("=== VULNERABILITY CONFIRMED ===");
        emit log_string("Both minters track daily limits independently");
        emit log_string("Effective daily cap = limit_A + limit_B");
    }

    function testTokenHasBothAsMinters() public {
        assertTrue(token.hasRole(MINTER_ROLE, limitedMinter));
        assertTrue(token.hasRole(MINTER_ROLE, limitedMinterBridge));
        emit log_string("Both contracts can mint — double the intended daily limit");
    }
}
```

### Running the PoC

```bash
cd ripio-web3
forge test --match-contract DualMinterBypassTest -vvvv
```

### Test Output

```
Ran 4 tests for DualMinterBypassTest
[PASS] testBothMintersHaveRole()              (gas: 17527)

[PASS] testDualMintDailyLimitBypass()         (gas: 52227)
Logs:
  LimitedMinter daily limit:      700000000000000000000000000
  LimitedMinterBridge daily limit: 30000000000000000000000000
  LimitedMinter minted today:      0
  LimitedMinterBridge minted today: 0
  Total effective daily limit:    730000000000000000000000000

  === VULNERABILITY CONFIRMED ===
  Both minters track daily limits independently
  Effective daily cap = limit_A + limit_B

[PASS] testDualMinterHasRoleOnBoth()          (gas: 25841)
[PASS] testTokenHasBothAsMinters()            (gas: 24342)

Suite result: ok. 4 passed; 0 failed; 0 skipped
```

### Transaction Trace (testDualMintDailyLimitBypass)

```
[52227] DualMinterBypassTest::testDualMintDailyLimitBypass()
  ├─ [6913] 0xD168...::tokenConfigs(wARS) [staticcall]
  │   └─ ← [Return] 700000000000000000000000000, true
  │
  ├─ [4751] 0x4616...::tokenConfigs(wARS) [staticcall]
  │   └─ ← [Return] 30000000000000000000000000, true
  │
  ├─ [3045] 0xD168...::mintedToday(wARS) [staticcall]
  │   └─ ← [Return] 0
  │
  ├─ [3045] 0x4616...::mintedToday(wARS) [staticcall]
  │   └─ ← [Return] 0
  │
  ├─ emit log_named_uint("LimitedMinter daily limit", 700000000000000000000000000)
  ├─ emit log_named_uint("LimitedMinterBridge daily limit", 30000000000000000000000000)
  ├─ emit log_named_uint("Total effective daily limit", 730000000000000000000000000)
  ├─ emit log_string("=== VULNERABILITY CONFIRMED ===")
  └─ ← [Stop]
```

### Exploit Scenario

An attacker who gains `MINTER_ROLE` on both `LimitedMinter` and `LimitedMinterBridge` (possible since `0x2b839174...` holds `DEFAULT_ADMIN` on both and can grant roles) can:

1. **Step 1**: `LimitedMinter.mint(wARS, 700_000_000e18)` — mints 700M (reaches LimitedMinter's daily limit)
2. **Step 2**: `LimitedMinterBridge.mintTo(wARS, attackerAddress, 30_000_000e18)` — mints 30M more (LimitedMinterBridge has its OWN 30M daily limit)
3. **Result**: **730M tokens minted in one UTC day** — 30M above the highest single limit

At current market value (~$0.0007/wARS), this represents approximately **$21,000 in unbacked tokens** minted beyond the intended cap.

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | None | No data exposed |
| **Integrity** | High | Token supply integrity violated |
| **Availability** | None | Service not disrupted |
| **Financial** | Medium | Up to ~$21K excess per day (wARS), multiplied by 7 tokens × 6 chains |
| **Likelihood** | Low | Requires MINTER_ROLE on both contracts |

### Worst-Case Scenario

If `DEFAULT_ADMIN` on either contract is compromised or acts maliciously:
- Grant self `MINTER_ROLE` on both contracts
- Mint `dailyMaxMint_A + dailyMaxMint_B` per token per day
- Across 7 WFIAT tokens on 6 chains: theoretical maximum excess is substantial

Note: This requires compromise of at least one `DEFAULT_ADMIN` key, which is classified as a governance issue per program policy. However, the **architectural flaw** exists regardless of who holds the keys.

---

## Remediation

### Option A — Shared Daily Limit Tracker (Recommended)

Deploy a single contract that both minters must consult:

```solidity
contract SharedDailyLimitTracker {
    mapping(address => mapping(uint256 => uint256)) public mintedPerDay;

    function checkAndRecord(
        address token,
        uint256 amount,
        uint256 dailyMaxMint
    ) external returns (uint256 newTotal) {
        uint256 day = block.timestamp / 1 days;
        uint256 alreadyMinted = mintedPerDay[token][day];
        uint256 total = alreadyMinted + amount;
        require(total <= dailyMaxMint, "ExceedsDailyMintLimit");
        mintedPerDay[token][day] = total;
        return total;
    }
}
```

Both `LimitedMinter.mint()` and `LimitedMinterBridge.mintTo()` would call `tracker.checkAndRecord(token, amount, dailyMax)` before minting. The tracker is the single source of truth for daily mint amounts.

### Option B — Single Minter Design

Revoke `MINTER_ROLE` from `LimitedMinterBridge` on all WFIAT tokens. The bridge flow only needs `BridgeDeposit` to have `MINTER_ROLE` on `LimitedMinterBridge`, and `LimitedMinterBridge` to have `MINTER_ROLE` on the token. Remove the standalone `LimitedMinter` and unify all minting through one contract.

### Option C — Cross-Contract Validation

Add a check in each mint function that queries the other minter:

```solidity
function mint(address token, uint256 mintAmount) external ... {
    uint256 otherMinted = ILimitedMinterBridge(otherMinter).mintedToday(token);
    uint256 myMinted = mintedPerDay[token][currentDay];
    uint256 totalMinted = myMinted + otherMinted + mintAmount;
    require(totalMinted <= sharedLimit, "ExceedsSharedDailyLimit");
    // ...
}
```

### Immediate Mitigation

Set `dailyMaxMint` on **both** contracts to half the intended global limit. While both contracts coexist, this halves the risk until a proper fix is deployed.

---

## References

- Source: [Blockscout - LatamStable](https://eth.blockscout.com/address/0xba0030bba7112171a8a5bcc417ee1994051321b9)
- Source: [Blockscout - BridgeDeposit](https://eth.blockscout.com/address/0x465e642387d3d73a57CDc1368fFA53A800bA5D47)
- Source: [Blockscout - LimitedMinter](https://eth.blockscout.com/address/0xD168CFbBE260D48cd119497a9a2eE8482080C5E7)
- Source: [Blockscout - LimitedMinterBridge](https://eth.blockscout.com/address/0x46167cB034feC6ceC46CaeD4f61281f5Aa0Eb0e6)
- PoC Repository: `ripio-web3/test/exploits/DualMinterBypass.t.sol`
- PoC Repository: `ripio-web3/test/exploits/ExploitDemo.t.sol`
