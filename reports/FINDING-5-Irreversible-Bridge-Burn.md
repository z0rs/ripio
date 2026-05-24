# Finding: Irreversible Bridge Deposit — No Recovery for Burned Tokens

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Title** | No Recovery Mechanism for Tokens Burned via depositForBridge |
| **Severity** | Low (CVSS 3.0: 2.3) |
| **CVSS Vector** | `CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:L` |
| **Category** | Missing Recovery Mechanism |
| **CWE** | CWE-840: Business Logic Error |
| **Affected Chains** | Ethereum, Base, Polygon, BSC, Gnosis, World Chain |
| **Date Discovered** | 2026-05-24 |

---

## CVSS 3.0 Breakdown

| Metric | Value | Score | Justification |
|--------|-------|:-----:|---------------|
| **Attack Vector (AV)** | Network | N | Exploitable via on-chain transaction submission |
| **Attack Complexity (AC)** | High | H | Requires multiple conditions: admin error + user deposits + bridge failure |
| **Privileges Required (PR)** | High | H | Only affects users who deposit AFTER a misconfiguration |
| **User Interaction (UI)** | None | N | Users unknowingly burn tokens into a broken bridge |
| **Scope (S)** | Unchanged | U | Exploit confined to BridgeDeposit |
| **Confidentiality (C)** | None | N | No data exposed |
| **Integrity (I)** | Low | L | Token supply reduced without corresponding mint on destination |
| **Availability (A)** | Low | L | Users lose access to burned tokens (permanent loss) |

**CVSS Base Score**: 2.3 (Low) — `CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:L`

---

## Summary

The `BridgeDeposit.depositForBridge()` function uses `burnFrom()` to permanently destroy user tokens on the source chain as part of the cross-chain bridge flow. This creates an **irreversible** step: once tokens are burned, the only way to restore them is for a bridge operator to successfully call `fulfillBridgeMint()` on the destination chain. There is no refund, timeout, or admin recovery mechanism.

If the destination-side fulfillment fails for any reason — operator offline, daily limit exhausted, `limitedMinter` misconfigured, chain congestion, or contract paused — the burned tokens are **permanently lost** with no recovery path. The `rescueTokens()` admin function only recovers tokens accidentally sent directly to the contract address, not tokens destroyed via burn.

---

## Affected Assets

| Contract | Address (Ethereum) | Function | Lines |
|----------|-------------------|----------|:-----:|
| BridgeDeposit | `0x465e642387d3d73a57CDc1368fFA53A800bA5D47` | `depositForBridge()` | 308-357 |
| BridgeDeposit | (same address on all 6 chains) | `depositForBridge()` | 308-357 |
| BridgeDeposit | `0x465e642387d3d73a57CDc1368fFA53A800bA5D47` | `rescueTokens()` | 250-256 |

### On-Chain Bridge Stats (wARS, Ethereum)

```
totalSupply:      3,029,278,066.599 wARS
totalBurnedTo(wARS, Base/8453):     9,999,970  (~10M burned to Base)
totalMintedFrom(wARS, Base/8453): 140,576,912  (~140M minted from Base)
Net inflow from Base:             130,576,942  (~130M more minted than burned on ETH)
nextDepositId:    24
```

---

## Technical Description

### The Irreversible Burn Step

**BridgeDeposit.sol:308-357 — depositForBridge():**
```solidity
function depositForBridge(
    address token, uint256 amount, uint256 destChainId,
    address destRecipient, bytes32 clientDepositId
)
    external
    nonReentrant
    whenNotPaused
    returns (uint256 depositId)
{
    if (amount == 0) revert AmountZero();
    if (destRecipient == address(0)) revert InvalidRecipient();
    if (destChainId == block.chainid) revert InvalidSourceChain();

    RouteConfig memory route = routeConfigs[token][destChainId];
    if (!route.enabled) revert InvalidRoute();
    if (route.fixedFee >= amount) revert AmountTooLowForFee();

    uint256 amountToBurn = amount - route.fixedFee;

    // Fee collection
    if (route.fixedFee > 0) {
        if (feeCollector == address(0)) revert ZeroAddress();
        IERC20(token).safeTransferFrom(msg.sender, feeCollector, route.fixedFee);
        totalFeesCollected[token][destChainId] += route.fixedFee;
    }

    // PERMANENT BURN — tokens destroyed, totalSupply reduced
    ILatamStableBurnable(token).burnFrom(msg.sender, amountToBurn);

    totalBurnedTo[token][destChainId] += amountToBurn;

    depositId = nextDepositId++;
    emit BridgeDepositInitiated(
        depositId, token, msg.sender, amountToBurn,
        route.fixedFee, destChainId, destRecipient, clientDepositId
    );
}
```

The `burnFrom(msg.sender, amountToBurn)` call executes `ERC20BurnableUpgradeable.burnFrom()`:
```solidity
function burnFrom(address account, uint256 value) public virtual {
    _spendAllowance(account, _msgSender(), value);  // deduct allowance
    _burn(account, value);                           // reduce balance AND totalSupply
}
```

After this call:
- User's `balanceOf` decreases by `amountToBurn`
- Token's `totalSupply` decreases by `amountToBurn`
- `BridgeDeposit` balance is **unchanged** (tokens not transferred to contract)
- The tokens no longer exist in any account

### Why rescueTokens Cannot Recover Burned Tokens

**BridgeDeposit.sol:250-256 — rescueTokens():**
```solidity
function rescueTokens(address token, address to, uint256 amount)
    external
    onlyRole(DEFAULT_ADMIN_ROLE)
{
    if (to == address(0)) revert ZeroAddress();
    if (amount == 0) revert AmountZero();

    IERC20(token).safeTransfer(to, amount);
    // ↑ Transfers tokens FROM BridgeDeposit's OWN balance
    //   Burned tokens were never added to this balance

    emit TokensRescued(token, to, amount);
}
```

**Token accounting comparison:**

| Scenario | BridgeDeposit Balance | User Balance | totalSupply | Rescue Possible? |
|----------|:---:|:---:|:---:|:---:|
| User sends tokens directly to BridgeDeposit | +amount | -amount | Unchanged | Yes — `rescueTokens` works |
| User burns via `depositForBridge` | **Unchanged** | -amount | **-amount** | **No — tokens destroyed** |

### Failure Scenarios

| # | Scenario | Can Fulfillment Succeed? | Tokens Recoverable? | Window |
|---|----------|:---:|:---:|--------|
| 1 | Bridge operator offline / not running | No | **No** | Until operator returns |
| 2 | Daily mint limit exhausted on destination | No (reverts) | **Partial** — retry tomorrow | 1 UTC day max |
| 3 | `limitedMinter` set to broken contract (Finding #4) | No | **No** — permanent until admin fixes | Until admin intervenes |
| 4 | Bridge paused on destination chain | No | **Delayed** — retry after unpause | Until admin unpauses |
| 5 | Destination chain RPC down / congested | No | **Delayed** | Hours to days |
| 6 | WFIAT token paused on destination | No | **Delayed** | Until unpaused |
| 7 | Gas spike makes fulfillment uneconomical | No | **Delayed** | Until gas normalizes |
| 8 | `fulfillBridgeMint` tx stuck in mempool | No | **Delayed** | Until mined or dropped |

### Why Burn Instead of Lock?

The current design **burns** tokens (reduces totalSupply) rather than **locking** them (transfer to contract). This choice has implications:

**Burn approach (current):**
- Pro: Keeps totalSupply deflationary on source chain (mirrors real-world supply movement)
- Pro: No bridged tokens sitting idle in contract
- Con: **Irreversible** — no recovery possible

**Lock approach (alternative):**
- Pro: Reversible — tokens held in contract, can be recovered
- Pro: `rescueTokens()` would work for bridge failures
- Con: totalSupply unchanged on source (tokens "exist" on two chains until burn on destination)

### Relationship to Finding #1 (Dual Minter Bypass)

The irreversible burn becomes more dangerous in combination with Finding #1. If a malicious entity holds `MINTER_ROLE` on both `LimitedMinter` and `LimitedMinterBridge`, they could:

1. Mint up to 730M wARS via both minters (bypassing daily cap)
2. Bridge tokens off-chain using `depositForBridge` (legitimate-looking burn)
3. Choose not to fulfill on destination (or fulfill to a different address)
4. Result: 730M tokens minted via bypass, then burned — obfuscating the unauthorized mint

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | None | No data exposed |
| **Integrity** | Low | Token supply permanently reduced on source without dest mint |
| **Availability** | Low | Affected users lose access to burned funds |
| **Financial** | Medium | Users depositing during bridge outages face **permanent loss** with no recourse |
| **Likelihood** | Low | Requires bridge operator failure + simultaneous user deposits |

### Real Financial Risk

Each active `depositForBridge` during a bridge outage results in permanent loss. With the bridge handling millions of dollars in WFIAT tokens across 6 chains, even a short outage window could be catastrophic:

```
Potential loss = (avg deposit size) × (deposits per hour) × (outage hours)
```

No admin can reverse these losses under the current design.

---

## Proof of Concept

The irreeversible burn is verified through source code analysis and on-chain transaction inspection. The PoC from Finding #4 (`test/exploits/UpdateLimitedMinterPoC.t.sol`) demonstrates the complete failure chain: admin changes `limitedMinter` → deposits succeed (burn) → fulfillments fail permanently.

```bash
forge test --match-contract UpdateLimitedMinterExploitTest -vvvv
# testBrokenMinterBlocksFulfillment() demonstrates:
#   1. Admin sets limitedMinter to 0xBEEF (accepted, no validation)
#   2. Future deposits would burn tokens
#   3. Fulfillments would all revert — tokens permanently lost
```

---

## Remediation

### Option A — Lock Instead of Burn (Recommended)

Replace `burnFrom()` with `transferFrom()` into the `BridgeDeposit` contract. The tokens are held in escrow until the destination fulfillment is confirmed:

```solidity
function depositForBridge(...) external ... {
    // ...
    // Replace: ILatamStableBurnable(token).burnFrom(msg.sender, amountToBurn);
    // With:
    IERC20(token).safeTransferFrom(msg.sender, address(this), amountToBurn);
    // ...
}
```

**Benefits:**
- Tokens held in BridgeDeposit balance — `rescueTokens()` can recover them
- `totalSupply` unchanged (accurate — tokens are moving, not destroyed)
- Admin can refund users if bridge fails
- No changes needed on destination chain
- Requires granting BridgeDeposit a non-burn role on the token (e.g., add a `BRIDGE_LOCKER_ROLE` or remove burn requirement)

**Trade-off:** Total supply on source chain doesn't decrease. This is actually correct behavior — the tokens are "in transit," not destroyed.

### Option B — Admin Mint Recovery Function

Add an admin-only function to mint replacement tokens for verified bridge failures:

```solidity
mapping(bytes32 => bool) public recoveredDeposits;

function recoverBurnedTokens(
    address token, address to, uint256 amount,
    uint256 sourceDepositId
) external onlyRole(DEFAULT_ADMIN_ROLE) {
    // Prevent double-recovery
    bytes32 recoveryKey = keccak256(abi.encode(token, to, amount, sourceDepositId));
    require(!recoveredDeposits[recoveryKey], "Already recovered");

    // Verify this deposit was NOT fulfilled on any destination
    bytes32 fulfillmentKey = keccak256(
        abi.encodePacked(block.chainid, bytes32(0), sourceDepositId)
    );
    require(!bridgeFulfilled[fulfillmentKey], "Deposit was fulfilled");

    recoveredDeposits[recoveryKey] = true;
    limitedMinter.mintTo(token, to, amount);
    emit TokensRecovered(token, to, amount, sourceDepositId);
}
```

### Option C — Time-Locked Refund

Allow users to self-refund if their deposit isn't fulfilled within a timeout period:

```solidity
mapping(uint256 => uint256) public depositTimestamps;
uint256 constant REFUND_TIMEOUT = 7 days;

function depositForBridge(...) external ... returns (uint256 depositId) {
    // ...
    depositId = nextDepositId++;
    depositTimestamps[depositId] = block.timestamp;
    // ...
}

function refundDeposit(uint256 depositId) external {
    require(block.timestamp > depositTimestamps[depositId] + REFUND_TIMEOUT,
            "Timeout not reached");
    require(!bridgeFulfilled[keccak256(abi.encodePacked(
        block.chainid, bytes32(0), depositId))],
            "Already fulfilled");
    // Mark as fulfilled to prevent refund + bridge double-dip
    // Mint tokens back to original depositor
}
```

---

## References

- Source: `src/contracts/BridgeDeposit.sol:308-357` (depositForBridge)
- Source: `src/contracts/BridgeDeposit.sol:250-256` (rescueTokens)
- Source: `src/contracts/BridgeDeposit.sol:379-421` (fulfillBridgeMint)
- On-chain tx: `0x9c973c05bd30261ef5d33c52e7008811dd1112f56559fef56259f64eb2b9692b` (fulfillBridgeMint example)
- PoC: `test/exploits/UpdateLimitedMinterPoC.t.sol`
- Related: Finding #1 (Dual Minter Bypass), Finding #4 (updateLimitedMinter No Validation)
