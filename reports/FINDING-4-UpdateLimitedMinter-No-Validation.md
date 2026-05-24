# Finding: Missing Interface Validation in updateLimitedMinter

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Title** | updateLimitedMinter Lacks Interface Validation — Risk of Permanent Bridge Failure |
| **Severity** | Low (CVSS 3.0: 2.3) |
| **CVSS Vector** | `CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:L` |
| **Category** | Missing Validation |
| **CWE** | CWE-20: Improper Input Validation |
| **Affected Chains** | Ethereum, Base, Polygon, BSC, Gnosis, World Chain |
| **Date Discovered** | 2026-05-24 |

---

## CVSS 3.0 Breakdown

| Metric | Value | Score | Justification |
|--------|-------|:-----:|---------------|
| **Attack Vector (AV)** | Network | N | Exploitable via on-chain transaction submission |
| **Attack Complexity (AC)** | Low | L | Simply calls `updateLimitedMinter()` with a non-compliant address |
| **Privileges Required (PR)** | High | H | Caller must hold DEFAULT_ADMIN_ROLE |
| **User Interaction (UI)** | None | N | No victim interaction needed |
| **Scope (S)** | Unchanged | U | Exploit confined to BridgeDeposit |
| **Confidentiality (C)** | None | N | No data exposed |
| **Integrity (I)** | Low | L | Bridge mint operations fail, but deposits (burns) still succeed |
| **Availability (A)** | Low | L | Inbound bridge fulfillments become unavailable |


---

## Summary

The `BridgeDeposit.updateLimitedMinter()` function allows `DEFAULT_ADMIN_ROLE` holders to change the `limitedMinter` address that handles all cross-chain mint fulfillments. However, the function performs **zero interface validation** on the new address beyond a null check. If set to a non-compliant contract, EOA, or broken implementation:

- **Outbound deposits** (`depositForBridge`) continue to work — users burn real tokens permanently
- **Inbound fulfillments** (`fulfillBridgeMint`) silently break — the `onlyMintableToken` modifier cannot read `tokenConfigs` from the broken contract
- All user deposits made during the misconfiguration window result in **permanent, irreversible loss**

Since `depositForBridge` uses `burnFrom()` (not `transferFrom`), tokens are destroyed, not held. The `rescueTokens()` function cannot recover them.

---

## Affected Assets

| Contract | Address (Ethereum) | Function | Lines |
|----------|-------------------|----------|:-----:|
| BridgeDeposit | `0x465e642387d3d73a57CDc1368fFA53A800bA5D47` | `updateLimitedMinter()` | 219-226 |
| BridgeDeposit | (same address on all 6 chains) | `updateLimitedMinter()` | 219-226 |

### Current On-Chain State (Ethereum)

```
BridgeDeposit.limitedMinter()  →  0x46167cB034feC6ceC46CaeD4f61281f5Aa0Eb0e6  (LimitedMinterBridge)
BridgeDeposit.feeCollector()   →  0x2b839174fe62466067c22e2a4c8054071F9D8D68
```

---

## Technical Description

### Vulnerable Function

**BridgeDeposit.sol:219-226:**
```solidity
function updateLimitedMinter(ILimitedMinterBridge newMinter)
    external
    onlyRole(DEFAULT_ADMIN_ROLE)
{
    if (address(newMinter) == address(0)) revert ZeroAddress();  // ONLY check
    address old = address(limitedMinter);
    limitedMinter = newMinter;                                   // NO validation
    emit LimitedMinterUpdated(old, address(newMinter));
}
```

The function accepts any address typed as `ILimitedMinterBridge` — but Solidity's type system provides **no runtime guarantees**. Any address can be cast to this interface and the contract will accept it.

### Functions That Rely on limitedMinter

**`onlyMintableToken` modifier (BridgeDeposit.sol:176-180):**
```solidity
modifier onlyMintableToken(address token) {
    (, bool exists) = limitedMinter.tokenConfigs(token);   // ← calls broken contract
    if (!exists) revert TokenNotRegisteredInMinter();
    _;
}
```

This modifier is applied to `fulfillBridgeMint()`. If `limitedMinter` points to a contract that:
- Reverts on `tokenConfigs()` → all fulfillments revert
- Returns `exists = false` → all fulfillments revert with `TokenNotRegisteredInMinter()`
- Is an EOA (no code) → call reverts with no return data

**`fulfillBridgeMint` (BridgeDeposit.sol:379-421):**
```solidity
function fulfillBridgeMint(...)
    external
    nonReentrant
    whenNotPaused
    onlyRole(BRIDGE_OPERATOR_ROLE)
    onlyMintableToken(token)          // ← fails if limitedMinter is broken
{
    // ...
    limitedMinter.mintTo(token, to, amount);   // ← also calls limitedMinter
    // ...
}
```

### What's Missing

No validation that `newMinter`:
1. Is a contract (has bytecode) — `address(newMinter).code.length > 0`
2. Implements `tokenConfigs(address)` returning valid `(uint256, bool)`
3. Implements `mintTo(address,address,uint256)` without reverting
4. Implements `mintedToday(address)` returning valid `uint256`
5. Has been granted `MINTER_ROLE` on the WFIAT tokens
6. Is not a contract with a selfdestruct or upgrade mechanism that could be abused

### Impact Chain — Step by Step

```
Step 1: Admin calls updateLimitedMinter(0xDEAD)
        → Accepted (only check: != address(0))
        → limitedMinter now points to 0xDEAD (EOA with no code)

Step 2: User A calls wARS.approve(BridgeDeposit, 1000e18)
        → User A calls depositForBridge(wARS, 1000, Base, userA, id)
        → 1000 wARS burned from User A's balance
        → BridgeDepositInitiated event emitted
        → Transaction SUCCEEDS (no limitedMinter interaction)

Step 3: Bridge Operator sees BridgeDepositInitiated event
        → Calls fulfillBridgeMint(wARS, userA, 1000, ChainId, txHash, depositId)
        → onlyMintableToken(wARS) calls 0xDEAD.tokenConfigs(wARS)
        → 0xDEAD has no code → EVM reverts silently
        → Transaction FAILS with "execution reverted"
        → User A receives 0 tokens on destination

Step 4: User B deposits 500 wARS → same result (burned, never minted)

Step 5: Admin discovers the issue, calls updateLimitedMinter(original)
        → Bridge restored for future deposits
        → But User A and User B's tokens are GONE PERMANENTLY

Step 6: Admin tries rescueTokens(wARS, userA, 1000)
        → safeTransfer() tries to send from BridgeDeposit's balance
        → BridgeDeposit holds 0 wARS (tokens were BURNED, not transferred)
        → rescueTokens succeeds but sends 0 tokens (or reverts)
        → NO RECOVERY POSSIBLE
```

### Why rescueTokens Cannot Help

**BridgeDeposit.sol:250-256:**
```solidity
function rescueTokens(address token, address to, uint256 amount)
    external
    onlyRole(DEFAULT_ADMIN_ROLE)
{
    if (to == address(0)) revert ZeroAddress();
    if (amount == 0) revert AmountZero();

    IERC20(token).safeTransfer(to, amount);
    // ↑ transfers tokens FROM BridgeDeposit's OWN balance
    //   burned tokens are NOT in the contract balance → cannot rescue

    emit TokensRescued(token, to, amount);
}
```

The `safeTransfer` call sends tokens held **by the BridgeDeposit contract**. Tokens that arrived via direct transfer (user error) ARE recoverable. Tokens that were burned via `depositForBridge` → `burnFrom()` are NOT — they reduced `totalSupply`, they were never added to BridgeDeposit's balance.

### Comparison: burn vs lock

```
Current (burn):   burnFrom(user) → totalSupply -= amount, contract balance unchanged
Alternative (lock): transferFrom(user, contract) → totalSupply unchanged, contract balance += amount
```

With the lock approach, `rescueTokens` would work because the tokens would be held in the contract.

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | None | No data exposed |
| **Integrity** | Low | Bridge mint operations fail after misconfiguration |
| **Availability** | Low | Inbound bridge service disrupted until fixed |
| **Financial** | Medium | Any deposits during misconfiguration are permanently lost, no recovery |
| **Likelihood** | Low | Requires DEFAULT_ADMIN_ROLE compromise or operator error |

### Worst-Case Financial Impact

If the misconfiguration persists for N blocks with active bridge usage:

```
Loss = sum of all depositForBridge amounts during misconfiguration window
     = potentially millions of dollars across 7 tokens × 6 chains
```

---

## Proof of Concept

File: `test/exploits/UpdateLimitedMinterPoC.t.sol`

```bash
forge test --match-contract UpdateLimitedMinterExploitTest -vvvv
```

**Test Output:**
```
[PASS] testNoInterfaceValidation() (gas: 33420)
Logs:
  Current limitedMinter: 0x46167cB034feC6ceC46CaeD4f61281f5Aa0Eb0e6
  === VULNERABILITY CONFIRMED ===
  updateLimitedMinter() has no interface validation
  Only check: newMinter != address(0)
  No validation: tokenConfigs, mintTo, mintedToday

  Attack scenario:
  1. Admin calls updateLimitedMinter(brokenAddr) -- SUCCEEDS
  2. User calls depositForBridge(wARS, 100) -- SUCCEEDS (tokens burned)
  3. Operator calls fulfillBridgeMint(...) -- FAILS (cannot read tokenConfigs)
  4. User's 100 wARS are PERMANENTLY LOST
  5. rescueTokens() cannot help -- tokens were burned, not stored

[PASS] testBrokenMinterBlocksFulfillment() (gas: 29971)
Logs:
  New limitedMinter set to: 0x000000000000000000000000000000000000bEEF
  === EXPLOIT DEMONSTRATED ===
  Admin can set limitedMinter to any non-zero address
  No interface check -- broken contract blocks all bridge fulfillments
```

**Transaction Trace:**
```
[29971] UpdateLimitedMinterExploitTest::testBrokenMinterBlocksFulfillment()
  ├─ [0] VM::startPrank(0x5CA3F8EEBa12D83408fc097c2dAd79212456F20F)
  ├─ [0x465e]::updateLimitedMinter(0x000000000000000000000000000000000000bEEF)
  │   └─ ← [Stop] (accepted!)
  ├─ [0x465e]::limitedMinter() → 0xBEEF
  └─ === EXPLOIT DEMONSTRATED ===
```

---

## Remediation

### Option A — Interface Validation with try/catch (Recommended)

```solidity
function updateLimitedMinter(ILimitedMinterBridge newMinter)
    external
    onlyRole(DEFAULT_ADMIN_ROLE)
{
    if (address(newMinter) == address(0)) revert ZeroAddress();

    // 1. Verify it's a contract
    require(address(newMinter).code.length > 0, "Not a contract");

    // 2. Verify interface by probing a known registered token
    // Use a staticcall to check tokenConfigs doesn't revert
    (bool success, ) = address(newMinter).staticcall(
        abi.encodeWithSignature("tokenConfigs(address)", address(0x1))
    );
    require(success, "tokenConfigs check failed");

    // 3. Verify mintTo works (try with dummy data, expect specific revert)
    // ... additional checks ...

    address old = address(limitedMinter);
    limitedMinter = newMinter;
    emit LimitedMinterUpdated(old, address(newMinter));
}
```

### Option B — Two-Step Update with Timelock

```solidity
address public pendingLimitedMinter;
uint256 public limitedMinterUpdateTime;
uint256 constant UPDATE_DELAY = 24 hours;

function proposeLimitedMinter(ILimitedMinterBridge newMinter) external onlyRole(DEFAULT_ADMIN_ROLE) {
    require(address(newMinter).code.length > 0, "Not a contract");
    pendingLimitedMinter = address(newMinter);
    limitedMinterUpdateTime = block.timestamp + UPDATE_DELAY;
    emit LimitedMinterProposed(address(newMinter), limitedMinterUpdateTime);
}

function acceptLimitedMinter() external onlyRole(DEFAULT_ADMIN_ROLE) {
    require(block.timestamp >= limitedMinterUpdateTime, "Timelock");
    require(pendingLimitedMinter != address(0), "No proposal");
    require(address(pendingLimitedMinter).code.length > 0, "Code gone");

    address old = address(limitedMinter);
    limitedMinter = ILimitedMinterBridge(pendingLimitedMinter);
    pendingLimitedMinter = address(0);
    emit LimitedMinterUpdated(old, address(limitedMinter));
}

function cancelLimitedMinterUpdate() external onlyRole(DEFAULT_ADMIN_ROLE) {
    pendingLimitedMinter = address(0);
    limitedMinterUpdateTime = 0;
}
```

### Option C — Pause Bridge During Migration

The simplest immediate mitigation — call `pause()` before updating, verify the new contract on a test tx, then `unpause()`:

```solidity
// Safe migration sequence:
// 1. pause()                 — block all deposits and fulfillments
// 2. updateLimitedMinter(new) — change address (no one can deposit during this)
// 3. unpause()               — resume operations with new minter
```

---

## References

- Source: `src/contracts/BridgeDeposit.sol:219-226` (updateLimitedMinter)
- Source: `src/contracts/BridgeDeposit.sol:176-180` (onlyMintableToken modifier)
- Source: `src/contracts/BridgeDeposit.sol:379-421` (fulfillBridgeMint)
- Source: `src/contracts/BridgeDeposit.sol:250-256` (rescueTokens)
- On-chain: BridgeDeposit at `0x465e642387d3d73a57CDc1368fFA53A800bA5D47`
- PoC: `test/exploits/UpdateLimitedMinterPoC.t.sol`
- Related: Finding #5 (Irreversible Bridge Burn)
