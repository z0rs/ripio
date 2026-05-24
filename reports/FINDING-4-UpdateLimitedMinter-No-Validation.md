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
| **Researcher** | eno |

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

**CVSS Base Score**: 2.3 (Low) — `CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:L`

---

## Summary

The `BridgeDeposit.updateLimitedMinter()` function allows `DEFAULT_ADMIN_ROLE` holders to change the `limitedMinter` address. However, there is **no validation** that the new address implements the `ILimitedMinterBridge` interface correctly. If set to a non-compliant or broken contract:

- **Outbound deposits** (`depositForBridge`) continue to work — users burn tokens ✅
- **Inbound fulfillments** (`fulfillBridgeMint`) break — `onlyMintableToken` check fails or `mintTo` reverts ❌
- **Result**: Permanent loss of user funds — tokens burned on source chain but never minted on destination

Since `depositForBridge` burns tokens (not locks them), there is **no recovery mechanism** for tokens burned after a misconfiguration. The `rescueTokens()` function only rescues tokens accidentally sent directly to the contract, not tokens burned via `depositForBridge`.

---

## Affected Assets

| Contract | Address (Ethereum) | Function |
|----------|-------------------|----------|
| BridgeDeposit | `0x465e642387d3d73a57CDc1368fFA53A800bA5D47` | `updateLimitedMinter()` |
| BridgeDeposit | (same address on all 6 chains) | `updateLimitedMinter()` |

---

## Technical Description

### Vulnerable Code

**BridgeDeposit.sol:219-226** — `updateLimitedMinter()`:

```solidity
function updateLimitedMinter(ILimitedMinterBridge newMinter) 
    external 
    onlyRole(DEFAULT_ADMIN_ROLE) 
{
    if (address(newMinter) == address(0)) revert ZeroAddress();  // only null check
    address old = address(limitedMinter);
    limitedMinter = newMinter;                                   // no interface validation
    emit LimitedMinterUpdated(old, address(newMinter));
}
```

### What's Missing

There is no check that `newMinter`:
1. Implements `ILimitedMinterBridge.mintTo(address,address,uint256)` correctly
2. Has `tokenConfigs(address)` returning valid `(uint256, bool)`
3. Has `mintedToday(address)` returning a valid `uint256`
4. Has `MINTER_ROLE` on the WFIAT tokens
5. Is actually a contract (not an EOA)

### Impact Chain

```
Step 1: Admin calls updateLimitedMinter(brokenContract) — no validation
Step 2: User calls depositForBridge(wARS, 100, Base, recipient) — SUCCESS
        → 100 wARS burned from user's balance
        → BridgeDepositInitiated event emitted
Step 3: Bridge operator calls fulfillBridgeMint(wARS, recipient, 100, ...) — FAILS
        → onlyMintableToken(token) calls brokenContract.tokenConfigs(wARS)
        → Reverts or returns incorrect data
        → Transaction fails, tokens NOT minted on destination
Step 4: User's 100 wARS are permanently lost — burned on source, never minted on destination
Step 5: rescueTokens() cannot help — tokens were burned (total supply reduced), not stored in contract
```

### rescueTokens Cannot Recover Burned Tokens

**BridgeDeposit.sol:250-256:**

```solidity
function rescueTokens(address token, address to, uint256 amount) 
    external 
    onlyRole(DEFAULT_ADMIN_ROLE) 
{
    if (to == address(0)) revert ZeroAddress();
    if (amount == 0) revert AmountZero();
    IERC20(token).safeTransfer(to, amount);  // transfers from contract's OWN balance
    emit TokensRescued(token, to, amount);
}
```

This function transfers tokens that the contract **holds** (sent accidentally to the contract address). Tokens burned via `depositForBridge` reduce the **total supply** of the WFIAT token — they are not stored in any contract balance. Recovery would require minting replacement tokens, which only `MINTER_ROLE` can do.

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | None | No data exposed |
| **Integrity** | Low | Bridge mint operations fail after misconfiguration |
| **Availability** | Low | Inbound bridge service disrupted until fixed |
| **Financial** | Low-Medium | Any deposits made during misconfiguration are permanently lost |
| **Likelihood** | Low | Requires DEFAULT_ADMIN_ROLE compromise or error |

---

## Remediation

### Option A — Interface Validation (Recommended)

Verify that `newMinter` supports the required interface:

```solidity
function updateLimitedMinter(ILimitedMinterBridge newMinter) 
    external 
    onlyRole(DEFAULT_ADMIN_ROLE) 
{
    if (address(newMinter) == address(0)) revert ZeroAddress();

    // Validate interface support
    try newMinter.tokenConfigs(address(0x1)) returns (uint256, bool) {
        // Interface check passed
    } catch {
        revert("Invalid limitedMinter: tokenConfigs failed");
    }

    // Validate it can mint (check MINTER_ROLE on a known token)
    // ...additional checks...

    address old = address(limitedMinter);
    limitedMinter = newMinter;
    emit LimitedMinterUpdated(old, address(newMinter));
}
```

### Option B — Two-Step Update with Timelock

```solidity
address public pendingLimitedMinter;
uint256 public limitedMinterUpdateTime;

function proposeLimitedMinter(ILimitedMinterBridge newMinter) external onlyRole(DEFAULT_ADMIN_ROLE) {
    pendingLimitedMinter = address(newMinter);
    limitedMinterUpdateTime = block.timestamp + 24 hours;
}

function acceptLimitedMinter() external onlyRole(DEFAULT_ADMIN_ROLE) {
    require(block.timestamp >= limitedMinterUpdateTime, "Timelock not expired");
    address old = address(limitedMinter);
    limitedMinter = ILimitedMinterBridge(pendingLimitedMinter);
    emit LimitedMinterUpdated(old, pendingLimitedMinter);
}
```

### Option C — Pause Deposits During Migration

Call `pause()` before updating `limitedMinter`, verify the new contract works, then `unpause()`.

---

## References

- Source: [Blockscout - BridgeDeposit](https://eth.blockscout.com/address/0x465e642387d3d73a57CDc1368fFA53A800bA5D47)
- File: `src/contracts/BridgeDeposit.sol:219-226`
