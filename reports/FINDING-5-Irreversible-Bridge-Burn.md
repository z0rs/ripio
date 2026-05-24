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
| **Researcher** | eno |

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

The `BridgeDeposit.depositForBridge()` function burns user tokens on the source chain as part of the cross-chain bridge flow. However, there is **no recovery or undo mechanism** in the event that the bridge fulfillment fails on the destination chain. The `rescueTokens()` function only recovers tokens accidentally **sent** to the contract address, not tokens **burned** via the bridge.

This design creates a scenario where tokens can be permanently destroyed if:
1. The bridge operator fails to call `fulfillBridgeMint` on the destination chain
2. The destination chain's `LimitedMinterBridge` is paused or misconfigured
3. The destination chain's daily mint limit is exhausted
4. The `limitedMinter` address is set to a broken contract (see Finding #4)

---

## Affected Assets

| Contract | Address (Ethereum) | Function |
|----------|-------------------|----------|
| BridgeDeposit | `0x465e642387d3d73a57CDc1368fFA53A800bA5D47` | `depositForBridge()` |
| BridgeDeposit | (same address on all 6 chains) | `depositForBridge()` |

---

## Technical Description

### The Burn Flow

**BridgeDeposit.sol:308-357** — `depositForBridge()`:

```solidity
function depositForBridge(
    address token, uint256 amount, uint256 destChainId,
    address destRecipient, bytes32 clientDepositId
) external nonReentrant whenNotPaused returns (uint256 depositId)
{
    // ...
    uint256 amountToBurn = amount - route.fixedFee;
    // ...
    ILatamStableBurnable(token).burnFrom(msg.sender, amountToBurn);  // ← PERMANENT BURN
    // ...
    depositId = nextDepositId++;
    emit BridgeDepositInitiated(depositId, token, msg.sender, amountToBurn,
                                route.fixedFee, destChainId, destRecipient, clientDepositId);
}
```

The `burnFrom()` call **reduces the total supply** of the WFIAT token. The tokens are not stored in the `BridgeDeposit` contract — they cease to exist. The only way to recreate them is through a `mint()` call on the destination chain via `fulfillBridgeMint()`.

### rescueTokens Cannot Recover Burned Tokens

**BridgeDeposit.sol:250-256:**

```solidity
function rescueTokens(address token, address to, uint256 amount) 
    external onlyRole(DEFAULT_ADMIN_ROLE) 
{
    IERC20(token).safeTransfer(to, amount);  // TRANSFER from contract's balance
    emit TokensRescued(token, to, amount);
}
```

This function calls `safeTransfer()`, which only transfers tokens the contract **already holds**. Since burned tokens are destroyed (not transferred to the contract), they cannot be rescued.

### Failure Scenarios

| Scenario | Consequence | Recoverable? |
|----------|-------------|:---:|
| Bridge operator offline | Tokens burned, never minted on destination | ❌ No |
| Daily mint limit exhausted on destination | `fulfillBridgeMint` reverts, tokens burned | ⚠️ Partial (retry next day) |
| `limitedMinter` misconfigured | All fulfillments fail permanently | ❌ No |
| Bridge paused on destination | Fulfillments fail until unpaused | ⚠️ Delayed |
| Destination chain down | Cannot call `fulfillBridgeMint` | ⚠️ Delayed |

### On-Chain Evidence

```
wARS totalSupply: 3,029,278,066.599 tokens

totalBurnedTo(wARS, Base/8453):   9,999,970 (~10M burned)
totalMintedFrom(wARS, Base/8453): 140,576,912 (~140M minted)

Net inflow from Base: ~130M tokens  (more minted than burned on ETH)
```

The discrepancy between `totalBurnedTo` and `totalMintedFrom` suggests significant bridge activity where more tokens flow into Ethereum via the bridge than out.

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | None | No data exposed |
| **Integrity** | Low | Token supply permanently reduced on source chain without corresponding destination mint |
| **Availability** | Low | Affected users lose access to burned funds |
| **Financial** | Medium | Users depositing during bridge outages face permanent loss |
| **Likelihood** | Low | Requires bridge operator failure + admin misconfiguration simultaneously |

---

## Remediation

### Option A — Lock Instead of Burn (Recommended)

Replace `burnFrom()` with a `transferFrom()` into the `BridgeDeposit` contract:

```solidity
function depositForBridge(...) external ... {
    // ...
    // Instead of: ILatamStableBurnable(token).burnFrom(msg.sender, amountToBurn);
    // Use:
    IERC20(token).safeTransferFrom(msg.sender, address(this), amountToBurn);
    // ...
}
```

**Benefits**:
- Tokens are held in the contract, not destroyed
- `rescueTokens()` can recover them if bridge fails
- Reversible via admin action
- Requires `BridgeDeposit` to have MINTER_ROLE on destination chain (already true)

**Trade-off**: Supply is not deflationary on source chain (but this is correct behavior — tokens are moving, not being destroyed).

### Option B — Admin Mint Recovery

Add a function that allows admin to mint replacement tokens to users who lost funds due to bridge failures:

```solidity
function recoverBurnedTokens(
    address token, address to, uint256 amount, uint256 sourceDepositId
) external onlyRole(DEFAULT_ADMIN_ROLE) {
    bytes32 fulfillmentKey = keccak256(abi.encodePacked(block.chainid, bytes32(0), sourceDepositId));
    require(!bridgeFulfilled[fulfillmentKey], "Already fulfilled");
    bridgeFulfilled[fulfillmentKey] = true;
    limitedMinter.mintTo(token, to, amount);  // mint on source chain as recovery
}
```

### Option C — Timelock + Auto-Refund

Implement a timeout: if `fulfillBridgeMint` is not called within N hours, allow the user to claim a refund:

```solidity
mapping(bytes32 => uint256) public depositTimestamps;

function depositForBridge(...) external ... {
    // ...
    depositTimestamps[depositId] = block.timestamp;
}

function refundDeposit(uint256 depositId) external {
    require(block.timestamp > depositTimestamps[depositId] + REFUND_TIMEOUT);
    // ... refund tokens by minting on source chain
}
```

---

## References

- Source: [Blockscout - BridgeDeposit](https://eth.blockscout.com/address/0x465e642387d3d73a57CDc1368fFA53A800bA5D47)
- File: `src/contracts/BridgeDeposit.sol:308-357` (depositForBridge), `src/contracts/BridgeDeposit.sol:250-256` (rescueTokens)
