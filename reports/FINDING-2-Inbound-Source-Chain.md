# Finding: Missing Inbound Source Chain Validation on Bridge

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Title** | Missing Inbound Source Chain Validation in fulfillBridgeMint |
| **Severity** | Informational (CVSS 3.0: 2.2) |
| **CVSS Vector** | `CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N` |
| **Category** | Missing Validation / Defense in Depth |
| **CWE** | CWE-20: Improper Input Validation |
| **Affected Chains** | Ethereum, Base, Polygon, BSC, Gnosis, World Chain |
| **Date Discovered** | 2026-05-24 |

---

## CVSS 3.0 Breakdown

| Metric | Value | Score | Justification |
|--------|-------|:-----:|---------------|
| **Attack Vector (AV)** | Network | N | Exploitable via on-chain transaction submission |
| **Attack Complexity (AC)** | High | H | Requires BRIDGE_OPERATOR_ROLE + token registered in LimitedMinterBridge |
| **Privileges Required (PR)** | High | H | Caller must hold BRIDGE_OPERATOR_ROLE on BridgeDeposit |
| **User Interaction (UI)** | None | N | No victim interaction needed |
| **Scope (S)** | Unchanged | U | Exploit confined to BridgeDeposit |
| **Confidentiality (C)** | None | N | No data or private information disclosed |
| **Integrity (I)** | Low | L | Could mint tokens from unregistered source chains (limited by daily cap + token registration) |
| **Availability (A)** | None | N | Service not disrupted |


---

## Summary

The `BridgeDeposit.fulfillBridgeMint()` function accepts a `sourceChainId` parameter but does not validate that the specified source chain is a registered or accepted inbound route. The route configuration system (`setBridgeRoutes()` + `routeConfigs` mapping) only governs **outbound** deposits — there is no equivalent whitelist for inbound fulfillments. While the function is protected by `onlyRole(BRIDGE_OPERATOR_ROLE)`, the absence of inbound chain validation represents a missing defense-in-depth control.

---

## Affected Assets

| Contract | Address (Ethereum) | Function |
|----------|-------------------|----------|
| BridgeDeposit | `0x465e642387d3d73a57CDc1368fFA53A800bA5D47` | `fulfillBridgeMint()` |
| BridgeDeposit | (same on Base, Polygon, BSC, Gnosis, World Chain) | `fulfillBridgeMint()` |

---

## Technical Description

### The Problem

`BridgeDeposit.fulfillBridgeMint()` (lines 379-421) validates several inputs but does not check whether `sourceChainId` is an approved inbound source:

```solidity
function fulfillBridgeMint(
    address token,
    address to,
    uint256 amount,
    uint256 sourceChainId,      // ← ACCEPTED WITHOUT VALIDATION
    bytes32 sourceTxHash,
    uint256 sourceDepositId
)
    external
    nonReentrant
    whenNotPaused
    onlyRole(BRIDGE_OPERATOR_ROLE)   // ← only trusted operators
    onlyMintableToken(token)          // ← checks token is registered
{
    // Only blocks same-chain fulfillment:
    if (sourceChainId == block.chainid) revert InvalidSourceChain();
    // No No check: is sourceChainId in acceptedInboundChains?
    // No No check: does routeConfigs[token][sourceChainId] exist inbound?

    bytes32 fulfillmentKey = keccak256(
        abi.encodePacked(sourceChainId, sourceTxHash, sourceDepositId)
    );

    if (bridgeFulfilled[fulfillmentKey]) revert BridgeAlreadyFulfilled();
    // ...
    limitedMinter.mintTo(token, to, amount);
    // ...
}
```

### Contrast with Outbound Route Validation

The outbound `depositForBridge()` function (lines 308-357) DOES validate routes:

```solidity
function depositForBridge(
    address token, uint256 amount, uint256 destChainId,
    address destRecipient, bytes32 clientDepositId
) external nonReentrant whenNotPaused returns (uint256 depositId)
{
    // ...
    RouteConfig memory route = routeConfigs[token][destChainId];
    if (!route.enabled) revert InvalidRoute();    // (Yes) validated
    // ...
}
```

And `setBridgeRoutes()` (lines 195-213) only manages OUTBOUND configs:

```solidity
function setBridgeRoutes(
    address token, uint256[] calldata destChainIds,
    bool enabled, uint256 fixedFee
) external onlyRole(DEFAULT_ADMIN_ROLE)
{
    for (uint256 i = 0; i < destChainIds.length; ) {
        if (destChainIds[i] == block.chainid) revert InvalidSourceChain();
        routeConfigs[token][destChainIds[i]] = RouteConfig({  // (Yes) outbound only
            enabled: enabled, fixedFee: fixedFee
        });
        unchecked { ++i; }
    }
}
```

### What Validation EXISTS

| Check | Outbound (`depositForBridge`) | Inbound (`fulfillBridgeMint`) |
|-------|:---:|:---:|
| Route enabled? | (Yes) `routeConfigs[token][destChainId].enabled` | No None |
| Not same chain? | (Yes) `destChainId != block.chainid` | (Yes) `sourceChainId != block.chainid` |
| Token registered? | N/A | (Yes) `onlyMintableToken(token)` |
| Caller authorized? | (Yes) Anyone (user-facing) | (Yes) `onlyRole(BRIDGE_OPERATOR_ROLE)` |

### On-Chain Evidence

Current route configuration for wARS:

```
routeConfigs(wARS, 8453/Base):
  enabled = 1 (true)
  fee     = 15,000,000,000,000,000,000 (~15 wARS)

totalBurnedTo(wARS, Base):   9,999,970,000,000,000,000,000,000 (~10M wARS)
totalMintedFrom(wARS, Base): 140,576,912,000,000,000,000,000,000 (~140M wARS)
```

Real transaction analyzed (fulfillBridgeMint on Ethereum):

```
Tx: 0x9c973c05bd30261ef5d33c52e7008811dd1112f56559fef56259f64eb2b9692b
Block: 25145864
Status: Success

fulfillBridgeMint(
  token         = wARS (0x0DC4...)
  to            = 0x49f4527E1443c86EaBf22eAD1E4BBa36EEA9ebf2
  amount        = 7,000,000,000,000,000,000,000,000 (~7B)
  sourceChainId = 8453 (Base)           ← accepted without route validation
  sourceTxHash  = 0x530886...
  sourceDepositId = 1
)

Events:
  1. wARS.Transfer(from=0x0, to=user, amount=7B)       → Mint
  2. LimitedMinterBridge.Minted(token, caller, user)    → Audit
  3. BridgeDeposit.BridgeMintFulfilled(token, user, 26) → Audit
```

The caller (`0xbc924F707cA021f9B220088AFe56C85b9Cb43085`) has `BRIDGE_OPERATOR_ROLE` — authorized but could fulfill from any chain ID without restriction.

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | None | No data exposed |
| **Integrity** | Low | Only trusted operators can call |
| **Availability** | None | Service not disrupted |
| **Financial** | Low | Requires BRIDGE_OPERATOR_ROLE compromise |
| **Likelihood** | Low | Only addresses with BRIDGE_OPERATOR_ROLE can exploit |

### Current Role Holders

```
BridgeDeposit.BRIDGE_OPERATOR_ROLE:
  - 0x5CA3F8EEBa12D83408fc097c2dAd79212456F20F
  - 0xbc924F707cA021f9B220088AFe56C85b9Cb43085
```

Without an inbound source chain whitelist, a compromised or malicious bridge operator could fulfill deposits from chains that were never intended to be bridged — provided the token is registered in LimitedMinterBridge.

---

## Remediation

### Add Inbound Source Chain Whitelist

```solidity
// Add to BridgeDeposit
mapping(uint256 => bool) public acceptedInboundChains;

function setAcceptedInboundChains(
    uint256[] calldata chainIds,
    bool accepted
) external onlyRole(DEFAULT_ADMIN_ROLE) {
    for (uint256 i = 0; i < chainIds.length; ) {
        if (chainIds[i] == block.chainid) revert InvalidSourceChain();
        acceptedInboundChains[chainIds[i]] = accepted;
        unchecked { ++i; }
    }
}

function fulfillBridgeMint(
    address token, address to, uint256 amount,
    uint256 sourceChainId, bytes32 sourceTxHash, uint256 sourceDepositId
)
    external nonReentrant whenNotPaused
    onlyRole(BRIDGE_OPERATOR_ROLE)
    onlyMintableToken(token)
{
    if (sourceChainId == block.chainid) revert InvalidSourceChain();
    require(acceptedInboundChains[sourceChainId], "Source chain not accepted"); // ← NEW
    // ... rest of function
}
```

### Alternative: Reuse Route Configs

If the outbound routes should be symmetric (same chains for deposit and fulfillment), reuse `routeConfigs`:

```solidity
function fulfillBridgeMint(...) external ... {
    // ...
    RouteConfig memory route = routeConfigs[token][sourceChainId];
    require(route.enabled, "Source chain route not enabled"); // ← reuse outbound config
    // ...
}
```

---

## References

- Source: [Blockscout - BridgeDeposit](https://eth.blockscout.com/address/0x465e642387d3d73a57CDc1368fFA53A800bA5D47)
- Transaction: [Etherscan](https://etherscan.io/tx/0x9c973c05bd30261ef5d33c52e7008811dd1112f56559fef56259f64eb2b9692b)
- PoC Repository: `ripio/src/contracts/BridgeDeposit.sol:379-421`
