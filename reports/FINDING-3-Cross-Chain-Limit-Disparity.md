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
| **Researcher** | eno |

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

Each chain deploys its own `LimitedMinter` instance with independently configured daily mint limits for the same WFIAT tokens. These limits vary significantly across chains (Ethereum = 700M, Base = 100M). An entity holding `MINTER_ROLE` on multiple chains can route mints through the chain with the highest configured limit, effectively bypassing the lower limits on other chains.

Additionally, since both `LimitedMinter` and `LimitedMinterBridge` have independent daily limits on each chain, the effective per-chain cap is the sum of both limits — and this sum varies by chain.

---

## Affected Assets

| Contract | Chain | Address | wARS Daily Limit | LMB wARS Daily Limit | Effective Combined |
|----------|-------|---------|:-----------------:|:---------------------:|:------------------:|
| LimitedMinter | Ethereum | `0xD168CFbBE260D48cd119497a9a2eE8482080C5E7` | 700,000,000 | 30,000,000 | 730,000,000 |
| LimitedMinter | Base | `0xf469eC9dEBf7F0adEBA4d1Db2FF5c70707bEeB30` | 100,000,000 | 30,000,000 | 130,000,000 |
| LimitedMinter | Gnosis | `0xD168CFbBE260D48cd119497a9a2eE8482080C5E7` | TBD | TBD | TBD |
| LimitedMinter | BSC | `0xD168CFbBE260D48cd119497a9a2eE8482080C5E7` | TBD | TBD | TBD |
| LimitedMinter | Polygon | `0xD168CFbBE260D48cd119497a9a2eE8482080C5E7` | TBD | TBD | TBD |
| LimitedMinter | World Chain | `0xDe7Ec97CFDeE9F20f9d256F4A0A0d694479fa2E0` | TBD | TBD | TBD |

> Note: Ethereum's combined limit (730M) is 5.6× higher than Base's combined limit (130M).

---

## Technical Description

### On-Chain Evidence

**Ethereum — LimitedMinter daily limit for wARS**: 700,000,000
```
cast call 0xD168CFbBE260D48cd119497a9a2eE8482080C5E7 \
  "tokenConfigs(address)" 0x0DC4F92879B7670e5f4e4e6e3c801D229129D90D
→ (0xB6C9e645..., 700000000000000000000000000, true)
```

**Base — LimitedMinter daily limit for wARS**: 100,000,000
```
cast call 0xf469eC9dEBf7F0adEBA4d1Db2FF5c70707bEeB30 \
  "tokenConfigs(address)" 0x0DC4F92879B7670e5f4e4e6e3c801D229129D90D --rpc-url https://mainnet.base.org
→ (0xB6C9e645..., 100000000000000000000000000, true)
```

### Why This Matters

The WFIAT tokens are designed to be fungible across chains via the bridge. However:

1. **Limit asymmetry**: Ethereum allows 5.6× more minting per day than Base
2. **No global cap**: There is no cross-chain enforcement of a global daily mint limit
3. **Bridge enables movement**: Tokens minted on Ethereum can be bridged to Base (and vice versa)

In combination with Finding #1 (Dual Minter Bypass), an entity with sufficient privileges could:
- Mint 730M wARS on Ethereum (high limit)
- Bridge to Base via `depositForBridge` (burns on ETH, mints on Base via `fulfillBridgeMint`)
- The tokens arrive on Base, which has only a 130M daily limit for native minting

This asymmetry means the effective daily mint limit is the **maximum of all chain limits**, not the minimum — violating the principle of having a global cap.

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | None | No data exposed |
| **Integrity** | Low | Limited bypass — only beneficial if one chain has higher limit than others |
| **Availability** | None | Service not disrupted |
| **Financial** | Low | Requires MINTER_ROLE on multiple chains (separate governance) |
| **Likelihood** | Low | Requires cross-chain privilege coordination |

---

## Remediation

1. **Standardize daily limits across all chains** for the same token
2. **Implement a global cross-chain mint cap** via a shared registry or message bridge
3. **Set the limit to the MINIMUM across chains** rather than allowing per-chain independence
4. **Document the per-chain limit policy** and monitor for cross-chain limit arbitrage

---

## References

- On-chain data: Ethereum block ~25159396, Base block per RPC
- Source: `LimitedMinter.sol` — `tokenConfigs` storage
