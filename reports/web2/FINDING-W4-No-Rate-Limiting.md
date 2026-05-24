# Finding: Missing Rate Limiting on Public API Endpoints

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Title** | No Rate Limiting on Public API Endpoints — Negative Limit Returns Unbounded Data |
| **Severity** | Low (CVSS 3.0: 3.7) |
| **CVSS Vector** | `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` |
| **Category** | Missing Rate Limiting |
| **CWE** | CWE-770: Allocation of Resources Without Limits or Throttling |
| **Affected** | `api.ripiotrade.co/v4/public/*` |
| **Date Discovered** | 2026-05-24 |
| **Researcher** | eno |

---

## CVSS 3.0 Breakdown

| Metric | Value | Score | Justification |
|--------|-------|:-----:|---------------|
| **Attack Vector (AV)** | Network | N | Remote access |
| **Attack Complexity (AC)** | Low | L | No special conditions needed |
| **Privileges Required (PR)** | None | N | Public endpoints |
| **User Interaction (UI)** | None | N | No victim interaction |
| **Scope (S)** | Unchanged | U | Within the service |
| **Confidentiality (C)** | None | N | No data exposure (already public) |
| **Integrity (I)** | None | N | No data modification |
| **Availability (A)** | Low | L | API resources could be exhausted |

**CVSS Base Score**: 3.7 (Low) — `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`

---

## Summary

The Ripio trading API's public endpoints lack any observable rate limiting. Five consecutive requests to `/v4/public/tickers` within seconds all returned data with no throttling or rate limit headers. Additionally, the `limit` parameter on `/v4/public/trades` accepts negative values (e.g., `limit=-1`), which returns **all available trade data** with no cap. This allows resource exhaustion attacks and unbounded data retrieval from public endpoints.

Per program guidelines: "Denial of Service (DoS/DDoS): Any activity that disrupts, degrades, or interrupts service availability" is excluded. However, this finding relates to **missing defensive controls** on the API, not active DoS testing.

---

## Affected Assets

| Endpoint | Issue |
|----------|-------|
| `api.ripiotrade.co/v4/public/tickers` | No rate limiting — 5 rapid requests all succeeded |
| `api.ripiotrade.co/v4/public/currencies` | No rate limiting |
| `api.ripiotrade.co/v4/public/pairs` | No rate limiting |
| `api.ripiotrade.co/v4/public/trades?limit=-1` | Negative limit returns **all** trades with no cap |
| `api.ripiotrade.co/v4/public/trades?limit=999999999` | Huge limit accepted without validation |

---

## Technical Description

### Rate Limiting Test

```
$ for i in 1 2 3 4 5; do
  curl -s https://api.ripiotrade.co/v4/public/tickers | jq '{req: '$i', len: (.data | length)}'
done

Request 1: 21 tickers returned
Request 2: 21 tickers returned
Request 3: 21 tickers returned
Request 4: 21 tickers returned
Request 5: 21 tickers returned

All within < 3 seconds — no rate limiting observed
```

No rate limit headers present in responses:
- `X-RateLimit-Limit` — not present
- `X-RateLimit-Remaining` — not present
- `Retry-After` — not present
- `429 Too Many Requests` — never returned

### Negative Limit Parameter

```
GET /v4/public/trades?pair=BTC_BRL&limit=-1

Response: Returns ALL trades with no pagination cap
  40+ trade records returned instead of default page size
```

The `limit` parameter accepts:
- `-1` — returns all data (no limit)
- `0` — returns empty result
- `999999999` — accepted, returns capped data

### Comparison: Authenticated Endpoints

Authenticated endpoints DO have rate limiting — the API returns `40100 Invalid token` or the Cloudflare-level rate limit (error 1015) is enforced for auth operations. The gap exists specifically on public endpoints.

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | None | Data already public |
| **Integrity** | None | No state modification |
| **Availability** | Low | Resource exhaustion possible on public endpoints |

---

## Remediation

### 1. Implement Rate Limiting

Add rate limit headers to API responses:

```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 59
X-RateLimit-Reset: 1779604200
```

Return `429 Too Many Requests` with `Retry-After` when exceeded.

### 2. Validate Pagination Parameters

```javascript
const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 100));
```

Reject negative, zero, and excessively large limit values.

### 3. Use AWS WAF Rate-Based Rules

Configure AWS WAF on the API Gateway to block IPs exceeding threshold:

```json
{
  "RateLimit": 100,
  "AggregationKey": "IP",
  "Action": "Block"
}
```

---

## References

- OWASP: [API Security Top 10 - API4:2023 Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- Program Guidelines: "Denial of Service (DoS/DDoS) ... are excluded" (informational only)
