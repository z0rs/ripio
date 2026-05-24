# Finding: Input Validation Gaps and Missing Resource Controls on Public API

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Title** | Negative Limit Accepted, Verbose Deprecation Messages, and Missing Rate Limiting |
| **Severity** | Low (CVSS 3.0: 3.7) |
| **CVSS Vector** | `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` |
| **Category** | Improper Input Validation / Missing Resource Controls |
| **CWE** | CWE-770: Allocation of Resources Without Limits or Throttling |
| **Affected** | `api.ripiotrade.co/v4/public/*` |
| **Date Discovered** | 2026-05-24 |
| **Researcher** | eno |

---

## CVSS 3.0 Breakdown

| Metric | Value | Score | Justification |
|--------|-------|:-----:|---------------|
| **Attack Vector (AV)** | Network | N | Remote access to public API |
| **Attack Complexity (AC)** | Low | L | No special conditions needed |
| **Privileges Required (PR)** | None | N | Public endpoints, no auth |
| **User Interaction (UI)** | None | N | No victim interaction |
| **Scope (S)** | Unchanged | U | Within the API service |
| **Confidentiality (C)** | None | N | No data exposure (already public) |
| **Integrity (I)** | None | N | No state modification |
| **Availability (A)** | Low | L | API resources could be exhausted |

**CVSS Base Score**: 3.7 (Low) — `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`

---

## Summary

The Ripio trading API's public endpoints exhibit three input validation and resource control weaknesses:

1. **Negative `limit` parameter accepted**: Values like `-1`, `-100`, `-999999999` are accepted without validation. While capped at 50 results, the API should reject invalid input with HTTP 400 rather than silently treating negatives as "max results."

2. **Verbose internal deprecation messages in production responses**: Calling pagination endpoints with edge-case parameters returns a message that reveals internal API migration plans, specific deprecation dates (2026-06-01), implementation details about cursor-based pagination, and placeholder behavior.

3. **No rate limiting on public endpoints**: Five consecutive rapid requests all return data with no rate limit headers, throttling, or 429 responses.

Per program guidelines: Denial of Service is excluded. These are input validation and defense-in-depth issues — not active DoS vectors.

---

## Affected Assets

| Endpoint | Issue |
|----------|-------|
| `api.ripiotrade.co/v4/public/tickers` | No rate limiting |
| `api.ripiotrade.co/v4/public/currencies` | No rate limiting |
| `api.ripiotrade.co/v4/public/pairs` | No rate limiting |
| `api.ripiotrade.co/v4/public/trades` | Negative `limit` accepted; verbose deprecation message; no rate limiting |

---

## Technical Description

### Issue 1 — Negative Limit Acceptance

```
GET /v4/public/trades?pair=BTC_BRL&limit=-1          → 50 trades (treated as max)
GET /v4/public/trades?pair=BTC_BRL&limit=-999999999   → 50 trades  
GET /v4/public/trades?pair=BTC_BRL&limit=-100         → 50 trades
GET /v4/public/trades?pair=BTC_BRL&limit=0            → 0 trades (empty result)
GET /v4/public/trades?pair=BTC_BRL&limit=999999999    → 50 trades (capped at max)
```

Expected behavior: `limit` values below 1 should return HTTP 400 Bad Request, not be silently treated as maximum.

### Issue 2 — Verbose Deprecation Message

Edge-case parameters (empty `nc=`, invalid cursor, `pc=null`) trigger a verbose message in the response:

```json
{
  "message": "Attention: Due to performance concerns, this endpoint now uses
  cursor-based pagination. The pagination object currently included in the
  response is now a placeholder and will be entirely removed as of 2026-06-01.
  The parameter current_page is also a placeholder and will be removed at the
  same time. Please update your integration accordingly and refer to the
  documentation for the correct pagination handling."
}
```

This reveals:
- Internal performance issues with the old pagination system
- Migration to cursor-based pagination
- Exact deprecation date (2026-06-01)
- Placeholder implementation details
- Upcoming breaking changes

### Issue 3 — No Rate Limiting

```
$ for i in 1 2 3 4 5; do
  curl -s https://api.ripiotrade.co/v4/public/tickers | jq '.data | length'
done
# All 5 requests return 21 tickers within 3 seconds
# No X-RateLimit-* headers present
# No 429 responses
```

Rate limit headers absent from all responses:
- `X-RateLimit-Limit` — not present
- `X-RateLimit-Remaining` — not present
- `Retry-After` — not present

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | None | Data already public |
| **Integrity** | None | No state modification possible |
| **Availability** | Low | Public endpoints could be exhausted without rate limits |

---

## Remediation

### 1. Validate the `limit` Parameter

```javascript
const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 100));
if (req.query.limit && (isNaN(req.query.limit) || req.query.limit < 1)) {
    return res.status(400).json({ error_code: 40000, message: 'Invalid limit' });
}
```

### 2. Move Deprecation Notices Out of Production Responses

Use standard HTTP headers instead of response body messages:

```http
Deprecation: true
Sunset: Sat, 01 Jun 2026 00:00:00 GMT
Link: <https://apidocs.ripiotrade.co/v4/migration>; rel="deprecation"
```

Notify API consumers via email or dashboard, not in production API responses.

### 3. Implement Rate Limiting with Standard Headers

```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 59
X-RateLimit-Reset: 1779604200
```

Return `429 Too Many Requests` with `Retry-After` when exceeded. Use AWS WAF rate-based rules on API Gateway to enforce at the edge.

---

## References

- OWASP API Security: [API4:2023 Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- IETF: [Deprecation HTTP Header](https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-deprecation-header)
- Program Guidelines: "DoS/DDoS activities that disrupt service availability are excluded" (informational only)
