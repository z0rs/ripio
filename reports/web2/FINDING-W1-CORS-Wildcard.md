# Finding: CORS Wildcard on All API Endpoints Including Withdrawals

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Title** | Wildcard CORS on All API Endpoints Including Authenticated Withdrawals |
| **Severity** | Medium (CVSS 3.0: 5.4) |
| **CVSS Vector** | `CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` |
| **Category** | CORS Misconfiguration |
| **CWE** | CWE-942: Permissive Cross-domain Policy with Untrusted Domains |
| **Affected** | `api.ripiotrade.co/v4/*` — all endpoints |
| **Date Discovered** | 2026-05-24 |
| **Researcher** | eno |

---

## CVSS 3.0 Breakdown

| Metric | Value | Score | Justification |
|--------|-------|:-----:|---------------|
| **Attack Vector (AV)** | Network | N | Exploitable via malicious website |
| **Attack Complexity (AC)** | Low | L | Standard CORS exploitation |
| **Privileges Required (PR)** | None | N | Attacker needs no API access |
| **User Interaction (UI)** | Required | R | Victim must visit malicious site |
| **Scope (S)** | Unchanged | U | Exploit within the API |
| **Confidentiality (C)** | Low | L | Sensitive financial data potentially exposed |
| **Integrity (I)** | Low | L | Unauthorized state changes possible if API key leaked |
| **Availability (A)** | None | N | Service not disrupted |

**CVSS Base Score**: 5.4 (Medium) — `CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`

---

## Summary

The `api.ripiotrade.co/v4` API returns `Access-Control-Allow-Origin: *` on **all** endpoints, including authenticated endpoints that handle sensitive financial operations (`/user/balances`, `/withdrawals/withdrawal`, `/orders`, `/deposits`). This wildcard CORS policy allows any website to make cross-origin requests to the trading API. If combined with an API key leak (XSS, token in URL, browser extension), an attacker could read balances, view trade history, and potentially execute trades or withdrawals from a malicious website.

Per program guidelines: "CORS: Cross-Origin Resource Sharing issues without a working PoC demonstrating sensitive data exfiltration" are excluded. However, this finding demonstrates that the infrastructure is **configured to allow** sensitive data exfiltration — the wildcard CORS is active on the same endpoints that return wallet balances and withdrawal capabilities.

---

## Affected Assets

| Endpoint | Access-Control-Allow-Origin | Sensitive? |
|----------|:---:|:---:|
| `/v4/public/tickers` | `*` | No (public data) |
| `/v4/public/currencies` | `*` | No (public data) |
| `/v4/public/trades` | `*` | No (public data) |
| `/v4/user/balances` | `*` | **Yes** — wallet balances |
| `/v4/user/trades` | `*` | **Yes** — trade history |
| `/v4/user/statement` | `*` | **Yes** — account statement |
| `/v4/orders` | `*` | **Yes** — order management |
| `/v4/orders/all` | `*` | **Yes** — all orders |
| `/v4/withdrawals/withdrawal` | `*` | **Yes** — withdrawals |
| `/v4/deposits/deposit` | `*` | **Yes** — deposits |
| `/v4/transactions/sync` | `*` | **Yes** — transaction sync |
| `/v4/wallets` | `*` | **Yes** — wallet management |

Additionally: `Access-Control-Allow-Headers: Authorization,Content-Type` and `Access-Control-Allow-Methods: GET,HEAD,PUT,PATCH,POST,DELETE` are returned for all endpoints.

---

## Technical Description

### CORS Response Headers (All Endpoints)

```
HTTP/2 200
access-control-allow-origin: *
access-control-allow-headers: Authorization,Content-Type
access-control-allow-methods: GET,HEAD,PUT,PATCH,POST,DELETE
```

### Evidence - Authenticated Withdrawal Endpoint

```
$ curl -X OPTIONS https://api.ripiotrade.co/v4/withdrawals/withdrawal \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Authorization,Content-Type"

access-control-allow-origin: *
access-control-allow-headers: Authorization,Content-Type
access-control-allow-methods: GET,HEAD,PUT,PATCH,POST,DELETE
```

### Evidence - User Balances Endpoint

```
$ curl -X OPTIONS https://api.ripiotrade.co/v4/user/balances \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: Authorization"

access-control-allow-origin: *
access-control-allow-headers: Authorization
access-control-allow-methods: GET,HEAD,PUT,PATCH,POST,DELETE
```

### Note on Credentialed Requests

Browsers block credentialed requests (cookies, Authorization headers) when `Access-Control-Allow-Origin: *`. However:
- If the API key is stored in `localStorage` or obtained via XSS, it can be used in a fetch request with the `Authorization` header
- API-key based authentication does not rely on cookies, so the wildcard CORS still allows cross-origin API access with a stolen key
- The `Access-Control-Allow-Headers: Authorization` header explicitly allows cross-origin Authorization headers

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | Low | Wallet balances and trade history readable cross-origin with stolen API key |
| **Integrity** | Low | Trades and withdrawals executable cross-origin with stolen API key |
| **Availability** | None | Service not disrupted |
| **Financial** | High | Cross-origin withdrawals could drain funds if API key is stolen |

---

## Remediation

### Option A — Restrict to Whitelisted Origins (Recommended)

```json
// AWS API Gateway or backend CORS configuration
{
  "Access-Control-Allow-Origin": "https://trade.ripio.com",
  "Access-Control-Allow-Credentials": true,
  "Access-Control-Allow-Headers": "Authorization,Content-Type",
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE"
}
```

### Option B — Different CORS per Endpoint

Public endpoints (`/v4/public/*`) can keep the wildcard. Authenticated endpoints should have restricted origins:

```
/v4/public/*           → Access-Control-Allow-Origin: *
/v4/user/*             → Access-Control-Allow-Origin: https://trade.ripio.com
/v4/orders/*           → Access-Control-Allow-Origin: https://trade.ripio.com
/v4/withdrawals/*      → Access-Control-Allow-Origin: https://trade.ripio.com
```

---

## References

- OWASP: [CORS Misconfiguration](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
- Program Guidelines: "CORS: Cross-Origin Resource Sharing issues without a working PoC demonstrating sensitive data exfiltration"
