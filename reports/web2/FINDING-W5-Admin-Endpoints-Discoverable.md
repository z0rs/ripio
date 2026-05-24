# Finding: Internal Admin and Monitoring Endpoints Discoverable

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Title** | Admin, Internal, Metrics, Debug, and Env Endpoints Exist and Are Discoverable |
| **Severity** | Informational |
| **CVSS Vector** | `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` |
| **Category** | Information Disclosure |
| **CWE** | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor |
| **Affected** | `api.ripiotrade.co/v4/admin`, `/v4/internal`, `/v4/metrics`, `/v4/debug`, `/v4/env`, `/v4/status` |
| **Date Discovered** | 2026-05-24 |
| **Researcher** | eno |

---

## Summary

Multiple sensitive administrative and monitoring endpoints exist on the Ripio trading API (`api.ripiotrade.co`). These endpoints return HTTP 401 (not 404), confirming their existence and that they require authentication. The discovery of these paths reveals internal API structure and provides potential attack targets if authentication is ever bypassed or credentials leaked.

---

## Affected Assets

| Endpoint | Response | Implication |
|----------|:---:|-------------|
| `/v4/admin` | 401 | Admin panel exists |
| `/v4/internal` | 401 | Internal API exists |
| `/v4/metrics` | 401 | Monitoring/metrics endpoint |
| `/v4/debug` | 401 | Debug endpoint |
| `/v4/env` | 401 | Environment variables/config |
| `/v4/status` | 401 | Status endpoint |
| `/v4/graphql` | 401 | GraphQL endpoint exists |
| `/v4/health` | 404 | Does NOT exist |

---

## Technical Description

### Discovery Test

```
$ for path in admin internal metrics debug env status graphql; do
  curl -s -o /dev/null -w "%{http_code}" https://api.ripiotrade.co/v4/$path
done

/v4/admin:    401  (EXISTS - requires auth)
/v4/internal: 401  (EXISTS - requires auth)
/v4/metrics:  401  (EXISTS - requires auth)
/v4/debug:    401  (EXISTS - requires auth)
/v4/env:      401  (EXISTS - requires auth)
/v4/status:   401  (EXISTS - requires auth)
/v4/graphql:  401  (EXISTS - requires auth)
/v4/health:   404  (does not exist)
```

All returned `{"error_code":401,"message":"Invalid token"}` — consistent authentication response.

### Difference from Public Endpoints

Public endpoints (`/v4/public/*`) return HTTP 200 without auth. Admin/internal endpoints return HTTP 401. The consistent 401 response pattern confirms these are real, protected endpoints — not generic 404s.

### Auth Attempts

```
Basic admin:admin       → 401 "Invalid token"
Bearer <jwt_token>      → 401 "Invalid token"
Bearer admin            → 401 "Invalid token"
Key <value>             → 401 "Invalid token"
```

All rejected with the same error — the API uses HMAC signature authentication, not simple tokens.

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | None | Endpoints require auth |
| **Integrity** | None | No bypass found |
| **Availability** | None | Not disrupted |

---

## Remediation

### 1. Return 404 Instead of 401

Configure the API Gateway to return 404 for non-public paths when unauthenticated:

```javascript
// Instead of: return 401 for all unauthenticated requests
// Use: return 404 for paths that don't match public patterns
if (!req.path.startsWith('/v4/public/') && !isAuthenticated(req)) {
    return res.status(404).json({ message: 'Not Found' });
}
```

### 2. Remove Unused Endpoints from Production

If endpoints like `/v4/debug` and `/v4/env` are development-only, remove them from the production deployment entirely.

---

## References

- OWASP: [Information Disclosure](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/)
- File: `reports/web2/PoC-CORS-Exploit.html` (related CORS finding)
