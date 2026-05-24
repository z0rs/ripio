# Finding: API Pagination Migration Details Leaked in Public Response

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Title** | Internal API Migration Plans and Deprecation Timeline Exposed |
| **Severity** | Informational |
| **CVSS Vector** | `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Category** | Information Disclosure |
| **CWE** | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor |
| **Affected** | `api.ripiotrade.co/v4/public/trades` |
| **Date Discovered** | 2026-05-24 |
| **Researcher** | eno |

---

## CVSS 3.0 Breakdown

| Metric | Value | Score | Justification |
|--------|-------|:-----:|---------------|
| **Attack Vector (AV)** | Network | N | Remote access |
| **Attack Complexity (AC)** | Low | L | Exposed in standard API response |
| **Privileges Required (PR)** | None | N | Public endpoint |
| **User Interaction (UI)** | None | N | Standard API response |
| **Scope (S)** | Unchanged | U | Within the service |
| **Confidentiality (C)** | Low | L | Internal development roadmap exposed |
| **Integrity (I)** | None | N | No data modification |
| **Availability (A)** | None | N | Service not disrupted |

**CVSS Base Score**: 3.7 (Low) — `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

---

## Summary

The public trade API endpoint (`/v4/public/trades`) returns a verbose deprecation warning in its response when called without pagination parameters. This message reveals internal API migration plans, specific deprecation dates, implementation details about cursor-based pagination, and placeholder behavior. This information could be used by attackers to understand the API's development roadmap and potentially exploit the transition period.

---

## Affected Assets

| Endpoint | Exposure |
|----------|----------|
| `api.ripiotrade.co/v4/public/trades` | Deprecation notice with migration timeline |

---

## Technical Description

### The Leaked Message

When calling `/v4/public/trades?pair=BTC_BRL&limit=-1`, the response includes:

```json
{
  "data": { "trades": [...], "pagination": {...}, "nc": "...", "pc": null },
  "error_code": null,
  "message": "Attention: Due to performance concerns, this endpoint now uses cursor-based pagination. The pagination object currently included in the response is now a placeholder and will be entirely removed as of 2026-06-01. The parameter current_page is also a placeholder and will be removed at the same time. Please update your integration accordingly and refer to the documentation for the correct pagination handling."
}
```

### What's Revealed

1. **Migration timeline**: "will be entirely removed as of 2026-06-01" — exact future change date
2. **Internal reasoning**: "Due to performance concerns" — reveals performance issues with current pagination
3. **Implementation details**: "cursor-based pagination" — reveals the new implementation approach
4. **Placeholder behavior**: "pagination object currently included in the response is now a placeholder" — reveals current implementation state
5. **Breaking change warning**: "will be entirely removed" — confirms backward-incompatible changes coming

### Exploitation Context

| Information | Attacker Use |
|-------------|-------------|
| Deprecation date (2026-06-01) | Plan attacks before/after the change window |
| Cursor-based pagination | New attack vectors on cursor implementation |
| Performance concerns | Indicates potential DoS vectors on the old pagination |
| Placeholder objects | Reveals incomplete/mid-migration state that may have bugs |

### Additional Parameter Behavior

The negative `limit=-1` parameter returns **all recent trades** (no limit applied), demonstrating:
- No input validation on negative pagination values
- The endpoint can return unbounded data sets when limit is negative

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | Low | Internal roadmap and implementation details exposed |
| **Integrity** | None | No data modification possible |
| **Availability** | None | Service not disrupted |

---

## Remediation

### 1. Remove Developer-Facing Messages from Production

Move deprecation notices to:
- API documentation (apidocs.ripiotrade.co)
- HTTP response headers (e.g., `Deprecation: true`, `Sunset: Sat, 01 Jun 2026 00:00:00 GMT`)
- Email notifications to registered API consumers

```http
# Standard deprecation headers
Deprecation: true
Sunset: Sat, 01 Jun 2026 00:00:00 GMT
Link: <https://apidocs.ripiotrade.co/v4/migration>; rel="deprecation"
```

### 2. Validate Pagination Parameters

Reject negative `limit` values:

```javascript
if (limit < 1 || limit > 100) {
  limit = 50; // default
}
```

### 3. Version the API

Create a `/v5/` endpoint with cursor-based pagination instead of modifying `/v4/` in-place. This avoids the need for deprecation messages in production responses.

---

## References

- IETF: [Deprecation HTTP Header](https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-deprecation-header)
- OWASP: [Information Disclosure](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/)
