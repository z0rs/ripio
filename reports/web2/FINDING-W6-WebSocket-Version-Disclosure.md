# Finding: WebSocket Library Version and Technology Stack Disclosure

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Title** | uWebSockets.js Version and Technology Stack Exposed via Response Headers |
| **Severity** | Informational |
| **CVSS Vector** | `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Category** | Information Disclosure |
| **CWE** | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor |
| **Affected** | `ws.ripiotrade.co`, `ws-api.ripio.com` |
| **Date Discovered** | 2026-05-24 |
| **Researcher** | eno |

---

## Summary

The Ripio WebSocket servers (`ws.ripiotrade.co` and `ws-api.ripio.com`) expose the `uWebSockets: 20` header, revealing both the WebSocket library in use (uWebSockets.js) and its specific version (v20). The `ws-api.ripio.com` server additionally leaks `AWSALB` and `AWSALBCORS` cookies, confirming the use of AWS Application Load Balancer for WebSocket traffic management.

---

## Affected Assets

| Domain | Exposed Information |
|--------|---------------------|
| `ws.ripiotrade.co` | `uWebSockets: 20` |
| `ws-api.ripio.com` | `uWebSockets: 20`, `AWSALB`, `AWSALBCORS` |

---

## Technical Description

### WebSocket Handshake Response

```
HTTP/1.1 404 Not Found
Date: Sun, 24 May 2026 06:42:51 GMT
Content-Length: 0
Connection: keep-alive
uWebSockets: 20
```

### AWS ALB Cookies (ws-api.ripio.com)

```
set-cookie: AWSALB=KN35pzji1AToHINx5WAX2ZpPq...; Expires=Sun, 31 May 2026; Path=/
set-cookie: AWSALBCORS=KN35pzji1AToHINx5WAX2ZpPq...; Expires=Sun, 31 May 2026; Path=/; SameSite=None; Secure
```

### Technology Stack Revealed

| Component | Evidence |
|-----------|----------|
| WebSocket Library | uWebSockets.js v20 |
| Cloud Provider | AWS |
| Load Balancer | AWS Application Load Balancer (ALB) |
| CDN/WAF | Cloudflare |
| API Gateway | AWS API Gateway |
| Backend Runtime | Node.js (uWebSockets.js is a Node.js C++ addon) |
| Push Notifications | OneSignal + Revopush |
| Attribution | AppsFlyer + Adjust |
| Error Tracking | Sentry |

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | Low | Technology stack fully mapped |
| **Integrity** | None | No data modification |
| **Availability** | None | Not disrupted |

---

## Remediation

### 1. Remove uWebSockets Header

In uWebSockets.js, configure the server to not send the version header:

```javascript
const app = uWS.App({
    // The 'uWebSockets' header is sent by default
    // Override or configure to not send it
});
```

Or use a reverse proxy to strip the header.

### 2. Remove AWS ALB Cookies

If the ALB is using application-controlled stickiness:

```terraform
resource "aws_lb_target_group" "ws" {
  stickiness {
    type    = "source_ip"  # IP-based instead of cookie-based
    enabled = false
  }
}
```

### 3. Strip Server Identifiers at CloudFlare

Use Cloudflare Workers or Transform Rules to remove server-identifying headers:

```javascript
// Cloudflare Worker
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  let response = await fetch(request)
  response = new Response(response.body, response)
  response.headers.delete('uwebsockets')
  return response
}
```

---

## References

- uWebSockets.js: [GitHub](https://github.com/uNetworking/uWebSockets.js)
- OWASP: [Information Disclosure](https://owasp.org/www-project-web-security-testing-guide/)
