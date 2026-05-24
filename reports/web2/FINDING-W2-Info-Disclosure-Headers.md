# Finding: AWS Infrastructure Details Exposed in Response Headers

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Title** | AWS API Gateway, CloudFront, and Load Balancer Details in Response Headers |
| **Severity** | Informational |
| **CVSS Vector** | `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Category** | Information Disclosure |
| **CWE** | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor |
| **Affected** | `api.ripiotrade.co`, `ws-api.ripio.com` |
| **Date Discovered** | 2026-05-24 |
| **Researcher** | eno |

---

## CVSS 3.0 Breakdown

| Metric | Value | Score | Justification |
|--------|-------|:-----:|---------------|
| **Attack Vector (AV)** | Network | N | Remote access |
| **Attack Complexity (AC)** | Low | L | Headers exposed on every response |
| **Privileges Required (PR)** | None | N | No auth needed |
| **User Interaction (UI)** | None | N | Default HTTP response |
| **Scope (S)** | Unchanged | U | Within the service |
| **Confidentiality (C)** | Low | L | Infrastructure architecture revealed |
| **Integrity (I)** | None | N | No data modification |
| **Availability (A)** | None | N | Service not disrupted |

**CVSS Base Score**: 3.7 (Low) — `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

---

## Summary

The Ripio trading API (`api.ripiotrade.co`) and WebSocket API (`ws-api.ripio.com`) expose detailed AWS infrastructure information in HTTP response headers. This includes API Gateway request IDs, CloudFront distribution details, AWS Application Load Balancer cookies, and backend technology version identifiers. This information helps attackers map the infrastructure and identify potential attack vectors.

---

## Affected Assets

| Domain | Exposed Headers |
|--------|----------------|
| `api.ripiotrade.co` | `x-amz-apigw-id`, `x-amzn-requestid`, `x-amzn-remapped-*`, `x-cache`, `via` (CloudFront), `x-response-time` |
| `ws-api.ripio.com` | `AWSALB`, `AWSALBCORS`, `uwebsockets: 20` |
| `ws.ripiotrade.co` | `uwebsockets: 20` |

---

## Technical Description

### api.ripiotrade.co Headers

```
x-amzn-remapped-date: Sun, 24 May 2026 06:26:26 GMT
x-amzn-requestid: 24f56e3b-48d3-4b78-81e6-a8406859b7fd
x-amz-apigw-id: d20C6Gv9oAMEDeA=
x-response-time: 5.790ms
x-cache: Miss from cloudfront
via: 1.1 32b143bf937823bc699440f905fa5e60.cloudfront.net (CloudFront)
```

**Revealed**: AWS API Gateway (`apigw-id`), AWS Request ID (traceable), CloudFront CDN distribution ID, backend response time

### ws-api.ripio.com Headers

```
AWSALB=KN35pzji1AToHINx5WAX2ZpPq5gTb9wzZ+OIGpqNXb...
AWSALBCORS=KN35pzji1AToHINx5WAX2ZpPq5gTb9wzZ+OIGpqNXb...
```

**Revealed**: AWS Application Load Balancer in use for WebSocket API

### ws.ripiotrade.co / ws-api.ripio.com Headers

```
uwebsockets: 20
```

**Revealed**: uWebSockets.js v20 — the specific WebSocket library and version

### What Attackers Can Learn

1. **Infrastructure**: AWS API Gateway + CloudFront + ALB + uWebSockets.js
2. **CloudFront distribution**: `32b143bf937823bc699440f905fa5e60.cloudfront.net`
3. **Request tracing**: `x-amzn-requestid` allows correlation of requests
4. **Backend performance**: `x-response-time` reveals API performance metrics
5. **Library versions**: `uwebsockets: 20` — known vulnerabilities can be cross-referenced

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | Low | Infrastructure architecture exposed |
| **Integrity** | None | No data modification possible |
| **Availability** | None | Service not disrupted |

---

## Remediation

### 1. Remove or Obfuscate AWS Headers

Configure CloudFront and API Gateway to strip or modify response headers:

```terraform
# AWS API Gateway
response_headers = {
  "x-amz-apigw-id" = ""
  "x-amzn-requestid" = ""
}
```

### 2. Remove uWebSockets Header

In the WebSocket server configuration:

```javascript
// uWebSockets.js
const app = uWS.App({}).ws('/*', {
  // ...
  sendPingsAutomatically: true,
});
// Remove default server header that exposes version
```

### 3. Use CloudFront Response Headers Policy

Create a CloudFront response headers policy that strips server-specific headers:

```json
{
  "Name": "SecurityHeaders",
  "CorsConfig": { ... },
  "RemoveHeadersConfig": {
    "Items": ["x-amz-apigw-id", "x-amzn-requestid", "x-amzn-remapped-date"]
  }
}
```

---

## References

- AWS: [CloudFront Response Headers Policies](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-response-headers.html)
- OWASP: [Information Disclosure](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/)
