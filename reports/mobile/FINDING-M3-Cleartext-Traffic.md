# Finding: Cleartext Traffic Permitted to Internal Domains

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Title** | Cleartext HTTP Traffic Permitted to Internal and Staging Domains |
| **Severity** | Low (CVSS 3.0: 3.3) |
| **CVSS Vector** | `CVSS:3.0/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N` |
| **Category** | Cleartext Transmission |
| **CWE** | CWE-319: Cleartext Transmission of Sensitive Information |
| **Affected** | `com.ripio.android` v6.5.4 |
| **Date Discovered** | 2026-05-24 |
| **Researcher** | eno |

---

## CVSS 3.0 Breakdown

| Metric | Value | Score | Justification |
|--------|-------|:-----:|---------------|
| **Attack Vector (AV)** | Adjacent | A | Requires same network as victim (WiFi, LAN) |
| **Attack Complexity (AC)** | High | H | Requires MITM position + victim to use app on compromised network |
| **Privileges Required (PR)** | None | N | No app privileges needed |
| **User Interaction (UI)** | Required | R | Victim must use the app on a compromised network |
| **Scope (S)** | Unchanged | U | Exploit confined to network traffic |
| **Confidentiality (C)** | Low | L | Internal API calls and data exposed in cleartext |
| **Integrity (I)** | Low | L | Possible request manipulation via MITM |
| **Availability (A)** | None | N | Service not disrupted |

**CVSS Base Score**: 3.3 (Low) — `CVSS:3.0/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`

---

## Summary

The Android app's `network_security_config.xml` explicitly permits cleartext HTTP traffic to 8 domains, including internal staging infrastructure and a malformed WebSocket entry. Combined with `android:usesCleartextTraffic="true"` in the manifest and `debug-overrides` that trust user-installed CA certificates, the app is vulnerable to man-in-the-middle attacks on compromised networks.

---

## Affected Assets

| Domain | Context |
|--------|---------|
| `core-base.prebitcointrade.com` | Cleartext allowed |
| `dapitalos.stg.ripio.internal` | Cleartext allowed (Talos staging) |
| `wss://ws.ripiotrade.co` | **Malformed** — URL scheme, not domain |
| `wallet-socket.stg.awsorg.ripiocorp.io` | Cleartext allowed (wallet staging) |
| `127.0.0.1`, `10.0.0.1`, `10.0.2.2`, `localhost` | Development/emulator |

---

## Technical Description

### Network Security Configuration

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">core-base.prebitcointrade.com</domain>
        <domain includeSubdomains="true">dapitalos.stg.ripio.internal</domain>
        <domain includeSubdomains="true">wss://ws.ripiotrade.co</domain>
        <domain includeSubdomains="true">127.0.0.1</domain>
        <domain includeSubdomains="true">10.0.0.1</domain>
        <domain includeSubdomains="true">10.0.2.2</domain>
        <domain includeSubdomains="true">localhost</domain>
        <domain includeSubdomains="true">wallet-socket.stg.awsorg.ripiocorp.io</domain>
    </domain-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

### Manifest Configuration

```xml
<application
    android:networkSecurityConfig="@xml/network_security_config"
    android:usesCleartextTraffic="true"
    ...>
```

### Issues Identified

#### 1. Malformed `wss://ws.ripiotrade.co` Entry

The entry `wss://ws.ripiotrade.co` is a **URL**, not a domain name. The `<domain>` tag expects a hostname like `ws.ripiotrade.co`, not `wss://ws.ripiotrade.co`. This malformed entry may:
- Not actually apply any cleartext policy (silently ignored by Android)
- Confuse developers about which domains allow cleartext
- Mask the fact that `ws.ripiotrade.co` may not be properly configured

#### 2. `debug-overrides` in Production

The `debug-overrides` section trusts user-installed CA certificates. In release builds, this section should be removed. Its presence means:
- If the app is run in debug mode (or if this config leaks to release), user-installed certificates are trusted
- MITM proxies with user-installed CA can decrypt app traffic

#### 3. Cleartext to Internal Infrastructure

The domains `dapitalos.stg.ripio.internal` and `wallet-socket.stg.awsorg.ripiocorp.io` are internal staging services. Allowing cleartext to them in production builds means:
- Authentication tokens, wallet data, and trading information could be exposed on compromised networks
- Internal service endpoints are revealed to attackers

#### 4. `usesCleartextTraffic="true"`

This global flag permits HTTP traffic app-wide. Combined with the network security config, it creates an unnecessarily permissive network posture.

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | Low | Internal API traffic potentially exposed on compromised networks |
| **Integrity** | Low | MITM could modify requests to internal services |
| **Availability** | None | Service not disrupted |
| **Financial** | Low | Data leakage could reveal trading patterns and wallet info |

---

## Remediation

### 1. Fix the Malformed Domain Entry

```xml
<!-- WRONG -->
<domain includeSubdomains="true">wss://ws.ripiotrade.co</domain>

<!-- CORRECT -->
<domain includeSubdomains="true">ws.ripiotrade.co</domain>
```

### 2. Remove debug-overrides from Release

Use build variants to apply different network security configs:

```
src/debug/res/xml/network_security_config.xml   ← includes debug-overrides
src/release/res/xml/network_security_config.xml  ← production only
```

### 3. Remove Cleartext for Remote Domains

Only allow cleartext for localhost/emulator IPs:

```xml
<domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="false">localhost</domain>
    <domain includeSubdomains="false">127.0.0.1</domain>
    <domain includeSubdomains="false">10.0.2.2</domain>
</domain-config>
```

### 4. Set usesCleartextTraffic to false

```xml
<application android:usesCleartextTraffic="false" ...>
```

---

## References

- Android: [Network Security Configuration](https://developer.android.com/training/articles/security-config)
- OWASP Mobile Top 10: M3 — Insecure Communication
- File: `res/xml/network_security_config.xml`
