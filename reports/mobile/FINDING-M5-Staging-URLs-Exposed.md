# Finding: Staging Environment URLs Hardcoded in Production APK

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Title** | Internal Staging Environment URLs Exposed in Production Build |
| **Severity** | Informational |
| **CVSS Vector** | `CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Category** | Information Disclosure |
| **CWE** | CWE-215: Insertion of Sensitive Information Into Externally-Accessible Data |
| **Affected** | `com.ripio.android` v6.5.4 |
| **Date Discovered** | 2026-05-24 |
| **Researcher** | eno |

---

## CVSS 3.0 Breakdown

| Metric | Value | Score | Justification |
|--------|-------|:-----:|---------------|
| **Attack Vector (AV)** | Local | L | Requires APK extraction |
| **Attack Complexity (AC)** | Low | L | Trivially extracted via unzip or apktool |
| **Privileges Required (PR)** | None | N | No privileges needed |
| **User Interaction (UI)** | None | N | No victim interaction needed |
| **Scope (S)** | Unchanged | U | Exploit confined to information gathering |
| **Confidentiality (C)** | Low | L | Internal infrastructure naming exposed |
| **Integrity (I)** | None | N | No data modification possible |
| **Availability (A)** | None | N | Service not disrupted |

**CVSS Base Score**: 3.7 (Low) — `CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

---

## Summary

The production APK contains hardcoded URLs and hostnames pointing to internal staging and development infrastructure. These URLs reveal Ripio's internal naming conventions, service architecture, and cloud provider usage. They allow attackers to map internal infrastructure and discover potential secondary attack surfaces.

---

## Affected Assets

| URL / Hostname | Location | Purpose |
|---------------|----------|---------|
| `dapiripio.stg.ripio.internal` | AndroidManifest, network_security_config | Staging deep link host |
| `dapitalos.stg.ripio.internal` | AndroidManifest, network_security_config | Staging Talos API host |
| `core-base.prebitcointrade.com` | network_security_config | Trading core service (cleartext) |
| `wallet-socket.stg.awsorg.ripiocorp.io` | network_security_config | Wallet WebSocket staging (cleartext) |
| `wss://ws.ripiotrade.co` | network_security_config | WebSocket endpoint (malformed) |
| `https://rpwebview.firebaseio.com` | strings.xml | Firebase Realtime Database |
| `https://api.revopush.org` | strings.xml | Push notification API |
| `api.ripio.com` | RN bundle | API gateway |
| `auth.ripio.com` | RN bundle, AndroidManifest | Auth service |
| `trade.ripio.com` | RN bundle | Trading platform |
| `kyc.ripio.com` | RN bundle | KYC service |
| `bridge.ripio.com` | RN bundle | Web3 bridge |
| `app.ripio.com` | RN bundle | Main app |

---

## Technical Description

### Internal Naming Conventions Revealed

The staging hostnames reveal Ripio's internal naming patterns:

```
Pattern: {service}.stg.ripio.internal
  - dapiripio.stg.ripio.internal  (Dapi Ripio — API service?)
  - dapitalos.stg.ripio.internal  (Dapi Talos — authentication?)

Pattern: {service}.stg.awsorg.ripiocorp.io
  - wallet-socket.stg.awsorg.ripiocorp.io  (Wallet WebSocket staging)

Pattern: core-base.{domain}
  - core-base.prebitcointrade.com  (Trading core)
```

This allows attackers to:
1. **Enumerate subdomains**: Knowing the pattern, attackers can discover additional internal services
2. **Target staging**: Staging environments often have weaker security controls
3. **Map cloud infrastructure**: `awsorg.ripiocorp.io` reveals AWS usage; `prebitcointrade.com` reveals a related trading brand

### Staging Deep Links in Production

The `autoVerify="true"` flag on staging deep links means the app actively verifies its association with staging domains. This could allow attacks if:
- The staging DNS is hijacked or taken over
- Certificate validation for staging domains is looser

```xml
<intent-filter android:autoVerify="true">
    <data android:host="dapiripio.stg.ripio.internal" android:scheme="https"/>
</intent-filter>
<intent-filter android:autoVerify="true">
    <data android:host="dapitalos.stg.ripio.internal" android:scheme="https"/>
</intent-filter>
```

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | Low | Internal infrastructure naming exposed |
| **Integrity** | None | No data modification possible |
| **Availability** | None | Service not disrupted |
| **Financial** | Low | Secondary attack surface discovery |

---

## Remediation

### 1. Remove Staging Configs from Production Builds

Use Gradle build variants to include staging-only configurations:

```gradle
// app/build.gradle
debug {
    resValue "string", "staging_host", "dapitalos.stg.ripio.internal"
}
release {
    resValue "string", "staging_host", ""
}
```

### 2. Use Generic Internal Domain Names

Avoid descriptive service names in internal domains:
```
dapitalos.stg.ripio.internal  →  api-stg-01.ripio.internal
dapiripio.stg.ripio.internal  →  app-stg-01.ripio.internal
```

### 3. Remove .internal TLD from Certificate Transparency Logs

Internal domains using `.internal` TLD should not appear in public Certificate Transparency logs. Use private CA-signed certificates for internal services.

### 4. Separate Production and Non-Production Network Security Configs

```xml
<!-- src/release/res/xml/network_security_config.xml -->
<network-security-config>
    <!-- Production only — no staging domains -->
    <domain-config cleartextTrafficPermitted="false"/>
</network-security-config>

<!-- src/debug/res/xml/network_security_config.xml -->
<network-security-config>
    <!-- Debug only — includes staging + debug-overrides -->
    ...
</network-security-config>
```

---

## References

- Android: [Build Variants](https://developer.android.com/build/build-variants)
- OWASP Mobile Top 10: M8 — Code Tampering
- File: `AndroidManifest.xml`, `res/xml/network_security_config.xml`, `res/values/strings.xml`
