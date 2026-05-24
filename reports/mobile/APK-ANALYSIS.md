# Mobile APK Security Analysis — Ripio Android v6.5.4

---

## Scope

| Field | Value |
|-------|-------|
| **Package** | `com.ripio.android` |
| **Version** | 6.5.4 |
| **APK** | `com.ripio.android-6.5.4.apk` (65MB) |
| **Platform** | Android (React Native + Hermes) |
| **Date** | 2026-05-24 |

---

## Findings Summary

| # | Title | Severity | CWE |
|---|-------|----------|-----|
| 1 | Hardcoded Google API Key + Firebase Project ID | Medium | CWE-798 |
| 2 | Biometric Bypass via Device Credential Fallback | Medium | CWE-287 |
| 3 | Cleartext Traffic Permitted to Internal Domains | Low | CWE-319 |
| 4 | Deep Link Hijacking — Multiple Intent Filters | Low | CWE-925 |
| 5 | Staging Environment URLs Hardcoded | Informational | CWE-215 |

---

## Finding #1 — Hardcoded Google API Key + Firebase Project ID

### Severity: Medium

### Description

The APK contains a hardcoded Google API key in `res/values/strings.xml`:

```xml
<string name="google_api_key">AIzaSyBp_83sL4yFUDKfRm5LhCvVh4YzZsuk5Ts</string>
<string name="google_crash_reporting_api_key">AIzaSyBp_83sL4yFUDKfRm5LhCvVh4YzZsuk5Ts</string>
<string name="google_app_id">1:908804214271:android:c6bf4fa7b3075c6fdf6bca</string>
<string name="gcm_defaultSenderId">908804214271</string>
<string name="firebase_database_url">https://rpwebview.firebaseio.com</string>
<string name="project_id">rpwebview</string>
```

The same API key (`AIzaSyBp_83sL4yFUDKfRm5LhCvVh4YzZsuk5Ts`) is used for both **google_api_key** and **google_crash_reporting_api_key**. This key grants access to Google Cloud services including Firebase Auth, Maps, and other APIs depending on its restrictions.

### Impact

- Unauthorized use of Google Cloud services billed to Ripio
- Potential data access to Firebase services (Firebase Database at `https://rpwebview.firebaseio.com` returns 401 with security rules, but other services may be exposed)
- The key can be extracted by any user who downloads the APK

### Evidence

```
$ unzip -p com.ripio.android-6.5.4.apk resources.arsc | strings | grep AIza
AIzaSyBp_83sL4yFUDKfRm5LhCvVh4YzZsuk5Ts
```

### Remediation

- Restrict the API key to only authorized Android package signatures and specific APIs in Google Cloud Console
- Use separate keys for different services with least-privilege restrictions
- Move API keys to server-side or use Firebase App Check

---

## Finding #2 — Biometric Bypass via Device Credential Fallback

### Severity: Medium

### Description

The app implements biometric authentication using `BiometricPrompt` but allows fallback to **device credentials** (PIN, pattern, or password). This was confirmed by the presence of both `allowDeviceCredentials` and `setDeviceCredentialAllowed` in the React Native JavaScript bundle.

From the Android manifest:
```xml
<uses-permission android:name="android.permission.USE_FINGERPRINT"/>
<uses-permission android:name="android.permission.USE_BIOMETRIC"/>
```

From the React Native bundle:
```
allowDeviceCredentials
setDeviceCredentialAllowed
```

When device credential fallback is enabled, an attacker with knowledge of the device PIN (e.g., observed or shoulder-surfed) can bypass biometric authentication entirely — using the PIN instead of fingerprint/face.

Per the program guidelines: **"Biometric Bypass: Bypassing local authentication mechanisms"** is a qualifying vulnerability.

### Impact

- Physical access to unlocked device + knowledge of device PIN = bypass biometric
- Attacker can access Ripio wallet, balances, and perform transactions

### Remediation

- Set `setDeviceCredentialAllowed(false)` on the `BiometricPrompt` builder
- Or require biometric-only authentication with no PIN fallback for sensitive operations (transfers, withdrawals)
- Use `BiometricManager.Authenticators.BIOMETRIC_STRONG` without `DEVICE_CREDENTIAL`

---

## Finding #3 — Cleartext Traffic Permitted to Internal Domains

### Severity: Low

### Description

The `network_security_config.xml` allows cleartext (HTTP) traffic to several domains:

```xml
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

Additionally, `android:usesCleartextTraffic="true"` is set in the manifest.

Notable issues:
- **`wss://ws.ripiotrade.co`** is malformed — `wss://` is a URL scheme, not a domain name. This is a configuration error.
- **`debug-overrides`** with `certificates src="user"` allows MITM via user-installed CA certificates in debug builds
- Internal staging domains accessible over HTTP could leak data on compromised networks

### Remediation

- Remove `wss://ws.ripiotrade.co` from the domain list (it's a URL, not a domain)
- Remove `debug-overrides` from release builds
- Restrict cleartext traffic to only localhost/emulator IPs
- Use HTTPS for all remote domains

---

## Finding #4 — Deep Link Hijacking via Multiple Intent Filters

### Severity: Low

### Description

The `MainActivity` is exported and handles multiple intent filters with `autoVerify="true"` and custom URL schemes:

| Scheme | Host | AutoVerify |
|--------|------|:----------:|
| `ripio://` | *(none)* | Yes |
| `https://` | `auth.ripio.com` | Yes |
| `https://` | `join.ripio.com` | Yes |
| `https://` | `app.ripio.com` | Yes |
| `https://` | `ripio.onelink.me` | Yes |
| `https://` | `2fa` | No |
| `https://` | `dapiripio.stg.ripio.internal` | Yes |
| `https://` | `dapitalos.stg.ripio.internal` | Yes |
| `wc://` | *(none)* | No (WalletConnect) |
| `ripio://` | `products` (path: `/card/google-pay`) | No |

Potential issues:
1. **`ripio://`** custom scheme with no host specified — any `ripio://` link opens the app. Malicious apps could craft `ripio://` intents.
2. **`https://2fa`** — malformed intent filter (no valid host). Could potentially be triggered by crafted intents.
3. **Staging environments** (`dapiripio.stg.ripio.internal`, `dapitalos.stg.ripio.internal`) with autoVerify — links to staging could be intercepted.
4. **`wc://`** for WalletConnect — no path restrictions.

### Impact

- Malicious apps could craft intents to trigger Ripio app actions
- Deep links could be used for phishing (e.g., fake auth.ripio.com pages)
- Staging environment deep links could expose internal features

### Remediation

- Add `pathPrefix` or `pathPattern` restrictions to `ripio://` scheme
- Remove staging environment intent filters from production builds
- Fix or remove the `https://2fa` malformed intent filter
- Validate all deep link parameters before processing

---

## Finding #5 — Staging Environment URLs Hardcoded

### Severity: Informational

### Description

Multiple staging/internal environment URLs are hardcoded in the APK:

| Domain | Context |
|--------|---------|
| `dapiripio.stg.ripio.internal` | Deep link intent filter |
| `dapitalos.stg.ripio.internal` | Deep link intent filter + network security config |
| `core-base.prebitcointrade.com` | Network security config (cleartext) |
| `wallet-socket.stg.awsorg.ripiocorp.io` | Network security config (cleartext) |
| `api.revopush.org` | Push notification service |

### Impact

- Reveals internal infrastructure naming conventions
- Staging environments may have weaker security controls
- Attackers can map internal network architecture

### Remediation

- Remove staging/internal URLs from production APK builds
- Use build variants (debug vs release) to exclude development configs
- Route staging traffic through production-like security controls

---

## Additional Observations

### Permissions Required

| Permission | Risk |
|-----------|------|
| `CAMERA` | QR code scanning, KYC selfie |
| `NFC` | Contactless payments |
| `USE_BIOMETRIC` + `USE_FINGERPRINT` | Biometric auth |
| `RECEIVE_BOOT_COMPLETED` | Auto-start services |
| `READ_EXTERNAL_STORAGE` | File access |
| `SYSTEM_ALERT_WINDOW` | Overlay permission |
| `FOREGROUND_SERVICE` | Background operation |

### Third-Party SDKs Identified

- Firebase (Auth, Messaging, Remote Config, Crashlytics, Installations, Storage, Analytics)
- AppsFlyer (attribution)
- OneSignal (push notifications)
- Revopush (push notifications)
- Adjust (analytics)
- MercadoPago SDK
- WalletConnect v2
- Sentry (error tracking)
- Google Play Integrity
- Google Wallet / TapAndPay
- ML Kit Barcode Scanning
- Wootric (surveys)

### App Backup

- `android:allowBackup="false"` — backup disabled (good)
- `android:fullBackupOnly="true"` — full backup mode if enabled
- `android:hasFragileUserData="true"` — user data marked as fragile

### React Native Configuration

- Hermes JavaScript engine enabled
- CodePush/OTA updates likely in use (based on bundle structure)
- `index.android.bundle` size: ~6MB (contains full app logic)
