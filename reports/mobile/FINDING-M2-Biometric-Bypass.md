# Finding: Biometric Bypass via Device Credential Fallback

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Title** | Biometric Authentication Bypass via Device Credential Fallback |
| **Severity** | Medium (CVSS 3.0: 4.6) |
| **CVSS Vector** | `CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Category** | Authentication Bypass |
| **CWE** | CWE-287: Improper Authentication |
| **Affected** | `com.ripio.android` v6.5.4 |
| **Date Discovered** | 2026-05-24 |
| **Researcher** | eno |

---

## CVSS 3.0 Breakdown

| Metric | Value | Score | Justification |
|--------|-------|:-----:|---------------|
| **Attack Vector (AV)** | Physical | P | Requires physical access to unlocked device |
| **Attack Complexity (AC)** | Low | L | Simply enter device PIN/pattern instead of biometric |
| **Privileges Required (PR)** | None | N | Attacker needs device PIN, not app credentials |
| **User Interaction (UI)** | None | N | No victim interaction needed after obtaining device |
| **Scope (S)** | Unchanged | U | Exploit confined to the app |
| **Confidentiality (C)** | High | H | Full access to wallet balances, transaction history, PII |
| **Integrity (I)** | High | H | Can perform transfers, withdrawals, and state-changing actions |
| **Availability (A)** | None | N | Service not disrupted |

**CVSS Base Score**: 4.6 (Medium) — `CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

---

## Summary

The Ripio Android app uses Android's `BiometricPrompt` API for local authentication. However, the app has configured the biometric prompt to allow fallback to **device credentials** (PIN, pattern, or password). When this fallback is enabled, an attacker with knowledge of the device's unlock method can bypass biometric authentication entirely — gaining full access to the Ripio wallet, balances, and the ability to perform transactions.

The program guidelines explicitly list **"Biometric Bypass: Bypassing local authentication mechanisms"** as a qualifying vulnerability.

---

## Affected Assets

| Asset | Context |
|-------|---------|
| `BiometricPrompt` configuration | React Native JS bundle |
| `android.permission.USE_BIOMETRIC` | AndroidManifest.xml |
| `android.permission.USE_FINGERPRINT` | AndroidManifest.xml |
| Wallet, balances, transfers | All sensitive in-app functionality |

---

## Technical Description

### Manifest Permissions

```xml
<uses-permission android:name="android.permission.USE_FINGERPRINT"/>
<uses-permission android:name="android.permission.USE_BIOMETRIC"/>
```

### Evidence from React Native Bundle

The following strings were found in the Hermes JavaScript bundle (`index.android.bundle`):

```
allowDeviceCredentials
setDeviceCredentialAllowed
showBiometricPromptForAuthentication
canAuthenticateWithFingerprintOrUnknownBiometric
```

The presence of `allowDeviceCredentials` and `setDeviceCredentialAllowed` confirms the app calls:

```java
// Android BiometricPrompt API
BiometricPrompt.PromptInfo.Builder builder = new BiometricPrompt.PromptInfo.Builder()
    .setTitle("Authenticate")
    .setDeviceCredentialAllowed(true)  // ← THIS IS THE PROBLEM
    .build();
```

### How the Bypass Works

```
1. Attacker obtains physical access to victim's unlocked device
2. Attacker knows or observes the device PIN/pattern/password
3. Attacker opens Ripio app
4. Biometric prompt appears
5. Instead of fingerprint/face, attacker taps "Use PIN" or similar fallback
6. Android system presents device lock screen
7. Attacker enters device PIN/pattern
8. BiometricPrompt returns success
9. Attacker has full access to Ripio wallet — can view balances, transfer funds
```

### Why This Matters

- **Biometric-only** would require the attacker to have the victim's actual fingerprint or face
- **With device credential fallback**, only the device PIN is needed — which is often observed or shared (e.g., family members)
- The app treats device PIN authentication equivalently to biometric authentication
- No secondary verification for sensitive operations (transfers, withdrawals)

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | High | Full wallet balances, transaction history, PII exposed |
| **Integrity** | High | Unauthorized transfers and withdrawals possible |
| **Availability** | None | Service not disrupted |
| **Financial** | High | Funds can be stolen via unauthorized transfers |
| **Likelihood** | Medium | Physical access + PIN observation is common (family, coworkers) |

---

## Remediation

### Option A — Disable Device Credential Fallback (Recommended)

Set `setDeviceCredentialAllowed(false)` and require biometric-only for sensitive operations:

```java
BiometricPrompt.PromptInfo.Builder builder = new BiometricPrompt.PromptInfo.Builder()
    .setTitle("Authenticate to access Ripio")
    .setSubtitle("Use your fingerprint or face")
    .setAllowedAuthenticators(
        BiometricManager.Authenticators.BIOMETRIC_STRONG
    )
    .setConfirmationRequired(true)
    .build();

// Do NOT call:
// builder.setDeviceCredentialAllowed(true);
```

### Option B — Tiered Authentication

Use biometric-only for viewing balances, but require biometric + second factor for transfers and withdrawals:

```java
if (operation == Operation.VIEW_BALANCE) {
    builder.setAllowedAuthenticators(BIOMETRIC_STRONG | DEVICE_CREDENTIAL);
} else if (operation == Operation.TRANSFER) {
    builder.setAllowedAuthenticators(BIOMETRIC_STRONG); // No device credential
    builder.setConfirmationRequired(true);
    requireSecondFactor(); // SMS OTP or email confirmation
}
```

### Option C — Crypto-Bound Authentication

Use `setCryptoObject()` to bind the biometric prompt to a cryptographic key stored in Android Keystore with `setUserAuthenticationRequired(true)` and `setInvalidatedByBiometricEnrollment(true)`. This ensures:

- The key can only be used after biometric authentication
- The key is invalidated if new biometrics are enrolled
- Device credential cannot satisfy the crypto requirement

---

## References

- Android Documentation: [BiometricPrompt](https://developer.android.com/reference/androidx/biometric/BiometricPrompt)
- OWASP Mobile Top 10: M4 — Insecure Authentication
- Program Guidelines: "Biometric Bypass: Bypassing local authentication mechanisms"
