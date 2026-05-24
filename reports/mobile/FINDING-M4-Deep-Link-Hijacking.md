# Finding: Deep Link Hijacking via Exported Intent Filters

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Title** | Multiple Exported Intent Filters Enable Deep Link Hijacking |
| **Severity** | Low (CVSS 3.0: 3.9) |
| **CVSS Vector** | `CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` |
| **Category** | Improper Authorization |
| **CWE** | CWE-925: Improper Verification of Intent by Broadcast Receiver |
| **Affected** | `com.ripio.android` v6.5.4 — `MainActivity` |
| **Date Discovered** | 2026-05-24 |
| **Researcher** | eno |

---

## CVSS 3.0 Breakdown

| Metric | Value | Score | Justification |
|--------|-------|:-----:|---------------|
| **Attack Vector (AV)** | Local | L | Malicious app on same device sends crafted intent |
| **Attack Complexity (AC)** | Low | L | Simply fires intent with crafted URI |
| **Privileges Required (PR)** | None | N | Any installed app can send intents |
| **User Interaction (UI)** | Required | R | Victim must tap/interact with the malicious link |
| **Scope (S)** | Unchanged | U | Exploit confined to Ripio app |
| **Confidentiality (C)** | Low | L | May navigate to attacker-controlled content |
| **Integrity (I)** | Low | L | May trigger unintended app actions |
| **Availability (A)** | None | N | Service not disrupted |

**CVSS Base Score**: 3.9 (Low) — `CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`

---

## Summary

The `MainActivity` is exported with `android:exported="true"` and handles **9 intent filters** including custom URL schemes (`ripio://`, `wc://`), multiple HTTPS hosts, and a malformed `https://2fa` filter. The `ripio://` scheme has no host or path restrictions. The `wc://` (WalletConnect) scheme has no path restrictions. The staging environment hosts (`dapiripio.stg.ripio.internal`, `dapitalos.stg.ripio.internal`) are included with `autoVerify="true"`. These loose configurations enable deep link hijacking by malicious apps.

---

## Affected Assets

| Intent Filter | Scheme | Host | AutoVerify | Risk |
|--------------|--------|------|:----------:|------|
| 1 | `ripio://` | *(none)* | Yes | Open scheme — any `ripio://` link triggers app |
| 2 | `https://` | `auth.ripio.com` | Yes | Standard OAuth/deep link |
| 3 | `https://` | `join.ripio.com` | Yes | Referral/onboarding links |
| 4 | `https://` | `app.ripio.com` | Yes | App deep links |
| 5 | `https://` | `ripio.onelink.me` | Yes | Attribution links |
| 6 | `https://` | `2fa` | No | **Malformed** — `2fa` is not a valid hostname |
| 7 | `https://` | `dapiripio.stg.ripio.internal` | Yes | **Staging** environment |
| 8 | `https://` | `dapitalos.stg.ripio.internal` | Yes | **Staging** environment (Talos) |
| 9 | `wc://` | *(none)* | No | WalletConnect deep links |
| 10 | `ripio://` | `products` (path: `/card/google-pay`) | No | Google Pay integration |

---

## Technical Description

### Manifest Configuration

```xml
<activity android:exported="true" android:name="com.ripio.android.MainActivity"
          android:launchMode="singleTask">

    <!-- Open custom scheme — no host/path restrictions -->
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="ripio"/>
    </intent-filter>

    <!-- Malformed — "2fa" is not a valid FQDN, should be "2fa.ripio.com" -->
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:host="2fa" android:scheme="https"/>
    </intent-filter>

    <!-- Staging environment — included in production APK -->
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:host="dapiripio.stg.ripio.internal" android:scheme="https"/>
    </intent-filter>

    <!-- WalletConnect — no path restrictions -->
    <intent-filter>
        <data android:scheme="wc"/>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
    </intent-filter>
</activity>
```

### Attack Scenarios

#### Scenario 1: `ripio://` Scheme Hijacking

A malicious app sends an intent:
```java
Intent intent = new Intent(Intent.ACTION_VIEW);
intent.setData(Uri.parse("ripio://evil.com/phishing?redirect=https://attacker.com"));
startActivity(intent);
```

The Ripio app opens and processes the deep link. If the app doesn't validate the host/path, it could navigate to attacker-controlled content.

#### Scenario 2: Staging Environment Spoofing

An attacker registers a domain that resolves similarly to the staging host (e.g., through DNS rebinding or on a compromised network) and crafts a deep link to `https://dapitalos.stg.ripio.internal`. The app auto-verifies and processes the link, potentially connecting to attacker-controlled infrastructure.

#### Scenario 3: WalletConnect Session Hijacking

A malicious app monitors for `wc://` intents or sends its own `wc://` links to intercept WalletConnect session proposals, potentially tricking users into connecting to a malicious dApp.

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | Low | May navigate to phishing content |
| **Integrity** | Low | May trigger unintended app actions |
| **Availability** | None | Service not disrupted |
| **Financial** | Low | WalletConnect hijacking could lead to malicious transaction signing |
| **Likelihood** | Low | Requires victim to have malicious app installed |

---

## Remediation

### 1. Add Host and Path Restrictions to `ripio://`

```xml
<intent-filter android:autoVerify="true">
    <data android:scheme="ripio" android:host="app" android:pathPrefix="/"/>
</intent-filter>
```

### 2. Fix the `https://2fa` Intent Filter

The host should be a valid FQDN:
```xml
<data android:host="2fa.ripio.com" android:scheme="https"/>
```

If this filter is for internal routing, use a custom scheme instead:
```xml
<data android:scheme="ripiotrade" android:host="2fa"/>
```

### 3. Remove Staging Filters from Production Builds

Use `manifestPlaceholders` in Gradle to conditionally include staging filters:

```gradle
buildTypes {
    debug {
        manifestPlaceholders = [includeStaging: true]
    }
    release {
        manifestPlaceholders = [includeStaging: false]
    }
}
```

### 4. Validate Deep Link Parameters

In `MainActivity.onCreate()` or the deep link handler, validate:
- The host matches an allowlist
- The path is valid
- Parameters are sanitized
- Redirect URLs are on the Ripio domain

### 5. WalletConnect Intent Validation

For `wc://` intents, validate the WalletConnect session proposal before connecting:
- Verify the dApp URL is not a known phishing domain
- Show the user the full dApp URL before connecting
- Require user confirmation for session approval

---

## References

- Android: [Verify Android App Links](https://developer.android.com/training/app-links/verify-android-app-links)
- OWASP Mobile Top 10: M1 — Improper Platform Usage
- File: `AndroidManifest.xml` — `MainActivity` intent filters
