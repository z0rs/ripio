# Finding: Hardcoded Google API Key + Firebase Project ID

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Title** | Hardcoded Google API Key in AndroidManifest Resources |
| **Severity** | Medium (CVSS 3.0: 5.3) |
| **CVSS Vector** | `CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` |
| **Category** | Hardcoded Credentials |
| **CWE** | CWE-798: Use of Hard-coded Credentials |
| **Affected** | `com.ripio.android` v6.5.4 |
| **Date Discovered** | 2026-05-24 |
| **Researcher** | eno |

---

## CVSS 3.0 Breakdown

| Metric | Value | Score | Justification |
|--------|-------|:-----:|---------------|
| **Attack Vector (AV)** | Local | L | Requires APK extraction from device or app store |
| **Attack Complexity (AC)** | Low | L | Trivially extracted via unzip + strings |
| **Privileges Required (PR)** | None | N | No privileges needed to extract from APK |
| **User Interaction (UI)** | None | N | No victim interaction needed |
| **Scope (S)** | Unchanged | U | Exploit confined to Google Cloud services |
| **Confidentiality (C)** | Low | L | Firebase project metadata exposed |
| **Integrity (I)** | Low | L | Potential unauthorized API usage |
| **Availability (A)** | None | N | Service not disrupted |

**CVSS Base Score**: 5.3 (Medium) — `CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`

---

## Summary

The APK contains a hardcoded Google API key (`AIzaSyBp_83sL4yFUDKfRm5LhCvVh4YzZsuk5Ts`) in `res/values/strings.xml`. The same key is reused for both `google_api_key` and `google_crash_reporting_api_key`. The APK also exposes the full Firebase project configuration including project ID, app ID, GCM sender ID, and Firebase database URL. Any user can extract these credentials by decompressing the APK.

---

## Affected Assets

| Asset | Location |
|-------|----------|
| `google_api_key` | `res/values/strings.xml` |
| `google_crash_reporting_api_key` | `res/values/strings.xml` |
| `google_app_id` | `res/values/strings.xml` |
| `gcm_defaultSenderId` | `res/values/strings.xml` |
| `firebase_database_url` | `res/values/strings.xml` |
| `project_id` | `res/values/strings.xml` |

---

## Technical Description

### Hardcoded Values

```xml
<!-- res/values/strings.xml -->
<string name="google_api_key">AIzaSyBp_83sL4yFUDKfRm5LhCvVh4YzZsuk5Ts</string>
<string name="google_crash_reporting_api_key">AIzaSyBp_83sL4yFUDKfRm5LhCvVh4YzZsuk5Ts</string>
<string name="google_app_id">1:908804214271:android:c6bf4fa7b3075c6fdf6bca</string>
<string name="gcm_defaultSenderId">908804214271</string>
<string name="firebase_database_url">https://rpwebview.firebaseio.com</string>
<string name="project_id">rpwebview</string>
```

### Extraction Method

```bash
# Extract API key from APK
unzip -p com.ripio.android-6.5.4.apk resources.arsc | strings | grep AIza
# Output: AIzaSyBp_83sL4yFUDKfRm5LhCvVh4YzZsuk5Ts

# Or decode with apktool
apktool d com.ripio.android-6.5.4.apk -o decoded/
grep -r 'AIza' decoded/res/values/strings.xml
```

### Firebase Project Reconnaissance

The exposed credentials reveal:
- **Project ID**: `rpwebview`
- **Firebase Database**: `https://rpwebview.firebaseio.com` (returns 401 — security rules enabled)
- **Firebase App ID**: `1:908804214271:android:c6bf4fa7b3075c6fdf6bca`
- **Same API key** shared across multiple services (no key rotation or service-specific keys)

### What an Attacker Can Do

With a valid, unrestricted Google API key, an attacker could:
1. Access Firebase services if the key lacks Android app restriction
2. Make unauthorized API calls billed to Ripio's Google Cloud account
3. Enumerate Firebase project resources
4. Use the key in a malicious app impersonating the real Ripio app

### Key Restriction Check

The Firebase Realtime Database at `https://rpwebview.firebaseio.com/.json` returns HTTP 401, indicating that database security rules are in place. However, other Firebase services (Storage, Firestore, Auth) may have different access controls.

---

## Impact Assessment

| Dimension | Rating | Explanation |
|-----------|:------:|-------------|
| **Confidentiality** | Low | Firebase project structure exposed |
| **Integrity** | Low | Potential unauthorized API usage if key is unrestricted |
| **Availability** | None | Service not disrupted |
| **Financial** | Low | API abuse could incur costs; data exposure depends on Firebase rules |

---

## Remediation

### Option A — Server-Side Key Management (Recommended)

Move all Google API interactions to a backend server. The mobile app authenticates to Ripio's server, which then proxies requests to Google APIs with the server-side key. The client never needs to hold the API key.

### Option B — Restrict the API Key

In Google Cloud Console:
1. Navigate to APIs & Services > Credentials
2. Edit the API key `AIzaSyBp_83sL4yFUDKfRm5LhCvVh4YzZsuk5Ts`
3. Under "Application restrictions", select "Android apps"
4. Add the Ripio Android app's package name (`com.ripio.android`) and SHA-1 certificate fingerprint
5. Under "API restrictions", select only the specific APIs needed (Firebase Auth, etc.)
6. Create separate keys for different services (crashlytics vs main API)

### Option C — Firebase App Check

Enable Firebase App Check which uses attestation providers (Play Integrity on Android) to verify that only the genuine Ripio app can access Firebase resources, even with a valid API key.

---

## References

- File: `res/values/strings.xml` in APK
- Google Cloud: APIs & Services > Credentials
- OWASP Mobile Top 10: M9 — Reverse Engineering
