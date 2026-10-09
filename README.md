# EncroNote

A minimal Android notes app that keeps note contents on the device. The Vercel site only provides the signed Android installer.

## Security model

- Notes and titles are encrypted with AES-256-GCM before storage. Native apps wrap the random 256-bit data key with an AES-256 key derived from the master password using PBKDF2-HMAC-SHA-256 (600,000 iterations). Only the encrypted data-key wrapper is stored alongside the encrypted vault; the plaintext data key and derived password key are not persisted. Older native vaults are upgraded to this format after a successful unlock.
- No password or derived encryption key is persisted. There is no notes backend, database, analytics, cloud sync, or network permission in the Android app.
- On Android, failed-attempt state is encrypted with an Android Keystore AES-GCM key and written synchronously before a failed login is reported, reducing the chance that an immediate process kill drops the updated counter. Older installations migrate their existing secure counter before continuing. On iOS, it remains in a device-only Keychain item; iCloud Keychain synchronization is disabled.
- Native lockout state is linked to a random vault identifier. On reaching the configured limit, the app first records the lockout, then removes the encrypted vault and any legacy platform-stored data key. The secure lockout tombstone prevents restoring an old vault copy and starting over to reset attempts.
- Android locks after one minute without interaction and when sent to the background. It immediately replaces the visible note editor with a temporary privacy screen before finishing an in-progress encrypted save. Android blocks screenshots and task-switcher previews.
- Password fields are cleared after each authentication submission. This reduces their time in the visible document but cannot guarantee erasure of immutable JavaScript strings from process memory.
- Android cloud/device backup is disabled.
- Android WebView remote debugging is explicitly disabled in release builds. This does not prevent reverse-engineering or privileged instrumentation on a compromised device.
- Android release builds use R8 code shrinking/optimization, identifier obfuscation, and resource shrinking. These make native code harder to inspect but do not prevent analysis; web UI JavaScript inside the APK can still be extracted and inspected.
- Android autofill is disabled for the app's WebView content to reduce accidental exposure of passwords or note text through autofill services.
- On Android 12 and later, the app requests hidden overlay windows while open, reducing tapjacking and overlay phishing. Note, title, and search fields disable browser spelling, autocorrection, capitalization, and autofill hints to reduce accidental third-party keyboard learning; a third-party keyboard may still observe typed text.
- The Vercel site distributes the Android app only; it does not provide a browser-based notes editor. A compromised hosting account, domain, or device could still alter the download page or APK.

## Build the Android app

```sh
npm install
npm run cap:sync
```

Capacitor sync builds the app's embedded interface and excludes the publicly downloadable APK from the native app bundle. A plain `npm run build` includes the APK in `dist/`, ready for Vercel's static deployment.

Then open Android Studio:

```sh
npm run android
```

Android signing/building requires Android Studio and the Android SDK.

## Android download site

The Vercel site is a minimalist Android download page; the notes editor is only available in the Android app. Both `/` and `/download` open the download page. Vercel serves the signed installer from `public/downloads/EncroNote.apk` with the Android APK content type and an attachment download header.

Create a release signing key once and store it outside the project and source control. Back it up securely: future app updates must use the same key. Never put the keystore or its passwords in the repository or on the public website. Set these environment variables in the build shell or secret manager:

- `ANDROID_KEYSTORE_FILE`: absolute path to the private `.jks`/`.keystore` file
- `ANDROID_KEYSTORE_PASSWORD`
- `ANDROID_KEY_ALIAS`
- `ANDROID_KEY_PASSWORD`

On Windows, with Android Studio/SDK and Java installed, build a signed release APK with `npm run android:release`. The command fails if signing credentials are missing or the keystore path is invalid. Add the Android SDK `build-tools` directory to `PATH`, then run `npm run android:publish`; this verifies the APK signature and copies it to `public/downloads/EncroNote.apk`. Commit/push that public APK and deploy the project to Vercel. Android users can then visit `https://<your-vercel-domain>/`. Increment `versionCode` in `android/app/build.gradle` for each future app release.

For this Windows development setup, the release key and its local credentials are stored outside the project in `%LOCALAPPDATA%\PrivateNotesSigning\`. Protect and back up both files privately; never upload them. To load the saved credentials into a PowerShell build session without printing them:

```powershell
Get-Content "$env:LOCALAPPDATA\PrivateNotesSigning\release-signing.env" | ForEach-Object {
  $name, $value = $_ -split '=', 2
  [Environment]::SetEnvironmentVariable($name, $value, 'Process')
}
$env:JAVA_HOME = 'C:\Program Files\Android\Android Studio\jbr'
$env:ANDROID_SDK_ROOT = "$env:LOCALAPPDATA\Android\Sdk"
$env:Path = "$env:JAVA_HOME\bin;$env:ANDROID_SDK_ROOT\build-tools\36.1.0;$env:Path"
```

Do not ship a debug or unsigned APK. A published APK is public and can be copied by anyone. Direct installation may require the user to permit installs from their browser. The website distributes the app but does not receive or sync notes.

## Run locally

```sh
npm run dev
```

This opens the Android download page at the local root URL. Build the static site with `npm run build`.

## Limits

This design raises the bar; it is not “unbreakable” and is not certified for state-level threats. A copied native vault can be attacked offline, so use a long, unique master password; the configured on-device attempt limit does not rate-limit guesses against a copied file. The current password KDF is PBKDF2-HMAC-SHA-256 with 600,000 iterations; a weak or reused password can still be guessed offline. The website, its delivery channel, or a rooted/jailbroken or otherwise compromised phone can inspect or alter app state or capture the password and plaintext. A client app can be reverse-engineered, and no app can guarantee physical erasure from flash storage or every operating-system snapshot. Do not rely on this app as the only safeguard for information whose exposure could put someone in danger.
