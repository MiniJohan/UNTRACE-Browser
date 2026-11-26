# Releasing UNTRACE

Releases are published on GitHub Releases (D-016). The installer is per-user (no administrator rights) and carries Microsoft's WebView2 bootstrapper for machines without the engine. Every update is signed with UNTRACE's Ed25519 update key. The app installs an update only if the signature is valid and was made for exactly the version the manifest announces (`requireSignedVersion`).

## One-time setup

*Status (2026-11-25): steps 1 to 3 are done for [MiniJohan/UNTRACE-Browser](https://github.com/MiniJohan/UNTRACE-Browser); the key is kept outside the repository. Step 4 is not done (unsigned, D-016).*

1. **Repository.** Create the GitHub repository with public releases, and push this repository to it.
   - Under *Settings › Code security*, turn on **private vulnerability reporting**, the channel SECURITY.md names.
2. **Update key.** In a terminal of your own, outside this repository, run:

   ```powershell
   cargo tauri signer generate -w D:\keys\untrace-update.key
   ```

   - Choose a strong password when asked.
   - Keep the key file and the password apart and backed up offline. Without them no existing installation can ever be updated again; whoever has both can publish updates that installations will accept.
   - Never commit the key: `.gitignore` refuses `*.key`.
3. **Configuration.** In `app/src-tauri/tauri.conf.json` › `plugins.updater`:
   - set `pubkey` to the contents of `untrace-update.key.pub` (public, safe to commit);
   - set `endpoints` to `["https://github.com/<owner>/<repo>/releases/latest/download/latest.json"]`.

   Until both are set, UNTRACE says in Settings and Diagnostics that the build does not check for updates.
4. **Code signing (optional, D-016).** Without an Authenticode signature, SmartScreen warns on download. With a certificate in your certificate store, pass its thumbprint to the release script (`-CertificateThumbprint`). The installer is signed before its update signature is made.

## Each release

1. Update `README.md` and the ROADMAP status, and note what changed.
2. In a fresh terminal, give the script the key without writing the password anywhere:

   ```powershell
   $env:TAURI_SIGNING_PRIVATE_KEY = 'D:\keys\untrace-update.key'   # the key file's path
   $p = Read-Host 'Update key password' -AsSecureString
   $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p))
   ```

   All three lines and the build must run in the same window: a variable set in another window is not seen. Check the password before the long build, in that window. It signs a throw-away file; "Your file was signed successfully" means the password is right:

   ```powershell
   Set-Content "$env:TEMP\untrace-pw-test.txt" 'test'
   ```
   ```powershell
   cargo tauri signer sign -k (Get-Content $env:TAURI_SIGNING_PRIVATE_KEY -Raw).Trim() "$env:TEMP\untrace-pw-test.txt"
   ```

   "Wrong password for that key" means the build got a different password: typed differently (Caps Lock, keyboard layout), or none at all because `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` was not set in this window (the build then tries an empty password). If the test asks for a password instead, the variable is not set.
3. Build:

   ```powershell
   powershell -File scripts/release.ps1 -Version 1.0.0 -Notes "What changed, in one or two sentences"
   ```

   The script:
   - sets the version in `tauri.conf.json`, `Cargo.toml` and `app/ui/package.json`;
   - runs the full check (`scripts/check.ps1`) and stops if anything fails;
   - builds the installer with its update signature;
   - writes `release/<version>/`: the installer, `*.sig`, `latest.json` and `SHA256SUMS.txt`.
4. Close the terminal, so the key password leaves memory.
5. Commit the version change, tag it `v<version>`, and push the tag.
6. Create the GitHub release `v<version>` from the tag and attach the four files from `release/<version>/`. The updater finds `latest.json` through `releases/latest/download/`, so the newest release must be marked *latest*.
7. Run the release checklist below on the published installer.

## Release checklist

On the machine named in D-054, or on a clean Windows 11 machine before a public release:

- [ ] The installer runs without administrator rights, installs for the current user, and starts UNTRACE.
- [ ] The first start shows the welcome screen once; Settings › About shows the version, the licence, the privacy notice and the third-party notices.
- [ ] Diagnostics › Run self-check: every check passes (the certificate check needs the developer test server and shows as not run).
- [ ] Diagnostics › Updates finds a newer test release and installs it: UNTRACE restarts in the new version, and settings and data are kept.
- [ ] Uninstall (Settings › Apps): the program is removed. With "Delete the application data", `%LOCALAPPDATA%\UNTRACE` is removed too; without it, the data stays.
- [ ] **Clean machine only** (not covered on the development PC, D-054): on a Windows 11 machine without the WebView2 Runtime, the installer gets the runtime with its bootstrapper. No tool or folder from the development machine is needed.
- [ ] `SHA256SUMS.txt` matches the published installer.
