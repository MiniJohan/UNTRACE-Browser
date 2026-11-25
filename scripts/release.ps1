# UNTRACE release build (D-016). See RELEASING.md for the one-time setup and the steps around it.
#
#   $env:TAURI_SIGNING_PRIVATE_KEY = 'D:\keys\untrace-update.key'   # the key file, outside the repository
#   $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = Read-Host -AsSecureString ... (see RELEASING.md)
#   powershell -File scripts/release.ps1 -Version 1.0.0 -Notes "First release"
#
# Output: release/<version>/ with the installer, its update signature, latest.json and
# SHA256SUMS.txt, ready to attach to the GitHub release v<version>.
param(
    [Parameter(Mandatory = $true)] [string]$Version,
    [string]$Notes = '',
    # Optional Authenticode signing (D-016: not yet bought). Thumbprint of a certificate in the
    # current user's store; Tauri signs before it computes the update signature.
    [string]$CertificateThumbprint = '',
    [string]$TimestampUrl = 'http://timestamp.digicert.com',
    # Test builds only: a JSON file merged into tauri.conf.json (e.g. a local update address and
    # a test key), and the address the installer is downloaded from.
    [string]$TestConfig = '',
    [string]$DownloadBase = '',
    [switch]$SkipCheck
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Version must look like 1.2.3 (got '$Version')." }
if (-not $env:TAURI_SIGNING_PRIVATE_KEY) {
    throw 'The update signing key is not set in this shell (TAURI_SIGNING_PRIVATE_KEY = path of the key file, see RELEASING.md).'
}

# The build must know where to look for updates and which key to trust, or the release would
# never update itself.
$confPath = Join-Path $root 'app/src-tauri/tauri.conf.json'
$conf = Get-Content $confPath -Raw | ConvertFrom-Json
$upd = $conf.plugins.updater
if ($TestConfig) {
    $test = Get-Content $TestConfig -Raw | ConvertFrom-Json
    if ($test.plugins.updater.pubkey) { $upd = $test.plugins.updater }
}
if (-not $upd.pubkey -or @($upd.endpoints).Count -eq 0) {
    throw 'tauri.conf.json has no update public key or address (plugins.updater); see RELEASING.md.'
}
if (-not $upd.requireSignedVersion) { throw 'plugins.updater.requireSignedVersion must be true.' }

# One version everywhere: the installer, the app's About page and the update manifest.
function Set-Version([string]$path, [string]$pattern, [string]$replacement) {
    $text = [IO.File]::ReadAllText($path)
    $rx = [regex]$pattern
    if (-not $rx.IsMatch($text)) { throw "No version found in $path" }
    [IO.File]::WriteAllText($path, $rx.Replace($text, $replacement, 1))
}
Set-Version $confPath '"version":\s*"\d+\.\d+\.\d+"' "`"version`": `"$Version`""
Set-Version (Join-Path $root 'Cargo.toml') '(?m)^version = "\d+\.\d+\.\d+"' "version = `"$Version`""
Set-Version (Join-Path $root 'app/ui/package.json') '"version":\s*"\d+\.\d+\.\d+"' "`"version`": `"$Version`""

if (-not $SkipCheck) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'scripts/check.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'The full check failed; no release was built.' }
}

# Build the UI and the installer, with the update signature (and Authenticode if configured).
Push-Location (Join-Path $root 'app/ui'); npm run build; if ($LASTEXITCODE -ne 0) { throw 'UI build failed' }; Pop-Location
$override = @{ bundle = @{ createUpdaterArtifacts = $true } }
if ($CertificateThumbprint) {
    $override.bundle.windows = @{ certificateThumbprint = $CertificateThumbprint; digestAlgorithm = 'sha256'; timestampUrl = $TimestampUrl }
}
$overridePath = Join-Path $env:TEMP "untrace-release-$Version.json"
[IO.File]::WriteAllText($overridePath, ($override | ConvertTo-Json -Depth 5))   # no BOM
$configs = @('--config', $overridePath)
if ($TestConfig) { $configs += @('--config', (Resolve-Path $TestConfig).Path) }
Push-Location (Join-Path $root 'app/src-tauri')
cargo tauri build --bundles nsis @configs
$built = $LASTEXITCODE
Pop-Location
Remove-Item $overridePath -ErrorAction SilentlyContinue
if ($built -ne 0) { throw 'The installer build failed.' }

$target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $root 'target' }
$name = "UNTRACE_${Version}_x64-setup.exe"
$exe = Join-Path $target "release/bundle/nsis/$name"
$sig = "$exe.sig"
if (-not (Test-Path $exe) -or -not (Test-Path $sig)) { throw "Missing $name or its update signature." }

# The update manifest the updater reads (latest.json), pointing at this release's installer.
if (-not $DownloadBase) {
    $endpoint = [string]@($upd.endpoints)[0]
    if ($endpoint -notmatch '^https://github\.com/([^/]+/[^/]+)/releases/') {
        throw "Cannot derive the download address from $endpoint; pass -DownloadBase."
    }
    $DownloadBase = "https://github.com/$($Matches[1])/releases/download/v$Version"
}
$out = Join-Path $root "release/$Version"
New-Item -ItemType Directory -Force $out | Out-Null
Copy-Item $exe, $sig $out
$manifest = [ordered]@{
    version   = $Version
    notes     = $Notes
    pub_date  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    platforms = [ordered]@{
        'windows-x86_64' = [ordered]@{
            signature = (Get-Content $sig -Raw).Trim()
            url       = "$DownloadBase/$name"
        }
    }
}
[IO.File]::WriteAllText((Join-Path $out 'latest.json'), ($manifest | ConvertTo-Json -Depth 5))
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
[IO.File]::WriteAllText((Join-Path $out 'SHA256SUMS.txt'), "$hash  $name`n")

Write-Host "Release $Version is in $out" -ForegroundColor Green
Get-ChildItem $out | ForEach-Object { Write-Host ("  {0,-40} {1,12:N0} bytes" -f $_.Name, $_.Length) }
if (-not $CertificateThumbprint) {
    Write-Host 'Not Authenticode-signed: Windows SmartScreen will warn about this installer (D-016).' -ForegroundColor Yellow
}
