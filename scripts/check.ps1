<#
  UNTRACE local check — the same steps CI runs.
    1. Rust formatting, lints (warnings are errors) and unit tests
    2. UI dependency install from the lockfile, audit, type-check and build
    3. Release build of the app
    4. End-to-end self-check of the real app (isolated data folder, no network), then a
       clean-exit check: closing the window ends the app and its engine processes
    5. cargo-deny / cargo-audit, if installed

  Usage:  powershell -File scripts/check.ps1 [-SkipSelfCheck]
  Long checkout paths: set CARGO_TARGET_DIR to a short folder (MSVC's linker is limited to 260 characters).
#>
param([switch]$SkipSelfCheck)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$failed = @()

function Invoke-Step([string]$Name, [scriptblock]$Body) {
    Write-Host "==> $Name" -ForegroundColor Cyan
    $global:LASTEXITCODE = 0
    & $Body
    if ($LASTEXITCODE -ne 0) {
        Write-Host "    FAILED ($LASTEXITCODE)" -ForegroundColor Red
        $script:failed += $Name
    }
}

Push-Location $root
try {
    Invoke-Step 'cargo fmt --check' { cargo fmt --all -- --check }
    Invoke-Step 'cargo clippy (deny warnings)' { cargo clippy --workspace --all-targets -- -D warnings }
    Invoke-Step 'cargo test' { cargo test --workspace }

    Push-Location (Join-Path $root 'app/ui')
    try {
        Invoke-Step 'npm ci' { npm ci --no-fund --no-audit }
        Invoke-Step 'npm audit (production deps)' { npm audit --omit=dev }
        Invoke-Step 'UI type-check and build' { npm run build }
    } finally { Pop-Location }

    # M9: the licences shipped with UNTRACE must match its dependencies (scripts/notices).
    Invoke-Step 'third-party notices up to date' { cargo run -q --release --manifest-path (Join-Path $root 'scripts/notices/Cargo.toml') -- --check }
    Invoke-Step 'cargo build --release' { cargo build --release -p untrace }

    if (-not $SkipSelfCheck) {
        $target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $root 'target' }
        $exe = Join-Path $target 'release/untrace.exe'
        $report = Join-Path $target 'untrace-self-check.json'
        # Test tooling: a local HTTPS server with a self-signed certificate (127.0.0.1 only).
        Invoke-Step 'build HTTPS test fixture' { cargo build --release -p untrace-webview --example tls_fixture }
        Invoke-Step 'self-check (real app, isolated data folder)' {
            $fixtureOut = Join-Path $target 'tls-fixture.out'
            Remove-Item $fixtureOut -ErrorAction SilentlyContinue
            $fixture = Start-Process -FilePath (Join-Path $target 'release/examples/tls_fixture.exe') `
                -ArgumentList '180' -RedirectStandardOutput $fixtureOut -WindowStyle Hidden -PassThru
            try {
                $port = $null
                foreach ($i in 1..50) {
                    if (Test-Path $fixtureOut) {
                        # The fixture still has the file open: read it with shared access.
                        $fs = [IO.File]::Open($fixtureOut, 'Open', 'Read', 'ReadWrite')
                        try { $line = (New-Object IO.StreamReader($fs)).ReadToEnd() } finally { $fs.Dispose() }
                        if ($line -match 'PORT (\d+)') { $port = $Matches[1]; break }
                    }
                    Start-Sleep -Milliseconds 100
                }
                if ($port) { $env:UNTRACE_SELFCHECK_TLS_URL = "https://127.0.0.1:$port/" }
                else { Write-Host '    HTTPS fixture did not start; the certificate check will be skipped' -ForegroundColor Yellow }
                $p = Start-Process -FilePath $exe -ArgumentList @('--self-check', "`"$report`"") -PassThru -Wait
                $text = [IO.File]::ReadAllText($report)
                Write-Host $text
                $global:LASTEXITCODE = $p.ExitCode
                # Inside this script every check must run: a skipped check is a failure here.
                if ($p.ExitCode -eq 0 -and ($text | ConvertFrom-Json).skipped.Count -gt 0) { $global:LASTEXITCODE = 2 }
            } finally {
                Remove-Item Env:UNTRACE_SELFCHECK_TLS_URL -ErrorAction SilentlyContinue
                if (-not $fixture.HasExited) { Stop-Process -Id $fixture.Id -Force }
            }
        }
        # Closing the window must end the process and its engine processes (M2 found a hang in
        # ExitProcess when WebView2 objects were released from thread-local teardown).
        Invoke-Step 'closes cleanly (real app, isolated data folder)' {
            $data = Join-Path $target 'exit-check-data'
            $saved = $env:UNTRACE_DATA_DIR
            $env:UNTRACE_DATA_DIR = $data
            try {
                # The single-instance plugin owns a helper window too, so find the main window by title.
                Add-Type 'using System; using System.Text; using System.Runtime.InteropServices; public static class UntraceWin { public delegate bool P(IntPtr h, IntPtr l); [DllImport("user32.dll")] static extern bool EnumWindows(P cb, IntPtr l); [DllImport("user32.dll")] static extern int GetWindowText(IntPtr h, StringBuilder s, int n); [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid); [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l); public static IntPtr Find(uint pid, string t) { IntPtr r = IntPtr.Zero; EnumWindows((h, l) => { uint p; GetWindowThreadProcessId(h, out p); if (p != pid) return true; var s = new StringBuilder(256); GetWindowText(h, s, 256); if (s.ToString() == t) { r = h; return false; } return true; }, IntPtr.Zero); return r; } }'
                $p = Start-Process -FilePath $exe -PassThru
                $win = [IntPtr]::Zero
                foreach ($i in 1..100) { $win = [UntraceWin]::Find([uint32]$p.Id, 'UNTRACE'); if ($win -ne [IntPtr]::Zero) { break }; Start-Sleep -Milliseconds 200 }
                Start-Sleep -Seconds 4   # let the engine and the first tab start
                [void][UntraceWin]::PostMessage($win, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)   # WM_CLOSE, like the title bar's X
                $exited = $p.WaitForExit(10000)
                # Engine processes notice the host is gone and exit on their own; allow them 10 s.
                $sw = [Diagnostics.Stopwatch]::StartNew()
                do {
                    $left = @(Get-CimInstance Win32_Process -Filter "Name='msedgewebview2.exe'" | Where-Object { $_.CommandLine -like "*$data*" })
                    if ($left.Count -eq 0) { break }
                    Start-Sleep -Milliseconds 250
                } while ($sw.ElapsedMilliseconds -lt 10000)
                # M4: "Delete the cache when UNTRACE closes" is on by default; the close must have
                # finished it and recorded the result.
                $record = Join-Path $data 'config/exit-clear.json'
                $clearState = if (Test-Path $record) { (Get-Content $record -Raw | ConvertFrom-Json).state } else { 'missing' }
                Write-Host "    exited: $exited$(if ($exited) { " (code $($p.ExitCode))" }); engine processes left after $($sw.ElapsedMilliseconds) ms: $($left.Count); cache cleared on exit: $clearState"
                $global:LASTEXITCODE = if ($exited -and $p.ExitCode -eq 0 -and $left.Count -eq 0 -and $clearState -eq 'done') { 0 } else { 3 }
                if (-not $exited) {
                    # A process stuck inside ExitProcess refuses TerminateProcess; end its last thread.
                    Add-Type 'using System; using System.Runtime.InteropServices; public static class UntraceTT { [DllImport("kernel32.dll")] public static extern IntPtr OpenThread(uint a, bool i, int t); [DllImport("kernel32.dll")] public static extern bool TerminateThread(IntPtr h, uint c); }'
                    foreach ($t in $p.Threads) { [void][UntraceTT]::TerminateThread([UntraceTT]::OpenThread(1, $false, $t.Id), 1) }
                }
                $left | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
            } finally {
                if ($null -eq $saved) { Remove-Item Env:UNTRACE_DATA_DIR -ErrorAction SilentlyContinue } else { $env:UNTRACE_DATA_DIR = $saved }
            }
        }
    }

    if (Get-Command cargo-deny -ErrorAction SilentlyContinue) {
        Invoke-Step 'cargo deny' { cargo deny check }
    } else { Write-Host '==> cargo deny: not installed (cargo install cargo-deny --locked), skipped' -ForegroundColor Yellow }
    if (Get-Command cargo-audit -ErrorAction SilentlyContinue) {
        Invoke-Step 'cargo audit' { cargo audit }
    } else { Write-Host '==> cargo audit: not installed (cargo install cargo-audit --locked), skipped' -ForegroundColor Yellow }
} finally { Pop-Location }

if ($failed.Count -gt 0) {
    Write-Host "FAILED: $($failed -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host 'All checks passed.' -ForegroundColor Green
