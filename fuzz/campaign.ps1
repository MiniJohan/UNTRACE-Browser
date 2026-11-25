# M8 fuzzing campaign (D-050): every target in parallel for $Seconds, then a summary.
# Run from the repository root:  powershell -File fuzz/campaign.ps1 [-Seconds 900] [-Only proxy_head,web_urls]
param([int]$Seconds = 900, [string[]]$Only = @())
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
$targets = @{
    proxy_head     = 4096
    web_urls       = 4096
    settings_file  = 8192
    block_list     = 65536
    cosmetic_rules = 65536
    user_input     = 4096
    request_match  = 4096
    bookmarks_file = 65536
}
cargo +nightly fuzz build --sanitizer none | Out-Null
$logs = Join-Path $PSScriptRoot 'logs'
New-Item -ItemType Directory -Force $logs | Out-Null
if ($Only.Count -gt 0) { foreach ($k in @($targets.Keys)) { if ($Only -notcontains $k) { $targets.Remove($k) } } }
$procs = foreach ($t in $targets.Keys) {
    $exe = Join-Path $PSScriptRoot "target\x86_64-pc-windows-msvc\release\$t.exe"
    $corpus = Join-Path $PSScriptRoot "corpus\$t"
    $art = Join-Path $PSScriptRoot "artifacts\$t"
    New-Item -ItemType Directory -Force $corpus, $art | Out-Null
    $fuzzArgs = @($corpus, "-max_total_time=$Seconds", '-timeout=10', '-rss_limit_mb=2048',
        "-max_len=$($targets[$t])", "-artifact_prefix=$art/", '-print_final_stats=1')
    Start-Process -FilePath $exe -ArgumentList $fuzzArgs -NoNewWindow -PassThru `
        -RedirectStandardError (Join-Path $logs "$t.log") -RedirectStandardOutput (Join-Path $logs "$t.out")
}
$procs | Wait-Process
foreach ($t in ($targets.Keys | Sort-Object)) {
    $log = Get-Content (Join-Path $logs "$t.log") -Raw
    $done = [regex]::Match($log, 'Done (\d+) runs in (\d+) second').Groups
    $cov = [regex]::Matches($log, 'cov: (\d+) ft: (\d+) corp: (\d+)') | Select-Object -Last 1
    $crash = if ($log -match 'panicked|deadly signal|ERROR: libFuzzer|SUMMARY') { 'FINDING' } else { 'no finding' }
    $artifacts = (Get-ChildItem (Join-Path $PSScriptRoot "artifacts\$t") -File -ErrorAction SilentlyContinue).Count
    "{0,-15} runs {1,12}  in {2,4} s  cov {3,5}  ft {4,6}  corpus {5,6}  {6}  artifacts {7}" -f $t, $done[1].Value, $done[2].Value,
        $cov.Groups[1].Value, $cov.Groups[2].Value, $cov.Groups[3].Value, $crash, $artifacts
}
