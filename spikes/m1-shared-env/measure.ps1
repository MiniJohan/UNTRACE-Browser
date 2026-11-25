<#
  D-003 experiment: memory of UNTRACE with a dedicated content environment vs. content views
  sharing the UI view's (Tauri-created) environment.
  Each run: fresh data folder, start the app, load the same loopback page in the first tab,
  wait, then sum all msedgewebview2.exe processes whose command line points at that run's
  data folder, plus untrace.exe itself.
#>
param(
  [Parameter(Mandatory)] [string]$Exe,
  [Parameter(Mandatory)] [string]$Work,
  [int]$Runs = 3,
  [string]$Out
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $Work | Out-Null
$log = Join-Path $Work 'server.log'
Remove-Item $log -ErrorAction SilentlyContinue
$server = Start-Process powershell -WindowStyle Hidden -PassThru -ArgumentList @(
  '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'testserver.ps1'),
  '-Seconds', [string](40 * $Runs * 2 + 30), '-Log', $log)
Start-Sleep -Seconds 2
$ws = New-Object -ComObject WScript.Shell
$results = @()

foreach ($run in 1..$Runs) {
  foreach ($mode in 'dedicated', 'shared') {
    $data = Join-Path $Work "$mode-$run"
    Remove-Item -Recurse -Force $data -ErrorAction SilentlyContinue
    $env:UNTRACE_DATA_DIR = $data
    if ($mode -eq 'shared') { $env:UNTRACE_EXPERIMENT_SHARED_ENV = '1' } else { Remove-Item Env:UNTRACE_EXPERIMENT_SHARED_ENV -ErrorAction SilentlyContinue }
    $hitsBefore = if (Test-Path $log) { (Get-Content $log | Where-Object { $_ -match ' /$' }).Count } else { 0 }

    $app = Start-Process -FilePath $Exe -PassThru
    Start-Sleep -Seconds 6
    [void]$ws.AppActivate($app.Id); Start-Sleep -Milliseconds 400
    $ws.SendKeys('^l'); Start-Sleep -Milliseconds 300
    $ws.SendKeys('http://localhost:8765/{ENTER}')
    Start-Sleep -Seconds 8

    $hitsAfter = if (Test-Path $log) { (Get-Content $log | Where-Object { $_ -match ' /$' }).Count } else { 0 }
    $procs = Get-CimInstance Win32_Process -Filter "Name='msedgewebview2.exe'" | Where-Object { $_.CommandLine -and $_.CommandLine.Contains($data) }
    $rows = foreach ($p in $procs) {
      $gp = Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
      if (-not $gp) { continue }
      [pscustomobject]@{
        type = if ($p.CommandLine -match '--type=(\S+)') { $Matches[1] } else { 'browser' }
        env  = if ($p.CommandLine -match [regex]::Escape((Join-Path $data 'content'))) { 'content' } else { 'ui' }
        priv = $gp.PrivateMemorySize64
        ws   = $gp.WorkingSet64
      }
    }
    $self = Get-Process -Id $app.Id
    $results += [pscustomobject]@{
      run = $run; mode = $mode; page_loaded = ($hitsAfter -gt $hitsBefore)
      webview2_processes = @($rows).Count
      browser_processes = @($rows | Where-Object type -eq 'browser').Count
      webview2_private_mb = [math]::Round((($rows | Measure-Object priv -Sum).Sum) / 1MB, 1)
      webview2_ws_mb = [math]::Round((($rows | Measure-Object ws -Sum).Sum) / 1MB, 1)
      untrace_private_mb = [math]::Round($self.PrivateMemorySize64 / 1MB, 1)
      by_type = ($rows | Group-Object env, type | ForEach-Object { "{0}={1:N0}MB" -f $_.Name.Replace(', ', '/'), (($_.Group | Measure-Object priv -Sum).Sum / 1MB) }) -join ' '
    }
    Stop-Process -Id $app.Id -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 4
  }
}
Stop-Process -Id $server.Id -ErrorAction SilentlyContinue
Remove-Item Env:UNTRACE_EXPERIMENT_SHARED_ENV -ErrorAction SilentlyContinue

$results | Format-Table run, mode, page_loaded, webview2_processes, browser_processes, webview2_private_mb, webview2_ws_mb, untrace_private_mb -AutoSize | Out-String -Width 200
$results | ForEach-Object { "{0}/{1}: {2}" -f $_.mode, $_.run, $_.by_type }
foreach ($m in 'dedicated', 'shared') {
  $r = $results | Where-Object mode -eq $m
  "{0,-9} median private {1} MB, median working set {2} MB" -f $m,
    (($r.webview2_private_mb | Sort-Object)[[int][math]::Floor($r.Count / 2)]),
    (($r.webview2_ws_mb | Sort-Object)[[int][math]::Floor($r.Count / 2)])
}
if ($Out) { $results | ConvertTo-Json -Depth 3 | Set-Content -Encoding utf8 $Out }
