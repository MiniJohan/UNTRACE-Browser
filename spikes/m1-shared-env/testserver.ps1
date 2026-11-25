# Throwaway loopback page server for the D-003 measurement. Logs every request to $Log.
param([int]$Seconds = 180, [string]$Log)
$l = New-Object System.Net.HttpListener
$l.Prefixes.Add("http://localhost:8765/")
$l.Start()
$deadline = (Get-Date).AddSeconds($Seconds)
$task = $l.GetContextAsync()
while ((Get-Date) -lt $deadline) {
  if (-not $task.Wait(500)) { continue }
  $c = $task.Result
  $path = $c.Request.Url.AbsolutePath
  if ($Log) { Add-Content -Path $Log -Value "$(Get-Date -Format o) $path" }
  if ($path -eq '/favicon.ico') {
    $c.Response.StatusCode = 404; $c.Response.Close()
  } else {
    $html = "<!doctype html><title>Measurement page</title><body style='font:16px system-ui;padding:40px'><h1>Measurement page</h1><p>" + ('Lorem ipsum dolor sit amet. ' * 200) + "</p></body>"
    $b = [Text.Encoding]::UTF8.GetBytes($html)
    $c.Response.ContentType = 'text/html; charset=utf-8'
    $c.Response.OutputStream.Write($b, 0, $b.Length)
    $c.Response.Close()
  }
  $task = $l.GetContextAsync()
}
$l.Stop()
