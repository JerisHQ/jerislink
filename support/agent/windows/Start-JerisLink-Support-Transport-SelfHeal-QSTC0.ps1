$ErrorActionPreference = 'Stop'

$base = if ($env:JERISLINK_SUPPORT_HOME) { $env:JERISLINK_SUPPORT_HOME } else { Join-Path $env:LOCALAPPDATA 'JerisLink Support' }
$exe = Join-Path $base 'bin\jeris-support-transport-windows-amd64.exe'
$addr = Join-Path $base 'config\jls-qstc0-addr.txt'
$logs = Join-Path $base 'logs'
$stdoutLog = Join-Path $logs 'transport-selfheal.stdout.log'
$stderrLog = Join-Path $logs 'transport-selfheal.stderr.log'
$pidFile = Join-Path $logs 'transport-selfheal.pid'

New-Item -ItemType Directory -Force -Path $logs | Out-Null

Get-Process 'jeris-support-transport-windows-amd64' -ErrorAction SilentlyContinue |
    Stop-Process -Force
Start-Sleep -Milliseconds 500

if (-not (Test-Path $exe)) {
    throw "Support transport helper not found: $exe"
}
if (-not (Test-Path $addr)) {
    throw "Tailcat address file not found: $addr"
}

Remove-Item $stdoutLog, $stderrLog, $pidFile -ErrorAction SilentlyContinue

$argumentLine = 'client --tailcat-file "' + $addr + '" --stats-every 2s --health-every 5s --health-failures 2 --restart-backoff 1s --restart-backoff-max 30s'

$startParams = @{
    FilePath = $exe
    ArgumentList = $argumentLine
    WindowStyle = 'Minimized'
    RedirectStandardOutput = $stdoutLog
    RedirectStandardError = $stderrLog
    PassThru = $true
}

$p = Start-Process @startParams
Set-Content -Path $pidFile -Value $p.Id -NoNewline

Write-Host "JerisLink Support self-heal transport started. PID=$($p.Id)"
Write-Host "Logs:"
Write-Host "  $stdoutLog"
Write-Host "  $stderrLog"
