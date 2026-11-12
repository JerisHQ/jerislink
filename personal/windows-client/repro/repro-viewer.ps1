# Windows side of the host-events repro. Starts the viewer without the control
# channel (so it never changes host settings), keeps it running for $secs, then
# reports whether it was still alive and copies its log.
#   repro-viewer.ps1 -exe <Jerislink.exe> -tag <name> [-secs 100] [-bindIp ip] [-sourceIp ip]
param([string]$exe,[string]$tag,[int]$secs=100,[string]$bindIp='100.64.0.6',[string]$sourceIp='100.64.0.25')
$d = Split-Path $exe
$log = "$env:TEMP\jerislink-viewer.log"
Remove-Item $log -ErrorAction SilentlyContinue
$args = @('--no-control','--bind-ip',$bindIp,'--source-ip',$sourceIp,'--codec','h264',
          '--width','1920','--height','1080','--startup-timeout-ms','60000')
$p = Start-Process $exe -ArgumentList $args -PassThru
$t0 = Get-Date
while (((Get-Date) - $t0).TotalSeconds -lt $secs -and -not $p.HasExited) { Start-Sleep 1 }
$alive = -not $p.HasExited
$ranFor = [int]((Get-Date) - $t0).TotalSeconds
if ($alive) {
  $p.CloseMainWindow() | Out-Null
  if (-not $p.WaitForExit(15000)) { $p.Kill(); 'killed' | Out-File "$d\repro-killed-$tag.txt" }
}
"alive_at_end=$alive ran_s=$ranFor exit=$($p.ExitCode)" | Out-File "$d\repro-result-$tag.txt"
Copy-Item $log "$d\repro-viewer-$tag.log" -ErrorAction SilentlyContinue
"done" | Out-File "$d\repro-done-$tag.txt"
