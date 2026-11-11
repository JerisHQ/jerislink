$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here
$version = (Get-Content (Join-Path $here "..\..\VERSION") -TotalCount 1).Trim()

& (Join-Path $here "build-release.ps1")
if ($LASTEXITCODE -ne 0) { throw "Jerislink release build failed: $LASTEXITCODE" }

$candidates = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles(x86)\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
)
$iscc = $null
foreach ($candidate in $candidates) {
    if ($candidate -and (Test-Path $candidate)) { $iscc = $candidate; break }
}
if (-not $iscc) {
    $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($cmd) { $iscc = $cmd.Source }
}
if (-not $iscc) {
    throw "Inno Setup 6 was not found. Portable ZIP was built successfully; install Inno Setup 6 to produce the setup EXE."
}

& $iscc (Join-Path $here "Jerislink.iss")
if ($LASTEXITCODE -ne 0) { throw "Inno Setup compile failed: $LASTEXITCODE" }

$setup = Join-Path $here "dist\Jerislink-$version-windows-x64-setup.exe"
if (-not (Test-Path $setup)) { throw "Installer compile completed but setup EXE was not found: $setup" }
Write-Host "INSTALLER_OK = $setup"
