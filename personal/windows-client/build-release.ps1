param(
    [string]$Configuration = "Release"
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

$cmake = (Get-Command cmake -ErrorAction Stop).Source
& $cmake -S . -B build -G "Visual Studio 17 2022" -A x64
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed: $LASTEXITCODE" }

& $cmake --build build --config $Configuration --target Jerislink --parallel
if ($LASTEXITCODE -ne 0) { throw "Build failed: $LASTEXITCODE" }

$exe = Join-Path $here "build\$Configuration\Jerislink.exe"
if (-not (Test-Path $exe)) { throw "Executable was not found: $exe" }

$outDir = Join-Path $here "dist\portable"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
Copy-Item $exe (Join-Path $outDir "Jerislink.exe") -Force
Copy-Item (Join-Path $here "README-Windows.txt") (Join-Path $outDir "README.txt") -Force

$zip = Join-Path $here "dist\Jerislink-0.0.9.5-windows-x64-portable.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $outDir "*") -DestinationPath $zip

Write-Host "BUILD_OK = $exe"
Write-Host "PORTABLE_ZIP = $zip"
