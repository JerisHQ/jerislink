<#
.SYNOPSIS
  Packages a built Jerislink.exe as an MSIX for the Microsoft Store.

.DESCRIPTION
  Produces, in -OutDir:
    Jerislink-<ver>.0-x64.msix         unsigned Store package (Partner Center re-signs it)
    Jerislink-<ver>.0-x64.msixupload   the same package in the Store upload container
  With -SideloadTest it also produces, in -OutDir\sideload:
    Jerislink-<ver>.0-x64-sideload.msix  signed with a throwaway self-signed certificate
    JerisLink-sideload-test.cer          the public half of that certificate
  The self-signed certificate is created for this run only. Its private key is
  never exported and is deleted from the certificate store before the script exits.

  The exe must be built with -DJERISLINK_STATIC_CRT=ON so the package needs no
  VCLibs framework dependency.
#>
param(
    [Parameter(Mandatory = $true)][string]$ExePath,
    [Parameter(Mandatory = $true)][string]$OutDir,
    [switch]$SideloadTest
)
$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$root = Resolve-Path (Join-Path $here '..\..\..')
$semver = (Get-Content (Join-Path $root 'VERSION') -TotalCount 1).Trim()
if ($semver -notmatch '^\d+\.\d+\.\d+$') { throw "VERSION must be MAJOR.MINOR.PATCH, got '$semver'" }
$msixVersion = "$semver.0"

function Find-SdkTool([string]$name) {
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $tool = Get-ChildItem -Path $kits -Recurse -Filter $name -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\' } |
        Sort-Object { [version]($_.FullName -replace '.*\\bin\\([\d\.]+)\\.*', '$1') } -Descending |
        Select-Object -First 1
    if (-not $tool) { throw "$name not found under $kits" }
    return $tool.FullName
}
$makeappx = Find-SdkTool 'makeappx.exe'
Write-Host "makeappx: $makeappx"

# Stage the package layout.
$stage = Join-Path $OutDir 'msix-layout'
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path (Join-Path $stage 'Assets') | Out-Null
Copy-Item $ExePath (Join-Path $stage 'Jerislink.exe')
Copy-Item (Join-Path $here 'Assets\*.png') (Join-Path $stage 'Assets')
$manifest = (Get-Content (Join-Path $here 'AppxManifest.xml.in') -Raw).Replace('@MSIX_VERSION@', $msixVersion)
if ($manifest -match '@[A-Z_]+@') { throw "unfilled placeholder in AppxManifest: $($Matches[0])" }
[IO.File]::WriteAllText((Join-Path $stage 'AppxManifest.xml'), $manifest, (New-Object Text.UTF8Encoding $false))

# Pack. makeappx validates the manifest against the schema.
$base = "Jerislink-$msixVersion-x64"
$msix = Join-Path $OutDir "$base.msix"
& $makeappx pack /o /h SHA256 /d $stage /p $msix
if ($LASTEXITCODE -ne 0) { throw "makeappx pack failed: $LASTEXITCODE" }

# .msixupload is a zip that holds the .msix (symbols could be added later as .appxsym).
$upload = Join-Path $OutDir "$base.msixupload"
$tmpZip = Join-Path $OutDir "$base.msixupload.zip"
Remove-Item $upload, $tmpZip -ErrorAction SilentlyContinue
Compress-Archive -Path $msix -DestinationPath $tmpZip
Move-Item $tmpZip $upload
Write-Host "Store package: $msix"
Write-Host "Store upload:  $upload"

if ($SideloadTest) {
    $signtool = Find-SdkTool 'signtool.exe'
    $side = Join-Path $OutDir 'sideload'
    New-Item -ItemType Directory -Force -Path $side | Out-Null
    $sideMsix = Join-Path $side "$base-sideload.msix"
    Copy-Item $msix $sideMsix

    # The certificate subject must equal the manifest Publisher.
    if ($manifest -notmatch 'Publisher="(CN=[^"]+)"') { throw 'Publisher not found in manifest' }
    $subject = $Matches[1]
    $cert = New-SelfSignedCertificate -Type Custom -Subject $subject `
        -KeyUsage DigitalSignature -FriendlyName 'JerisLink sideload test (CI, throwaway)' `
        -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddDays(90) `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
    try {
        & $signtool sign /fd SHA256 /sha1 $cert.Thumbprint /s My $sideMsix
        if ($LASTEXITCODE -ne 0) { throw "signtool sign failed: $LASTEXITCODE" }
        Export-Certificate -Cert $cert -FilePath (Join-Path $side 'JerisLink-sideload-test.cer') -Type CERT | Out-Null
        Write-Host "Sideload test cert thumbprint: $($cert.Thumbprint)"
    } finally {
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey -ErrorAction SilentlyContinue
    }
    Copy-Item (Join-Path $here 'INSTALL-SIDELOAD.txt') (Join-Path $side 'INSTALL.txt')
    Write-Host "Sideload test package: $sideMsix"
}
