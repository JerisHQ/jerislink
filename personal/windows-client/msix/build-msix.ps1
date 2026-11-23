<#
.SYNOPSIS
  Packages a built Jerislink.exe and JerisLinkSendTo.dll as an MSIX for the
  Microsoft Store.

.DESCRIPTION
  Produces, in -OutDir:
    Jerislink-<ver>.0-x64.msix         unsigned Store package (Partner Center re-signs it)
    Jerislink-<ver>.0-x64.msixupload   the same package in the Store upload container
  With -SideloadTest it also produces, in -OutDir\sideload:
    Jerislink-<ver>.0-x64-sideload.msix  signed with the fixed self-signed test certificate
    JerisLink-sideload-test.cer          the public half of that certificate
  The fixed test certificate comes from the environment variables
  MSIX_SIDELOAD_TEST_PFX (base64 PFX) and MSIX_SIDELOAD_TEST_PFX_PASSWORD, set
  from CI secrets; its public half is msix\JerisLink-sideload-test.cer. When
  they are not set, a throwaway certificate is created for this run only. Either
  way the private key is removed from the certificate store before the script
  exits. The test certificate never signs the Store package.

  The exe and the DLL must be built with -DJERISLINK_STATIC_CRT=ON so the
  package needs no VCLibs framework dependency. JerisLinkSendTo.dll is
  Explorer's "Send to JerisLink" command (send_to_shell.cpp); the manifest
  registers it, so it sits next to Jerislink.exe in the package root.
#>
param(
    [Parameter(Mandatory = $true)][string]$ExePath,
    [Parameter(Mandatory = $true)][string]$SendToDllPath,
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
Copy-Item $SendToDllPath (Join-Path $stage 'JerisLinkSendTo.dll')
Copy-Item (Join-Path $here 'Assets\*.png') (Join-Path $stage 'Assets')
# libopus is BSD-3-Clause: its notice ships with every binary.
Copy-Item (Join-Path $here '..\..\third_party\opus\COPYING') (Join-Path $stage 'COPYING-opus.txt')
$manifest = (Get-Content (Join-Path $here 'AppxManifest.xml.in') -Raw).Replace('@MSIX_VERSION@', $msixVersion)
if ($manifest -match '@[A-Z_]+@') { throw "unfilled placeholder in AppxManifest: $($Matches[0])" }
[IO.File]::WriteAllText((Join-Path $stage 'AppxManifest.xml'), $manifest, (New-Object Text.UTF8Encoding $false))

# The assets carry MRT qualifiers (scale-*, targetsize-*, altform-unplated), so
# Windows resolves them through resources.pri. One PRI file for the whole
# package: the <packaging> split into resource packs is only for bundles.
$makepri = Find-SdkTool 'makepri.exe'
$priConfig = Join-Path $OutDir 'priconfig.xml'
& $makepri createconfig /cf $priConfig /dq en-US /pv 10.0.0 /o
if ($LASTEXITCODE -ne 0) { throw "makepri createconfig failed: $LASTEXITCODE" }
[xml]$pc = Get-Content $priConfig
$pc.resources.SelectNodes('packaging') | ForEach-Object { [void]$pc.resources.RemoveChild($_) }
$pc.Save($priConfig)
& $makepri new /pr $stage /cf $priConfig /mn (Join-Path $stage 'AppxManifest.xml') /of (Join-Path $stage 'resources.pri') /o
if ($LASTEXITCODE -ne 0) { throw "makepri new failed: $LASTEXITCODE" }
Remove-Item $priConfig

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

    # Fixed test certificate: its PFX lives only in the CI secrets
    # MSIX_SIDELOAD_TEST_PFX (base64) and MSIX_SIDELOAD_TEST_PFX_PASSWORD.
    # Its public half is checked in as JerisLink-sideload-test.cer, so a tester
    # trusts it once. Without the secrets (forks, local runs) a throwaway
    # certificate is made for this run instead.
    $fixedCer = Join-Path $here 'JerisLink-sideload-test.cer'
    $pfxB64 = $env:MSIX_SIDELOAD_TEST_PFX
    $pfxPass = $env:MSIX_SIDELOAD_TEST_PFX_PASSWORD
    $pfxFile = $null
    if ($pfxB64 -and $pfxPass) {
        $pfxFile = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName() + '.pfx')
        [IO.File]::WriteAllBytes($pfxFile, [Convert]::FromBase64String($pfxB64.Trim()))
        try {
            $sec = ConvertTo-SecureString -String $pfxPass -AsPlainText -Force
            $cert = Import-PfxCertificate -FilePath $pfxFile -CertStoreLocation 'Cert:\CurrentUser\My' -Password $sec
        } finally {
            Remove-Item $pfxFile -Force -ErrorAction SilentlyContinue
        }
        $want = (New-Object Security.Cryptography.X509Certificates.X509Certificate2 $fixedCer).Thumbprint
        $kind = 'fixed'
    } else {
        Write-Host '::warning::MSIX_SIDELOAD_TEST_PFX secret not available: signing the sideload test package with a throwaway certificate. Testers must import this build''s .cer.'
        $cert = New-SelfSignedCertificate -Type Custom -Subject $subject `
            -KeyUsage DigitalSignature -FriendlyName 'JerisLink sideload test (CI, throwaway)' `
            -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddDays(90) `
            -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
        $want = $null
        $kind = 'throwaway'
    }
    try {
        if ($cert.Subject -ne $subject) { throw "sideload cert subject '$($cert.Subject)' is not the manifest Publisher '$subject'" }
        if ($want -and $cert.Thumbprint -ne $want) { throw "secret PFX thumbprint $($cert.Thumbprint) does not match msix/JerisLink-sideload-test.cer ($want)" }
        & $signtool sign /fd SHA256 /sha1 $cert.Thumbprint /s My $sideMsix
        if ($LASTEXITCODE -ne 0) { throw "signtool sign failed: $LASTEXITCODE" }
        if ($kind -eq 'fixed') {
            Copy-Item $fixedCer (Join-Path $side 'JerisLink-sideload-test.cer')
        } else {
            Export-Certificate -Cert $cert -FilePath (Join-Path $side 'JerisLink-sideload-test.cer') -Type CERT | Out-Null
        }
        Write-Host "Sideload test cert ($kind) thumbprint: $($cert.Thumbprint)"
    } finally {
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey -ErrorAction SilentlyContinue
    }
    Copy-Item (Join-Path $here 'INSTALL-SIDELOAD.txt') (Join-Path $side 'INSTALL.txt')
    Write-Host "Sideload test package: $sideMsix"
}
