# pwsh -NoProfile -File .github/scripts/store-msix-signer.test.ps1
# Tests for store-msix-signer.psm1. Plain PowerShell, no Pester or other module.
# Subjects, issuers and thumbprints are the ones the verify job logged for the
# real Store packages (runs 45129684649 and 45559045182).

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'store-msix-signer.psm1') -Force

$publisher = 'CN=89A018EB-5C52-49CB-B478-B462FA6B08DD'
$msRoot = '8F43288AD272F3103B6FB1428485EA3014C0BCFE'
$msRootSubject = 'CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
$otherRoot = '1111111111111111111111111111111111111111'
$otherRootSubject = 'CN=Contoso Root CA, O=Contoso, C=US'
$testCert = '5E6E211F60E17FFD44F7772BE0E8C11E40DD6661'
$eoc = 'CN=Microsoft Marketplace CA G 026, OU=EOC, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
$aoc = 'CN=Microsoft Marketplace CA G 023, OU=AOC, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'

# The 0.4.1.0 signer (run 45559045182); each case changes some fields.
$base = @{
  Subject            = $publisher
  Issuer             = $eoc
  Thumbprint         = '98CA2144EF5264C8B9CD2D664493EBA7D79D23FF'
  RootSubject        = $msRootSubject
  RootThumbprint     = $msRoot
  ExpectedPublisher  = $publisher
  TestCertThumbprint = $testCert
  MsRootThumbprint   = $msRoot
}

$issuerError = 'signer issuer is not a Microsoft Marketplace CA'
$rootError = 'chain root is not Microsoft Root Certificate Authority 2011'
$cases = @(
  @{ Name = 'OU=EOC (G 026, 0.4.1.0) with the Microsoft Root 2011 root passes'; Set = @{}; Error = $null }
  @{ Name = 'OU=AOC (G 023, 0.3.0.0) with the Microsoft Root 2011 root passes'; Set = @{ Issuer = $aoc; Thumbprint = 'FEA8A2C4053DC38A4A46B3BC842426A930BC1773' }; Error = $null }
  @{ Name = 'OU=EOC with another root fails'; Set = @{ RootSubject = $otherRootSubject; RootThumbprint = $otherRoot }; Error = $rootError }
  @{ Name = 'OU=EOC with the right root subject but another root thumbprint fails'; Set = @{ RootThumbprint = $otherRoot }; Error = $rootError }
  @{ Name = 'OU=AOC with another root fails'; Set = @{ Issuer = $aoc; RootSubject = $otherRootSubject; RootThumbprint = $otherRoot }; Error = $rootError }
  @{ Name = 'another OU fails'; Set = @{ Issuer = 'CN=Microsoft Marketplace CA G 026, OU=XOC, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' }; Error = $issuerError }
  @{ Name = 'an OU that only starts with EOC fails'; Set = @{ Issuer = 'CN=Microsoft Marketplace CA G 026, OU=EOCX, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' }; Error = $issuerError }
  @{ Name = 'no OU fails'; Set = @{ Issuer = 'CN=Microsoft Marketplace CA G 026, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' }; Error = $issuerError }
  @{ Name = 'OU=EOC from another organisation fails'; Set = @{ Issuer = 'CN=Microsoft Marketplace CA G 026, OU=EOC, O=Contoso, C=US' }; Error = $issuerError }
  @{ Name = 'OU=EOC under another CA name fails'; Set = @{ Issuer = 'CN=Contoso CN=Microsoft Marketplace CA G 026, OU=EOC, O=Microsoft Corporation, C=US' }; Error = $issuerError }
  @{ Name = 'the sideload test certificate fails'; Set = @{ Thumbprint = $testCert }; Error = 'signed with the sideload test certificate' }
  @{ Name = 'a self-signed signer fails'; Set = @{ Issuer = $publisher }; Error = 'signer certificate is self-signed' }
  @{ Name = 'a signer that is not the package publisher fails'; Set = @{ Subject = 'CN=00000000-0000-0000-0000-000000000000' }; Error = 'signer subject is not the package publisher' }
)

$failed = 0
foreach ($c in $cases) {
  $p = $base.Clone()
  foreach ($k in $c.Set.Keys) { $p[$k] = $c.Set[$k] }
  $got = $null
  try { Assert-StoreSigner @p } catch { $got = $_.Exception.Message }
  $ok = if ($null -eq $c.Error) { $null -eq $got } else { $null -ne $got -and $got.StartsWith($c.Error) }
  if ($ok) {
    Write-Host "ok   $($c.Name)"
  } else {
    $failed++
    $want = if ($null -eq $c.Error) { 'pass' } else { "error '$($c.Error)'" }
    $have = if ($null -eq $got) { 'pass' } else { "error '$got'" }
    Write-Host "FAIL $($c.Name): want $want, got $have"
  }
}
Write-Host "tests $($cases.Count), pass $($cases.Count - $failed), fail $failed"
if ($failed -ne 0) { exit 1 }
