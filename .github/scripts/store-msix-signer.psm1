# Signer policy for the Store-signed MSIX (store-msix-to-release.yml, verify).
# The verify job reads these values from the real signature and from the chain
# it built; this module only decides on them, so store-msix-signer.test.ps1 can
# run every rule without a certificate.
#
# Accepted issuers are named one by one. The Store signed JerisLink with:
# - CN=Microsoft Marketplace CA G 023, OU=AOC (0.3.0.0, run 45129684649)
# - CN=Microsoft Marketplace CA G 026, OU=EOC (0.4.1.0, run 45559045182)
# Any other OU fails. Whatever the issuer, the chain root must be Microsoft
# Root Certificate Authority 2011, by thumbprint.

Set-StrictMode -Version Latest

$StoreIssuerPattern = '^CN=Microsoft Marketplace CA G \d+, OU=(AOC|EOC), O=Microsoft Corporation,'

function Assert-StoreSigner {
  param(
    [Parameter(Mandatory)][string]$Subject,
    [Parameter(Mandatory)][string]$Issuer,
    [Parameter(Mandatory)][string]$Thumbprint,
    [Parameter(Mandatory)][string]$RootSubject,
    [Parameter(Mandatory)][string]$RootThumbprint,
    [Parameter(Mandatory)][string]$ExpectedPublisher,
    [Parameter(Mandatory)][string]$TestCertThumbprint,
    [Parameter(Mandatory)][string]$MsRootThumbprint
  )
  if ($Thumbprint -eq $TestCertThumbprint) { throw "signed with the sideload test certificate" }
  if ($Subject -eq $Issuer) { throw "signer certificate is self-signed" }
  if ($Subject -cne $ExpectedPublisher) { throw "signer subject is not the package publisher" }
  if ($Issuer -notmatch $StoreIssuerPattern) { throw "signer issuer is not a Microsoft Marketplace CA" }
  if ($RootThumbprint -ne $MsRootThumbprint) { throw "chain root is not Microsoft Root Certificate Authority 2011: $RootSubject $RootThumbprint" }
}

Export-ModuleMember -Function Assert-StoreSigner
