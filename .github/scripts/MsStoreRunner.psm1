# Helpers for msstore-publish.yml and msstore-publish-check.yml (Windows runners, pwsh).
#
# Written against Microsoft Store Developer CLI v0.4.4, the version both workflows
# pin. What the CLI does there (MSStore.CLI source at tag v0.4.4):
# - `msstore publish <pathOrUrl>`: the MSIX publisher takes pathOrUrl as the
#   package file itself and accepts it only if its extension is exactly (ordinal,
#   case-sensitive) .msix, .msixbundle or .msixupload. A folder is not a package.
#   There is no --inputFile option; -i/--inputDirectory is unused for MSIX files.
# - `msstore reconfigure` stores the client secret as a Windows generic credential
#   "MicrosoftStoreCli:user=<clientId>" (persist LocalMachine), and settings.json
#   plus the MSAL token cache under %LOCALAPPDATA%\Microsoft\MSStore.CLI.
# - `msstore reconfigure --reset` always asks a y/n question and throws
#   "Failed to read input in non-interactive mode" on a runner, so it cannot be
#   used in CI. Clear-MsStoreCliState removes the same things directly.

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:CredentialPrefix = 'MicrosoftStoreCli:'
$script:StateDir = Join-Path $env:LOCALAPPDATA 'Microsoft\MSStore.CLI'

if (-not ('JerisLink.WinCred' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace JerisLink {
  public static class WinCred {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CREDENTIAL {
      public int Flags;
      public int Type;
      public string TargetName;
      public string Comment;
      public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
      public int CredentialBlobSize;
      public IntPtr CredentialBlob;
      public int Persist;
      public int AttributeCount;
      public IntPtr Attributes;
      public string TargetAlias;
      public string UserName;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CredEnumerateW(string filter, int flags, out int count, out IntPtr credentials);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CredDeleteW(string target, int type, int flags);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CredWriteW(ref CREDENTIAL credential, int flags);
    [DllImport("advapi32.dll")]
    static extern void CredFree(IntPtr buffer);

    const int ERROR_NOT_FOUND = 1168;

    // Target name and type of every credential matching filter (e.g. "Prefix:*").
    public static List<KeyValuePair<string, int>> List(string filter) {
      var result = new List<KeyValuePair<string, int>>();
      int count; IntPtr list;
      if (!CredEnumerateW(filter, 0, out count, out list)) {
        int err = Marshal.GetLastWin32Error();
        if (err == ERROR_NOT_FOUND) return result;
        throw new Win32Exception(err);
      }
      try {
        for (int i = 0; i < count; i++) {
          IntPtr p = Marshal.ReadIntPtr(list, i * IntPtr.Size);
          var c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
          result.Add(new KeyValuePair<string, int>(c.TargetName, c.Type));
        }
      } finally { CredFree(list); }
      return result;
    }

    public static void Delete(string target, int type) {
      if (!CredDeleteW(target, type, 0)) {
        int err = Marshal.GetLastWin32Error();
        if (err != ERROR_NOT_FOUND) throw new Win32Exception(err);
      }
    }

    // Generic credential, persist LocalMachine: the same shape the CLI writes.
    public static void WriteGeneric(string target, string userName, string secret) {
      byte[] blob = Encoding.Unicode.GetBytes(secret);
      IntPtr p = Marshal.AllocHGlobal(blob.Length);
      try {
        Marshal.Copy(blob, 0, p, blob.Length);
        var c = new CREDENTIAL { Type = 1, TargetName = target, UserName = userName,
                                 CredentialBlobSize = blob.Length, CredentialBlob = p, Persist = 2 };
        if (!CredWriteW(ref c, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
      } finally { Marshal.FreeHGlobal(p); }
    }
  }
}
'@
}

function Get-MsStoreCliCredentialTargets {
  [JerisLink.WinCred]::List("$($script:CredentialPrefix)*") | ForEach-Object { $_.Key }
}

# Removes every MSStore CLI credential and the CLI's settings/token cache folder,
# then checks both are gone. Throws if anything is left. Prints no secret values
# (target names hold the client id, which GitHub masks as a secret in logs).
function Clear-MsStoreCliState {
  $creds = @([JerisLink.WinCred]::List("$($script:CredentialPrefix)*"))
  foreach ($c in $creds) { [JerisLink.WinCred]::Delete($c.Key, $c.Value) }
  if (Test-Path -LiteralPath $script:StateDir) { Remove-Item -LiteralPath $script:StateDir -Recurse -Force }

  $left = @(Get-MsStoreCliCredentialTargets)
  if ($left.Count -ne 0) { throw "$($left.Count) MSStore CLI credential(s) still in Credential Manager" }
  if (Test-Path -LiteralPath $script:StateDir) { throw "$($script:StateDir) still exists" }
  Write-Host "MSStore CLI state cleared: removed $($creds.Count) credential(s); $($script:StateDir) is gone"
}

# Writes a throwaway CLI configuration (dummy ids, dummy secret) exactly where and
# how `msstore reconfigure` stores a real one. Test use only (msstore-publish-check).
function Set-MsStoreCliDummyState {
  param([Parameter(Mandatory)][string]$DevCenterServiceUrl)
  $clientId = [guid]::NewGuid().ToString()
  New-Item -ItemType Directory -Force -Path $script:StateDir | Out-Null
  [ordered]@{
    SellerId            = 1
    TenantId            = '00000000-0000-0000-0000-000000000000'
    ClientId            = $clientId
    DevCenterServiceUrl = $DevCenterServiceUrl
  } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $script:StateDir 'settings.json') -Encoding utf8NoBOM
  [JerisLink.WinCred]::WriteGeneric("$($script:CredentialPrefix)user=$clientId", $clientId, 'dummy-not-a-secret')
  New-Item -ItemType Directory -Force -Path (Join-Path $script:StateDir 'Cache') | Out-Null
  Set-Content -LiteralPath (Join-Path $script:StateDir 'Cache\msstore_msal_cache.txt') -Value 'dummy'
  $clientId
}

# Finds the one Store package in $Dir and checks its identity and version.
# Returns the full path of the .msixupload, which is what `msstore publish` takes.
function Get-StorePackage {
  param(
    [Parameter(Mandatory)][string]$Dir,
    [Parameter(Mandatory)][string]$ExpectedName,
    [Parameter(Mandatory)][string]$ExpectedPublisher,
    [string]$ExpectedVersion = ''
  )
  $all = @(Get-ChildItem -LiteralPath $Dir -File | Where-Object { $_.Name -like '*.msixupload' })
  if ($all.Count -ne 1) { throw "expected exactly one .msixupload in $Dir, found $($all.Count)" }
  $upload = $all[0]
  # The CLI compares the extension ordinally; a .MSIXUPLOAD would be rejected there.
  if ($upload.Extension -cne '.msixupload') { throw "extension '$($upload.Extension)' is not exactly .msixupload" }
  if ($upload.Length -le 0) { throw "$($upload.Name) is empty" }

  $work = Join-Path ([IO.Path]::GetTempPath()) ("msix-inspect-" + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory $work | Out-Null
  try {
    Copy-Item -LiteralPath $upload.FullName (Join-Path $work 'upload.zip')
    Expand-Archive (Join-Path $work 'upload.zip') (Join-Path $work 'upload')
    $msix = @(Get-ChildItem (Join-Path $work 'upload') -Filter *.msix)
    if ($msix.Count -ne 1) { throw "expected one .msix inside the .msixupload, found $($msix.Count)" }
    Copy-Item -LiteralPath $msix[0].FullName (Join-Path $work 'pkg.zip')
    Expand-Archive (Join-Path $work 'pkg.zip') (Join-Path $work 'pkg')
    [xml]$m = Get-Content (Join-Path $work 'pkg\AppxManifest.xml')
    $id = $m.Package.Identity
    Write-Host "Identity Name=$($id.Name) Publisher=$($id.Publisher) Version=$($id.Version)"
    if ($id.Name -ne $ExpectedName) { throw "unexpected Identity Name" }
    if ($id.Publisher -ne $ExpectedPublisher) { throw "unexpected Identity Publisher" }
    if ($id.Version -notmatch '^\d+\.\d+\.\d+\.0$') { throw "Store versions must end in .0" }
    if ($ExpectedVersion -and $id.Version -ne $ExpectedVersion) { throw "package version $($id.Version) does not match the release ($ExpectedVersion)" }
  } finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  }
  Write-Host ((Get-FileHash -LiteralPath $upload.FullName -Algorithm SHA256).Hash.ToLower() + '  ' + $upload.Name)
  $upload.FullName
}

Export-ModuleMember -Function Get-StorePackage, Clear-MsStoreCliState, Set-MsStoreCliDummyState, Get-MsStoreCliCredentialTargets
