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
#   plus the interactive MSAL token cache under %LOCALAPPDATA%\Microsoft\MSStore.CLI.
# - Every Partner Center call signs in with the client secret through
#   MSStore.API (SubmissionClient.CreateAppAsync), which keeps its own MSAL token
#   cache in %LOCALAPPDATA%\Microsoft\MSStore.API\Cache (msstore_msal_cache.txt).
#   Clear-MsStoreCliState removes that folder too.
# - `msstore publish` for an app that already has a published submission
#   DELETES the app's pending submission before it creates a new draft
#   (IStorePackagedAPIExtensions.PublishAsync); with no published submission it
#   reuses the pending one. Assert-NoPendingSubmission runs `msstore apps get`
#   first and stops if any pending submission exists, so nothing is deleted.
# - `msstore publish` without --noCommit commits the submission
#   (CommitSubmissionAsync), polls its status while it is CommitStarted, and
#   exits non-zero on CommitFailed. Partner Center only takes in the uploaded
#   package on that commit. A draft left uncommitted and then submitted from the
#   Partner Center UI ships the packages cloned from the live submission instead.
# - `msstore submission get <productId>` takes the product id, not a submission
#   id. It prints the app's pending submission (or the last published one when
#   nothing is pending) as JSON with PascalCase names. That JSON holds
#   FileUploadUrl, a SAS URL with write access, so it is never printed.
#   Assert-SubmissionHasPackage reads it back after publish.
# - `msstore reconfigure --reset` always asks a y/n question and throws
#   "Failed to read input in non-interactive mode" on a runner, so it cannot be
#   used in CI. Clear-MsStoreCliState removes the same things directly.

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:CredentialPrefix = 'MicrosoftStoreCli:'
$script:StateDir = Join-Path $env:LOCALAPPDATA 'Microsoft\MSStore.CLI'
$script:ApiStateDir = Join-Path $env:LOCALAPPDATA 'Microsoft\MSStore.API'

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

# Removes every MSStore CLI credential, the CLI's settings/token cache folder and
# the MSStore.API token cache folder, then checks all of them are gone. Throws if anything is left. Prints no secret values
# (target names hold the client id, which GitHub masks as a secret in logs).
function Clear-MsStoreCliState {
  $creds = @([JerisLink.WinCred]::List("$($script:CredentialPrefix)*"))
  foreach ($c in $creds) { [JerisLink.WinCred]::Delete($c.Key, $c.Value) }
  foreach ($d in $script:StateDir, $script:ApiStateDir) {
    if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }
  }

  $left = @(Get-MsStoreCliCredentialTargets)
  if ($left.Count -ne 0) { throw "$($left.Count) MSStore CLI credential(s) still in Credential Manager" }
  foreach ($d in $script:StateDir, $script:ApiStateDir) {
    if (Test-Path -LiteralPath $d) { throw "$d still exists" }
  }
  Write-Host "MSStore CLI state cleared: removed $($creds.Count) credential(s); $($script:StateDir) and $($script:ApiStateDir) are gone"
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
  # Stand-in for the token cache MSStore.API writes after a real sign-in.
  New-Item -ItemType Directory -Force -Path (Join-Path $script:ApiStateDir 'Cache') | Out-Null
  Set-Content -LiteralPath (Join-Path $script:ApiStateDir 'Cache\msstore_msal_cache.txt') -Value 'dummy'
  $clientId
}

# Finds the one Store package in $Dir and checks its identity and version.
# Returns Path (the full path of the .msixupload, which is what `msstore publish`
# takes), FileName, Version (the manifest Identity Version) and Sha256.
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
    Write-Host "Package: $($upload.FullName) contains $($msix[0].Name) ($($msix[0].Length) bytes)"
    Copy-Item -LiteralPath $msix[0].FullName (Join-Path $work 'pkg.zip')
    Expand-Archive (Join-Path $work 'pkg.zip') (Join-Path $work 'pkg')
    [xml]$m = Get-Content (Join-Path $work 'pkg\AppxManifest.xml')
    $id = $m.Package.Identity
    Write-Host "Identity Name=$($id.Name) Publisher=$($id.Publisher) Version=$($id.Version)"
    $version = [string]$id.Version
    if ($id.Name -ne $ExpectedName) { throw "unexpected Identity Name" }
    if ($id.Publisher -ne $ExpectedPublisher) { throw "unexpected Identity Publisher" }
    if ($id.Version -notmatch '^\d+\.\d+\.\d+\.0$') { throw "Store versions must end in .0" }
    if ($ExpectedVersion -and $id.Version -ne $ExpectedVersion) { throw "package version $($id.Version) does not match the release ($ExpectedVersion)" }
  } finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  }
  $sha = (Get-FileHash -LiteralPath $upload.FullName -Algorithm SHA256).Hash.ToLower()
  Write-Host "$sha  $($upload.Name)"
  [pscustomobject]@{ Path = $upload.FullName; FileName = $upload.Name; Version = $version; Sha256 = $sha }
}

# Checks the JSON that `msstore apps get <productId>` prints (DevCenterApplication)
# and throws if the app has a pending submission, or if the JSON is not that app.
function Test-NoPendingSubmission {
  param([Parameter(Mandatory)][AllowEmptyString()][string]$AppJson, [Parameter(Mandatory)][string]$ProductId)
  $start = $AppJson.IndexOf('{')
  if ($start -lt 0) { throw "msstore apps get printed no application JSON; not publishing" }
  try { $app = $AppJson.Substring($start) | ConvertFrom-Json -ErrorAction Stop }
  catch { throw "msstore apps get printed JSON that does not parse; not publishing" }
  $idProp = $app.PSObject.Properties['Id']
  if (-not $idProp -or $idProp.Value -ne $ProductId) { throw "msstore apps get returned a different or empty application id; not publishing" }
  $pendingProp = $app.PSObject.Properties['PendingApplicationSubmission']
  if (-not $pendingProp) { throw "msstore apps get output has no PendingApplicationSubmission field; cannot tell whether a draft exists; not publishing" }
  $pending = $pendingProp.Value
  if ($null -ne $pending) {
    $pid_ = $pending.PSObject.Properties['Id']
    $pendingId = if ($pid_) { $pid_.Value } else { '(no id)' }
    throw ("Partner Center already has a pending submission $pendingId for $ProductId. " +
      "msstore publish would delete it (or reuse it) before uploading, so this run stops and touches nothing. " +
      "Open Partner Center, decide what to do with that draft (submit or delete it), then re-run this workflow.")
  }
  Write-Host "No pending submission for $ProductId; safe to create a new draft."
}

# Asks Partner Center (msstore apps get) whether the app has a pending submission
# and throws unless the CLI succeeded and reported none. Fails closed.
function Assert-NoPendingSubmission {
  param([Parameter(Mandatory)][string]$ProductId)
  $ErrorActionPreference = 'Continue'
  $out = (& msstore apps get $ProductId | Out-String)
  $code = $LASTEXITCODE
  $ErrorActionPreference = 'Stop'
  if ($code -ne 0) { throw "msstore apps get failed (exit $code); cannot check for a pending submission; not publishing" }
  Test-NoPendingSubmission -AppJson $out -ProductId $ProductId
}

function Get-JsonField($Object, [string]$Name) {
  if ($null -eq $Object) { return '' }
  $p = $Object.PSObject.Properties[$Name]
  if ($p -and $null -ne $p.Value) { [string]$p.Value } else { '' }
}

# Checks the JSON that `msstore submission get <productId>` prints after a
# committed publish. Pure: runs no CLI and prints nothing. Returns Result
# ('Pass', 'Pending' or 'Fail'), Reason and safe fields only: Id, Status,
# TargetPublishMode, and FileName, Version, FileStatus for each package.
# FileUploadUrl (a SAS URL) is never copied into the result.
# - Fail: no JSON, a different submission id than the pending one, any *Failed
#   status (CommitFailed, PreProcessingFailed, CertificationFailed, ...), no
#   packages, an Uploaded package with another version (the old 0.3.0.0 still in,
#   or a version mismatch), more than one Uploaded package with the expected
#   version, or no Uploaded/PendingUpload package with the expected version.
# - Pending: status CommitStarted, an Uploaded package whose version Partner
#   Center has not filled in yet, or a package still PendingUpload.
# - Pass: exactly one Uploaded package, it has the expected version, and no other
#   package is Uploaded.
function Test-SubmissionHasPackage {
  param(
    [Parameter(Mandatory)][AllowEmptyString()][string]$SubmissionJson,
    [Parameter(Mandatory)][string]$ExpectedVersion,
    [string]$ExpectedSubmissionId = ''
  )
  $sub = [pscustomobject]@{ Id = ''; Status = ''; TargetPublishMode = '' }
  $pkgs = @()
  $result = {
    param([string]$Result, [string]$Reason)
    [pscustomobject]@{ Result = $Result; Reason = $Reason; Id = $sub.Id; Status = $sub.Status
                       TargetPublishMode = $sub.TargetPublishMode; Packages = @($pkgs) }
  }

  $start = $SubmissionJson.IndexOf('{')
  if ($start -lt 0) { return & $result 'Fail' 'msstore submission get printed no submission JSON' }
  try { $raw = $SubmissionJson.Substring($start) | ConvertFrom-Json -ErrorAction Stop }
  catch { return & $result 'Fail' 'msstore submission get printed JSON that does not parse' }

  $sub = [pscustomobject]@{
    Id                = Get-JsonField $raw 'Id'
    Status            = Get-JsonField $raw 'Status'
    TargetPublishMode = Get-JsonField $raw 'TargetPublishMode'
  }
  $pkgProp = $raw.PSObject.Properties['ApplicationPackages']
  if ($pkgProp -and $null -ne $pkgProp.Value) {
    $pkgs = @(foreach ($p in @($pkgProp.Value)) {
      [pscustomobject]@{ FileName = Get-JsonField $p 'FileName'; Version = Get-JsonField $p 'Version'; FileStatus = Get-JsonField $p 'FileStatus' }
    })
  }

  if (-not $sub.Id) { return & $result 'Fail' 'submission JSON has no Id' }
  if ($ExpectedSubmissionId -and $sub.Id -ne $ExpectedSubmissionId) {
    return & $result 'Fail' "submission get returned submission $($sub.Id), not the pending submission $ExpectedSubmissionId"
  }
  if ($sub.Status -like '*Failed') { return & $result 'Fail' "submission status is $($sub.Status)" }
  if ($pkgs.Count -eq 0) { return & $result 'Fail' 'submission has no application packages' }

  $uploaded = @($pkgs | Where-Object { $_.FileStatus -eq 'Uploaded' })
  $match    = @($uploaded | Where-Object { $_.Version -eq $ExpectedVersion })
  $unset    = @($uploaded | Where-Object { -not $_.Version })
  $other    = @($uploaded | Where-Object { $_.Version -and $_.Version -ne $ExpectedVersion })
  $pendUp   = @($pkgs | Where-Object { $_.FileStatus -eq 'PendingUpload' })

  if ($other.Count -gt 0) {
    $v = ($other | ForEach-Object { $_.Version }) -join ', '
    return & $result 'Fail' "submission still has Uploaded package(s) with version $v; expected only $ExpectedVersion"
  }
  if ($match.Count -gt 1) { return & $result 'Fail' "submission has $($match.Count) Uploaded packages with version $ExpectedVersion; expected exactly one" }
  if ($sub.Status -eq 'CommitStarted') { return & $result 'Pending' 'commit still processing (CommitStarted)' }
  if ($unset.Count -gt 0) { return & $result 'Pending' 'package version not filled in yet' }
  if ($pendUp.Count -gt 0) { return & $result 'Pending' 'package still PendingUpload' }
  if ($match.Count -eq 1) { return & $result 'Pass' "submission holds exactly one Uploaded package, version $ExpectedVersion" }
  return & $result 'Fail' "submission has no Uploaded package with version $ExpectedVersion"
}

# Prints only the safe fields of a Test-SubmissionHasPackage result.
function Write-SubmissionSummary {
  param([Parameter(Mandatory)]$Check)
  Write-Host "submission id=$($Check.Id) status=$($Check.Status) targetPublishMode=$($Check.TargetPublishMode)"
  foreach ($p in $Check.Packages) { Write-Host "  package fileName=$($p.FileName) version=$($p.Version) fileStatus=$($p.FileStatus)" }
}

# Runs after `msstore publish` committed. Reads the app's pending submission id
# from `msstore apps get`, then `msstore submission get <productId>`, and throws
# unless that submission holds the new package (Test-SubmissionHasPackage).
# Checks again every IntervalSeconds while the result is Pending, and throws
# "not verified" after TimeoutMinutes. Prints only id, status, targetPublishMode
# and (fileName, version, fileStatus); never the raw CLI output (SAS URL).
# targetPublishMode other than Manual is a warning only: the commit has already
# happened, so failing the job here would stop nothing.
function Assert-SubmissionHasPackage {
  param(
    [Parameter(Mandatory)][string]$ProductId,
    [Parameter(Mandatory)][string]$ExpectedVersion,
    [int]$TimeoutMinutes = 30,
    [int]$IntervalSeconds = 60
  )
  $ErrorActionPreference = 'Continue'
  $out = (& msstore apps get $ProductId | Out-String)
  $code = $LASTEXITCODE
  $ErrorActionPreference = 'Stop'
  if ($code -ne 0) { throw "msstore apps get failed (exit $code); submission not verified" }
  $start = $out.IndexOf('{')
  if ($start -lt 0) { throw "msstore apps get printed no application JSON; submission not verified" }
  try { $app = $out.Substring($start) | ConvertFrom-Json -ErrorAction Stop }
  catch { throw "msstore apps get printed JSON that does not parse; submission not verified" }
  if ((Get-JsonField $app 'Id') -ne $ProductId) { throw "msstore apps get returned a different or empty application id; submission not verified" }
  $pendingProp = $app.PSObject.Properties['PendingApplicationSubmission']
  $subId = if ($pendingProp) { Get-JsonField $pendingProp.Value 'Id' } else { '' }
  if (-not $subId) { throw "Partner Center shows no pending submission for $ProductId after publish; the commit did not land; submission not verified" }
  Write-Host "pending submission id=$subId"

  $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
  $warned = $false
  while ($true) {
    $ErrorActionPreference = 'Continue'
    $json = (& msstore submission get $ProductId | Out-String)
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($code -ne 0) {
      $check = [pscustomobject]@{ Result = 'Pending'; Reason = "msstore submission get failed (exit $code)"; Id = $subId
                                  Status = ''; TargetPublishMode = ''; Packages = @() }
    } else {
      $check = Test-SubmissionHasPackage -SubmissionJson $json -ExpectedVersion $ExpectedVersion -ExpectedSubmissionId $subId
    }
    $json = $null
    Write-SubmissionSummary -Check $check
    if ($check.TargetPublishMode -and $check.TargetPublishMode -ne 'Manual' -and -not $warned) {
      Write-Host ("::warning title=Store publish mode::targetPublishMode is '$($check.TargetPublishMode)', not Manual. " +
        "This submission goes live by itself once it passes certification. Set Publish to manual in Partner Center if a person should release it.")
      $warned = $true
    }
    if ($check.Result -eq 'Pass') { Write-Host "verified: $($check.Reason)"; return }
    if ($check.Result -eq 'Fail') { throw "submission check failed: $($check.Reason)" }
    if ((Get-Date).AddSeconds($IntervalSeconds) -gt $deadline) {
      throw "submission not verified after $TimeoutMinutes min: $($check.Reason)"
    }
    Write-Host "pending: $($check.Reason); checking again in $IntervalSeconds s"
    Start-Sleep -Seconds $IntervalSeconds
  }
}

Export-ModuleMember -Function Get-StorePackage, Clear-MsStoreCliState, Set-MsStoreCliDummyState, Get-MsStoreCliCredentialTargets, Test-NoPendingSubmission, Assert-NoPendingSubmission, Test-SubmissionHasPackage, Assert-SubmissionHasPackage
