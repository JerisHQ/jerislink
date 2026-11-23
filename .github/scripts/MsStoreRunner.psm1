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
# - `msstore publish --noCommit` creates the draft, marks for deletion
#   (PendingDelete) only the FIRST existing package with the same file extension
#   as the upload (IStorePackagedAPIExtensions.cs, the bundle step), adds the new
#   package, uploads it, and does not commit. Any other old package (another
#   extension, a second package) stays in the draft. Assert-DraftReadyToCommit
#   checks the draft before anything is committed.
# - `msstore submission publish <productId>` commits the app's pending
#   submission (CommitSubmissionAsync). Partner Center only takes in the uploaded
#   package on an API commit. A draft left uncommitted and then submitted from
#   the Partner Center UI ships the packages cloned from the live submission.
# - `msstore submission get <productId>` takes the product id, not a submission
#   id. It prints the app's pending submission, or the last published one when
#   nothing is pending (GetAnySubmissionAsync), as JSON with PascalCase names.
#   That JSON holds FileUploadUrl, a SAS URL with write access, so it is never
#   printed. Every check compares its Id with the submission this run created.
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

# Submissions this workflow creates through the API are changed, committed and
# deleted only through the API (msstore). A draft committed from the Partner
# Center UI ships the packages cloned from the live submission, not the uploaded
# one. The one Partner Center action is Publish, after certification has passed.
$script:ApiOnlyNote = 'Submissions this workflow creates are changed, committed or deleted only through the Store submission API (msstore), never in the Partner Center UI; the only Partner Center action is Publish after certification has passed.'

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
      "$script:ApiOnlyNote If it is in certification, let certification finish. If it is an uncommitted draft, " +
      "delete it through the API (msstore submission delete $ProductId --no-confirm). Then re-run this workflow.")
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

# Parses `msstore apps get <productId>` output. Pure. Returns Ok, Reason,
# PendingId and LastPublishedId ('' when that submission is absent).
function Read-AppSubmissionIds {
  param([Parameter(Mandatory)][AllowEmptyString()][string]$AppJson, [Parameter(Mandatory)][string]$ProductId)
  $fail = { param([string]$Reason) [pscustomobject]@{ Ok = $false; Reason = $Reason; PendingId = ''; LastPublishedId = '' } }
  $start = $AppJson.IndexOf('{')
  if ($start -lt 0) { return & $fail 'msstore apps get printed no application JSON' }
  try { $app = $AppJson.Substring($start) | ConvertFrom-Json -ErrorAction Stop }
  catch { return & $fail 'msstore apps get printed JSON that does not parse' }
  if ((Get-JsonField $app 'Id') -ne $ProductId) { return & $fail 'msstore apps get returned a different or empty application id' }
  if (-not $app.PSObject.Properties['PendingApplicationSubmission']) { return & $fail 'msstore apps get output has no PendingApplicationSubmission field' }
  $pending = $app.PSObject.Properties['PendingApplicationSubmission'].Value
  $lastProp = $app.PSObject.Properties['LastPublishedApplicationSubmission']
  $last = if ($lastProp) { $lastProp.Value } else { $null }
  [pscustomobject]@{ Ok = $true; Reason = ''; PendingId = (Get-JsonField $pending 'Id'); LastPublishedId = (Get-JsonField $last 'Id') }
}

# Runs `msstore apps get` and returns Read-AppSubmissionIds; throws on a CLI
# failure or output it cannot read.
function Get-AppSubmissionIds {
  param([Parameter(Mandatory)][string]$ProductId, [Parameter(Mandatory)][string]$What)
  $ErrorActionPreference = 'Continue'
  $out = (& msstore apps get $ProductId | Out-String)
  $code = $LASTEXITCODE
  $ErrorActionPreference = 'Stop'
  if ($code -ne 0) { throw "msstore apps get failed (exit $code); $What" }
  $ids = Read-AppSubmissionIds -AppJson $out -ProductId $ProductId
  if (-not $ids.Ok) { throw "$($ids.Reason); $What" }
  $ids
}

# Which submission `msstore submission get <productId>` returns for the
# submission this run created (SubmissionId). Pure. CLI v0.4.4
# (GetAnySubmissionAsync) returns the pending submission, or the last published
# one when nothing is pending. Returns Source 'Pending' or 'LastPublished' when
# that is SubmissionId, otherwise 'Fail' with Reason.
function Resolve-RunSubmission {
  param([Parameter(Mandatory)]$Ids, [Parameter(Mandatory)][string]$SubmissionId)
  if ($Ids.PendingId -eq $SubmissionId) { return [pscustomobject]@{ Source = 'Pending'; Reason = '' } }
  if ($Ids.PendingId) {
    return [pscustomobject]@{ Source = 'Fail'; Reason = "the app's pending submission is $($Ids.PendingId), not submission $SubmissionId that this run created" }
  }
  if ($Ids.LastPublishedId -eq $SubmissionId) { return [pscustomobject]@{ Source = 'LastPublished'; Reason = '' } }
  $lp = if ($Ids.LastPublishedId) { $Ids.LastPublishedId } else { 'none' }
  [pscustomobject]@{ Source = 'Fail'; Reason = "submission $SubmissionId that this run created is neither pending nor the last published one (last published: $lp)" }
}

# Parses submission JSON into safe fields only: Id, Status, TargetPublishMode,
# and FileName, Version, FileStatus per package. FileUploadUrl (a SAS URL with
# write access) is never copied. Returns $null when there is no JSON object.
function Read-SubmissionSafe {
  param([Parameter(Mandatory)][AllowEmptyString()][string]$SubmissionJson)
  $start = $SubmissionJson.IndexOf('{')
  if ($start -lt 0) { return $null }
  try { $raw = $SubmissionJson.Substring($start) | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
  $pkgs = @()
  $pkgProp = $raw.PSObject.Properties['ApplicationPackages']
  if ($pkgProp -and $null -ne $pkgProp.Value) {
    $pkgs = @(foreach ($p in @($pkgProp.Value)) {
      [pscustomobject]@{ FileName = Get-JsonField $p 'FileName'; Version = Get-JsonField $p 'Version'; FileStatus = Get-JsonField $p 'FileStatus' }
    })
  }
  [pscustomobject]@{ Id = Get-JsonField $raw 'Id'; Status = Get-JsonField $raw 'Status'
                     TargetPublishMode = Get-JsonField $raw 'TargetPublishMode'; Packages = $pkgs }
}

function New-CheckResult($Sub, [string]$Result, [string]$Reason) {
  [pscustomobject]@{ Result = $Result; Reason = $Reason
                     Id = $(if ($Sub) { $Sub.Id } else { '' }); Status = $(if ($Sub) { $Sub.Status } else { '' })
                     TargetPublishMode = $(if ($Sub) { $Sub.TargetPublishMode } else { '' })
                     Packages = $(if ($Sub) { @($Sub.Packages) } else { @() }) }
}

# Before commit: checks the draft this run created (`msstore submission get`
# after `msstore publish --noCommit`). Pure. CLI v0.4.4 marks for deletion only
# the first existing package with the same extension as the upload
# (IStorePackagedAPIExtensions.PublishAsync); any other package (another
# extension, a second package) would stay in the submission on commit.
# Pass only when: the id is SubmissionId, the status is PendingCommit (an
# uncommitted draft), and every package except PendingDelete ones is exactly
# one entry: ExpectedFileName, PendingUpload or Uploaded, and its Version (if
# Partner Center filled it in) is ExpectedVersion. Fail otherwise.
function Test-DraftReadyToCommit {
  param(
    [Parameter(Mandatory)][AllowEmptyString()][string]$SubmissionJson,
    [Parameter(Mandatory)][string]$SubmissionId,
    [Parameter(Mandatory)][string]$ExpectedFileName,
    [Parameter(Mandatory)][string]$ExpectedVersion
  )
  $sub = Read-SubmissionSafe -SubmissionJson $SubmissionJson
  if (-not $sub) { return New-CheckResult $null 'Fail' 'msstore submission get printed no submission JSON that parses' }
  if ($sub.Id -ne $SubmissionId) { return New-CheckResult $sub 'Fail' "submission get returned submission '$($sub.Id)', not draft $SubmissionId that this run created" }
  if ($sub.Status -cne 'PendingCommit') { return New-CheckResult $sub 'Fail' "draft status is '$($sub.Status)', not PendingCommit" }
  $remain = @($sub.Packages | Where-Object { $_.FileStatus -cne 'PendingDelete' })
  $list = ($remain | ForEach-Object { "$($_.FileName) version=$($_.Version) fileStatus=$($_.FileStatus)" }) -join '; '
  if ($remain.Count -ne 1) { return New-CheckResult $sub 'Fail' "$($remain.Count) package(s) would remain after commit ($list); expected only $ExpectedFileName" }
  $p = $remain[0]
  if ($p.FileName -cne $ExpectedFileName) { return New-CheckResult $sub 'Fail' "the package that would remain after commit is $list, not $ExpectedFileName" }
  if ($p.FileStatus -cnotin @('PendingUpload', 'Uploaded')) { return New-CheckResult $sub 'Fail' "new package fileStatus is '$($p.FileStatus)'" }
  if ($p.Version -and $p.Version -ne $ExpectedVersion) { return New-CheckResult $sub 'Fail' "new package version is $($p.Version), not $ExpectedVersion" }
  New-CheckResult $sub 'Pass' "only $ExpectedFileName would remain after commit"
}

# Statuses of a submission that has been committed and is on its way (Microsoft
# app submission resource). CommitStarted is still in progress (Pending); every
# *Failed status fails; None, Canceled, PendingCommit, an empty or unknown
# status is not a committed submission and fails.
$script:CommittedStatuses = @('PreProcessing', 'Certification', 'Release', 'PendingPublication', 'Publishing', 'Published')

# After commit: checks `msstore submission get <productId>` output for the
# submission this run created. Pure. Returns Result ('Pass', 'Pending' or
# 'Fail'), Reason and the safe fields of Read-SubmissionSafe.
# - Fail: no JSON, another submission id than ExpectedSubmissionId, a status that
#   is not committed (see CommittedStatuses), no packages, an Uploaded package
#   with another version, more than one Uploaded package with the expected
#   version, or none with it.
# - Pending: CommitStarted, an Uploaded package whose version is not filled in
#   yet, or a package still PendingUpload.
# - Pass: a committed status, and exactly one Uploaded package, with the
#   expected version, and no other Uploaded package. Published counts.
function Test-SubmissionHasPackage {
  param(
    [Parameter(Mandatory)][AllowEmptyString()][string]$SubmissionJson,
    [Parameter(Mandatory)][string]$ExpectedVersion,
    [string]$ExpectedSubmissionId = ''
  )
  $sub = Read-SubmissionSafe -SubmissionJson $SubmissionJson
  if (-not $sub) { return New-CheckResult $null 'Fail' 'msstore submission get printed no submission JSON that parses' }
  if (-not $sub.Id) { return New-CheckResult $sub 'Fail' 'submission JSON has no Id' }
  if ($ExpectedSubmissionId -and $sub.Id -ne $ExpectedSubmissionId) {
    return New-CheckResult $sub 'Fail' "submission get returned submission $($sub.Id), not submission $ExpectedSubmissionId that this run created"
  }
  if ($sub.Status -like '*Failed') { return New-CheckResult $sub 'Fail' "submission status is $($sub.Status)" }
  $committing = $sub.Status -ceq 'CommitStarted'
  if (-not $committing -and $sub.Status -cnotin $script:CommittedStatuses) {
    return New-CheckResult $sub 'Fail' "submission status is '$($sub.Status)', not a committed status"
  }
  $pkgs = @($sub.Packages)
  if ($pkgs.Count -eq 0) { return New-CheckResult $sub 'Fail' 'submission has no application packages' }

  $uploaded = @($pkgs | Where-Object { $_.FileStatus -eq 'Uploaded' })
  $match    = @($uploaded | Where-Object { $_.Version -eq $ExpectedVersion })
  $unset    = @($uploaded | Where-Object { -not $_.Version })
  $other    = @($uploaded | Where-Object { $_.Version -and $_.Version -ne $ExpectedVersion })
  $pendUp   = @($pkgs | Where-Object { $_.FileStatus -eq 'PendingUpload' })

  if ($other.Count -gt 0) {
    $v = ($other | ForEach-Object { $_.Version }) -join ', '
    return New-CheckResult $sub 'Fail' "submission still has Uploaded package(s) with version $v; expected only $ExpectedVersion"
  }
  if ($match.Count -gt 1) { return New-CheckResult $sub 'Fail' "submission has $($match.Count) Uploaded packages with version $ExpectedVersion; expected exactly one" }
  if ($committing) { return New-CheckResult $sub 'Pending' 'commit still processing (CommitStarted)' }
  if ($unset.Count -gt 0) { return New-CheckResult $sub 'Pending' 'package version not filled in yet' }
  if ($pendUp.Count -gt 0) { return New-CheckResult $sub 'Pending' 'package still PendingUpload' }
  if ($match.Count -eq 1) { return New-CheckResult $sub 'Pass' "submission holds exactly one Uploaded package, version $ExpectedVersion" }
  New-CheckResult $sub 'Fail' "submission has no Uploaded package with version $ExpectedVersion"
}

# Prints only the safe fields of a check result.
function Write-SubmissionSummary {
  param([Parameter(Mandatory)]$Check)
  Write-Host "submission id=$($Check.Id) status=$($Check.Status) targetPublishMode=$($Check.TargetPublishMode)"
  foreach ($p in $Check.Packages) { Write-Host "  package fileName=$($p.FileName) version=$($p.Version) fileStatus=$($p.FileStatus)" }
}

function Invoke-SubmissionGet([string]$ProductId) {
  $ErrorActionPreference = 'Continue'
  $json = (& msstore submission get $ProductId | Out-String)
  $code = $LASTEXITCODE
  $ErrorActionPreference = 'Stop'
  [pscustomobject]@{ Code = $code; Json = $json }
}

# Runs after `msstore publish --noCommit` (with Assert-NoPendingSubmission
# before it, so the app's pending submission now is the draft this run
# created). Reads that draft's id, checks it with Test-DraftReadyToCommit and
# returns the id. Throws, without committing, if anything other than the new
# package would remain. Prints only safe fields.
function Assert-DraftReadyToCommit {
  param(
    [Parameter(Mandatory)][string]$ProductId,
    [Parameter(Mandatory)][string]$ExpectedFileName,
    [Parameter(Mandatory)][string]$ExpectedVersion
  )
  $ids = Get-AppSubmissionIds -ProductId $ProductId -What 'draft not checked; not committing'
  if (-not $ids.PendingId) { throw "Partner Center shows no pending submission for $ProductId after the upload; not committing" }
  if ($ids.PendingId -eq $ids.LastPublishedId) { throw "pending submission $($ids.PendingId) is the last published one; not committing" }
  $subId = $ids.PendingId
  Write-Host "draft submission created by this run: id=$subId"
  $r = Invoke-SubmissionGet $ProductId
  if ($r.Code -ne 0) { throw "msstore submission get failed (exit $($r.Code)); draft $subId not checked; not committing" }
  $check = Test-DraftReadyToCommit -SubmissionJson $r.Json -SubmissionId $subId -ExpectedFileName $ExpectedFileName -ExpectedVersion $ExpectedVersion
  $r = $null
  Write-SubmissionSummary -Check $check
  if ($check.Result -ne 'Pass') {
    throw ("draft check failed, not committing: $($check.Reason). Draft $subId stays uncommitted. $script:ApiOnlyNote " +
      "Delete it through the API (msstore submission delete $ProductId --no-confirm), then re-run this workflow.")
  }
  Write-Host "draft verified: $($check.Reason)"
  $subId
}

# Commits the draft this run created and checked: throws unless the app's
# pending submission is still SubmissionId, then `msstore submission publish`
# (CommitSubmissionAsync on that pending submission).
function Invoke-SubmissionCommit {
  param([Parameter(Mandatory)][string]$ProductId, [Parameter(Mandatory)][string]$SubmissionId)
  $ids = Get-AppSubmissionIds -ProductId $ProductId -What 'not committing'
  if ($ids.PendingId -ne $SubmissionId) { throw "pending submission is '$($ids.PendingId)', not checked draft $SubmissionId; not committing" }
  $ErrorActionPreference = 'Continue'
  $out = (& msstore submission publish $ProductId 2>&1 | Out-String)
  $code = $LASTEXITCODE
  $ErrorActionPreference = 'Stop'
  # Never print an upload URL, should the CLI ever echo one.
  Write-Host (($out -replace 'https?://\S+', '[url]').Trim())
  if ($code -ne 0) { throw "msstore submission publish failed (exit $code); submission $SubmissionId not committed" }
  Write-Host "submission $SubmissionId committed through the API"
}

# Runs after the commit. Each round: `msstore apps get` (Resolve-RunSubmission:
# the run's SubmissionId must be the pending one, or the last published one
# once nothing is pending), then `msstore submission get <productId>`, checked
# with Test-SubmissionHasPackage against that same SubmissionId. Checks again
# every IntervalSeconds while Pending; throws "not verified" after
# TimeoutMinutes. Prints only safe fields, never the raw CLI output (SAS URL).
# targetPublishMode other than Manual is a warning only: the commit has already
# happened, so failing the job here would stop nothing.
function Assert-SubmissionHasPackage {
  param(
    [Parameter(Mandatory)][string]$ProductId,
    [Parameter(Mandatory)][string]$SubmissionId,
    [Parameter(Mandatory)][string]$ExpectedVersion,
    [int]$TimeoutMinutes = 30,
    [int]$IntervalSeconds = 60
  )
  Write-Host "checking submission id=$SubmissionId (created and committed by this run)"
  $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
  $warned = $false
  while ($true) {
    $ids = Get-AppSubmissionIds -ProductId $ProductId -What 'submission not verified'
    $where = Resolve-RunSubmission -Ids $ids -SubmissionId $SubmissionId
    if ($where.Source -eq 'Fail') { throw "submission check failed: $($where.Reason)" }
    $r = Invoke-SubmissionGet $ProductId
    if ($r.Code -ne 0) {
      $check = [pscustomobject]@{ Result = 'Pending'; Reason = "msstore submission get failed (exit $($r.Code))"; Id = $SubmissionId
                                  Status = ''; TargetPublishMode = ''; Packages = @() }
    } else {
      $check = Test-SubmissionHasPackage -SubmissionJson $r.Json -ExpectedVersion $ExpectedVersion -ExpectedSubmissionId $SubmissionId
    }
    $r = $null
    Write-SubmissionSummary -Check $check
    if ($check.TargetPublishMode -and $check.TargetPublishMode -ne 'Manual' -and -not $warned) {
      Write-Host ("::warning title=Store publish mode::targetPublishMode is '$($check.TargetPublishMode)', not Manual: " +
        "this submission goes live by itself once it passes certification. Publish mode is part of the submission and is " +
        "set through the submission API before commit, not in the Partner Center UI.")
      $warned = $true
    }
    if ($check.Result -eq 'Pass') { Write-Host "verified ($($where.Source) submission $SubmissionId): $($check.Reason)"; return }
    if ($check.Result -eq 'Fail') { throw "submission check failed: $($check.Reason)" }
    if ((Get-Date).AddSeconds($IntervalSeconds) -gt $deadline) {
      throw "submission not verified after $TimeoutMinutes min: $($check.Reason)"
    }
    Write-Host "pending: $($check.Reason); checking again in $IntervalSeconds s"
    Start-Sleep -Seconds $IntervalSeconds
  }
}

Export-ModuleMember -Function Get-StorePackage, Clear-MsStoreCliState, Set-MsStoreCliDummyState, Get-MsStoreCliCredentialTargets, Test-NoPendingSubmission, Assert-NoPendingSubmission, Read-AppSubmissionIds, Resolve-RunSubmission, Test-DraftReadyToCommit, Assert-DraftReadyToCommit, Invoke-SubmissionCommit, Test-SubmissionHasPackage, Assert-SubmissionHasPackage
