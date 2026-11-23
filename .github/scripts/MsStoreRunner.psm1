# Helpers for msstore-publish.yml and msstore-publish-check.yml (pwsh 7).
#
# Talks to the Microsoft Store submission API directly
# (https://manage.devcenter.microsoft.com/v1.0/my, Entra client credentials,
# scope https://manage.devcenter.microsoft.com/.default: the same calls the
# Microsoft Store Developer CLI makes). Every call after create names this run's
# submission id. Why not the CLI (MSStore.CLI source at tag v0.4.4):
# - `msstore publish` DELETES the app's pending submission before it creates a
#   new one when a published submission exists
#   (IStorePackagedAPIExtensions.cs#L389-L410), and only logs the id it created.
# - `msstore submission publish|get|delete <productId>` act on whatever
#   submission is pending at that moment (or the last published one), not on a
#   given submission id (PublishCommand.cs#L43-L77).
# - with logging on, it logs the package upload SAS URL at Information level
#   (IStorePackagedAPIExtensions.cs#L521-L522).
#
# Flow (Publish-StoreSubmission), each step on this run's submission id:
#   GET app: stop if a submission is pending (never delete one this run did not
#   create) -> POST create, id taken from the response -> GET app: the pending
#   submission must be that id -> GET submission -> price check -> PUT with every
#   old package PendingDelete and the new file PendingUpload -> PUT the zip to
#   the SAS upload URL -> GET submission, Test-DraftReadyToCommit -> POST
#   .../submissions/{id}/commit. Assert-SubmissionHasPackage then reads that id
#   back until it is committed with the new package.
#
# Nothing here prints the token, the client secret, a SAS URL or a raw
# submission JSON (it holds fileUploadUrl). Error text from the API or the
# network goes through Protect-StoreText first. All HTTP goes through
# Invoke-StoreHttp, which the Pester tests mock. The token lives only in this
# PowerShell session; nothing is written to disk.

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:DefaultApiBase = 'https://manage.devcenter.microsoft.com'
$script:DefaultAuthorityHost = 'https://login.microsoftonline.com'
$script:ApiScope = 'https://manage.devcenter.microsoft.com/.default'
$script:ApiBase = $script:DefaultApiBase
$script:Token = ''

# Finds the one Store package in $Dir and checks its identity and version.
# Returns Path (the full path of the .msixupload that is uploaded), FileName, Version (the manifest Identity Version) and Sha256.
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
  # Only the exact lower-case extension is accepted, as the Store CLI did.
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

# Masks what must never reach a log: URLs (a SAS upload URL carries a write
# signature), any sig= value, bearer tokens and the current access token.
function Protect-StoreText {
  param([AllowNull()][AllowEmptyString()][string]$Text)
  if (-not $Text) { return '' }
  $t = $Text -replace 'https?:(?:\\?/){2}[^\s"''<>]+', '[url]'
  $t = $t -replace '(?i)(\bsig=)[^&\s"''<>]+', '$1[redacted]'
  $t = $t -replace '(?i)(\bbearer\s+)[A-Za-z0-9\-._~+/]+=*', '$1[redacted]'
  if ($script:Token) { $t = $t.Replace($script:Token, '[token]') }
  $t
}

# The one place that touches the network. Returns StatusCode and Body (text);
# an HTTP error status is returned, not thrown; a network failure throws.
function Invoke-StoreHttp {
  param(
    [Parameter(Mandatory)][string]$Method,
    [Parameter(Mandatory)][string]$Uri,
    [hashtable]$Headers = @{},
    [string]$Body,
    [string]$ContentType,
    [string]$InFile
  )
  $a = @{ Method = $Method; Uri = $Uri; Headers = $Headers; SkipHttpErrorCheck = $true; TimeoutSec = 600 }
  if ($PSBoundParameters.ContainsKey('Body')) { $a.Body = $Body }
  if ($ContentType) { $a.ContentType = $ContentType }
  if ($InFile) { $a.InFile = $InFile }
  $ProgressPreference = 'SilentlyContinue'
  $r = Invoke-WebRequest @a
  $text = if ($r.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($r.Content) } else { [string]$r.Content }
  [pscustomobject]@{ StatusCode = [int]$r.StatusCode; Body = $text }
}

# A short, masked description of an error response body.
function Get-StoreErrorText {
  param([AllowNull()][AllowEmptyString()][string]$Body)
  if (-not $Body) { return '(empty body)' }
  $text = $Body
  try {
    $e = $Body | ConvertFrom-Json -ErrorAction Stop
    $parts = foreach ($n in 'code', 'error', 'message', 'error_description') {
      $v = Get-JsonField $e $n
      if ($v) { "${n}: $(($v -split "`n")[0])" }
    }
    if ($parts) { $text = $parts -join '; ' }
  } catch { }
  $text = Protect-StoreText (($text -replace '\s+', ' ').Trim())
  if ($text.Length -gt 300) { $text = $text.Substring(0, 300) + '...' }
  $text
}

function Get-JsonField($Object, [string]$Name) {
  if ($null -eq $Object -or $Object -is [string]) { return '' }
  $p = $Object.PSObject.Properties[$Name]
  if ($p -and $null -ne $p.Value) { [string]$p.Value } else { '' }
}

# Gets an access token for the Store submission API with the Entra app's client
# credentials (what the CLI's MSAL AcquireTokenForClient does) and keeps it in
# this session only. Never prints the token or the secret. AuthorityHost and
# ApiBase exist for msstore-publish-check.yml (local stand-in, dead port);
# msstore-publish.yml never passes them.
function Connect-StoreApi {
  param(
    [AllowEmptyString()][string]$TenantId,
    [AllowEmptyString()][string]$ClientId,
    [AllowEmptyString()][string]$ClientSecret,
    [string]$AuthorityHost = $script:DefaultAuthorityHost,
    [string]$ApiBase = $script:DefaultApiBase
  )
  $script:Token = ''
  if (-not $TenantId -or -not $ClientId -or -not $ClientSecret) { throw "tenant id, client id or client secret is empty (store environment secret missing?)" }
  if ($TenantId -notmatch '^[0-9A-Za-z.-]+$') { throw "tenant id has unexpected characters" }
  $mask = { param([string]$s) (Protect-StoreText $s).Replace($ClientSecret, '[secret]') }
  $body = 'grant_type=client_credentials&client_id=' + [uri]::EscapeDataString($ClientId) +
          '&client_secret=' + [uri]::EscapeDataString($ClientSecret) + '&scope=' + [uri]::EscapeDataString($script:ApiScope)
  try {
    $r = Invoke-StoreHttp -Method POST -Uri "$($AuthorityHost.TrimEnd('/'))/$TenantId/oauth2/v2.0/token" -Body $body -ContentType 'application/x-www-form-urlencoded'
  } catch { throw "could not get a Partner Center access token: $(& $mask $_.Exception.Message)" }
  finally { $body = $null }
  if ($r.StatusCode -ne 200) { throw "could not get a Partner Center access token: HTTP $($r.StatusCode) $(& $mask (Get-StoreErrorText $r.Body))" }
  $tok = ''
  try { $tok = Get-JsonField ($r.Body | ConvertFrom-Json -ErrorAction Stop) 'access_token' } catch { }
  if (-not $tok) { throw "the token response has no access_token" }
  $script:Token = $tok
  $script:ApiBase = $ApiBase.TrimEnd('/')
  Write-Host "signed in to the Store submission API (token kept in memory, not printed)"
}

# One Store submission API call. Path is relative to /v1.0/my/. Returns the
# response body; throws a masked message on a network error or a non-2xx status.
function Invoke-StoreApi {
  param(
    [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PUT', 'DELETE')][string]$Method,
    [Parameter(Mandatory)][string]$Path,
    [string]$Body
  )
  if (-not $script:Token) { throw "not signed in to the Store submission API (Connect-StoreApi)" }
  $what = "$Method /v1.0/my/$Path"
  $a = @{ Method = $Method; Uri = "$script:ApiBase/v1.0/my/$Path"; Headers = @{ Authorization = "Bearer $script:Token" } }
  if ($PSBoundParameters.ContainsKey('Body')) { $a.Body = $Body; $a.ContentType = 'application/json; charset=utf-8' }
  try { $r = Invoke-StoreHttp @a }
  catch { throw "Store API $what failed: $(Protect-StoreText $_.Exception.Message)" }
  if ($r.StatusCode -lt 200 -or $r.StatusCode -ge 300) { throw "Store API $what failed: HTTP $($r.StatusCode) $(Get-StoreErrorText $r.Body)" }
  [string]$r.Body
}

function Assert-ProductId([string]$ProductId) {
  if ($ProductId -notmatch '^[0-9A-Za-z]+$') { throw "product id '$ProductId' is not a Store product id" }
}
function Assert-SubmissionId([string]$SubmissionId) {
  if ($SubmissionId -notmatch '^\d+$') { throw "submission id '$SubmissionId' is not a number" }
}

# Submissions this workflow creates are changed, committed and deleted only
# through the API. A draft committed from the Partner Center UI ships the
# packages cloned from the live submission, not the uploaded one.
$script:ApiOnlyNote = 'Submissions this workflow creates are changed, committed or deleted only through the Store submission API, never in the Partner Center UI; the only Partner Center action is Publish after certification has passed.'

# How to delete exactly one submission, by id.
function Get-DeleteByIdText([string]$ProductId, [string]$SubmissionId) {
  "Delete exactly this submission through the API: DELETE /v1.0/my/applications/$ProductId/submissions/$SubmissionId " +
  "(Remove-StoreDraftSubmission -ProductId $ProductId -SubmissionId $SubmissionId in .github/scripts/MsStoreRunner.psm1 " +
  "does this, and only while it is still an uncommitted PendingCommit draft). Then re-run this workflow."
}

# Parses GET /applications/{productId}: returns the pending submission id, or
# '' when none is pending. The docs do not say whether "none" is a missing
# field or null, so both count as none; the create call (HTTP 409 while a
# submission is pending) and the post-create pending check back this up.
# Throws on JSON that does not parse or is another app.
function Read-AppPendingSubmissionId {
  param([Parameter(Mandatory)][AllowEmptyString()][string]$AppJson, [Parameter(Mandatory)][string]$ProductId)
  try { $app = $AppJson | ConvertFrom-Json -ErrorAction Stop } catch { throw "GET application returned JSON that does not parse" }
  if ($null -eq $app -or (Get-JsonField $app 'id') -ne $ProductId) { throw "GET application returned a different or empty application id" }
  $p = $app.PSObject.Properties['pendingApplicationSubmission']
  if (-not $p -or $null -eq $p.Value) { return '' }
  $id = Get-JsonField $p.Value 'id'
  if (-not $id) { return '(no id)' }
  $id
}

# Throws if the app (GET /applications/{productId} JSON) has a pending
# submission. Pure. Deletes nothing.
function Test-NoPendingSubmission {
  param([Parameter(Mandatory)][AllowEmptyString()][string]$AppJson, [Parameter(Mandatory)][string]$ProductId)
  $pendingId = Read-AppPendingSubmissionId -AppJson $AppJson -ProductId $ProductId
  if ($pendingId) {
    throw ("Partner Center already has a pending submission $pendingId for $ProductId. This run did not create it, " +
      "so it stops and touches nothing (it never deletes a submission it did not create). $script:ApiOnlyNote " +
      "If it is in certification, let certification finish. If it is an uncommitted draft: " + (Get-DeleteByIdText $ProductId $pendingId))
  }
  Write-Host "No pending submission for $ProductId; safe to create a new one."
}

function Get-StoreApp([string]$ProductId) {
  Assert-ProductId $ProductId
  Invoke-StoreApi -Method GET -Path "applications/$ProductId"
}

function Get-StoreSubmissionJson([string]$ProductId, [string]$SubmissionId) {
  Assert-ProductId $ProductId; Assert-SubmissionId $SubmissionId
  Invoke-StoreApi -Method GET -Path "applications/$ProductId/submissions/$SubmissionId"
}

# Asks Partner Center whether the app has a pending submission; throws unless
# the call succeeded and reported none. Fails closed.
function Assert-NoPendingSubmission {
  param([Parameter(Mandatory)][string]$ProductId)
  try { $json = Get-StoreApp $ProductId } catch { throw "$_; cannot check for a pending submission; not publishing" }
  Test-NoPendingSubmission -AppJson $json -ProductId $ProductId
}

# POST /applications/{productId}/submissions. Returns the new submission's id,
# taken from the create response. On failure nothing was created and nothing is
# deleted.
function New-StoreSubmission {
  param([Parameter(Mandatory)][string]$ProductId)
  Assert-ProductId $ProductId
  try { $json = Invoke-StoreApi -Method POST -Path "applications/$ProductId/submissions" }
  catch {
    throw ("$_. No submission was created and none was deleted. HTTP 409 means the app's current state does not " +
      "allow a new submission, for example because another submission is pending; see the pending-submission check above.")
  }
  $id = ''
  try { $id = Get-JsonField ($json | ConvertFrom-Json -ErrorAction Stop) 'id' } catch { }
  $json = $null
  if ($id -notmatch '^\d+$') {
    throw "the create response has no submission id. A draft may have been created; look it up with GET /v1.0/my/applications/$ProductId (pendingApplicationSubmission.id). $script:ApiOnlyNote"
  }
  Write-Host "created submission id=$id (from the create response)"
  $id
}

# The service rejects or mishandles some pricing on PUT; the CLI refuses the
# same cases before its PUT (PriceIds.IsRoundTrippable): no pricing, an empty
# priceId (a PUT with it makes the product free) or 'Base'. Pure.
function Test-SubmissionPricing {
  param([Parameter(Mandatory)][AllowEmptyString()][string]$SubmissionJson)
  try { $s = $SubmissionJson | ConvertFrom-Json -ErrorAction Stop } catch { return [pscustomobject]@{ Result = 'Fail'; Reason = 'submission JSON does not parse' } }
  $p = if ($null -ne $s) { $s.PSObject.Properties['pricing'] } else { $null }
  if (-not $p -or $null -eq $p.Value) { return [pscustomobject]@{ Result = 'Fail'; Reason = 'submission has no pricing; a PUT without it could change the price' } }
  $price = Get-JsonField $p.Value 'priceId'
  if (-not $price) { return [pscustomobject]@{ Result = 'Fail'; Reason = 'pricing.priceId is empty; a PUT with it would make the product free' } }
  if ($price -eq 'Base') { return [pscustomobject]@{ Result = 'Fail'; Reason = "pricing.priceId is 'Base', which the service rejects on PUT" } }
  [pscustomobject]@{ Result = 'Pass'; Reason = "pricing.priceId=$price is kept as is" }
}

# Returns the submission JSON for the PUT: every existing package is marked
# PendingDelete (one still PendingUpload is dropped), and FileName is added as
# the only PendingUpload package. Everything else is passed through unchanged
# (System.Text.Json nodes, no re-typing of dates or numbers). Pure.
function Set-SubmissionPackage {
  param([Parameter(Mandatory)][string]$SubmissionJson, [Parameter(Mandatory)][string]$FileName)
  $o = [System.Text.Json.Nodes.JsonNodeOptions]::new()
  $o.PropertyNameCaseInsensitive = $true
  $n = [System.Text.Json.Nodes.JsonNode]::Parse($SubmissionJson, $o)
  if ($n -isnot [System.Text.Json.Nodes.JsonObject]) { throw "submission JSON is not an object" }
  $pk = $n['applicationPackages']
  if ($null -eq $pk) { $pk = [System.Text.Json.Nodes.JsonArray]::new(); $n['applicationPackages'] = $pk }
  if ($pk -isnot [System.Text.Json.Nodes.JsonArray]) { throw "applicationPackages is not a list" }
  for ($i = $pk.Count - 1; $i -ge 0; $i--) {
    $st = if ($null -ne $pk[$i]) { [string]$pk[$i]['fileStatus'] } else { '' }
    if ($st -ceq 'PendingUpload') { $pk.RemoveAt($i) }
    elseif ($st -cne 'PendingDelete') { $pk[$i]['fileStatus'] = [System.Text.Json.Nodes.JsonValue]::Create('PendingDelete') }
  }
  $new = [System.Text.Json.Nodes.JsonObject]::new()
  $new['fileName'] = [System.Text.Json.Nodes.JsonValue]::Create($FileName)
  $new['fileStatus'] = [System.Text.Json.Nodes.JsonValue]::Create('PendingUpload')
  $pk.Add($new)
  $n.ToJsonString()
}

# fileUploadUrl from submission JSON. Never print the result.
function Get-SubmissionUploadUrl([string]$SubmissionJson) {
  $u = ''
  try { $u = Get-JsonField ($SubmissionJson | ConvertFrom-Json -ErrorAction Stop) 'fileUploadUrl' } catch { }
  if ($u -notmatch '^https?://') { throw "the submission has no fileUploadUrl" }
  $u
}

# Zips the package (at the zip root, as the CLI does) and PUTs the zip to the
# submission's SAS upload URL as a block blob. Prints one fixed line on success;
# on failure throws with the URL and signature masked.
function Send-StorePackage {
  param([Parameter(Mandatory)][string]$UploadUrl, [Parameter(Mandatory)][string]$PackagePath)
  if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) { throw "package file missing" }
  $name = Split-Path -Leaf $PackagePath
  $work = Join-Path ([IO.Path]::GetTempPath()) ("store-upload-" + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory $work | Out-Null
  try {
    $zip = Join-Path $work 'Upload.zip'
    $z = [IO.Compression.ZipFile]::Open($zip, [IO.Compression.ZipArchiveMode]::Create)
    try { [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($z, $PackagePath, $name) | Out-Null } finally { $z.Dispose() }
    $len = (Get-Item -LiteralPath $zip).Length
    # The CLI escapes '+' in the SAS URL the same way before uploading.
    try {
      $r = Invoke-StoreHttp -Method PUT -Uri $UploadUrl.Replace('+', '%2B') -Headers @{ 'x-ms-blob-type' = 'BlockBlob' } -ContentType 'application/zip' -InFile $zip
    } catch { throw "package upload failed: $(Protect-StoreText $_.Exception.Message)" }
    if ($r.StatusCode -lt 200 -or $r.StatusCode -ge 300) { throw "package upload failed: HTTP $($r.StatusCode) $(Get-StoreErrorText $r.Body)" }
    Write-Host "package uploaded: $name in Upload.zip ($len bytes), HTTP $($r.StatusCode)"
  } finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# POST /applications/{productId}/submissions/{submissionId}/commit: commits
# exactly this submission, whatever else the app has.
function Invoke-SubmissionCommit {
  param([Parameter(Mandatory)][string]$ProductId, [Parameter(Mandatory)][string]$SubmissionId)
  Assert-ProductId $ProductId; Assert-SubmissionId $SubmissionId
  $json = Invoke-StoreApi -Method POST -Path "applications/$ProductId/submissions/$SubmissionId/commit"
  $st = ''
  try { $st = Get-JsonField ($json | ConvertFrom-Json -ErrorAction Stop) 'status' } catch { }
  Write-Host "submission $SubmissionId commit requested through the API: status=$st"
}

# Deletes one submission by id, only while it is an uncommitted draft
# (PendingCommit). For recovery by hand; the publish workflow never deletes.
function Remove-StoreDraftSubmission {
  param([Parameter(Mandatory)][string]$ProductId, [Parameter(Mandatory)][string]$SubmissionId)
  $sub = Read-SubmissionSafe -SubmissionJson (Get-StoreSubmissionJson $ProductId $SubmissionId)
  if (-not $sub -or $sub.Id -ne $SubmissionId) { throw "GET submission $SubmissionId did not return that submission; not deleting" }
  if ($sub.Status -cne 'PendingCommit') { throw "submission $SubmissionId is '$($sub.Status)', not an uncommitted PendingCommit draft; not deleting" }
  Invoke-StoreApi -Method DELETE -Path "applications/$ProductId/submissions/$SubmissionId" | Out-Null
  Write-Host "deleted draft submission $SubmissionId"
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

# Before commit: checks the draft this run created, read back by its id after
# the package update and upload. Pure. Set-SubmissionPackage marks every old
# package PendingDelete; this checks Partner Center kept it that way, so no old
# package (another extension, a second package) stays in the submission on commit.
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
  if (-not $sub) { return New-CheckResult $null 'Fail' 'the submission GET returned no submission JSON that parses' }
  if ($sub.Id -ne $SubmissionId) { return New-CheckResult $sub 'Fail' "the submission GET returned submission '$($sub.Id)', not draft $SubmissionId that this run created" }
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

# After commit: checks the submission this run created, read back by its id. Pure. Returns Result ('Pass', 'Pending' or
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
  if (-not $sub) { return New-CheckResult $null 'Fail' 'the submission GET returned no submission JSON that parses' }
  if (-not $sub.Id) { return New-CheckResult $sub 'Fail' 'submission JSON has no Id' }
  if ($ExpectedSubmissionId -and $sub.Id -ne $ExpectedSubmissionId) {
    return New-CheckResult $sub 'Fail' "the submission GET returned submission $($sub.Id), not submission $ExpectedSubmissionId that this run created"
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

# The publish job's API flow, every step after create on the id the create
# response returned (see the header). Returns that submission id once the
# commit was accepted. Before the commit, any failure leaves this run's draft
# uncommitted and says how to delete exactly that draft.
function Publish-StoreSubmission {
  param(
    [Parameter(Mandatory)][string]$ProductId,
    [Parameter(Mandatory)][string]$PackagePath,
    [Parameter(Mandatory)][string]$ExpectedFileName,
    [Parameter(Mandatory)][string]$ExpectedVersion
  )
  Assert-ProductId $ProductId
  if ((Split-Path -Leaf $PackagePath) -cne $ExpectedFileName) { throw "package file is not $ExpectedFileName" }
  if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) { throw "package file missing" }

  Assert-NoPendingSubmission -ProductId $ProductId
  $id = New-StoreSubmission -ProductId $ProductId
  try {
    $pending = Read-AppPendingSubmissionId -AppJson (Get-StoreApp $ProductId) -ProductId $ProductId
    if ($pending -ne $id) { throw "after create, the app's pending submission is '$pending', not $id" }

    $sub = Get-StoreSubmissionJson $ProductId $id
    $safe = Read-SubmissionSafe -SubmissionJson $sub
    if (-not $safe -or $safe.Id -ne $id) { throw "GET submission $id returned another submission" }
    $price = Test-SubmissionPricing -SubmissionJson $sub
    if ($price.Result -ne 'Pass') { throw "price check failed: $($price.Reason)" }
    Write-Host "price check: $($price.Reason)"

    $put = Set-SubmissionPackage -SubmissionJson $sub -FileName $ExpectedFileName
    $sub = $null
    $updated = Invoke-StoreApi -Method PUT -Path "applications/$ProductId/submissions/$id" -Body $put
    $put = $null
    $safe = Read-SubmissionSafe -SubmissionJson $updated
    if (-not $safe -or $safe.Id -ne $id) { throw "PUT submission $id returned another submission" }
    $url = Get-SubmissionUploadUrl $updated
    $updated = $null
    Write-Host "submission $id updated: old packages PendingDelete, $ExpectedFileName PendingUpload"
    Send-StorePackage -UploadUrl $url -PackagePath $PackagePath
    $url = $null

    $check = Test-DraftReadyToCommit -SubmissionJson (Get-StoreSubmissionJson $ProductId $id) -SubmissionId $id `
      -ExpectedFileName $ExpectedFileName -ExpectedVersion $ExpectedVersion
    Write-SubmissionSummary -Check $check
    if ($check.Result -ne 'Pass') { throw "draft check failed: $($check.Reason)" }
    Write-Host "draft verified: $($check.Reason)"
  } catch {
    throw "$_. Not committed: draft $id stays uncommitted. $script:ApiOnlyNote $(Get-DeleteByIdText $ProductId $id)"
  }
  try { Invoke-SubmissionCommit -ProductId $ProductId -SubmissionId $id }
  catch {
    throw ("$_. Commit of submission $id was not accepted. Read it back with GET /v1.0/my/applications/$ProductId/submissions/$id; " +
      "if it is still PendingCommit: $(Get-DeleteByIdText $ProductId $id)")
  }
  $id
}

# Runs after the commit: reads submission SubmissionId back by its id and
# checks it with Test-SubmissionHasPackage. Checks again every IntervalSeconds
# while Pending (a failed GET counts as Pending); throws "not verified" after
# TimeoutMinutes. Prints only safe fields. targetPublishMode other than Manual
# is a warning only: the commit has already happened, so failing the job here
# would stop nothing.
function Assert-SubmissionHasPackage {
  param(
    [Parameter(Mandatory)][string]$ProductId,
    [Parameter(Mandatory)][string]$SubmissionId,
    [Parameter(Mandatory)][string]$ExpectedVersion,
    [int]$TimeoutMinutes = 30,
    [int]$IntervalSeconds = 60
  )
  Assert-SubmissionId $SubmissionId
  Write-Host "checking submission id=$SubmissionId (created and committed by this run)"
  $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
  $warned = $false
  while ($true) {
    try {
      $json = Get-StoreSubmissionJson $ProductId $SubmissionId
      $check = Test-SubmissionHasPackage -SubmissionJson $json -ExpectedVersion $ExpectedVersion -ExpectedSubmissionId $SubmissionId
    } catch {
      $check = [pscustomobject]@{ Result = 'Pending'; Reason = "$_"; Id = $SubmissionId; Status = ''; TargetPublishMode = ''; Packages = @() }
    }
    $json = $null
    Write-SubmissionSummary -Check $check
    if ($check.TargetPublishMode -and $check.TargetPublishMode -ne 'Manual' -and -not $warned) {
      Write-Host ("::warning title=Store publish mode::targetPublishMode is '$($check.TargetPublishMode)', not Manual: " +
        "this submission goes live by itself once it passes certification. Publish mode is part of the submission and is " +
        "set through the submission API before commit, not in the Partner Center UI.")
      $warned = $true
    }
    if ($check.Result -eq 'Pass') { Write-Host "verified submission ${SubmissionId}: $($check.Reason)"; return }
    if ($check.Result -eq 'Fail') { throw "submission check failed: $($check.Reason)" }
    if ((Get-Date).AddSeconds($IntervalSeconds) -gt $deadline) {
      throw "submission not verified after $TimeoutMinutes min: $($check.Reason)"
    }
    Write-Host "pending: $($check.Reason); checking again in $IntervalSeconds s"
    Start-Sleep -Seconds $IntervalSeconds
  }
}

Export-ModuleMember -Function Get-StorePackage, Protect-StoreText, Invoke-StoreHttp, Connect-StoreApi, Test-NoPendingSubmission, Read-AppPendingSubmissionId, Assert-NoPendingSubmission, New-StoreSubmission, Test-SubmissionPricing, Set-SubmissionPackage, Send-StorePackage, Test-DraftReadyToCommit, Invoke-SubmissionCommit, Remove-StoreDraftSubmission, Publish-StoreSubmission, Test-SubmissionHasPackage, Assert-SubmissionHasPackage
