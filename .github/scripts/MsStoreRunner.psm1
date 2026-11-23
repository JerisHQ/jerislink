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
#   the SAS upload URL -> GET submission: every field except the packages is
#   unchanged (Compare-SubmissionFields) and Test-DraftReadyToCommit passes ->
#   POST .../submissions/{id}/commit. Assert-SubmissionHasPackage then reads
#   that id back until it is committed with the new package. When create or
#   commit gets no answer, the run reads the app or the submission back before
#   it says what happened (Resolve-UnconfirmedCreate/-Commit).
#
# Nothing here prints the token, the client secret, a SAS URL or a raw
# submission JSON (it holds fileUploadUrl). HTTP errors are reported as fixed
# text: the status code, a plain error code, or the exception type names
# (Get-StoreErrorText, Get-StoreFailureText); strings from the API are printed
# only when they match a plain pattern (Get-SafeValue). All HTTP goes through
# Invoke-StoreHttp (the Pester tests mock it): https to the Store hosts only,
# no redirects, no verbose or debug output. The token lives only in this
# PowerShell session; nothing is written to disk.

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:DefaultApiBase = 'https://manage.devcenter.microsoft.com'
$script:DefaultAuthorityHost = 'https://login.microsoftonline.com'
$script:ApiScope = 'https://manage.devcenter.microsoft.com/.default'
$script:ApiBase = $script:DefaultApiBase
$script:Token = ''
# Set only by Connect-StoreApi -LoopbackTestServer (msstore-publish-check.yml
# and the HTTP tests): then a stand-in on 127.0.0.1/localhost is also allowed.
$script:LoopbackTestServer = $false

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

# Where requests may go. In production: https on the default port to the
# sign-in host (Token), the Store API host (Api) or a blob storage account
# (Upload, the SAS URL the API hands out). With Connect-StoreApi
# -LoopbackTestServer, also http(s) to a loopback address (127.0.0.1,
# localhost, ::1) and nothing else. Pure apart from reading that switch.
function Test-StoreUri {
  param([AllowEmptyString()][string]$Uri, [Parameter(Mandatory)][ValidateSet('Token', 'Api', 'Upload')][string]$Kind)
  $u = $null
  if (-not [uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$u)) { return $false }
  if ($u.UserInfo) { return $false }
  if ($script:LoopbackTestServer -and $u.Scheme -in 'http', 'https' -and $u.IsLoopback) { return $true }
  if ($u.Scheme -cne 'https' -or -not $u.IsDefaultPort) { return $false }
  $h = $u.Host.ToLowerInvariant()
  switch ($Kind) {
    'Token' { return $h -ceq 'login.microsoftonline.com' }
    'Api' { return $h -ceq 'manage.devcenter.microsoft.com' }
    'Upload' { return $h -cmatch '^[a-z0-9-]{1,63}\.blob\.core\.windows\.net\z' }
  }
}

$script:UriRule = @{ Token = 'https://login.microsoftonline.com'; Api = 'https://manage.devcenter.microsoft.com'; Upload = 'https://<account>.blob.core.windows.net' }

# An exception whose message is fixed text that is safe to print. OutcomeUnknown:
# the request may have reached the service and no answer says what it did.
# NotSent: refused before anything was sent.
function New-StoreError([string]$Message, [switch]$OutcomeUnknown, [switch]$NotSent) {
  $e = [System.InvalidOperationException]::new($Message)
  $e.Data['StoreText'] = $Message
  $e.Data['StoreOutcomeUnknown'] = [bool]$OutcomeUnknown
  $e.Data['StoreNotSent'] = [bool]$NotSent
  $e
}

# Text for a failed call that got no HTTP response: a New-StoreError message,
# or else only the exception type names (and HttpRequestError/SocketErrorCode
# enum names) of the chain. Exception messages can hold the URL; never printed.
function Get-StoreFailureText($ErrorRecord) {
  $ex = $ErrorRecord.Exception
  if ($ex.Data.Contains('StoreText')) { return [string]$ex.Data['StoreText'] }
  $names = [System.Collections.Generic.List[string]]::new()
  while ($ex -and $names.Count -lt 6) {
    $n = $ex.GetType().Name
    foreach ($p in 'HttpRequestError', 'SocketErrorCode') {
      $v = $ex.PSObject.Properties[$p]
      if ($v -and "$($v.Value)" -cmatch '^[A-Za-z]{1,40}\z') { $n += " $($v.Value)" }
    }
    $names.Add($n)
    $ex = $ex.InnerException
  }
  "no response ($($names -join ' <- '))"
}

# True when the request may have been carried out although no answer says so:
# no response at all (except a refusal before sending), HTTP 408 or 5xx.
function Test-StoreOutcomeUnknown($ErrorRecord) {
  $d = $ErrorRecord.Exception.Data
  [bool]($d.Contains('StoreOutcomeUnknown') -and $d['StoreOutcomeUnknown'])
}

# The one place that touches the network. Returns StatusCode and Body (text);
# an HTTP error status (a redirect too) is returned, not thrown; a network
# failure throws. Refuses, before sending, a Uri that Test-StoreUri does not
# allow for Kind. No redirects: a redirect could take the token, the secret or
# the package elsewhere. No progress, verbose or debug output: PowerShell 7.6
# writes the URL, the headers and the body of a web request (the client
# secret, the bearer token, the SAS signature) to the debug stream
# (PowerShell/PowerShell#27695), so both are switched off for the call.
function Invoke-StoreHttp {
  param(
    [Parameter(Mandatory)][string]$Method,
    [Parameter(Mandatory)][string]$Uri,
    [Parameter(Mandatory)][ValidateSet('Token', 'Api', 'Upload')][string]$Kind,
    [hashtable]$Headers = @{},
    [string]$Body,
    [string]$ContentType,
    [string]$InFile
  )
  if (-not (Test-StoreUri -Uri $Uri -Kind $Kind)) {
    throw (New-StoreError "refused: $Kind requests go only to $($script:UriRule[$Kind]); nothing was sent" -NotSent)
  }
  $a = @{ Method = $Method; Uri = $Uri; Headers = $Headers; SkipHttpErrorCheck = $true; TimeoutSec = 600; MaximumRedirection = 0 }
  if ($PSBoundParameters.ContainsKey('Body')) { $a.Body = $Body }
  if ($ContentType) { $a.ContentType = $ContentType }
  if ($InFile) { $a.InFile = $InFile }
  $ProgressPreference = 'SilentlyContinue'
  # A redirect comes back as the 3xx response plus a non-terminating "maximum
  # redirection count exceeded" error; the caller reports the 3xx status.
  # Network failures are terminating errors and still throw.
  $webErr = $null
  $r = Invoke-WebRequest @a -Verbose:$false -Debug:$false -ErrorAction SilentlyContinue -ErrorVariable webErr
  if ($null -eq $r) {
    if ($webErr) { throw $webErr[0] }
    throw (New-StoreError "no response (no result)" -OutcomeUnknown)
  }
  $text = if ($r.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($r.Content) } else { [string]$r.Content }
  [pscustomobject]@{ StatusCode = [int]$r.StatusCode; Body = $text }
}

# Fixed diagnostics for an HTTP error response: the status code and, when the
# body has them, error codes that are plain identifiers (the Store API's code,
# the token endpoint's error and AADSTS numbers, blob storage's <Code>). No
# message text, URL or other part of the body is printed.
function Get-StoreErrorText {
  param([int]$StatusCode, [AllowNull()][AllowEmptyString()][string]$Body)
  $codes = [System.Collections.Generic.List[string]]::new()
  if ($Body) {
    $j = $null
    try { $j = $Body | ConvertFrom-Json -ErrorAction Stop } catch { }
    if ($j -is [System.Management.Automation.PSCustomObject]) {
      foreach ($n in 'code', 'error') {
        $p = $j.PSObject.Properties[$n]
        if (-not $p -or $null -eq $p.Value) { continue }
        if ($p.Value -is [string]) { $codes.Add($p.Value) }
        elseif ($p.Value -is [System.Management.Automation.PSCustomObject] -and $p.Value.PSObject.Properties['code']) { $codes.Add([string]$p.Value.code) }
      }
      $ec = $j.PSObject.Properties['error_codes']
      if ($ec -and $null -ne $ec.Value) { foreach ($c in @($ec.Value)) { if ("$c" -cmatch '^\d{1,9}\z') { $codes.Add("AADSTS$c") } } }
    } else {
      $m = [regex]::Match($Body, '<Code>([^<]{1,64})</Code>')
      if ($m.Success) { $codes.Add($m.Groups[1].Value) }
    }
  }
  $safe = @($codes | Where-Object { $_ -cmatch '^[A-Za-z][A-Za-z0-9_.]{0,63}\z' } | Select-Object -Unique | Select-Object -First 3)
  if ($safe.Count) { "HTTP $StatusCode ($($safe -join ', '))" } else { "HTTP $StatusCode" }
}

function Get-JsonField($Object, [string]$Name) {
  if ($null -eq $Object -or $Object -is [string]) { return '' }
  $p = $Object.PSObject.Properties[$Name]
  if ($p -and $null -ne $p.Value) { [string]$p.Value } else { '' }
}

# Strings from the API are printed (and compared) only when they match a plain
# pattern; anything else (a newline, a workflow command, a URL) becomes
# [invalid]. Empty stays empty.
$script:SafeWord = '^[A-Za-z]{1,40}\z'
$script:SafeId = '^\d{1,20}\z'
$script:SafeVersion = '^\d{1,5}(\.\d{1,5}){0,3}\z'
$script:SafePriceId = '^[A-Za-z][A-Za-z0-9]{0,39}\z'
$script:SafeFileName = '^[A-Za-z0-9_][A-Za-z0-9_.()+ -]{0,199}\z'
function Get-SafeValue([AllowNull()][AllowEmptyString()][string]$Value, [string]$Pattern) {
  if (-not $Value) { return '' }
  if ($Value -cmatch $Pattern) { $Value } else { '[invalid]' }
}

# Gets an access token for the Store submission API with the Entra app's client
# credentials (what the CLI's MSAL AcquireTokenForClient does) and keeps it in
# this session only. Never prints the token or the secret. AuthorityHost,
# ApiBase and LoopbackTestServer exist for msstore-publish-check.yml and the
# HTTP tests (a stand-in on 127.0.0.1); msstore-publish.yml never passes them.
# Without LoopbackTestServer only the default hosts over https are accepted,
# and a wrong host fails before the client secret is sent anywhere.
function Connect-StoreApi {
  [CmdletBinding()]
  param(
    [AllowEmptyString()][string]$TenantId,
    [AllowEmptyString()][string]$ClientId,
    [AllowEmptyString()][string]$ClientSecret,
    [string]$AuthorityHost = $script:DefaultAuthorityHost,
    [string]$ApiBase = $script:DefaultApiBase,
    [switch]$LoopbackTestServer
  )
  $script:Token = ''
  $script:LoopbackTestServer = [bool]$LoopbackTestServer
  if (-not $TenantId -or -not $ClientId -or -not $ClientSecret) { throw "tenant id, client id or client secret is empty (store environment secret missing?)" }
  if ($TenantId -notmatch '^[0-9A-Za-z.-]+\z') { throw "tenant id has unexpected characters" }
  $tokenUri = "$($AuthorityHost.TrimEnd('/'))/$TenantId/oauth2/v2.0/token"
  $base = $ApiBase.TrimEnd('/')
  if (-not (Test-StoreUri -Uri $tokenUri -Kind Token) -or -not (Test-StoreUri -Uri "$base/v1.0/my/" -Kind Api)) {
    throw "refused: sign-in goes only to $($script:UriRule.Token) and API calls only to $($script:UriRule.Api) (a loopback stand-in only with -LoopbackTestServer); the client secret was not sent"
  }
  $body = 'grant_type=client_credentials&client_id=' + [uri]::EscapeDataString($ClientId) +
          '&client_secret=' + [uri]::EscapeDataString($ClientSecret) + '&scope=' + [uri]::EscapeDataString($script:ApiScope)
  try {
    $r = Invoke-StoreHttp -Method POST -Uri $tokenUri -Kind Token -Body $body -ContentType 'application/x-www-form-urlencoded'
  } catch { throw "could not get a Partner Center access token: $(Get-StoreFailureText $_)" }
  finally { $body = $null }
  if ($r.StatusCode -ne 200) { throw "could not get a Partner Center access token: $(Get-StoreErrorText $r.StatusCode $r.Body)" }
  $tok = ''
  try { $tok = Get-JsonField ($r.Body | ConvertFrom-Json -ErrorAction Stop) 'access_token' } catch { }
  if (-not $tok) { throw "the token response has no access_token" }
  $script:Token = $tok
  $script:ApiBase = $base
  Write-Host "signed in to the Store submission API (token kept in memory, not printed)"
}

# One Store submission API call. Path is relative to /v1.0/my/. Returns the
# response body; throws a New-StoreError with fixed text on a network error or
# a non-2xx status. OutcomeUnknown is set when no answer came back (except a
# refusal before sending) or the status is 408 or 5xx: the service may have
# carried the request out.
function Invoke-StoreApi {
  param(
    [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PUT', 'DELETE')][string]$Method,
    [Parameter(Mandatory)][string]$Path,
    [string]$Body
  )
  if (-not $script:Token) { throw "not signed in to the Store submission API (Connect-StoreApi)" }
  $what = "$Method /v1.0/my/$Path"
  $a = @{ Method = $Method; Uri = "$script:ApiBase/v1.0/my/$Path"; Kind = 'Api'; Headers = @{ Authorization = "Bearer $script:Token" } }
  if ($PSBoundParameters.ContainsKey('Body')) { $a.Body = $Body; $a.ContentType = 'application/json; charset=utf-8' }
  try { $r = Invoke-StoreHttp @a }
  catch {
    $notSent = $_.Exception.Data.Contains('StoreNotSent') -and $_.Exception.Data['StoreNotSent']
    throw (New-StoreError "Store API $what failed: $(Get-StoreFailureText $_)" -OutcomeUnknown:(-not $notSent))
  }
  if ($r.StatusCode -lt 200 -or $r.StatusCode -ge 300) {
    throw (New-StoreError "Store API $what failed: $(Get-StoreErrorText $r.StatusCode $r.Body)" -OutcomeUnknown:($r.StatusCode -eq 408 -or $r.StatusCode -ge 500))
  }
  [string]$r.Body
}

function Assert-ProductId([string]$ProductId) {
  if ($ProductId -cnotmatch '^[0-9A-Za-z]{1,20}\z') { throw "product id is not a Store product id" }
}
function Assert-SubmissionId([string]$SubmissionId) {
  if ($SubmissionId -cnotmatch $script:SafeId) { throw "submission id '$(Get-SafeValue $SubmissionId $script:SafeId)' is not a number" }
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
# A pending submission without a numeric id is '(no usable id)'.
# Throws on JSON that does not parse or is another app.
function Read-AppPendingSubmissionId {
  param([Parameter(Mandatory)][AllowEmptyString()][string]$AppJson, [Parameter(Mandatory)][string]$ProductId)
  try { $app = $AppJson | ConvertFrom-Json -ErrorAction Stop } catch { throw "GET application returned JSON that does not parse" }
  if ($null -eq $app -or (Get-JsonField $app 'id') -cne $ProductId) { throw "GET application returned a different or empty application id" }
  $p = $app.PSObject.Properties['pendingApplicationSubmission']
  if (-not $p -or $null -eq $p.Value) { return '' }
  $id = Get-JsonField $p.Value 'id'
  if ($id -cnotmatch $script:SafeId) { return '(no usable id)' }
  $id
}

# Throws if the app (GET /applications/{productId} JSON) has a pending
# submission. Pure. Deletes nothing.
function Test-NoPendingSubmission {
  param([Parameter(Mandatory)][AllowEmptyString()][string]$AppJson, [Parameter(Mandatory)][string]$ProductId)
  $pendingId = Read-AppPendingSubmissionId -AppJson $AppJson -ProductId $ProductId
  if ($pendingId -ceq '(no usable id)') {
    throw ("Partner Center already has a pending submission (no usable id) for $ProductId. This run did not create it, " +
      "so it stops and touches nothing. Check GET /v1.0/my/applications/$ProductId before doing anything. $script:ApiOnlyNote")
  }
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
# taken from the create response. When the service answered with an error,
# nothing was created and nothing is deleted. When no answer came back (or
# HTTP 408/5xx), the result is unconfirmed: Resolve-UnconfirmedCreate reads the
# app back before saying what to do.
function New-StoreSubmission {
  param([Parameter(Mandatory)][string]$ProductId)
  Assert-ProductId $ProductId
  try { $json = Invoke-StoreApi -Method POST -Path "applications/$ProductId/submissions" }
  catch {
    if (Test-StoreOutcomeUnknown $_) { throw (Resolve-UnconfirmedCreate -ProductId $ProductId -Failure "$_") }
    throw ("$_. No submission was created and none was deleted. HTTP 409 means the app's current state does not " +
      "allow a new submission, for example because another submission is pending; see the pending-submission check above.")
  }
  $id = ''
  try { $id = Get-JsonField ($json | ConvertFrom-Json -ErrorAction Stop) 'id' } catch { }
  $json = $null
  if ($id -cnotmatch $script:SafeId) {
    throw "the create response has no submission id. A draft may have been created; look it up with GET /v1.0/my/applications/$ProductId (pendingApplicationSubmission.id). $script:ApiOnlyNote"
  }
  Write-Host "created submission id=$id (from the create response)"
  $id
}

# The create request got no answer. Before this run created anything the app
# had no pending submission (Assert-NoPendingSubmission), so a pending one now
# is most likely this run's draft. Returns the error text to throw; deletes
# nothing.
function Resolve-UnconfirmedCreate([string]$ProductId, [string]$Failure) {
  $head = "$Failure. Result unconfirmed: the create request got no answer, so a submission may or may not have been created. Read-back of the app:"
  try { $pending = Read-AppPendingSubmissionId -AppJson (Get-StoreApp $ProductId) -ProductId $ProductId }
  catch {
    return ("$head failed too ($_). The result stays unknown: do not delete anything yet. Once the API answers, read " +
      "GET /v1.0/my/applications/${ProductId}: no pendingApplicationSubmission means nothing was created (re-run this workflow); " +
      "a pending submission there is most likely this run's uncommitted draft. $script:ApiOnlyNote")
  }
  if (-not $pending) { return "$head no pending submission, so none was created and there is nothing to clean up. Re-run this workflow." }
  if ($pending -ceq '(no usable id)') {
    return "$head it shows a pending submission without a usable id. Check GET /v1.0/my/applications/$ProductId before doing anything. $script:ApiOnlyNote"
  }
  ("$head submission $pending is pending now and was not before this run's create, so it is most likely this run's draft; " +
    "it was not committed. Check it with GET /v1.0/my/applications/$ProductId/submissions/$pending (an uncommitted " +
    "PendingCommit draft), then: $(Get-DeleteByIdText $ProductId $pending) $script:ApiOnlyNote")
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
  [pscustomobject]@{ Result = 'Pass'; Reason = "pricing.priceId=$(Get-SafeValue $price $script:SafePriceId) is kept as is" }
}

# Returns the submission JSON for the PUT: every existing package is marked
# PendingDelete (one still PendingUpload is dropped), and FileName is added as
# the only PendingUpload package. Everything else is passed through unchanged
# (System.Text.Json nodes, no re-typing of dates or numbers). Pure.
# The update docs require fileName, fileStatus, minimumDirectXVersion and
# minimumSystemRam on every package object. The last two only apply to
# Windows 8.x/Phone 8.x packages; for an MSIX the value "must be present ...
# but the value you specify is ignored", so the new entry sends "None" (the
# docs' sample and the API's "no minimum").
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
  $new['minimumDirectXVersion'] = [System.Text.Json.Nodes.JsonValue]::Create('None')
  $new['minimumSystemRam'] = [System.Text.Json.Nodes.JsonValue]::Create('None')
  $pk.Add($new)
  $n.ToJsonString()
}

# Top-level submission fields left out of the before/after comparison:
# Partner Center owns them (id, status, statusDetails, fileUploadUrl) or this
# run changes them on purpose (applicationPackages). Every other field, known
# or not (pricing, listings, visibility, targetPublishMode, targetPublishDate,
# allowTargetFutureDeviceFamilies, ...), must come back from the PUT unchanged.
$script:UncomparedFields = @('id', 'status', 'statusDetails', 'fileUploadUrl', 'applicationPackages')

function ConvertTo-SubmissionNode([AllowEmptyString()][string]$Json) {
  $o = [System.Text.Json.Nodes.JsonNodeOptions]::new()
  $o.PropertyNameCaseInsensitive = $true
  $n = $null
  try { $n = [System.Text.Json.Nodes.JsonNode]::Parse($Json, $o) } catch { }
  if ($n -isnot [System.Text.Json.Nodes.JsonObject]) { throw "submission JSON is not an object" }
  foreach ($f in $script:UncomparedFields) { [void]$n.Remove($f) }
  , $n
}

# The compared fields of a submission as JSON (no fileUploadUrl, so no SAS
# URL is kept). Pure.
function Get-SubmissionComparedFields {
  param([Parameter(Mandatory)][string]$SubmissionJson)
  (ConvertTo-SubmissionNode $SubmissionJson).ToJsonString()
}

# Compares the fields kept by Get-SubmissionComparedFields with a submission
# read later. Returns Compared (how many fields) and Changed: the names of
# fields that differ, were dropped or were added (names that are not plain
# identifiers are shown as [unexpected field name]). Pure.
function Compare-SubmissionFields {
  param([Parameter(Mandatory)][string]$ExpectedJson, [Parameter(Mandatory)][AllowEmptyString()][string]$SubmissionJson)
  $want = ConvertTo-SubmissionNode $ExpectedJson
  $got = ConvertTo-SubmissionNode $SubmissionJson
  $names = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($kv in $want) {
    if (-not $got.ContainsKey($kv.Key) -or -not [System.Text.Json.Nodes.JsonNode]::DeepEquals($kv.Value, $got[$kv.Key])) { [void]$names.Add($kv.Key) }
  }
  foreach ($kv in $got) { if (-not $want.ContainsKey($kv.Key)) { [void]$names.Add($kv.Key) } }
  [pscustomobject]@{
    Compared = $want.Count
    Changed = @($names | ForEach-Object { if ($_ -cmatch '^[A-Za-z][A-Za-z0-9]{0,63}\z') { $_ } else { '[unexpected field name]' } } | Select-Object -Unique)
  }
}

# fileUploadUrl from submission JSON. Never print the result.
function Get-SubmissionUploadUrl([string]$SubmissionJson) {
  $u = ''
  try { $u = Get-JsonField ($SubmissionJson | ConvertFrom-Json -ErrorAction Stop) 'fileUploadUrl' } catch { }
  if (-not $u) { throw "the submission has no fileUploadUrl" }
  $u
}

# Zips the package (at the zip root, as the CLI does) and PUTs the zip to the
# submission's SAS upload URL as a block blob. Refuses an upload URL that is
# not https to a blob storage account (Test-StoreUri Upload) before zipping.
# Prints one fixed line on success; on failure throws fixed text only.
function Send-StorePackage {
  param([Parameter(Mandatory)][string]$UploadUrl, [Parameter(Mandatory)][string]$PackagePath)
  if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) { throw "package file missing" }
  if (-not (Test-StoreUri -Uri $UploadUrl -Kind Upload)) { throw "package upload refused: the upload URL is not $($script:UriRule.Upload); nothing was sent" }
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
      $r = Invoke-StoreHttp -Method PUT -Uri $UploadUrl.Replace('+', '%2B') -Kind Upload -Headers @{ 'x-ms-blob-type' = 'BlockBlob' } -ContentType 'application/zip' -InFile $zip
    } catch { throw "package upload failed: $(Get-StoreFailureText $_)" }
    if ($r.StatusCode -lt 200 -or $r.StatusCode -ge 300) { throw "package upload failed: $(Get-StoreErrorText $r.StatusCode $r.Body)" }
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
  Write-Host "submission $SubmissionId commit requested through the API: status=$(Get-SafeValue $st $script:SafeWord)"
}

# The commit request got no answer: reads this submission back by its id.
# Returns (the caller goes on to the read-back step) only when the read-back
# shows it committed; throws otherwise, with delete-by-id advice only when the
# read-back shows it is still an uncommitted PendingCommit draft.
function Resolve-UnconfirmedCommit([string]$ProductId, [string]$SubmissionId, [string]$Failure) {
  $head = "$Failure. Result unconfirmed: the commit request for submission $SubmissionId got no answer, so it may or may not have been committed. Read-back by id:"
  $sub = $null; $readErr = ''
  try { $sub = Read-SubmissionSafe -SubmissionJson (Get-StoreSubmissionJson $ProductId $SubmissionId) } catch { $readErr = "$_" }
  if (-not $sub -or $sub.Id -cne $SubmissionId) {
    $why = if ($readErr) { "failed too ($readErr)" } else { 'did not return that submission' }
    throw ("$head $why. The result stays unknown: do not delete, edit or commit anything yet. Once the API answers, read " +
      "GET /v1.0/my/applications/$ProductId/submissions/${SubmissionId}: CommitStarted or a later status means it was committed; " +
      "PendingCommit means it was not. $script:ApiOnlyNote")
  }
  if ($sub.Status -ceq 'PendingCommit') {
    throw "$head status is still PendingCommit, so it was not committed. $script:ApiOnlyNote $(Get-DeleteByIdText $ProductId $SubmissionId)"
  }
  if ($sub.Status -ceq 'CommitStarted' -or $sub.Status -cin $script:CommittedStatuses) {
    Write-Host ("::warning title=Store commit::The commit request for submission $SubmissionId got no answer, but the read-back " +
      "by id shows status $($sub.Status): it was committed. The next step checks its package.")
    return
  }
  throw "$head status is '$($sub.Status)'. Nothing is deleted or retried; check it with GET /v1.0/my/applications/$ProductId/submissions/$SubmissionId. $script:ApiOnlyNote"
}

# Deletes one submission by id, only while it is an uncommitted draft
# (PendingCommit). For recovery by hand; the publish workflow never deletes.
function Remove-StoreDraftSubmission {
  param([Parameter(Mandatory)][string]$ProductId, [Parameter(Mandatory)][string]$SubmissionId)
  $sub = Read-SubmissionSafe -SubmissionJson (Get-StoreSubmissionJson $ProductId $SubmissionId)
  if (-not $sub -or $sub.Id -cne $SubmissionId) { throw "GET submission $SubmissionId did not return that submission; not deleting" }
  if ($sub.Status -cne 'PendingCommit') { throw "submission $SubmissionId is '$($sub.Status)', not an uncommitted PendingCommit draft; not deleting" }
  Invoke-StoreApi -Method DELETE -Path "applications/$ProductId/submissions/$SubmissionId" | Out-Null
  Write-Host "deleted draft submission $SubmissionId"
}
# Parses submission JSON into safe fields only: Id, Status, TargetPublishMode,
# and FileName, Version, FileStatus per package, each passed through
# Get-SafeValue (a value that is not a plain id, word, version or file name is
# [invalid]). FileUploadUrl (a SAS URL with write access) is never copied.
# Returns $null when there is no JSON object.
function Read-SubmissionSafe {
  param([Parameter(Mandatory)][AllowEmptyString()][string]$SubmissionJson)
  $start = $SubmissionJson.IndexOf('{')
  if ($start -lt 0) { return $null }
  try { $raw = $SubmissionJson.Substring($start) | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
  $pkgs = @()
  $pkgProp = $raw.PSObject.Properties['ApplicationPackages']
  if ($pkgProp -and $null -ne $pkgProp.Value) {
    $pkgs = @(foreach ($p in @($pkgProp.Value)) {
      [pscustomobject]@{ FileName = Get-SafeValue (Get-JsonField $p 'FileName') $script:SafeFileName
                         Version = Get-SafeValue (Get-JsonField $p 'Version') $script:SafeVersion
                         FileStatus = Get-SafeValue (Get-JsonField $p 'FileStatus') $script:SafeWord }
    })
  }
  [pscustomobject]@{ Id = Get-SafeValue (Get-JsonField $raw 'Id') $script:SafeId; Status = Get-SafeValue (Get-JsonField $raw 'Status') $script:SafeWord
                     TargetPublishMode = Get-SafeValue (Get-JsonField $raw 'TargetPublishMode') $script:SafeWord; Packages = $pkgs }
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
  if ($sub.Id -cne $SubmissionId) { return New-CheckResult $sub 'Fail' "the submission GET returned submission '$($sub.Id)', not draft $SubmissionId that this run created" }
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
  if ($ExpectedSubmissionId -and $sub.Id -cne $ExpectedSubmissionId) {
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
# commit was accepted (or, when the commit got no answer, once the read-back
# by id shows it committed). Before the commit, any failure leaves this run's
# draft uncommitted and says how to delete exactly that draft.
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
    if ($pending -cne $id) { throw "after create, the app's pending submission is '$pending', not $id" }

    $sub = Get-StoreSubmissionJson $ProductId $id
    $safe = Read-SubmissionSafe -SubmissionJson $sub
    if (-not $safe -or $safe.Id -cne $id) { throw "GET submission $id returned another submission" }
    $price = Test-SubmissionPricing -SubmissionJson $sub
    if ($price.Result -ne 'Pass') { throw "price check failed: $($price.Reason)" }
    Write-Host "price check: $($price.Reason)"
    # Every field but the packages, as this run read it before its PUT.
    $kept = Get-SubmissionComparedFields -SubmissionJson $sub

    $put = Set-SubmissionPackage -SubmissionJson $sub -FileName $ExpectedFileName
    $sub = $null
    $updated = Invoke-StoreApi -Method PUT -Path "applications/$ProductId/submissions/$id" -Body $put
    $put = $null
    $safe = Read-SubmissionSafe -SubmissionJson $updated
    if (-not $safe -or $safe.Id -cne $id) { throw "PUT submission $id returned another submission" }
    $url = Get-SubmissionUploadUrl $updated
    $updated = $null
    Write-Host "submission $id updated: old packages PendingDelete, $ExpectedFileName PendingUpload"
    Send-StorePackage -UploadUrl $url -PackagePath $PackagePath
    $url = $null

    $now = Get-StoreSubmissionJson $ProductId $id
    $check = Test-DraftReadyToCommit -SubmissionJson $now -SubmissionId $id `
      -ExpectedFileName $ExpectedFileName -ExpectedVersion $ExpectedVersion
    Write-SubmissionSummary -Check $check
    if ($check.Result -ne 'Pass') { throw "draft check failed: $($check.Reason)" }
    $diff = Compare-SubmissionFields -ExpectedJson $kept -SubmissionJson $now
    $now = $null
    if ($diff.Changed.Count -gt 0) {
      throw ("submission fields changed after this run's update: $($diff.Changed -join ', '). Only applicationPackages " +
        "may change; every other field (pricing, listings, visibility, publish mode and date, device families, ...) " +
        "must read back as it was before the update")
    }
    Write-Host "fields unchanged: $($diff.Compared) submission fields other than applicationPackages read back as before the update"
    Write-Host "draft verified: $($check.Reason)"
  } catch {
    throw "$_. Not committed: draft $id stays uncommitted. $script:ApiOnlyNote $(Get-DeleteByIdText $ProductId $id)"
  }
  try { Invoke-SubmissionCommit -ProductId $ProductId -SubmissionId $id }
  catch {
    if (Test-StoreOutcomeUnknown $_) { Resolve-UnconfirmedCommit -ProductId $ProductId -SubmissionId $id -Failure "$_" }
    else {
      throw ("$_. Commit of submission $id was not accepted. Read it back with GET /v1.0/my/applications/$ProductId/submissions/$id; " +
        "if it is still PendingCommit: $(Get-DeleteByIdText $ProductId $id)")
    }
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

Export-ModuleMember -Function Get-StorePackage, Protect-StoreText, Test-StoreUri, Invoke-StoreHttp, Get-StoreErrorText, Connect-StoreApi, Test-NoPendingSubmission, Read-AppPendingSubmissionId, Assert-NoPendingSubmission, New-StoreSubmission, Test-SubmissionPricing, Set-SubmissionPackage, Get-SubmissionComparedFields, Compare-SubmissionFields, Send-StorePackage, Test-DraftReadyToCommit, Invoke-SubmissionCommit, Remove-StoreDraftSubmission, Publish-StoreSubmission, Test-SubmissionHasPackage, Assert-SubmissionHasPackage
