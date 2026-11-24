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
#   commit gets no answer, the run reads the app or the submission back and
#   reports what it shows (Resolve-UnconfirmedCreate/-Commit); while the result
#   is unconfirmed it gives no delete or retry advice.
# Time budget: the publish step has one timeout, and nothing prints once the
# runner kills it. Publish-StoreSubmission works to a deadline set before that
# timeout: the commit and its read-backs keep their own time at the end, every
# call before the commit is cut short so it cannot eat that time, and the
# submission id and how to check it by hand are printed before the commit
# request is sent and again as soon as it gets no answer.
#
# Nothing here prints the token, the client secret, a SAS URL or a raw
# submission JSON (it holds fileUploadUrl). No string from an API answer is
# printed as it came (Pepper, PR #74 r8): what a log line holds from an answer
# is its HTTP status, or a value from a fixed list in this module. An error
# code is printed only when it is a listed one ($script:StoreKnownCodes, the
# codes of $script:StoreCodeHint), else as [unlisted code]; a target or a
# changed field name only when it is a documented submission field name
# ($script:StoreTargetNames, printed as this module spells it); a submission
# status, publish mode, file status or price id only when it is one of the
# documented values (Get-ListedValue), else as [unlisted]; a package file name
# only when it is exactly the file this run uploads, else as
# [file name not shown]. Submission ids and versions are printed only when
# they are ASCII digits (and dots), which cannot carry a token, a secret or a
# signature, else as [invalid]. A Store API error line adds a hint written
# here for the code or status; the API's message text is never printed. A
# failed call without an answer is reported by its exception type names
# (Get-StoreFailureText). JSON that the parser rejects is reported with fixed
# text, never the parser's message (it quotes the JSON). Every such line also
# goes through Protect-WorkflowCommand, so neither "::" nor
# "##[" workflow command syntax reaches the log. All HTTP goes through
# Invoke-StoreHttp (the Pester tests mock it): https to the Store hosts only,
# no redirects, no verbose or debug output, and one time limit for the whole
# call (headers and body). An answer whose status came in but whose body could
# not be read is classified by that status, with a fixed text for the lost
# body. Request header values are checked before anything is sent (printable
# ASCII, then HttpHeaders.Add); the access token must be a plain bearer token
# (Test-StoreBearerToken) and is never printed when it is refused. The token
# lives only in this PowerShell session; nothing is written to disk.

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:DefaultApiBase = 'https://manage.devcenter.microsoft.com'
$script:DefaultAuthorityHost = 'https://login.microsoftonline.com'
$script:ApiScope = 'https://manage.devcenter.microsoft.com/.default'
$script:ApiBase = $script:DefaultApiBase
# UTC time no call may wait past (Get-CallTimeout); $null: no limit. Set and
# cleared by Publish-StoreSubmission and Resolve-UnconfirmedCommit.
$script:CallDeadline = $null
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
function New-StoreError([string]$Message, [switch]$OutcomeUnknown, [switch]$NotSent, [int]$Status = 0) {
  $e = [System.InvalidOperationException]::new($Message)
  $e.Data['StoreText'] = $Message
  $e.Data['StoreOutcomeUnknown'] = [bool]$OutcomeUnknown
  $e.Data['StoreNotSent'] = [bool]$NotSent
  $e.Data['StoreStatus'] = $Status
  $e
}

# The HTTP status a failed Invoke-StoreApi call got (New-StoreError -Status),
# or 0 when it got none (no answer, or not sent). Never throws: a mark that
# cannot be read is 0, which is never taken for an answered 2xx.
function Get-StoreErrorStatus($ErrorRecord) {
  try {
    $d = $ErrorRecord.Exception.Data
    if ($d.Contains('StoreStatus')) { return [int]$d['StoreStatus'] }
  } catch { }
  0
}
function Test-Store2xx([int]$Status) { $Status -ge 200 -and $Status -lt 300 }
# How each 2xx is handled; every code from 200 to 299 is listed below
# (Pepper, PR #74 r7 and r8). A change is a POST (create, commit), a PUT
# (update, the upload) or a DELETE.
# "Done": Test-StoreDone, the change counts as done. "Accepted":
# Test-StoreAccepted, "accepted, completion unconfirmed" (OutcomeUnknown with
# its status): checked once by id where there is one, never committed after,
# no delete or re-run advice. A GET's answer is used only on 200; every other
# 2xx is a failed read (Invoke-StoreApi), which before the commit stops with
# "Could not verify" (Get-UnverifiedDraftText). An accepted code is accepted
# whether its body was read or lost; a GET answered 200 whose body was lost is
# a failed read, and a change answered 200, 201 or 204 whose body was lost is
# done, but its answer is not used (Invoke-StoreApi).
#   200 OK                             GET: used         change: done
#   201 Created                        GET: failed read  change: done
#   202 Accepted                       GET: failed read  change: accepted
#   203 Non-Authoritative Information  GET: failed read  change: accepted
#   204 No Content                     GET: failed read  change: done (no body)
#   205 Reset Content                  GET: failed read  change: accepted
#   206 Partial Content                GET: failed read  change: accepted
#   207 Multi-Status                   GET: failed read  change: accepted
#   208 Already Reported               GET: failed read  change: accepted
#   209 210 211 212 213 214 215 216 217 218 219 220 221 222 223 224 225
#     (no registered meaning; each)    GET: failed read  change: accepted
#   226 IM Used                        GET: failed read  change: accepted
#   227 228 229 230 231 232 233 234 235 236 237 238 239 240 241 242 243
#   244 245 246 247 248 249 250 251 252 253 254 255 256 257 258 259 260
#   261 262 263 264 265 266 267 268 269 270 271 272 273 274 275 276 277
#   278 279 280 281 282 283 284 285 286 287 288 289 290 291 292 293 294
#   295 296 297 298 299
#     (no registered meaning; each)    GET: failed read  change: accepted
# 202 means the service took the request but has not finished it (RFC 9110,
# 15.3.3); the Store API and the blob upload are not documented to finish a
# change with any 2xx but 200, 201 and 204, so every other one is accepted.
function Test-StoreDone([int]$Status) { $Status -in 200, 201, 204 }
function Test-StoreAccepted([int]$Status) { (Test-Store2xx $Status) -and -not (Test-StoreDone $Status) }
# The submission id an accepted change's answer named (Invoke-StoreApi keeps
# only a plain number), or ''. Never throws.
function Get-StoreAcceptedId($ErrorRecord) {
  try {
    $d = $ErrorRecord.Exception.Data
    if ($d.Contains('StoreAcceptedId') -and [string]$d['StoreAcceptedId'] -cmatch $script:SafeId) { return [string]$d['StoreAcceptedId'] }
  } catch { }
  ''
}

# Fixed text printed instead of the diagnostics of a failed call when they
# cannot be formatted (Get-StoreErrorText, Get-StoreFailureText). Formatting
# never decides how an error is classified: Invoke-StoreApi decides
# OutcomeUnknown before it formats anything, and neither function throws
# (Pepper, PR #74 r2).
$script:NoDiagnostic = 'diagnostics not shown (they could not be formatted)'

# Text for a failed call that got no HTTP response: a New-StoreError message,
# or else only the exception type names (and HttpRequestError/SocketErrorCode
# enum names) of the chain. Exception messages can hold the URL; never printed.
# Never throws: if formatting fails, the text is "no HTTP response;" and the
# fixed $script:NoDiagnostic text.
function Get-StoreFailureText($ErrorRecord) {
  try {
    $t = Format-StoreFailureText $ErrorRecord
    if ($t -is [string] -and $t) { return $t }
  } catch { }
  "no HTTP response; $script:NoDiagnostic"
}
function Format-StoreFailureText($ErrorRecord) {
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

# The one place that touches the network. Returns StatusCode, Body (text) and
# BodyLost; an HTTP error status (a redirect too) is returned, not thrown; a
# network failure before the status arrives throws. Once the status line and
# headers are in, the status is always returned: if the body then cannot be
# read (the time limit is reached, the connection breaks), Body is '' and
# BodyLost is one of two fixed texts ($script:BodyLostText), so the caller
# still classifies the call by its status (Pepper, PR #74 r4). BodyLost is ''
# when the body was read. The body is decoded by ConvertFrom-StoreBodyBytes
# (an unknown charset is read as UTF-8, as Invoke-WebRequest read it).
# Refuses, before sending, a Uri that Test-StoreUri does not allow for Kind,
# and a header whose name or value is not valid (Test-StoreHeaderValue, then
# the validating HttpHeaders.Add that Invoke-WebRequest used). No redirects: a
# redirect could take the token, the secret or the package elsewhere.
# TimeoutSec is the time limit for the whole call: connecting, sending, the
# answer's headers and its body. Invoke-WebRequest -TimeoutSec is not that:
# since PowerShell 7.4 it bounds only the wait for the headers, so a server
# that answers in time and then drips its body held a call far past it
# (Pepper, PR #74 r3). So the call goes through HttpClient: one stopwatch for
# the whole call, every wait bounded by what is left of the limit
# (Wait-StoreHttpTask), and when the limit is reached the call is cancelled,
# its connection closed, and the fixed "no response (time limit ...)" error
# thrown (OutcomeUnknown). HttpClient writes nothing to PowerShell's streams
# (Invoke-WebRequest in PowerShell 7.6 writes the URL, the headers and the
# body of a request to the debug stream, PowerShell/PowerShell#27695).
function Invoke-StoreHttp {
  param(
    [Parameter(Mandatory)][string]$Method,
    [Parameter(Mandatory)][string]$Uri,
    [Parameter(Mandatory)][ValidateSet('Token', 'Api', 'Upload')][string]$Kind,
    [hashtable]$Headers = @{},
    [string]$Body,
    [string]$ContentType,
    [string]$InFile,
    [ValidateRange(1, 3600)][int]$TimeoutSec = 600
  )
  if (-not (Test-StoreUri -Uri $Uri -Kind $Kind)) {
    throw (New-StoreError "refused: $Kind requests go only to $($script:UriRule[$Kind]); nothing was sent" -NotSent)
  }
  $clock = [System.Diagnostics.Stopwatch]::StartNew()
  $handler = [System.Net.Http.SocketsHttpHandler]::new()
  $handler.AllowAutoRedirect = $false
  $handler.UseCookies = $false
  # As Invoke-WebRequest did: ask for gzip, deflate or br and decompress.
  $handler.AutomaticDecompression = [System.Net.DecompressionMethods]::All
  $client = [System.Net.Http.HttpClient]::new($handler, $true)
  # The limit is enforced below; HttpClient's own 100 s default must not cut
  # a long upload short.
  $client.Timeout = [System.Threading.Timeout]::InfiniteTimeSpan
  $cts = [System.Threading.CancellationTokenSource]::new()
  $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method), $Uri)
  $file = $null; $resp = $null
  try {
    # Invoke-WebRequest sent a User-Agent; HttpClient sends none by default.
    $req.Headers.Add('User-Agent', 'JerisLink-msstore-publish/1.0')
    foreach ($k in $Headers.Keys) {
      # The error names the header (only when the name itself is valid) and
      # never prints the value: it may be the bearer token.
      $name = [string]$k
      $v = [string]$Headers[$k]
      if ($name -cnotmatch '^[A-Za-z0-9-]{1,64}\z') { throw (New-StoreError "refused: a request header name is not valid; nothing was sent" -NotSent) }
      if (-not (Test-StoreHeaderValue $v)) { throw (New-StoreError "refused: request header $name has an invalid value (not printed); nothing was sent" -NotSent) }
      try { $req.Headers.Add($name, $v) }
      catch { throw (New-StoreError "refused: request header $name has an invalid value (not printed); nothing was sent" -NotSent) }
    }
    if ($InFile) { $file = [System.IO.File]::OpenRead($InFile); $req.Content = [System.Net.Http.StreamContent]::new($file) }
    elseif ($PSBoundParameters.ContainsKey('Body')) { $req.Content = [System.Net.Http.ByteArrayContent]::new([System.Text.UTF8Encoding]::new($false).GetBytes($Body)) }
    if ($req.Content -and $ContentType) { $req.Content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse($ContentType) }
    $resp = Wait-StoreHttpTask ($client.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cts.Token)) $clock $TimeoutSec $cts
    # The status is in: from here on the call has an answer, and a body that
    # cannot be read does not take the status away.
    $status = [int]$resp.StatusCode
    $text = ''; $lost = ''
    try {
      $bytes = [byte[]](Wait-StoreHttpTask ($resp.Content.ReadAsByteArrayAsync($cts.Token)) $clock $TimeoutSec $cts)
      $type = $resp.Content.Headers.ContentType
      $text = ConvertFrom-StoreBodyBytes $bytes $(if ($type) { $type.CharSet } else { '' })
    }
    catch {
      $text = ''
      $lost = if ($_.Exception.Data.Contains('StoreText')) { $script:BodyLostText.TimeLimit -f $TimeoutSec } else { $script:BodyLostText.Broken }
    }
    [pscustomobject]@{ StatusCode = $status; Body = $text; BodyLost = $lost }
  } finally {
    if ($resp) { $resp.Dispose() }
    $req.Dispose(); $client.Dispose(); $cts.Dispose()
    if ($file) { $file.Dispose() }
  }
}

# Waits for one step of an Invoke-StoreHttp call (Task), at most until TimeoutSec
# have passed on Clock since the call started. Then it cancels the call (Cts)
# and throws the fixed "no response (time limit ...)" error, OutcomeUnknown:
# the service may have received the request. Returns the step's result, or
# throws the exception the step failed with.
function Wait-StoreHttpTask($Task, [System.Diagnostics.Stopwatch]$Clock, [int]$TimeoutSec, [System.Threading.CancellationTokenSource]$Cts) {
  $left = [Math]::Max(0, [Math]::Ceiling($TimeoutSec * 1000 - $Clock.Elapsed.TotalMilliseconds))
  $done = $false
  try { $done = $Task.Wait([int]$left) } catch { $done = $Task.IsCompleted }
  if (-not $done -or $Task.IsCanceled) {
    $Cts.Cancel()
    throw (New-StoreError "no response (time limit of $TimeoutSec s for the whole request reached)" -OutcomeUnknown)
  }
  if ($Task.IsFaulted) { throw $Task.Exception.InnerException }
  $Task.Result
}

# The fixed text Invoke-StoreHttp returns as BodyLost when the status and
# headers arrived but the body did not: the time limit for the whole call was
# reached while it was read, or the connection broke (or the body could not be
# decoded). Fixed text only: nothing from the exception is printed.
$script:BodyLostText = @{
  TimeLimit = 'body not received (time limit of {0} s for the whole request reached)'
  Broken = 'body not received (the connection broke or the body could not be read)'
}

# BodyLost of an Invoke-StoreHttp result, or '' (a result without it, as the
# Pester mocks return, has its body). Never throws.
function Get-StoreBodyLost($Response) {
  try {
    $p = $Response.PSObject.Properties['BodyLost']
    if ($p -and $p.Value) { return [string]$p.Value }
  } catch { }
  ''
}

# The text of an answer's body (Bytes): a byte order mark decides first, then
# the charset of its Content-Type, else UTF-8, as HttpContent.ReadAsStringAsync
# reads it, except that a charset .NET does not know is read as UTF-8 (as
# Invoke-WebRequest did) instead of failing, so a body that came in is never
# lost to its charset. Invalid bytes become U+FFFD; never throws for them.
function ConvertFrom-StoreBodyBytes([byte[]]$Bytes, [string]$CharSet) {
  if (-not $Bytes -or $Bytes.Length -eq 0) { return '' }
  $enc = $null
  if ($CharSet) { try { $enc = [System.Text.Encoding]::GetEncoding($CharSet.Trim('"', ' ')) } catch { $enc = $null } }
  if (-not $enc) { $enc = [System.Text.UTF8Encoding]::new($false) }
  $reader = [System.IO.StreamReader]::new([System.IO.MemoryStream]::new($Bytes), $enc, $true)
  try { $reader.ReadToEnd() } finally { $reader.Dispose() }
}

# A request header value Invoke-StoreHttp sends: printable ASCII (space to ~)
# only, not empty, not blank, no space at either end. So no CR or LF (a header
# injection), no other control character (TAB, NUL, DEL, NEL), no non-ASCII.
# Invoke-WebRequest checked header values only through HttpHeaders.Add, which
# lets TAB, DEL, NEL and non-ASCII through; Invoke-StoreHttp also calls Add
# after this check.
function Test-StoreHeaderValue([AllowNull()][AllowEmptyString()][string]$Value) {
  [bool]($Value -cmatch '^[!-~]([ -~]*[!-~])?\z')
}

# An access token Invoke-StoreApi sends: an RFC 6750 b64token (letters,
# digits, - . _ ~ + /, then = padding). A JWT is one. Checked when the token
# arrives (Connect-StoreApi) and before every call; the error never prints the
# token or any part of it.
function Test-StoreBearerToken([AllowNull()][AllowEmptyString()][string]$Token) {
  [bool]($Token -cmatch '^[A-Za-z0-9._~+/-]+=*\z')
}

# The current UTC time (the tests replace it with a fake clock).
function Get-StoreUtcNow { [datetime]::UtcNow }

# Seconds a call may wait for its answer: Requested, cut to what is left before
# $script:CallDeadline. Throws (NotSent: nothing goes out) when less than one
# second is left.
function Get-CallTimeout([int]$Requested) {
  if ($null -eq $script:CallDeadline) { return $Requested }
  $left = [int][Math]::Floor(($script:CallDeadline - (Get-StoreUtcNow)).TotalSeconds)
  if ($left -lt 1) { throw (New-StoreError "not sent: no time left in this step's time budget" -NotSent) }
  [Math]::Min($Requested, $left)
}

# Makes text inert for the GitHub Actions runner, which reads workflow commands
# from every output line: "::name::" at the start of a line, and the legacy
# "##[name]" anywhere in a line (actions/runner ActionCommand.cs). Line breaks
# and other control or format characters become spaces, runs of ":" become one
# ":" and runs of "#" before "[" become one "#". Used on the error line
# (Get-StoreErrorText) and on every value that passes Get-SafeValue.
function Protect-WorkflowCommand([AllowNull()][AllowEmptyString()][string]$Text) {
  if (-not $Text) { return '' }
  $t = $Text -replace '[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+', ' '
  $t = $t -replace ':{2,}', ':'
  $t -replace '#{2,}\[', '#['
}

# Field names of the app submission resource and the resources inside it, as
# documented in "Manage app submissions" (learn.microsoft.com, Windows Store
# submission API). The only target names an error line prints.
$script:StoreTargetNames = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($n in @(
    # app submission
    'id', 'applicationCategory', 'pricing', 'visibility', 'targetPublishMode', 'targetPublishDate', 'listings',
    'hardwarePreferences', 'automaticBackupEnabled', 'canInstallOnRemovableMedia', 'isGameDvrEnabled', 'gamingOptions',
    'hasExternalInAppProducts', 'meetAccessibilityGuidelines', 'notesForCertification', 'status', 'statusDetails',
    'fileUploadUrl', 'applicationPackages', 'packageDeliveryOptions', 'enterpriseLicensing',
    'allowMicrosoftDecideAppAvailabilityToFutureDeviceFamilies', 'allowTargetFutureDeviceFamilies', 'friendlyName', 'trailers',
    # pricing, sale
    'trialPeriod', 'marketSpecificPricings', 'sales', 'priceId', 'isAdvancedPricingModel', 'name', 'basePriceId', 'startDate', 'endDate',
    # listing, base listing, image
    'baseListing', 'platformOverrides', 'copyrightAndTrademarkInfo', 'keywords', 'licenseTerms', 'privacyPolicy', 'supportContact',
    'websiteUrl', 'description', 'features', 'releaseNotes', 'images', 'recommendedHardware', 'minimumHardware', 'title',
    'shortDescription', 'shortTitle', 'sortTitle', 'voiceTitle', 'devStudio', 'fileName', 'fileStatus', 'imageType',
    # gaming options
    'genres', 'isLocalMultiplayer', 'isLocalCooperative', 'isOnlineMultiplayer', 'isOnlineCooperative', 'localMultiplayerMinPlayers',
    'localMultiplayerMaxPlayers', 'localCooperativeMinPlayers', 'localCooperativeMaxPlayers', 'isBroadcastingPrivilegeGranted',
    'isCrossPlayEnabled', 'kinectDataForExternal',
    # status details, certification report
    'errors', 'warnings', 'certificationReports', 'code', 'details', 'date', 'reportUrl',
    # application package
    'version', 'architecture', 'languages', 'capabilities', 'minimumDirectXVersion', 'minimumSystemRam', 'targetDeviceFamilies',
    # package delivery options, package rollout
    'packageRollout', 'isMandatoryUpdate', 'mandatoryUpdateEffectiveDate', 'isPackageRollout', 'packageRolloutPercentage',
    'packageRolloutStatus', 'fallbackSubmissionId',
    # trailers
    'videoFileName', 'videoFileId', 'trailerAssets', 'imageList')) { $script:StoreTargetNames[$n] = $n }

# The target of a Store API error as this module spells it: a listed field
# name, or a path of up to 8 of them joined by "." with an optional [index] of
# 1 to 4 ASCII digits (applicationPackages[0].fileName). Anything else is
# "[unlisted target]". [0-9], not \d: \d also matches the digits of other
# scripts (Arabic-Indic, fullwidth, ...), which [int] cannot convert (Pepper,
# PR #74 r2).
function Get-ListedTarget([AllowNull()][AllowEmptyString()][string]$Target) {
  $no = '[unlisted target]'
  if (-not $Target -or $Target.Length -gt 300) { return $no }
  $segments = $Target.Split('.')
  if ($segments.Count -gt 8) { return $no }
  $out = [System.Collections.Generic.List[string]]::new()
  foreach ($seg in $segments) {
    $m = [regex]::Match($seg, '^([A-Za-z]{1,64})(?:\[([0-9]{1,4})\])?\z')
    $name = ''
    if (-not $m.Success -or -not $script:StoreTargetNames.TryGetValue($m.Groups[1].Value, [ref]$name)) { return $no }
    $out.Add($(if ($m.Groups[2].Success) { "$name[$([int]$m.Groups[2].Value)]" } else { $name }))
  }
  $out -join '.'
}

# Hints written here, picked by the Store API error code (the submission
# status codes in "Manage app submissions") or else by the HTTP status (the
# error code tables of the create, update and commit pages). They say what kind
# of error it is; none of them advises deleting or retrying, and none says
# whether a request that timed out or got a 5xx was carried out (that stays
# unconfirmed).
$script:StoreCodeHint = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
$script:StoreCodeHint['InvalidParameterValue'] = 'a parameter in the request body is invalid'
$script:StoreCodeHint['InvalidOperation'] = 'the operation is not valid'
$script:StoreCodeHint['InvalidState'] = 'the operation is not valid for the current state of the app or submission'
$script:StoreCodeHint['ResourceNotFound'] = 'the app or submission was not found'
$script:StoreCodeHint['ServiceError'] = 'the service reported an internal error'
$script:StoreCodeHint['InvalidArchive'] = 'the package ZIP archive is invalid'
$script:StoreCodeHint['MissingFiles'] = 'the package ZIP archive lacks files the submission lists'
$script:StoreCodeHint['PackageValidationFailed'] = 'a package failed validation'
$script:StoreStatusHint = @{
  400 = 'the request is invalid'
  401 = 'the access token was not accepted'
  403 = 'the Entra app is not allowed to do this'
  404 = 'the app or submission was not found'
  408 = 'the request timed out'
  409 = 'the current state of the app does not allow this, or the app uses a Partner Center feature the submission API does not support'
  429 = 'too many requests'
  500 = 'the service reported an internal error'
  502 = 'a gateway in front of the service reported an error'
  503 = 'the service reported that it is unavailable'
  504 = 'a gateway in front of the service timed out'
}
$script:StoreUnknownHint = 'no description of this error is known here (the API''s message text is not printed)'

# The only error codes an error line prints (Pepper, PR #74 r8): a code is
# printed when it is in this list or in $script:StoreCodeHint (same spelling,
# case-sensitive), else as [unlisted code], so no string the API put in a code
# field (a token, a secret, a SAS signature) reaches the log. The lists: the
# Store API's documented codes and the generic codes it and its gateways send;
# the OAuth 2.0 error values (RFC 6749 5.2) and the AADSTS numbers of the
# client-credentials sign-in that the Entra docs list for a wrong tenant,
# client, secret or scope; the Blob storage error codes a Put Blob with a SAS
# can get (learn.microsoft.com, "Blob Storage error codes", "Common REST API
# error codes").
$script:StoreKnownCodes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($c in @(
    # Store API and generic HTTP codes
    'BadRequest', 'Unauthorized', 'Forbidden', 'NotFound', 'Conflict', 'TooManyRequests', 'InternalServerError',
    'ServiceUnavailable', 'RequestTimeout', 'MethodNotAllowed', 'GatewayTimeout',
    # OAuth 2.0 token endpoint
    'invalid_request', 'invalid_client', 'invalid_grant', 'unauthorized_client', 'unsupported_grant_type', 'invalid_scope',
    'invalid_resource', 'access_denied', 'server_error', 'temporarily_unavailable',
    'AADSTS7000215', 'AADSTS7000222', 'AADSTS7000218', 'AADSTS700016', 'AADSTS7000112', 'AADSTS7000229', 'AADSTS90002',
    'AADSTS900023', 'AADSTS50059', 'AADSTS90014', 'AADSTS900144', 'AADSTS70011', 'AADSTS500011', 'AADSTS53003',
    # Blob storage
    'AuthenticationFailed', 'AuthorizationFailure', 'AuthorizationPermissionMismatch', 'AuthorizationResourceTypeMismatch',
    'AuthorizationProtocolMismatch', 'AuthorizationSourceIPMismatch', 'AuthorizationServiceMismatch', 'InvalidAuthenticationInfo',
    'InsufficientAccountPermissions', 'AccountIsDisabled', 'ContainerNotFound', 'ContainerBeingDeleted', 'ContainerDisabled',
    'InvalidBlobOrBlock', 'InvalidBlobType', 'InvalidHeaderValue', 'InvalidQueryParameterValue', 'InvalidUri', 'InvalidInput',
    'InvalidMd5', 'Md5Mismatch', 'MissingContentLengthHeader', 'MissingRequiredHeader', 'MissingRequiredQueryParameter',
    'UnsupportedHeader', 'UnsupportedQueryParameter', 'RequestBodyTooLarge', 'InternalError', 'ServerBusy', 'OperationTimedOut',
    'ConditionNotMet', 'ResourceNotFound', 'OutOfRangeInput', 'InvalidResourceName')) { [void]$script:StoreKnownCodes.Add($c) }

# A code as an error line prints it: the code when it is listed (above, or a
# key of $script:StoreCodeHint), else [unlisted code].
function Get-ListedCode([AllowNull()][AllowEmptyString()][string]$Code) {
  if ($Code -and ($script:StoreKnownCodes.Contains($Code) -or $script:StoreCodeHint.ContainsKey($Code))) { return $Code }
  '[unlisted code]'
}

# Diagnostics for an HTTP error response: the status code and, when the body
# has them, its error codes through Get-ListedCode (the Store API's code, the
# token endpoint's error and AADSTS numbers, blob storage's <Code>). Without
# Detail nothing else of the body is printed (the token endpoint and the blob
# upload). With Detail (Store API calls only), also the API's target through
# Get-ListedTarget (read from the top level of the JSON body or from its error
# object) and a hint from the tables above. No message text from the body is
# ever printed. Never throws: if formatting fails, the line is the status and
# the fixed $script:NoDiagnostic text.
function Get-StoreErrorText {
  param([int]$StatusCode, [AllowNull()][AllowEmptyString()][string]$Body, [switch]$Detail)
  try {
    $t = Format-StoreErrorText -StatusCode $StatusCode -Body $Body -Detail:$Detail
    if ($t -is [string] -and $t) { return $t }
  } catch { }
  "HTTP $StatusCode; $script:NoDiagnostic"
}
function Format-StoreErrorText {
  param([int]$StatusCode, [AllowNull()][AllowEmptyString()][string]$Body, [switch]$Detail)
  $codes = [System.Collections.Generic.List[string]]::new()
  $target = $null
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
      if ($Detail) {
        $e = $j.PSObject.Properties['error']
        foreach ($o in @($j, $(if ($e -and $e.Value -is [System.Management.Automation.PSCustomObject]) { $e.Value }))) {
          if ($null -eq $o) { continue }
          $p = $o.PSObject.Properties['target']
          if ($null -eq $target -and $p -and $null -ne $p.Value -and "$($p.Value)" -ne '') { $target = $p.Value }
        }
      }
    } else {
      $m = [regex]::Match($Body, '<Code>([^<]{1,64})</Code>')
      if ($m.Success) { $codes.Add($m.Groups[1].Value) }
    }
  }
  $safe = @($codes | ForEach-Object { Get-ListedCode $_ } | Select-Object -Unique | Select-Object -First 3)
  $t = if ($safe.Count) { "HTTP $StatusCode ($($safe -join ', '))" } else { "HTTP $StatusCode" }
  if ($Detail) {
    if ($null -ne $target) { $t += "; target: $(if ($target -is [string]) { Get-ListedTarget $target } else { '[unlisted target]' })" }
    $hint = ''
    foreach ($c in $safe) { if ($script:StoreCodeHint.TryGetValue($c, [ref]$hint)) { break } }
    if (-not $hint) { $hint = if ($script:StoreStatusHint.ContainsKey($StatusCode)) { $script:StoreStatusHint[$StatusCode] } else { $script:StoreUnknownHint } }
    $t += "; hint: $hint"
  }
  Protect-WorkflowCommand $t
}

function Get-JsonField($Object, [string]$Name) {
  if ($null -eq $Object -or $Object -is [string]) { return '' }
  $p = $Object.PSObject.Properties[$Name]
  if ($p -and $null -ne $p.Value) { [string]$p.Value } else { '' }
}

# Ids and versions from the API are printed (and compared) only when they are
# ASCII digits (a version: up to four dot-separated numbers); anything else
# becomes [invalid]. Empty stays empty. A value that passes still goes through
# Protect-WorkflowCommand (a second line of defence). Digits are [0-9] only:
# \d would also pass the digits of other scripts.
$script:SafeId = '^[0-9]{1,20}\z'
$script:SafeVersion = '^[0-9]{1,5}(\.[0-9]{1,5}){0,3}\z'
function Get-SafeValue([AllowNull()][AllowEmptyString()][string]$Value, [string]$Pattern) {
  if (-not $Value) { return '' }
  if ($Value -cmatch $Pattern) { Protect-WorkflowCommand $Value } else { '[invalid]' }
}

# Every other string from the API is printed (and compared) only when it is
# exactly one of the documented values below, same case (Pepper, PR #74 r8);
# Get-ListedValue then returns the list's own string. Empty stays empty;
# anything else is [unlisted]. Values from "Manage app submissions"
# (learn.microsoft.com, Windows Store submission API): the submission status
# (also the commit response's status), the publish mode, a package's file
# status, and the price ids Base, NotAvailable, Free and Tier<number>
# (Get-ListedPriceId).
$script:SubmissionStatuses = @('None', 'Canceled', 'PendingCommit', 'CommitStarted', 'CommitFailed', 'PendingPublication',
  'Publishing', 'Published', 'PublishFailed', 'PreProcessing', 'PreProcessingFailed', 'Certification', 'CertificationFailed',
  'Release', 'ReleaseFailed')
$script:PublishModes = @('Immediate', 'Manual', 'SpecificDate')
$script:FileStatuses = @('None', 'PendingUpload', 'Uploaded', 'PendingDelete')
$script:PriceIds = @('Base', 'NotAvailable', 'Free')
function Get-ListedValue([AllowNull()][AllowEmptyString()][string]$Value, [string[]]$List) {
  if (-not $Value) { return '' }
  foreach ($v in $List) { if ($v -ceq $Value) { return $v } }
  '[unlisted]'
}
function Get-ListedPriceId([AllowNull()][AllowEmptyString()][string]$Value) {
  if ($Value -cmatch '^Tier[0-9]{1,5}\z') { return "Tier$($Value.Substring(4))" }
  Get-ListedValue $Value $script:PriceIds
}

# A package file name from the API is printed only when it is exactly
# Expected (the file this run uploads; Pepper, PR #74 r8). Empty stays empty;
# any other name is [file name not shown].
function Get-ListedFileName([AllowNull()][AllowEmptyString()][string]$Value, [AllowEmptyString()][string]$Expected) {
  if (-not $Value) { return '' }
  if ($Expected -and $Value -ceq $Expected) { return $Expected }
  '[file name not shown]'
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
  $lost = Get-StoreBodyLost $r
  if ($r.StatusCode -ne 200 -or $lost) {
    $t = if ($r.StatusCode -eq 200) { 'HTTP 200' } else { Get-StoreErrorText $r.StatusCode $r.Body }
    if ($lost) { $t += "; $lost" }
    throw "could not get a Partner Center access token: $t"
  }
  $tok = ''
  try { $tok = Get-JsonField ($r.Body | ConvertFrom-Json -ErrorAction Stop) 'access_token' } catch { }
  if (-not $tok) { throw "the token response has no access_token" }
  if (-not (Test-StoreBearerToken $tok)) { $tok = $null; throw "the token response's access_token is not a valid bearer token (it is not printed); not signed in" }
  $script:Token = $tok
  $script:ApiBase = $base
  Write-Host "signed in to the Store submission API (token kept in memory, not printed)"
}

# One Store submission API call. Path is relative to /v1.0/my/ and may end in a
# query string. Returns the response body; throws a New-StoreError on a network
# error (fixed text) or a non-2xx status (status, error codes and the API's
# listed target and a hint: Get-StoreErrorText -Detail). OutcomeUnknown is
# set when no answer came back (except a
# refusal before sending) or the status is 408 or 5xx: the service may have
# carried the request out. That is decided before any diagnostic text is
# formatted, and a failure while reading the NotSent mark counts as sent, so
# an unconfirmed outcome stays unconfirmed whatever the text turns out to be.
# A status whose body was lost (Invoke-StoreHttp BodyLost) is classified by
# that status alone (Pepper, PR #74 r4): 408 and 5xx OutcomeUnknown, another
# error status (400, 409, ...) refused; the text is the status, its hint and
# the fixed BodyLost text. A 2xx whose body was lost is OutcomeUnknown: the
# service did it, but what it answered (a create's new id) is not known. The
# status goes with the error (Get-StoreErrorStatus), so a caller can tell an
# answered 2xx (done, answer unread) from no answer at all.
# Which 2xx count (Pepper, PR #74 r7): a GET returns its body only on HTTP
# 200; a 201, 202, 204 or other 2xx carries no resource to read, so it is a
# failed read. A POST, PUT or DELETE returns its body only on 200, 201 or 204
# (Test-StoreDone). HTTP 202 or another 2xx (Test-StoreAccepted) is thrown as
# "accepted, completion unconfirmed", OutcomeUnknown with its status, whether
# or not its body was read: an accepted answer does not say the change is
# done. Only a plain-number "id" from a body that was read goes with that
# error (Get-StoreAcceptedId), so the caller can check that id; nothing else
# of the body is used or printed.
# The access token is checked (Test-StoreBearerToken) before anything is sent.
function Invoke-StoreApi {
  param(
    [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PUT', 'DELETE')][string]$Method,
    [Parameter(Mandatory)][string]$Path,
    [string]$Body,
    [ValidateRange(1, 3600)][int]$TimeoutSec = 600
  )
  if (-not $script:Token) { throw "not signed in to the Store submission API (Connect-StoreApi)" }
  $what = "$Method /v1.0/my/$Path"
  $a = @{ Method = $Method; Uri = "$script:ApiBase/v1.0/my/$Path"; Kind = 'Api'; Headers = @{ Authorization = "Bearer $script:Token" } }
  if ($PSBoundParameters.ContainsKey('Body')) { $a.Body = $Body; $a.ContentType = 'application/json; charset=utf-8' }
  try {
    if (-not (Test-StoreBearerToken $script:Token)) { throw (New-StoreError "not sent: the access token is not a valid bearer token (it is not printed)" -NotSent) }
    $a.TimeoutSec = Get-CallTimeout $TimeoutSec
    $r = Invoke-StoreHttp @a
  }
  catch {
    $notSent = $false
    $failure = $_
    try { $notSent = [bool]($failure.Exception.Data.Contains('StoreNotSent') -and $failure.Exception.Data['StoreNotSent']) } catch { }
    $unknown = -not $notSent
    throw (New-StoreError "Store API $what failed: $(Get-StoreFailureText $failure)" -OutcomeUnknown:$unknown)
  }
  $lost = Get-StoreBodyLost $r
  $s = $r.StatusCode
  $used = if ($Method -eq 'GET') { $s -eq 200 } else { Test-StoreDone $s }
  if ($used -and -not $lost) { return [string]$r.Body }
  if ($Method -ne 'GET' -and (Test-StoreAccepted $s)) {
    $e = New-StoreError "Store API $what answered HTTP ${s}: accepted, completion unconfirmed$(if ($lost) { "; $lost" })" -OutcomeUnknown -Status $s
    if (-not $lost) {
      $id = ''
      try { $id = Get-JsonField ($r.Body | ConvertFrom-Json -ErrorAction Stop) 'id' } catch { }
      if ($id -cmatch $script:SafeId) { $e.Data['StoreAcceptedId'] = $id }
    }
    throw $e
  }
  $ok = Test-Store2xx $s
  $unknown = $ok -or $s -eq 408 -or $s -ge 500
  $t = if ($ok) { "HTTP $s" } else { Get-StoreErrorText $s $r.Body -Detail }
  if ($ok -and -not $used) { $t += ' (a read is used only when answered HTTP 200)' }
  if ($lost) { $t += "; $lost" }
  throw (New-StoreError "Store API $what failed: $t" -OutcomeUnknown:$unknown -Status $s)
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

function Get-StoreApp([string]$ProductId, [int]$TimeoutSec = 600) {
  Assert-ProductId $ProductId
  Invoke-StoreApi -Method GET -Path "applications/$ProductId" -TimeoutSec $TimeoutSec
}

function Get-StoreSubmissionJson([string]$ProductId, [string]$SubmissionId, [int]$TimeoutSec = 600) {
  Assert-ProductId $ProductId; Assert-SubmissionId $SubmissionId
  Invoke-StoreApi -Method GET -Path "applications/$ProductId/submissions/$SubmissionId" -TimeoutSec $TimeoutSec
}

# Asks Partner Center whether the app has a pending submission; throws unless
# the call succeeded and reported none. Fails closed.
function Assert-NoPendingSubmission {
  param([Parameter(Mandatory)][string]$ProductId)
  try { $json = Get-StoreApp $ProductId } catch { throw "$_; cannot check for a pending submission; not publishing" }
  Test-NoPendingSubmission -AppJson $json -ProductId $ProductId
}

# POST /applications/{productId}/submissions?isMinimalResponse=true (the query
# the msstore CLI and StoreBroker send). Returns the new submission's id, the
# only field read from the create response. When the service answered with an
# error, nothing was created and nothing is deleted. That error is printed
# first ("create refused: ..."), so it is in the log whatever happens next;
# then one read-only GET of the app, within ReadBackTimeoutSec for the whole
# call, reports whether a submission is pending (Get-RefusedCreateReadBack),
# and the error is thrown with that report. When no answer came back (or HTTP
# 408/5xx), the result is unconfirmed: Resolve-UnconfirmedCreate reads the app
# back and reports what it shows. HTTP 200, 201 or 204 means the service
# created a submission; when its id cannot be read (the body was lost, or it
# has no usable id) that is "created, id unknown", never "not created":
# Resolve-CreatedIdUnknown reads the app back and the run stops. HTTP 202 (or
# another 2xx, Test-StoreAccepted) means accepted, completion unconfirmed:
# Resolve-AcceptedCreate checks once (by the answer's id, if it named one)
# and the run stops, with or without that id.
function New-StoreSubmission {
  param([Parameter(Mandatory)][string]$ProductId, [ValidateRange(1, 600)][int]$ReadBackTimeoutSec = 30)
  Assert-ProductId $ProductId
  try { $json = Invoke-StoreApi -Method POST -Path "applications/$ProductId/submissions?isMinimalResponse=true" }
  catch {
    $status = Get-StoreErrorStatus $_
    if (Test-StoreAccepted $status) {
      throw (Resolve-AcceptedCreate -ProductId $ProductId -Answer "$_" -Status $status -Id (Get-StoreAcceptedId $_) -TimeoutSec $ReadBackTimeoutSec)
    }
    if (Test-Store2xx $status) { throw (Resolve-CreatedIdUnknown -ProductId $ProductId -Answer "$_" -Status "HTTP $status" -TimeoutSec $ReadBackTimeoutSec) }
    if (Test-StoreOutcomeUnknown $_) { throw (Resolve-UnconfirmedCreate -ProductId $ProductId -Failure "$_") }
    $refused = "$_. No submission was created and none was deleted."
    Write-Host "create refused: $refused"
    $readBack = 'Read-back of the app after the refused create: not done.'
    try { $readBack = Get-RefusedCreateReadBack $ProductId $ReadBackTimeoutSec } catch { }
    throw ("$refused HTTP 409 means the app's current state does not allow a new submission, for example because " +
      "another submission is pending; see the pending-submission check above. $readBack")
  }
  $id = ''
  try { $id = Get-JsonField ($json | ConvertFrom-Json -ErrorAction Stop) 'id' } catch { }
  $json = $null
  if ($id -cnotmatch $script:SafeId) {
    throw (Resolve-CreatedIdUnknown -ProductId $ProductId -Answer "the create response (HTTP 200, 201 or 204) has no usable submission id" -Status 'HTTP 200, 201 or 204' -TimeoutSec $ReadBackTimeoutSec)
  }
  Write-Host "created submission id=$id (from the create response)"
  $id
}

# The service answered the create with an error, so nothing was created. For
# the log only: one read-only GET of the app (at most TimeoutSec for the whole
# call, headers and body, and no longer than the call deadline) and a
# sentence saying whether a submission is pending, by id only. A failure or a
# timeout of the GET is reported in that sentence, never thrown. Changes and
# deletes nothing and gives no delete advice: the pending check before create
# found none, so a pending submission now did not come from this run.
function Get-RefusedCreateReadBack([string]$ProductId, [int]$TimeoutSec) {
  $h = 'Read-back of the app after the refused create (one GET; nothing changed or deleted):'
  try { $pending = Read-AppPendingSubmissionId -AppJson (Get-StoreApp $ProductId -TimeoutSec $TimeoutSec) -ProductId $ProductId }
  catch { return "$h failed ($_)." }
  if (-not $pending) { return "$h no pendingApplicationSubmission." }
  if ($pending -ceq '(no usable id)') { return "$h pendingApplicationSubmission exists, without a usable id. This run did not create it." }
  "$h pendingApplicationSubmission id $pending. This run did not create it."
}

# The create was answered with HTTP 200, 201 or 204 (Test-StoreDone), so the
# service created a submission, but this run did not get its id: the answer's
# body was lost or has no usable id (Pepper, PR #74 r5). Prints a warning first (so the facts are in the log
# even if the step is killed during the read-back), then reads the app back
# once (one GET, at most TimeoutSec) and returns the error text to throw, so
# the run stops. A pending submission is reported by its id only; none yet,
# none with a usable id, or a failed read-back (the Store may show a new
# submission only after a while) is left to a person to check. Never updates,
# uploads to, commits or deletes a submission, and gives no re-run or delete
# advice.
function Resolve-CreatedIdUnknown([string]$ProductId, [string]$Answer, [string]$Status, [int]$TimeoutSec) {
  $app = "GET /v1.0/my/applications/$ProductId"
  $look = "A person needs to check the app's pending submission in Partner Center (look only, change nothing there) or with $app (pendingApplicationSubmission.id)"
  Write-Host ("::warning title=Store create::Created, id unknown: the Store answered the create with $Status, so it created " +
    "a submission, but this run did not get its id ($Answer). The run stops; it updates, commits and deletes nothing. " +
    "Reading the app back once. If this step ends before a result is printed below: $look; the Store may take a while to show it.")
  $head = ("$Answer. Created, id unknown: the Store answered the create with $Status, so it created a submission, but this " +
    "run did not get the new submission's id. This run stops: it does not update, upload to, commit or delete any submission. " +
    "Read-back of the app (one GET):")
  try { $pending = Read-AppPendingSubmissionId -AppJson (Get-StoreApp $ProductId -TimeoutSec $TimeoutSec) -ProductId $ProductId }
  catch { return "$head failed ($_). $look once the API answers; the Store may take a while to show the new submission. $script:ApiOnlyNote" }
  if (-not $pending) {
    return ("$head no pending submission yet. That does not mean none was created: the Store may take a while to show the " +
      "new submission. $look later. $script:ApiOnlyNote")
  }
  if ($pending -ceq '(no usable id)') { return "$head a pending submission without a usable id. $look. $script:ApiOnlyNote" }
  ("$head pending submission $pending. Reported by id only: not updated, not committed, not deleted. A person needs to " +
    "check submission $pending in Partner Center (look only, change nothing there) or with $app/submissions/$pending. $script:ApiOnlyNote")
}

# The create was answered with HTTP 202 Accepted or another 2xx that does not
# confirm a change (Test-StoreAccepted): accepted, completion unconfirmed. The
# service took the request but has not said the submission exists (RFC 9110,
# 15.3.3; Pepper, PR #74 r7). Prints a warning first, then checks once: by
# the id the answer named (Id, one GET of that submission,
# Get-AcceptedReadBack), else by reading the app back (one GET; a pending
# submission is reported by its id only). Returns the error text to throw, so
# the run stops whatever the check shows: it never updates, uploads to,
# commits or deletes a submission, and gives no re-run or delete advice (the
# create may still be carried out). Never throws.
function Resolve-AcceptedCreate([string]$ProductId, [string]$Answer, [int]$Status, [string]$Id, [int]$TimeoutSec) {
  $app = "GET /v1.0/my/applications/$ProductId"
  $what = "the Store answered the create with HTTP ${Status}: it accepted the request but has not confirmed that a submission was created"
  if ($Id) {
    $look = "A person needs to check submission $Id later in Partner Center (look only, change nothing there) or with $app/submissions/$Id"
    $how = "Checking submission $Id (the id in the answer) once by id"
  } else {
    $look = "A person needs to check the app's pending submission later in Partner Center (look only, change nothing there) or with $app (pendingApplicationSubmission.id)"
    $how = 'The answer named no usable id; reading the app back once'
  }
  Write-Host ("::warning title=Store create::Accepted, completion unconfirmed: $what ($Answer). The run stops; it updates, " +
    "uploads to, commits and deletes nothing. $how. If this step ends before a result is printed below: $look.")
  $head = "$Answer. Accepted, completion unconfirmed: $what. This run stops: it does not update, upload to, commit or delete any submission."
  if ($Id) { return "$head $(Get-AcceptedReadBack $ProductId $Id $TimeoutSec) $look. $script:ApiOnlyNote" }
  $rb = 'Read-back of the app (one GET; nothing changed):'
  try { $pending = Read-AppPendingSubmissionId -AppJson (Get-StoreApp $ProductId -TimeoutSec $TimeoutSec) -ProductId $ProductId }
  catch { return "$head $rb failed ($_). $look once the API answers. $script:ApiOnlyNote" }
  if (-not $pending) {
    return "$head $rb no pending submission yet. That does not mean none will be created: the Store may still be processing the request. $look. $script:ApiOnlyNote"
  }
  if ($pending -ceq '(no usable id)') { return "$head $rb a pending submission without a usable id. $look. $script:ApiOnlyNote" }
  ("$head $rb pending submission $pending. Reported by id only: not updated, not committed, not deleted. A person needs to " +
    "check submission $pending later in Partner Center (look only, change nothing there) or with $app/submissions/$pending. $script:ApiOnlyNote")
}

# One read-only GET of submission SubmissionId (at most TimeoutSec, and no
# longer than the call deadline) after a change to it was accepted without
# being confirmed (Test-StoreAccepted). Returns one sentence for the log: the
# status and packages that id shows (listed fields only, Read-SubmissionSafe:
# a file name only when it is ExpectedFileName), that it returned another
# submission, or that the GET failed (an HTTP 404 among them). Draws no
# conclusion: the change may still be processing. Never throws.
function Get-AcceptedReadBack([string]$ProductId, [string]$SubmissionId, [int]$TimeoutSec, [string]$ExpectedFileName = '') {
  $h = "Read-back of submission $SubmissionId by id (one GET; nothing changed):"
  try { $sub = Read-SubmissionSafe -SubmissionJson (Get-StoreSubmissionJson $ProductId $SubmissionId -TimeoutSec $TimeoutSec) -ExpectedFileName $ExpectedFileName }
  catch { return "$h failed ($_)." }
  if (-not $sub -or $sub.Id -cne $SubmissionId) { return "$h it did not return that submission." }
  $p = @(foreach ($k in $sub.Packages) { "$($k.FileName) $($k.FileStatus)" })
  "$h status $($sub.Status); packages: $(if ($p.Count) { $p -join ', ' } else { 'none' })."
}

# A change to this run's own draft (the PUT of the submission, What 'update',
# or the package upload, What 'package upload') was answered with HTTP 202
# Accepted or another 2xx that does not confirm it (Test-StoreAccepted):
# accepted, completion unconfirmed (Pepper, PR #74 r7). The run stops before
# its next call, so the draft stays uncommitted and nothing more is sent to
# it. Prints a warning first, then reads the draft back once by id
# (Get-AcceptedReadBack) and returns the error text to throw. No delete or
# re-run advice: the change may still be carried out. Never throws.
function Resolve-AcceptedChange([string]$ProductId, [string]$SubmissionId, [string]$Answer, [string]$What, [int]$TimeoutSec, [string]$ExpectedFileName = '') {
  $look = "A person needs to check submission $SubmissionId later (look only, change nothing in Partner Center) with GET /v1.0/my/applications/$ProductId/submissions/$SubmissionId"
  Write-Host ("::warning title=Store ${What}::Accepted, completion unconfirmed: $Answer. The run stops; draft $SubmissionId " +
    "stays uncommitted and nothing more is sent to it. Reading it back once by id. If this step ends before a result is printed below: $look.")
  ("$Answer. Accepted, completion unconfirmed: the Store accepted the $What of submission $SubmissionId but has not confirmed it is done. Not committed: this " +
    "run stops, draft $SubmissionId stays uncommitted and nothing more is sent to it. " +
    "$(Get-AcceptedReadBack $ProductId $SubmissionId $TimeoutSec $ExpectedFileName) $look. $script:ApiOnlyNote")
}

# The create request got no answer. This run has no submission id of its own
# (that comes only from a create response), so a pending submission on the
# read-back cannot be tied to this run: someone else (a person in the Partner
# Center UI, another tool) may have created it after Assert-NoPendingSubmission
# while this run's POST failed or never landed. Reports only what the
# read-back shows. Returns the error text to throw; deletes nothing and gives
# no delete or re-run advice: the create may have been carried out, and the
# Store may show a new submission only after a while, so a read-back without
# one does not show none was created (Pepper, PR #74 r5).
function Resolve-UnconfirmedCreate([string]$ProductId, [string]$Failure) {
  $head = "$Failure. Result unconfirmed: the create request got no answer, so a submission may or may not have been created. Read-back of the app:"
  try { $pending = Read-AppPendingSubmissionId -AppJson (Get-StoreApp $ProductId) -ProductId $ProductId }
  catch {
    return ("$head failed too ($_). The result stays unknown: do not delete anything. A person needs to read " +
      "GET /v1.0/my/applications/${ProductId} once the API answers; a pending submission there is of unconfirmed origin, " +
      "since this run never got a submission id to compare. $script:ApiOnlyNote")
  }
  if (-not $pending) {
    return ("$head no pending submission yet. That does not show none was created: the Store may take a while to show a new " +
      "submission. This run changes and deletes nothing. A person needs to read GET /v1.0/my/applications/$ProductId later; " +
      "a pending submission there is of unconfirmed origin, since this run never got a submission id to compare. $script:ApiOnlyNote")
  }
  if ($pending -ceq '(no usable id)') {
    return "$head it shows a pending submission without a usable id, origin unconfirmed. Check GET /v1.0/my/applications/$ProductId before doing anything. $script:ApiOnlyNote"
  }
  ("$head a pending submission $pending exists, origin unconfirmed. This run never got a submission id from a create " +
    "response, so it cannot tell whether $pending is its own draft or one someone else created after the pending-submission " +
    "check (for example in the Partner Center UI). This run changes and deletes nothing. Find out who created submission " +
    "$pending (GET /v1.0/my/applications/$ProductId/submissions/$pending shows its status and packages) before anything is " +
    "done with it. $script:ApiOnlyNote")
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
  [pscustomobject]@{ Result = 'Pass'; Reason = "pricing.priceId=$(Get-ListedPriceId $price) is kept as is" }
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
# Throws fixed text only: System.Text.Json's own messages quote the JSON (a
# duplicate key, an invalid literal), so they are never passed on (Pepper,
# PR #74 r8).
function Set-SubmissionPackage {
  param([Parameter(Mandatory)][string]$SubmissionJson, [Parameter(Mandatory)][string]$FileName)
  $why = ''
  try {
    $o = [System.Text.Json.Nodes.JsonNodeOptions]::new()
    $o.PropertyNameCaseInsensitive = $true
    $n = $null
    try { $n = [System.Text.Json.Nodes.JsonNode]::Parse($SubmissionJson, $o) } catch { }
    if ($n -isnot [System.Text.Json.Nodes.JsonObject]) { $why = 'submission JSON is not an object'; throw $why }
    $pk = $n['applicationPackages']
    if ($null -eq $pk) { $pk = [System.Text.Json.Nodes.JsonArray]::new(); $n['applicationPackages'] = $pk }
    if ($pk -isnot [System.Text.Json.Nodes.JsonArray]) { $why = 'applicationPackages is not a list'; throw $why }
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
  } catch {
    if ($why) { throw $why }
    throw 'the submission JSON could not be read to set the packages (the parser''s message is not printed)'
  }
}

# Top-level submission fields left out of the before/after comparison:
# Partner Center owns them (id, status, statusDetails, fileUploadUrl) or this
# run changes them on purpose (applicationPackages). Every other field, known
# or not (pricing, listings, visibility, targetPublishMode, targetPublishDate,
# allowTargetFutureDeviceFamilies, ...), must come back from the PUT unchanged.
$script:UncomparedFields = @('id', 'status', 'statusDetails', 'fileUploadUrl', 'applicationPackages')

# Parses Json into a JsonObject without the uncompared fields. Throws fixed
# text only (a System.Text.Json message quotes the JSON; Pepper, PR #74 r8).
# A JsonObject reads its properties only on first use, and a duplicate key
# throws then, so the Remove calls stay inside the try.
function ConvertTo-SubmissionNode([AllowEmptyString()][string]$Json) {
  $o = [System.Text.Json.Nodes.JsonNodeOptions]::new()
  $o.PropertyNameCaseInsensitive = $true
  $n = $null
  try {
    $n = [System.Text.Json.Nodes.JsonNode]::Parse($Json, $o)
    if ($n -is [System.Text.Json.Nodes.JsonObject]) { foreach ($f in $script:UncomparedFields) { [void]$n.Remove($f) } }
  } catch { $n = $null }
  if ($n -isnot [System.Text.Json.Nodes.JsonObject]) { throw 'submission JSON is not an object that can be read (the parser''s message is not printed)' }
  , $n
}

# The compared fields of a submission as JSON (no fileUploadUrl, so no SAS
# URL is kept). Pure. Throws fixed text only.
function Get-SubmissionComparedFields {
  param([Parameter(Mandatory)][string]$SubmissionJson)
  $n = ConvertTo-SubmissionNode $SubmissionJson
  try { $n.ToJsonString() } catch { throw 'the submission JSON could not be read to keep its fields (the parser''s message is not printed)' }
}

# Compares the fields kept by Get-SubmissionComparedFields with a submission
# read later. Returns Compared (how many fields) and Changed: the names of
# fields that differ, were dropped or were added, each as this module spells
# it when it is a documented submission field name ($script:StoreTargetNames),
# else [unlisted field name] (Pepper, PR #74 r8). Pure. Throws fixed text
# only: a nested object with a duplicate key throws while it is compared, and
# that message quotes the key.
function Compare-SubmissionFields {
  param([Parameter(Mandatory)][string]$ExpectedJson, [Parameter(Mandatory)][AllowEmptyString()][string]$SubmissionJson)
  $want = ConvertTo-SubmissionNode $ExpectedJson
  $got = ConvertTo-SubmissionNode $SubmissionJson
  $names = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  try {
    foreach ($kv in $want) {
      if (-not $got.ContainsKey($kv.Key) -or -not [System.Text.Json.Nodes.JsonNode]::DeepEquals($kv.Value, $got[$kv.Key])) { [void]$names.Add($kv.Key) }
    }
    foreach ($kv in $got) { if (-not $want.ContainsKey($kv.Key)) { [void]$names.Add($kv.Key) } }
  } catch { throw 'the submission fields could not be compared (the parser''s message is not printed)' }
  [pscustomobject]@{
    Compared = $want.Count
    Changed = @($names | ForEach-Object { $c = ''; if ($script:StoreTargetNames.TryGetValue($_, [ref]$c)) { $c } else { '[unlisted field name]' } } | Select-Object -Unique)
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
      $wait = Get-CallTimeout 600
      $r = Invoke-StoreHttp -Method PUT -Uri $UploadUrl.Replace('+', '%2B') -Kind Upload -Headers @{ 'x-ms-blob-type' = 'BlockBlob' } -ContentType 'application/zip' -InFile $zip -TimeoutSec $wait
    } catch { throw "package upload failed: $(Get-StoreFailureText $_)" }
    # Put Blob answers 201 with an empty body once the blob is stored, so 200,
    # 201 or 204 is success even when the body was lost (BodyLost); an error
    # status is reported with the fixed BodyLost text when its body was lost.
    # HTTP 202 or another 2xx (Test-StoreAccepted) does not say the blob is
    # stored: thrown as accepted, completion unconfirmed, with its status
    # (Pepper, PR #74 r7).
    $lost = Get-StoreBodyLost $r
    if (Test-StoreAccepted $r.StatusCode) {
      throw (New-StoreError "package upload answered HTTP $($r.StatusCode): accepted, completion unconfirmed (not confirmed stored)$(if ($lost) { "; $lost" })" -OutcomeUnknown -Status $r.StatusCode)
    }
    if ($r.StatusCode -lt 200 -or $r.StatusCode -ge 300) { throw "package upload failed: $(Get-StoreErrorText $r.StatusCode $r.Body)$(if ($lost) { "; $lost" })" }
    Write-Host "package uploaded: $name in Upload.zip ($len bytes), HTTP $($r.StatusCode)$(if ($lost) { " (the answer's body was not read: $lost)" })"
  } finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# POST /applications/{productId}/submissions/{submissionId}/commit: commits
# exactly this submission, whatever else the app has. Only HTTP 200, 201 or
# 204 with its body read returns here; a 202 or another 2xx is thrown by
# Invoke-StoreApi as accepted, completion unconfirmed (OutcomeUnknown), and
# Publish-StoreSubmission reads it back by id (Resolve-UnconfirmedCommit).
function Invoke-SubmissionCommit {
  param([Parameter(Mandatory)][string]$ProductId, [Parameter(Mandatory)][string]$SubmissionId, [ValidateRange(1, 600)][int]$TimeoutSec = 600)
  Assert-ProductId $ProductId; Assert-SubmissionId $SubmissionId
  $json = Invoke-StoreApi -Method POST -Path "applications/$ProductId/submissions/$SubmissionId/commit" -TimeoutSec $TimeoutSec
  $st = ''
  try { $st = Get-JsonField ($json | ConvertFrom-Json -ErrorAction Stop) 'status' } catch { }
  Write-Host "submission $SubmissionId commit requested through the API: status=$(Get-ListedValue $st $script:SubmissionStatuses)"
}

# The commit request got no answer, an HTTP 200, 201 or 204 whose body was
# lost (Status: the commit was accepted, but whether it has started is not
# read), or an HTTP 202 or other 2xx (Test-StoreAccepted: accepted, completion
# unconfirmed, body read or not; Pepper, PR #74 r7). The text says which. The
# commit API is asynchronous
# (https://learn.microsoft.com/en-us/windows/uwp/monetize/commit-an-app-submission),
# so a PendingCommit read-back does not show the commit did not happen: the
# request may still be on its way or being processed. First prints (an
# annotation) that the result is unconfirmed, with the id and how to check it
# by hand, so that text is in the log even if the step is killed during the
# read-backs. Then reads this submission back by id up to Attempts times,
# IntervalSeconds apart, each GET waiting at most TimeoutSeconds, all of them
# within BudgetSeconds and before DeadlineUtc:
# - CommitStarted or a committed status: committed; warns and returns (the
#   caller goes on to the read-back step).
# - any other status (e.g. CommitFailed): throws; no delete or retry advice.
# - PendingCommit, a failed read-back or another submission on every attempt,
#   or the budget used up: throws "result unconfirmed" and asks a person to
#   check that id later; no delete or retry advice.
function Resolve-UnconfirmedCommit {
  param(
    [Parameter(Mandatory)][string]$ProductId,
    [Parameter(Mandatory)][string]$SubmissionId,
    [Parameter(Mandatory)][string]$Failure,
    [int]$Status = 0,
    [ValidateRange(1, 100)][int]$Attempts = 10,
    [ValidateRange(0, 600)][int]$IntervalSeconds = 30,
    [ValidateRange(1, 600)][int]$TimeoutSeconds = 30,
    [ValidateRange(1, 3600)][int]$BudgetSeconds = 300,
    [datetime]$DeadlineUtc = [datetime]::MaxValue
  )
  $accepted = Test-Store2xx $Status
  $got = if (Test-StoreAccepted $Status) { "was accepted (HTTP $Status) but the Store has not confirmed it is done" }
         elseif ($accepted) { "was accepted (HTTP $Status) but its answer's body was not read" } else { 'got no answer' }
  $may = if ($accepted) { 'so whether the commit has started is not confirmed' } else { 'so it may or may not have been committed' }
  $label = if (Test-StoreAccepted $Status) { 'Accepted, completion unconfirmed' } else { 'Result unconfirmed' }
  $head = "$Failure. ${label}: the commit request for submission $SubmissionId $got, $may."
  $get = "GET /v1.0/my/applications/$ProductId/submissions/$SubmissionId"
  Write-Host ("::warning title=Store commit::${label}: the commit request for submission $SubmissionId $got " +
    "($Failure). Reading it back by id for up to $BudgetSeconds s. If this step ends before a result is printed below, check " +
    "$get by hand: CommitStarted or a later status means it was committed. Do not delete, edit, commit or re-submit it, " +
    "and do not re-run this workflow for it.")
  $end = (Get-StoreUtcNow).AddSeconds($BudgetSeconds)
  $why = "the read-back time budget of $BudgetSeconds s is used up"
  if ($DeadlineUtc -ne [datetime]::MaxValue) { $DeadlineUtc = $DeadlineUtc.ToUniversalTime() }
  if ($DeadlineUtc -lt $end) { $end = $DeadlineUtc; $why = "the step's deadline $($DeadlineUtc.ToString('u')) is near" }
  $saved = $script:CallDeadline
  $script:CallDeadline = $end
  $last = ''; $done = 0; $stopped = ''
  try {
    for ($i = 1; $i -le $Attempts; $i++) {
      if ($i -gt 1) {
        # The next read-back needs the interval plus at least one second.
        if ((Get-StoreUtcNow).AddSeconds($IntervalSeconds + 1) -ge $end) { $stopped = " (stopped: $why)"; break }
        Write-Host "commit of submission $SubmissionId not confirmed yet ($last); reading it back again in $IntervalSeconds s"
        Start-Sleep -Seconds $IntervalSeconds
      }
      $done = $i
      $sub = $null; $readErr = ''
      try { $sub = Read-SubmissionSafe -SubmissionJson (Get-StoreSubmissionJson $ProductId $SubmissionId -TimeoutSec $TimeoutSeconds) } catch { $readErr = "$_" }
      if ($readErr) { $last = "read-back $i of ${Attempts} failed ($readErr)"; continue }
      if (-not $sub -or $sub.Id -cne $SubmissionId) { $last = "read-back $i of ${Attempts} did not return that submission"; continue }
      if ($sub.Status -ceq 'CommitStarted' -or $sub.Status -cin $script:CommittedStatuses) {
        $but = if ($accepted) { ';' } else { ', but' }
        Write-Host ("::warning title=Store commit::The commit request for submission $SubmissionId $got$but read-back " +
          "$i by id shows status $($sub.Status): it was committed. The next step checks its package.")
        return
      }
      if ($sub.Status -ceq 'PendingCommit') { $last = "read-back $i of ${Attempts} shows status PendingCommit"; continue }
      throw "$head Read-back $i by id: status is '$($sub.Status)'. Nothing is deleted or retried; check it with $get. $script:ApiOnlyNote"
    }
  } finally { $script:CallDeadline = $saved }
  throw ("$head Read back by id $done time(s), $IntervalSeconds s apart$stopped; last: $last. The commit API is asynchronous, " +
    "so PendingCommit does not show the commit failed: it may still be processing. The result stays unconfirmed: do not " +
    "delete, edit, commit or re-submit this submission, and do not re-run this workflow for it. A person needs to check " +
    "$get later: CommitStarted or a later status means it was committed. $script:ApiOnlyNote")
}

# Deletes one submission by id, only while it is an uncommitted draft
# (PendingCommit). For recovery by hand; the publish workflow never deletes.
# HTTP 200, 201 or 204 counts as deleted, also when its body was lost (the
# body is not used). HTTP 202 or another 2xx (Test-StoreAccepted) is never
# reported as deleted: accepted, completion unconfirmed; it reads that id back
# once (Get-AcceptedReadBack) and throws, sending nothing more (Pepper, PR #74
# r7).
function Remove-StoreDraftSubmission {
  param([Parameter(Mandatory)][string]$ProductId, [Parameter(Mandatory)][string]$SubmissionId)
  $sub = Read-SubmissionSafe -SubmissionJson (Get-StoreSubmissionJson $ProductId $SubmissionId)
  if (-not $sub -or $sub.Id -cne $SubmissionId) { throw "GET submission $SubmissionId did not return that submission; not deleting" }
  if ($sub.Status -cne 'PendingCommit') { throw "submission $SubmissionId is '$($sub.Status)', not an uncommitted PendingCommit draft; not deleting" }
  $note = ''
  try { Invoke-StoreApi -Method DELETE -Path "applications/$ProductId/submissions/$SubmissionId" | Out-Null }
  catch {
    $status = Get-StoreErrorStatus $_
    if (Test-StoreAccepted $status) {
      throw ("$_. Accepted, completion unconfirmed: the Store accepted the delete of submission $SubmissionId but has not confirmed it is done, so it is not " +
        "reported as deleted; nothing more is sent. $(Get-AcceptedReadBack $ProductId $SubmissionId 30) A person needs to check " +
        "GET /v1.0/my/applications/$ProductId/submissions/$SubmissionId later: HTTP 404 there means it is gone.")
    }
    if (-not (Test-Store2xx $status)) { throw }
    $note = " (HTTP $status; the answer's body was not read)"
  }
  Write-Host "deleted draft submission $SubmissionId$note"
}
# Parses submission JSON into listed fields only (Pepper, PR #74 r8): Id
# (digits, else [invalid]), Status and TargetPublishMode (a documented value,
# else [unlisted]), and per package FileName (only when it is exactly
# ExpectedFileName, else [file name not shown]), Version (digits and dots,
# else [invalid]) and FileStatus (a documented value, else [unlisted]).
# Nothing else of the JSON is kept; FileUploadUrl (a SAS URL with write
# access) is never copied. Returns $null when there is no JSON object, or when
# reading it fails (the error is not passed on: a parser message can quote the
# JSON). Never throws.
function Read-SubmissionSafe {
  param([Parameter(Mandatory)][AllowEmptyString()][string]$SubmissionJson, [AllowEmptyString()][string]$ExpectedFileName = '')
  try {
    $start = $SubmissionJson.IndexOf('{')
    if ($start -lt 0) { return $null }
    $raw = $SubmissionJson.Substring($start) | ConvertFrom-Json -ErrorAction Stop
    if ($raw -isnot [System.Management.Automation.PSCustomObject]) { return $null }
    $pkgs = @()
    $pkgProp = $raw.PSObject.Properties['ApplicationPackages']
    if ($pkgProp -and $null -ne $pkgProp.Value) {
      $pkgs = @(foreach ($p in @($pkgProp.Value)) {
        [pscustomobject]@{ FileName = Get-ListedFileName (Get-JsonField $p 'FileName') $ExpectedFileName
                           Version = Get-SafeValue (Get-JsonField $p 'Version') $script:SafeVersion
                           FileStatus = Get-ListedValue (Get-JsonField $p 'FileStatus') $script:FileStatuses }
      })
    }
    [pscustomobject]@{ Id = Get-SafeValue (Get-JsonField $raw 'Id') $script:SafeId; Status = Get-ListedValue (Get-JsonField $raw 'Status') $script:SubmissionStatuses
                       TargetPublishMode = Get-ListedValue (Get-JsonField $raw 'TargetPublishMode') $script:PublishModes; Packages = $pkgs }
  } catch { $null }
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
  $sub = Read-SubmissionSafe -SubmissionJson $SubmissionJson -ExpectedFileName $ExpectedFileName
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
# 'Fail'), Reason and the listed fields of Read-SubmissionSafe (a file name
# only when it is ExpectedFileName).
# - Fail: no JSON, another submission id than ExpectedSubmissionId, a status that
#   is not committed (see CommittedStatuses), no packages, a package whose
#   fileStatus is not a documented value ([unlisted]: it could be an Uploaded
#   package spelled another way; Pepper, PR #74 r8), an Uploaded package
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
    [string]$ExpectedSubmissionId = '',
    [string]$ExpectedFileName = ''
  )
  $sub = Read-SubmissionSafe -SubmissionJson $SubmissionJson -ExpectedFileName $ExpectedFileName
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
  if (@($pkgs | Where-Object { $_.FileStatus -ceq '[unlisted]' }).Count -gt 0) {
    return New-CheckResult $sub 'Fail' "a package's fileStatus is [unlisted], not one of $($script:FileStatuses -join ', ')"
  }

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

# Prints only the listed fields of a check result (Read-SubmissionSafe).
function Write-SubmissionSummary {
  param([Parameter(Mandatory)]$Check)
  Write-Host "submission id=$($Check.Id) status=$($Check.Status) targetPublishMode=$($Check.TargetPublishMode)"
  foreach ($p in $Check.Packages) { Write-Host "  package fileName=$($p.FileName) version=$($p.Version) fileStatus=$($p.FileStatus)" }
}

# A read before the commit (the app after create, the new submission before
# the PUT, the draft after the upload) gave no usable answer: no answer, not
# sent, any status but HTTP 200 (a 202 or another 2xx among them, its body
# read or not), HTTP 200 with its body lost, JSON that does not parse or
# cannot be read, another app or submission, or a pending submission without
# a usable id. This run cannot verify what draft SubmissionId holds, so it
# stops with "Could not verify" and only says how to look at that id: no
# delete or re-run advice (Pepper, PR #74 r8). Failure is the failed read's
# own text. Pure.
function Get-UnverifiedDraftText([string]$ProductId, [string]$SubmissionId, [string]$Failure, [string]$Read) {
  ("$Failure. Could not verify: $Read gave no usable answer, so this run does not know what draft $SubmissionId " +
    "holds now. Not committed: this run stops, draft $SubmissionId stays uncommitted and nothing more is sent to it. " +
    "A person needs to check submission $SubmissionId (look only, change nothing in Partner Center) with " +
    "GET /v1.0/my/applications/$ProductId/submissions/$SubmissionId. $script:ApiOnlyNote")
}

# The publish job's API flow, every step after create on the id the create
# response returned (see the header). Returns that submission id once the
# commit was accepted (or, when the commit got no answer, once a read-back by
# id shows it committed within CommitReadBackAttempts read-backs,
# CommitReadBackIntervalSeconds apart). Before the commit, a stop leaves
# this run's draft uncommitted, and the text says which of three it is:
# - a read (GET of the app after create, GET of the submission before the
#   PUT, GET of the draft after the upload) gave no usable answer: "Could not
#   verify", look by id only, no delete or re-run advice
#   (Get-UnverifiedDraftText; Pepper, PR #74 r8);
# - the PUT or the upload was accepted without being confirmed (HTTP 202 or
#   another 2xx, Test-StoreAccepted): a read-back by id, no delete or re-run
#   advice (Resolve-AcceptedChange; Pepper, PR #74 r7);
# - anything else (a read answered HTTP 200 and readable shows no pending
#   submission or another pending id, a price, draft or field check failed,
#   the PUT or the upload failed, no time left for the commit): how to
#   delete exactly that draft by id, which Remove-StoreDraftSubmission does
#   only while it is PendingCommit.
# Time budget: DeadlineUtc is the last moment a call may still wait for an
# answer; msstore-publish.yml sets it some minutes before the step's timeout so
# the error text still prints. The last CommitTimeoutSeconds +
# CommitReadBackBudgetSeconds before it are kept for the commit and its
# read-backs: every call before the commit waits at most until then (an upload
# or a GET that would run into it is cut short and stops the run uncommitted),
# and the commit is not sent when that point has passed. Each read-back GET
# waits at most CommitReadBackTimeoutSeconds.
function Publish-StoreSubmission {
  param(
    [Parameter(Mandatory)][string]$ProductId,
    [Parameter(Mandatory)][string]$PackagePath,
    [Parameter(Mandatory)][string]$ExpectedFileName,
    [Parameter(Mandatory)][string]$ExpectedVersion,
    [ValidateRange(1, 100)][int]$CommitReadBackAttempts = 10,
    [ValidateRange(0, 600)][int]$CommitReadBackIntervalSeconds = 30,
    [ValidateRange(1, 600)][int]$CommitTimeoutSeconds = 60,
    [ValidateRange(1, 600)][int]$CommitReadBackTimeoutSeconds = 30,
    [ValidateRange(1, 3600)][int]$CommitReadBackBudgetSeconds = 300,
    [datetime]$DeadlineUtc = (Get-StoreUtcNow).AddMinutes(18)
  )
  Assert-ProductId $ProductId
  if ((Split-Path -Leaf $PackagePath) -cne $ExpectedFileName) { throw "package file is not $ExpectedFileName" }
  if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) { throw "package file missing" }
  $DeadlineUtc = $DeadlineUtc.ToUniversalTime()
  $reserve = $CommitTimeoutSeconds + $CommitReadBackBudgetSeconds
  $commitBy = $DeadlineUtc.AddSeconds(-$reserve)
  if ($commitBy -le (Get-StoreUtcNow).AddSeconds(60)) {
    throw ("not publishing: the deadline $($DeadlineUtc.ToString('u')) leaves less than 60 s for the work before the commit " +
      "($reserve s are kept for the commit and its read-backs); nothing was sent")
  }
  # try/finally clears the call deadline however this ends (body kept at its
  # old indent to keep the diff small).
  try {
  $script:CallDeadline = $commitBy

  Assert-NoPendingSubmission -ProductId $ProductId
  $id = New-StoreSubmission -ProductId $ProductId
  # Set when a read gave no usable answer (Get-UnverifiedDraftText) or the
  # PUT or the upload was accepted without being confirmed
  # (Resolve-AcceptedChange): the stop text, thrown as is (no delete or re-run
  # advice).
  $stop = ''
  try {
    $read = 'the read of the app after create (GET application)'
    $pending = ''
    try { $pending = Read-AppPendingSubmissionId -AppJson (Get-StoreApp $ProductId) -ProductId $ProductId }
    catch { $stop = Get-UnverifiedDraftText $ProductId $id "$_" $read; throw $stop }
    if ($pending -ceq '(no usable id)') { $stop = Get-UnverifiedDraftText $ProductId $id "after create, the app's pending submission has no usable id" $read; throw $stop }
    if ($pending -cne $id) { throw "after create, the app's pending submission is '$pending', not $id" }

    $read = "the read of submission $id before the update (GET submission)"
    $sub = ''
    try { $sub = Get-StoreSubmissionJson $ProductId $id }
    catch { $stop = Get-UnverifiedDraftText $ProductId $id "$_" $read; throw $stop }
    $safe = Read-SubmissionSafe -SubmissionJson $sub -ExpectedFileName $ExpectedFileName
    if (-not $safe) { $stop = Get-UnverifiedDraftText $ProductId $id "GET submission $id returned JSON that does not parse" $read; throw $stop }
    if ($safe.Id -cne $id) { $stop = Get-UnverifiedDraftText $ProductId $id "GET submission $id returned another submission" $read; throw $stop }
    $price = Test-SubmissionPricing -SubmissionJson $sub
    if ($price.Result -ne 'Pass') { throw "price check failed: $($price.Reason)" }
    Write-Host "price check: $($price.Reason)"
    # Every field but the packages, as this run read it before its PUT, and
    # the PUT body. Both throw fixed text only.
    try {
      $kept = Get-SubmissionComparedFields -SubmissionJson $sub
      $put = Set-SubmissionPackage -SubmissionJson $sub -FileName $ExpectedFileName
    } catch { $stop = Get-UnverifiedDraftText $ProductId $id "$_" $read; throw $stop }
    $sub = $null
    try { $updated = Invoke-StoreApi -Method PUT -Path "applications/$ProductId/submissions/$id" -Body $put }
    catch {
      if (Test-StoreAccepted (Get-StoreErrorStatus $_)) { $stop = Resolve-AcceptedChange $ProductId $id "$_" 'update' 30 $ExpectedFileName; throw $stop }
      throw
    }
    $put = $null
    $safe = Read-SubmissionSafe -SubmissionJson $updated
    if (-not $safe -or $safe.Id -cne $id) { throw "PUT submission $id returned another submission" }
    $url = Get-SubmissionUploadUrl $updated
    $updated = $null
    Write-Host "submission $id updated: old packages PendingDelete, $ExpectedFileName PendingUpload"
    try { Send-StorePackage -UploadUrl $url -PackagePath $PackagePath }
    catch {
      if (Test-StoreAccepted (Get-StoreErrorStatus $_)) { $stop = Resolve-AcceptedChange $ProductId $id "$_" 'package upload' 30 $ExpectedFileName; throw $stop }
      throw
    }
    $url = $null

    $read = "the draft check's read of submission $id after the upload (GET submission)"
    $now = ''
    try { $now = Get-StoreSubmissionJson $ProductId $id }
    catch { $stop = Get-UnverifiedDraftText $ProductId $id "$_" $read; throw $stop }
    $safe = Read-SubmissionSafe -SubmissionJson $now -ExpectedFileName $ExpectedFileName
    if (-not $safe) { $stop = Get-UnverifiedDraftText $ProductId $id "GET submission $id returned JSON that does not parse" $read; throw $stop }
    if ($safe.Id -cne $id) { $stop = Get-UnverifiedDraftText $ProductId $id "GET submission $id returned another submission" $read; throw $stop }
    $check = Test-DraftReadyToCommit -SubmissionJson $now -SubmissionId $id `
      -ExpectedFileName $ExpectedFileName -ExpectedVersion $ExpectedVersion
    Write-SubmissionSummary -Check $check
    if ($check.Result -ne 'Pass') { throw "draft check failed: $($check.Reason)" }
    $diff = $null
    try { $diff = Compare-SubmissionFields -ExpectedJson $kept -SubmissionJson $now }
    catch { $stop = Get-UnverifiedDraftText $ProductId $id "$_" $read; throw $stop }
    $now = $null
    if ($diff.Changed.Count -gt 0) {
      throw ("submission fields changed after this run's update: $($diff.Changed -join ', '). Only applicationPackages " +
        "may change; every other field (pricing, listings, visibility, publish mode and date, device families, ...) " +
        "must read back as it was before the update")
    }
    Write-Host "fields unchanged: $($diff.Compared) submission fields other than applicationPackages read back as before the update"
    Write-Host "draft verified: $($check.Reason)"
    if ((Get-StoreUtcNow) -ge $commitBy) {
      throw ("no time left for the commit: it and its read-backs need the last $reserve s before the deadline " +
        "$($DeadlineUtc.ToString('u')), and that time has started")
    }
  } catch {
    if ($stop) { throw $stop }
    throw "$_. Not committed: draft $id stays uncommitted. $script:ApiOnlyNote $(Get-DeleteByIdText $ProductId $id)"
  }
  $script:CallDeadline = $commitBy.AddSeconds($CommitTimeoutSeconds)
  Write-Host ("committing submission $id (waiting up to $CommitTimeoutSeconds s for the answer). If this step ends before a " +
    "commit result is printed below, the result is unconfirmed: check GET /v1.0/my/applications/$ProductId/submissions/$id " +
    "by hand (CommitStarted or a later status means it was committed); do not delete or re-submit it.")
  try { Invoke-SubmissionCommit -ProductId $ProductId -SubmissionId $id -TimeoutSec $CommitTimeoutSeconds }
  catch {
    if (Test-StoreOutcomeUnknown $_) {
      Resolve-UnconfirmedCommit -ProductId $ProductId -SubmissionId $id -Failure "$_" -Status (Get-StoreErrorStatus $_) `
        -Attempts $CommitReadBackAttempts -IntervalSeconds $CommitReadBackIntervalSeconds `
        -TimeoutSeconds $CommitReadBackTimeoutSeconds -BudgetSeconds $CommitReadBackBudgetSeconds -DeadlineUtc $DeadlineUtc
    }
    else {
      throw ("$_. Commit of submission $id was not accepted. Read it back with GET /v1.0/my/applications/$ProductId/submissions/$id; " +
        "if it is still PendingCommit: $(Get-DeleteByIdText $ProductId $id)")
    }
  }
  $id
  } finally { $script:CallDeadline = $null }
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
    [int]$IntervalSeconds = 60,
    [string]$ExpectedFileName = ''
  )
  Assert-SubmissionId $SubmissionId
  Write-Host "checking submission id=$SubmissionId (created and committed by this run)"
  $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
  $warned = $false
  while ($true) {
    try {
      $json = Get-StoreSubmissionJson $ProductId $SubmissionId
      $check = Test-SubmissionHasPackage -SubmissionJson $json -ExpectedVersion $ExpectedVersion -ExpectedSubmissionId $SubmissionId -ExpectedFileName $ExpectedFileName
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

Export-ModuleMember -Function Get-StorePackage, Protect-StoreText, Test-StoreUri, Invoke-StoreHttp, Protect-WorkflowCommand, Get-ListedTarget, Get-StoreErrorText, Connect-StoreApi, Test-NoPendingSubmission, Read-AppPendingSubmissionId, Assert-NoPendingSubmission, New-StoreSubmission, Test-SubmissionPricing, Set-SubmissionPackage, Get-SubmissionComparedFields, Compare-SubmissionFields, Send-StorePackage, Test-DraftReadyToCommit, Invoke-SubmissionCommit, Remove-StoreDraftSubmission, Publish-StoreSubmission, Test-SubmissionHasPackage, Assert-SubmissionHasPackage
