# A small in-memory stand-in for the Store submission API and the SAS blob
# upload, for tests only: the Pester tests route the mocked Invoke-StoreHttp
# here, and msstore-publish-check.yml serves it over real HTTP on 127.0.0.1
# (Start-FakeStoreServer). It models only what MsStoreRunner.psm1 relies on;
# the real service's JSON shapes and status changes are not verified by it.

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:FakeSas = 'sv=2020-08-04&sr=b&sp=w&sig=FAKE+SAS%2FSIGNATURE-0123456789'
# An upload host that passes the module's production URL rule (https, a blob
# storage account). Start-FakeStoreServer serves the upload on 127.0.0.1 instead.
$script:DefaultUploadBase = 'https://jlfakeupload.blob.core.windows.net'

# The submission fields other than id, status, statusDetails, fileUploadUrl and
# applicationPackages, shaped after the app submission resource in the docs.
# Two listings, one with non-ASCII text, so a dropped or re-encoded listing shows.
$script:FieldsTemplate = @'
{
  "applicationCategory": "Productivity",
  "pricing": { "trialPeriod": "NoFreeTrial", "marketSpecificPricings": { "HK": "Tier2" }, "sales": [], "priceId": "Free", "isAdvertisingFunded": false },
  "visibility": "Public",
  "targetPublishMode": "Manual",
  "targetPublishDate": "1601-01-01T00:00:00Z",
  "listings": {
    "en-us": { "baseListing": { "copyrightAndTrademarkInfo": "", "keywords": ["remote desktop"], "licenseTerms": "", "privacyPolicy": "",
      "supportContact": "", "websiteUrl": "", "description": "JerisLink remote desktop.", "features": ["Remote desktop over a tailnet"],
      "releaseNotes": "", "images": [ { "fileName": "img/screenshot1.png", "fileStatus": "Uploaded", "id": "1152921504672272757",
      "description": "Main window", "imageType": "Screenshot" } ], "recommendedHardware": [], "title": "JerisLink" }, "platformOverrides": {} },
    "zh-hk": { "baseListing": { "copyrightAndTrademarkInfo": "", "keywords": ["遠端桌面"], "licenseTerms": "", "privacyPolicy": "",
      "supportContact": "", "websiteUrl": "", "description": "JerisLink 遠端桌面。", "features": [], "releaseNotes": "", "images": [],
      "recommendedHardware": [], "title": "JerisLink" }, "platformOverrides": {} }
  },
  "hardwarePreferences": [],
  "automaticBackupEnabled": false,
  "canInstallOnRemovableMedia": true,
  "isGameDvrEnabled": false,
  "gamingOptions": [],
  "hasExternalInAppProducts": false,
  "meetAccessibilityGuidelines": true,
  "notesForCertification": "",
  "packageDeliveryOptions": { "packageRollout": { "isPackageRollout": false, "packageRolloutPercentage": 0.0,
    "packageRolloutStatus": "PackageRolloutNotStarted", "fallbackSubmissionId": "0" }, "isMandatoryUpdate": false,
    "mandatoryUpdateEffectiveDate": "1601-01-01T00:00:00.0000000Z" },
  "enterpriseLicensing": "Online",
  "allowMicrosoftDecideAppAvailabilityToFutureDeviceFamilies": false,
  "allowTargetFutureDeviceFamilies": { "Desktop": true, "Mobile": false, "Holographic": false, "Xbox": false },
  "friendlyName": "Submission 2",
  "trailers": []
}
'@
# Fields the service owns: a PUT cannot change them.
$script:ServerOwned = @('id', 'status', 'statusDetails', 'fileUploadUrl', 'friendlyName')

function ConvertTo-FakeNode([string]$Json) {
  $o = [System.Text.Json.Nodes.JsonNodeOptions]::new()
  $o.PropertyNameCaseInsensitive = $true
  , [System.Text.Json.Nodes.JsonNode]::Parse($Json, $o)
}

# Options: PendingId (a pending submission that exists before the run),
# HidePending (GET app does not show it, as if it appeared after the check),
# OtherDraftAfterCheck (someone else creates a pending submission with this id
# right after the first GET app, i.e. after the run's pending check; a create
# that lands afterwards gets 409),
# NoPendingAs ('Null' or 'Omit': how GET app shows no pending submission),
# PendingAfterCreate (GET app shows this id as pending once the run created
# its submission), PendingLag (GET app does not show the run's new submission
# yet, as if the Store were slow to show it), PriceId (NoPricing drops
# pricing), UploadStatus/UploadBody, UploadBase (where the SAS upload URL
# points), CreateWithoutId, CreateErrorStatus/CreateErrorBody (the create is refused with that status
# and that raw body; nothing is created). Every create records its query
# string in CreateQuery; with isMinimalResponse=true the create answers with
# id and status only, without it with the whole submission.
# KeepOldPackage (the PUT leaves the old .msix Uploaded), CommitStatus (status
# after commit), TargetPublishMode.
# DriftOnPut: the PUT changes a field it should keep ('Pricing': priceId
# becomes Tier1; 'DropListing': the zh-hk listing is gone).
# LoseResponse ('Create' or 'Commit'): that request gets no answer, either
# After the service carried it out or Before; LoseAsStatus 0 means no
# response at all (the mocked Invoke-StoreHttp throws), another value is the
# status sent instead (e.g. 504), with LoseBody as its body. LoseWhen Delayed
# (Commit only): the commit is still being processed; the next
# CommitDelayReads GETs of that submission still show PendingCommit, the one
# after shows CommitStarted, later ones CommitStatus. FailAfterLoss: every API
# call after a lost answer or a refused create (CreateErrorStatus) gets 503.
# Redirect ('Token', 'Api' or 'Upload'): those requests get a 302 to
# /redirected/<kind> on the same host.
# HangOn: a request that never gets an answer, so the caller waits until its
# own timeout ('Commit': the commit request, which is not carried out;
# 'ReadBack': every GET of a submission once a commit request came in). The
# handler returns status -1 for it; Start-FakeStoreServer keeps the connection
# open without answering. CallSeconds/UploadSeconds: how long an API call and
# the upload take, for the mocked Invoke-StoreHttp and its fake clock (the
# HTTP server ignores them). Calls: what the mocked Invoke-StoreHttp was asked
# to send, with its timeout.
# DripOn ('AppRead': every GET of the app; 'AppReadAfterCreate': every GET of
# the app once a create request came in; 'Token', 'Create', 'Update' (the
# PUT of the submission), 'Commit', 'Upload', 'Delete': the answer to that
# request, whatever its status) with
# DripSeconds: Start-FakeStoreServer waits DripHeadSeconds, sends the status,
# the headers and the first byte of that answer, then a space every 250 ms for
# DripSeconds, then the rest of the body (a server that answers but drips its
# body); DripEnd 'Break' breaks the connection instead of sending the rest.
# AnswerContentType: the Content-Type of every answer with a body. Seen:
# every request Start-FakeStoreServer got (Line 'METHOD /path', Headers).
# The mocked Invoke-StoreHttp (Use-FakeStore) ignores AppRead and
# AppReadAfterCreate; it returns a dripping answer to Token, Create, Update,
# Commit, Upload or Delete with its status and its body lost, as the real
# Invoke-StoreHttp does when the drip outlasts the call's time limit (or
# breaks).
# AcceptOn ('Token', 'Create', 'Update', 'Commit', 'Upload', 'Delete', or
# 'AppRead' / 'SubmissionRead': a GET of the app / of a submission): the
# AcceptAt-th such request (default the first) is answered with AcceptStatus
# (default 202) instead of its usual 2xx (a 204 has no body); the others as
# usual. The request is carried out as usual, unless
# AcceptNotDone is set for a request that changes something (Create, Update,
# Commit, Upload, Delete): then nothing is changed and the answer is
# AcceptStatus with Create: id and status (no id with CreateWithoutId),
# Update: the unchanged submission, Commit: status PendingCommit, Upload:
# UploadBody, Delete: no body. Accepted: whether that answer was sent.
# Combine with DripOn for an accepted answer whose body is lost.
function New-FakeStore {
  param(
    [string]$AppId = '9NM3VWQ9MD7N',
    [string]$Version = '0.4.1.0',
    [string]$PendingId = '',
    [switch]$HidePending,
    [string]$OtherDraftAfterCheck = '',
    [string]$PendingAfterCreate = '',
    [switch]$PendingLag,
    [string]$TargetPublishMode = 'Manual',
    [ValidateSet('Null', 'Omit')][string]$NoPendingAs = 'Null',
    [string]$PriceId = 'Free',
    [switch]$NoPricing,
    [int]$UploadStatus = 201,
    [string]$UploadBody = '',
    [string]$UploadBase = '',
    [switch]$CreateWithoutId,
    [int]$CreateErrorStatus = 0,
    [string]$CreateErrorBody = '',
    [switch]$KeepOldPackage,
    [string]$CommitStatus = 'Certification',
    [ValidateSet('', 'Pricing', 'DropListing')][string]$DriftOnPut = '',
    [ValidateSet('', 'Create', 'Commit')][string]$LoseResponse = '',
    [ValidateSet('After', 'Before', 'Delayed')][string]$LoseWhen = 'After',
    [int]$LoseAsStatus = 0,
    [string]$LoseBody = 'lost',
    [int]$CommitDelayReads = 1,
    [switch]$FailAfterLoss,
    [ValidateSet('', 'Token', 'Api', 'Upload')][string]$Redirect = '',
    [ValidateSet('', 'Commit', 'ReadBack')][string]$HangOn = '',
    [ValidateRange(0, 100000)][int]$CallSeconds = 0,
    [ValidateRange(0, 100000)][int]$UploadSeconds = 0,
    [ValidateSet('', 'AppRead', 'AppReadAfterCreate', 'Token', 'Create', 'Update', 'Commit', 'Upload', 'Delete')][string]$DripOn = '',
    [ValidateRange(0, 600)][int]$DripSeconds = 0,
    [ValidateRange(0, 600)][int]$DripHeadSeconds = 0,
    [ValidateSet('Body', 'Break')][string]$DripEnd = 'Body',
    [ValidateSet('', 'Token', 'Create', 'Update', 'Commit', 'Upload', 'Delete', 'AppRead', 'SubmissionRead')][string]$AcceptOn = '',
    [ValidateRange(200, 299)][int]$AcceptStatus = 202,
    [switch]$AcceptNotDone,
    [ValidateRange(1, 100)][int]$AcceptAt = 1,
    [string]$AnswerContentType = 'application/json',
    [string]$BaseUrl = 'https://manage.devcenter.microsoft.com'
  )
  $f = ConvertTo-FakeNode $script:FieldsTemplate
  $f['targetPublishMode'] = [System.Text.Json.Nodes.JsonValue]::Create($TargetPublishMode)
  if ($NoPricing) { [void]$f.Remove('pricing') } else { $f['pricing']['priceId'] = [System.Text.Json.Nodes.JsonValue]::Create($PriceId) }
  [hashtable]::Synchronized(@{
    AppId = $AppId; Version = $Version; PendingId = $PendingId; HidePending = [bool]$HidePending
    OtherDraftAfterCheck = $OtherDraftAfterCheck; PendingAfterCreate = $PendingAfterCreate; PendingLag = [bool]$PendingLag; NoPendingAs = $NoPendingAs
    UploadStatus = $UploadStatus; UploadBody = $UploadBody; UploadBase = $UploadBase; CreateWithoutId = [bool]$CreateWithoutId
    CreateErrorStatus = $CreateErrorStatus; CreateErrorBody = $CreateErrorBody; CreateQuery = $null
    KeepOldPackage = [bool]$KeepOldPackage; CommitStatus = $CommitStatus; BaseUrl = $BaseUrl; Served = $false
    DriftOnPut = $DriftOnPut; LoseResponse = $LoseResponse; LoseWhen = $LoseWhen; LoseAsStatus = $LoseAsStatus; LoseBody = $LoseBody
    FailAfterLoss = [bool]$FailAfterLoss; Lost = $false; Redirect = $Redirect
    CommitDelayReads = $CommitDelayReads; HeldCommit = ''; FinalStatus = ''
    HangOn = $HangOn; CallSeconds = $CallSeconds; UploadSeconds = $UploadSeconds; CommitTried = $false
    DripOn = $DripOn; DripSeconds = $DripSeconds; DripHeadSeconds = $DripHeadSeconds; DripEnd = $DripEnd; Dripped = ''
    AnswerContentType = $AnswerContentType
    AcceptOn = $AcceptOn; AcceptStatus = $AcceptStatus; AcceptNotDone = [bool]$AcceptNotDone; AcceptAt = $AcceptAt; AcceptSeen = 0; Accepted = $false
    Seen = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
    Calls = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
    Held = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
    Fields = $f.ToJsonString()
    Token = 'fake-access-token-' + [guid]::NewGuid().ToString('N'); NewId = '1152921505000000099'
    Sub = $null; Log = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
    Blob = $null; BlobHeaders = $null; BlobQuery = ''; TokenRequest = ''; LastPut = ''
  })
}

function Get-FakeSasUrl($Store) {
  $base = if ($Store.UploadBase) { $Store.UploadBase } elseif ($Store.Served) { $Store.BaseUrl } else { $script:DefaultUploadBase }
  "$base/blob/upload.zip?$script:FakeSas"
}

function New-FakeResponse([int]$StatusCode, $Object, [string]$Location = '') {
  $body = if ($null -eq $Object) { '' } elseif ($Object -is [string]) { $Object } else { $Object | ConvertTo-Json -Depth 20 -Compress }
  [pscustomobject]@{ StatusCode = $StatusCode; Body = $body; Location = $Location; DripSeconds = 0 }
}

# The submission as JSON text: the stored fields plus id, status,
# statusDetails, fileUploadUrl and the packages.
function Get-FakeSubmission($Store) {
  $s = $Store.Sub
  $n = ConvertTo-FakeNode $Store.Fields
  $n['id'] = [System.Text.Json.Nodes.JsonValue]::Create([string]$s.id)
  $n['status'] = [System.Text.Json.Nodes.JsonValue]::Create([string]$s.status)
  $n['statusDetails'] = ConvertTo-FakeNode '{"errors":[],"warnings":[],"certificationReports":[]}'
  $n['fileUploadUrl'] = [System.Text.Json.Nodes.JsonValue]::Create((Get-FakeSasUrl $Store))
  $n['applicationPackages'] = ConvertTo-FakeNode (ConvertTo-Json -InputObject @($s.applicationPackages) -Depth 10 -Compress)
  $n.ToJsonString()
}

# A PUT body is refused (HTTP 400, as the docs require these on every package
# object) unless each package has fileName, fileStatus and a valid
# minimumDirectXVersion and minimumSystemRam. Returns the error code or ''.
function Test-FakePackageList($Packages) {
  if ($Packages -isnot [System.Text.Json.Nodes.JsonArray]) { return 'applicationPackages missing' }
  foreach ($p in $Packages) {
    if ($p -isnot [System.Text.Json.Nodes.JsonObject]) { return 'package is not an object' }
    foreach ($k in 'fileName', 'fileStatus', 'minimumDirectXVersion', 'minimumSystemRam') {
      if ($null -eq $p[$k]) { return "package without $k" }
    }
    if ([string]$p['minimumDirectXVersion'] -cnotin 'None', 'DirectX93', 'DirectX100') { return 'bad minimumDirectXVersion' }
    if ([string]$p['minimumSystemRam'] -cnotin 'None', 'Memory2GB') { return 'bad minimumSystemRam' }
  }
  ''
}

# What a request is: 'Token', 'Create', 'Commit', 'Upload', 'Update',
# 'Delete', 'AppRead', 'SubmissionRead' or ''.
function Get-FakeCallKind([string]$Method, [string]$Path) {
  if ($Method -eq 'POST' -and $Path -match '^/[^/]+/oauth2/v2\.0/token$') { return 'Token' }
  if ($Method -eq 'POST' -and $Path -match '^/v1\.0/my/applications/[^/]+/submissions$') { return 'Create' }
  if ($Method -eq 'POST' -and $Path -match '^/v1\.0/my/applications/[^/]+/submissions/\d+/commit$') { return 'Commit' }
  if ($Method -eq 'PUT' -and $Path -eq '/blob/upload.zip') { return 'Upload' }
  if ($Method -eq 'PUT' -and $Path -match '^/v1\.0/my/applications/[^/]+/submissions/\d+$') { return 'Update' }
  if ($Method -eq 'DELETE' -and $Path -match '^/v1\.0/my/applications/[^/]+/submissions/\d+$') { return 'Delete' }
  if ($Method -eq 'GET' -and $Path -match '^/v1\.0/my/applications/[^/]+$') { return 'AppRead' }
  if ($Method -eq 'GET' -and $Path -match '^/v1\.0/my/applications/[^/]+/submissions/\d+$') { return 'SubmissionRead' }
  ''
}

# Handles one request. Headers: a hashtable (case-insensitive keys).
function Invoke-FakeStoreRequest {
  param($Store, [string]$Method, [string]$Uri, [hashtable]$Headers = @{}, [byte[]]$BodyBytes = @())
  $path = ([uri]$Uri).AbsolutePath
  $kind = Get-FakeCallKind $Method $path
  $accept = $false
  if ($Store.AcceptOn -and $kind -ceq $Store.AcceptOn -and -not $Store.Accepted) { $Store.AcceptSeen++; $accept = $Store.AcceptSeen -eq $Store.AcceptAt }
  if ($accept -and $Store.AcceptNotDone -and $kind -in 'Create', 'Update', 'Commit', 'Upload', 'Delete') {
    # Accepted but not carried out: nothing changes.
    $Store.Accepted = $true
    [void]$Store.Log.Add("$Method $path")
    if ($kind -eq 'Create') { $Store.CreateQuery = ([uri]$Uri).Query }
    $o = switch ($kind) {
      'Create' { if ($Store.CreateWithoutId) { [ordered]@{ status = 'PendingCommit' } } else { [ordered]@{ id = $Store.NewId; status = 'PendingCommit' } } }
      'Update' { if ($Store.Sub) { Get-FakeSubmission $Store } else { $null } }
      'Commit' { @{ status = 'PendingCommit' } }
      'Upload' { $Store.UploadBody }
      default { $null }
    }
    $r = New-FakeResponse $Store.AcceptStatus $(if ($Store.AcceptStatus -eq 204) { $null } else { $o })
  } else {
    $r = Invoke-FakeStoreRoute -Store $Store -Method $Method -Uri $Uri -Headers $Headers -BodyBytes $BodyBytes
    if ($accept -and $r.StatusCode -ge 200 -and $r.StatusCode -lt 300) {
      $Store.Accepted = $true
      $r.StatusCode = $Store.AcceptStatus
      if ($Store.AcceptStatus -eq 204) { $r.Body = '' }
    }
  }
  $on = $Store.DripOn -and $kind -ceq $Store.DripOn -and $kind -notin 'AppRead', 'SubmissionRead'
  if ($on -and $r.StatusCode -gt 0) { $r.DripSeconds = $Store.DripSeconds }
  $r
}

function Invoke-FakeStoreRoute {
  param($Store, [string]$Method, [string]$Uri, [hashtable]$Headers = @{}, [byte[]]$BodyBytes = @())
  if ($null -eq $BodyBytes) { $BodyBytes = [byte[]]::new(0) }
  $u = [uri]$Uri
  $path = $u.AbsolutePath
  [void]$Store.Log.Add("$Method $path")
  $text = [Text.Encoding]::UTF8.GetString($BodyBytes)

  if ($Method -eq 'POST' -and $path -match '^/[^/]+/oauth2/v2\.0/token$') {
    if ($Store.Redirect -eq 'Token') { return New-FakeResponse 302 '' '/redirected/token' }
    $Store.TokenRequest = $text
    if ($text -notmatch '(^|&)grant_type=client_credentials(&|$)' -or $text -notmatch 'scope=https%3A%2F%2Fmanage\.devcenter\.microsoft\.com%2F\.default') {
      return New-FakeResponse 400 @{ error = 'invalid_request' }
    }
    return New-FakeResponse 200 @{ token_type = 'Bearer'; expires_in = 3599; access_token = $Store.Token }
  }
  if ($Method -eq 'PUT' -and $path -eq '/blob/upload.zip') {
    if ($Store.Redirect -eq 'Upload') { return New-FakeResponse 302 '' '/redirected/upload' }
    $Store.Blob = $BodyBytes; $Store.BlobHeaders = $Headers; $Store.BlobQuery = $u.Query
    return New-FakeResponse $Store.UploadStatus $Store.UploadBody
  }
  if ($path -notlike '/v1.0/my/*') { return New-FakeResponse 404 @{ code = 'NotFound'; message = 'no such route' } }
  if ($Headers['Authorization'] -cne "Bearer $($Store.Token)") { return New-FakeResponse 401 @{ code = 'Unauthorized'; message = 'bad token' } }
  if ($Store.Redirect -eq 'Api') { return New-FakeResponse 302 '' '/redirected/api' }
  if ($Store.Lost -and $Store.FailAfterLoss) { return New-FakeResponse 503 @{ code = 'ServiceUnavailable' } }

  $app = [regex]::Escape($Store.AppId)
  if ($Method -eq 'POST' -and $path -match "^/v1\.0/my/applications/$app/submissions$") { $Store.CreateQuery = $u.Query }
  if ($Method -eq 'POST' -and $path -match "^/v1\.0/my/applications/$app/submissions/\d+/commit$") {
    $Store.CommitTried = $true
    if ($Store.HangOn -eq 'Commit') { return New-FakeResponse -1 'hang' }
  }
  if ($Store.HangOn -eq 'ReadBack' -and $Store.CommitTried -and $Method -eq 'GET' -and $path -match "^/v1\.0/my/applications/$app/submissions/\d+$") {
    return New-FakeResponse -1 'hang'
  }
  $lose = ''
  if ($Method -eq 'POST' -and $Store.LoseResponse -and -not $Store.Lost) {
    if ($Store.LoseResponse -eq 'Create' -and $path -match "^/v1\.0/my/applications/$app/submissions$") { $lose = 'Create' }
    if ($Store.LoseResponse -eq 'Commit' -and $path -match "^/v1\.0/my/applications/$app/submissions/\d+/commit$") { $lose = 'Commit' }
  }
  if ($lose) {
    $Store.Lost = $true
    if ($Store.LoseWhen -eq 'Before') { return New-FakeResponse $Store.LoseAsStatus $Store.LoseBody }
    if ($Store.LoseWhen -eq 'Delayed' -and $lose -eq 'Commit') { $Store.HeldCommit = $path; return New-FakeResponse $Store.LoseAsStatus $Store.LoseBody }
  }
  # A held (delayed) commit: GETs of that submission see PendingCommit until
  # CommitDelayReads have passed, then the commit is processed and the next
  # GET sees CommitStarted; the GET after that sees the final status.
  if ($Method -eq 'GET' -and $Store.HeldCommit -and $path -ceq ($Store.HeldCommit -replace '/commit$', '')) {
    if ($Store.CommitDelayReads -gt 0) { $Store.CommitDelayReads-- }
    else {
      [void](Invoke-FakeApiRoute -Store $Store -Method POST -Path $Store.HeldCommit -Text '' -App $app)
      $Store.HeldCommit = ''
      $Store.FinalStatus = $Store.Sub.status; $Store.Sub.status = 'CommitStarted'
    }
  } elseif ($Method -eq 'GET' -and $Store.FinalStatus -and $Store.Sub) { $Store.Sub.status = $Store.FinalStatus; $Store.FinalStatus = '' }
  $r = Invoke-FakeApiRoute -Store $Store -Method $Method -Path $path -Text $text -App $app
  if ($lose) { return New-FakeResponse $Store.LoseAsStatus $Store.LoseBody }
  if ($Method -eq 'GET' -and $path -match "^/v1\.0/my/applications/$app$" -and
    ($Store.DripOn -eq 'AppRead' -or ($Store.DripOn -eq 'AppReadAfterCreate' -and $null -ne $Store.CreateQuery))) { $r.DripSeconds = $Store.DripSeconds }
  $r
}

function Invoke-FakeApiRoute($Store, [string]$Method, [string]$Path, [string]$Text, [string]$App) {
  if ($Path -match "^/v1\.0/my/applications/$App$" -and $Method -eq 'GET') {
    $o = [ordered]@{ id = $Store.AppId; primaryName = 'JerisLink'; lastPublishedApplicationSubmission = @{ id = '1152921505000000001'; resourceLocation = 'x' } }
    $shown = if ($Store.Sub -and $Store.PendingAfterCreate) { $Store.PendingAfterCreate } elseif ($Store.HidePending -and -not $Store.Sub) { '' } elseif ($Store.PendingLag -and $Store.Sub) { '' } else { $Store.PendingId }
    if ($shown) { $o.pendingApplicationSubmission = @{ id = $shown; resourceLocation = 'y' } }
    elseif ($Store.NoPendingAs -eq 'Null') { $o.pendingApplicationSubmission = $null }
    # Someone else creates a draft right after this (the run's pending check).
    if ($Store.OtherDraftAfterCheck -and -not $Store.PendingId) { $Store.PendingId = $Store.OtherDraftAfterCheck }
    return New-FakeResponse 200 $o
  }
  if ($Path -match "^/v1\.0/my/applications/$App/submissions$" -and $Method -eq 'POST') {
    if ($Store.PendingId) { return New-FakeResponse 409 @{ code = 'InvalidState'; message = 'The application has a pending submission.' } }
    if ($Store.CreateErrorStatus) {
      if ($Store.FailAfterLoss) { $Store.Lost = $true }
      return New-FakeResponse $Store.CreateErrorStatus $Store.CreateErrorBody
    }
    $Store.Sub = @{ id = $Store.NewId; status = 'PendingCommit'; applicationPackages = @(
      [ordered]@{ id = 'p1'; fileName = 'Jerislink-0.3.0.0-x64.msixupload'; fileStatus = 'Uploaded'; version = '0.3.0.0'; minimumDirectXVersion = 'None'; minimumSystemRam = 'None' }
      [ordered]@{ id = 'p2'; fileName = 'Jerislink-0.3.0.0-x64.msix'; fileStatus = 'Uploaded'; version = '0.3.0.0'; minimumDirectXVersion = 'None'; minimumSystemRam = 'None' }) }
    $Store.PendingId = $Store.NewId
    if ($Store.CreateWithoutId) { return New-FakeResponse 201 @{ status = 'PendingCommit'; fileUploadUrl = (Get-FakeSasUrl $Store) } }
    if ([string]$Store.CreateQuery -match '[?&]isMinimalResponse=true(&|$)') { return New-FakeResponse 201 ([ordered]@{ id = $Store.NewId; status = 'PendingCommit' }) }
    return New-FakeResponse 201 (Get-FakeSubmission $Store)
  }
  if ($Path -match "^/v1\.0/my/applications/$App/submissions/(\d+)(/commit)?$") {
    $id = $Matches[1]; $commit = [bool]$Matches[2]
    if (-not $Store.Sub -or $Store.Sub.id -ne $id) { return New-FakeResponse 404 @{ code = 'NotFound'; message = "submission $id not found" } }
    if ($commit -and $Method -eq 'POST') {
      if ($Store.Sub.status -ne 'PendingCommit') { return New-FakeResponse 409 @{ code = 'InvalidState'; message = 'not PendingCommit' } }
      $Store.Sub.status = $Store.CommitStatus
      $Store.Sub.applicationPackages = @(foreach ($p in $Store.Sub.applicationPackages) {
        if ($p.fileStatus -eq 'PendingDelete') { continue }
        $q = [ordered]@{}; foreach ($k in $p.Keys) { $q[$k] = $p[$k] }
        if ($q.fileStatus -eq 'PendingUpload') { $q.fileStatus = 'Uploaded'; $q.version = $Store.Version }
        $q
      })
      $Store.PendingId = ''
      return New-FakeResponse 200 @{ status = 'CommitStarted' }
    }
    if ($commit) { return New-FakeResponse 405 @{ code = 'MethodNotAllowed' } }
    switch ($Method) {
      'GET' { return New-FakeResponse 200 (Get-FakeSubmission $Store) }
      'PUT' {
        $Store.LastPut = $Text
        $b = $null
        try { $b = ConvertTo-FakeNode $Text } catch { }
        if ($b -isnot [System.Text.Json.Nodes.JsonObject]) { return New-FakeResponse 400 @{ code = 'InvalidParameterValue'; message = 'body' } }
        if ([string]$b['id'] -ne $id) { return New-FakeResponse 400 @{ code = 'InvalidParameterValue'; message = 'id mismatch' } }
        if ($null -eq $b['pricing'] -or -not [string]$b['pricing']['priceId']) { return New-FakeResponse 400 @{ code = 'InvalidParameterValue'; message = 'pricing' } }
        $bad = Test-FakePackageList $b['applicationPackages']
        if ($bad) { return New-FakeResponse 400 @{ code = 'InvalidParameterValue'; message = $bad } }
        $pk = @(foreach ($p in @($b['applicationPackages'].ToJsonString() | ConvertFrom-Json -AsHashtable)) { $q = [ordered]@{}; foreach ($k in $p.Keys) { $q[$k] = $p[$k] }; $q })
        if ($Store.KeepOldPackage) { foreach ($p in $pk) { if ($p.fileName -like '*.msix') { $p.fileStatus = 'Uploaded' } } }
        $Store.Sub.applicationPackages = $pk
        $old = ConvertTo-FakeNode $Store.Fields
        foreach ($k in @($script:ServerOwned + 'applicationPackages')) { [void]$b.Remove($k) }
        if ($null -ne $old['friendlyName']) { $b['friendlyName'] = [System.Text.Json.Nodes.JsonValue]::Create([string]$old['friendlyName']) }
        switch ($Store.DriftOnPut) {
          'Pricing' { $b['pricing']['priceId'] = [System.Text.Json.Nodes.JsonValue]::Create('Tier1') }
          'DropListing' { [void]$b['listings'].AsObject().Remove('zh-hk') }
        }
        $Store.Fields = $b.ToJsonString()
        return New-FakeResponse 200 (Get-FakeSubmission $Store)
      }
      'DELETE' {
        if ($Store.Sub.status -ne 'PendingCommit') { return New-FakeResponse 409 @{ code = 'InvalidState'; message = 'not PendingCommit' } }
        $Store.Sub = $null; $Store.PendingId = ''
        return New-FakeResponse 204 $null
      }
    }
  }
  New-FakeResponse 404 @{ code = 'NotFound'; message = 'no such route' }
}

# Serves Invoke-FakeStoreRequest on http://127.0.0.1:<free port> from a thread
# job; the SAS upload URL points there too. Sets $Store.BaseUrl and returns it.
function Start-FakeStoreServer {
  param([Parameter(Mandatory)]$Store)
  $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
  $probe.Start(); $port = $probe.LocalEndpoint.Port; $probe.Stop()
  $Store.BaseUrl = "http://127.0.0.1:$port"
  $Store.Served = $true
  $Store.Job = Start-ThreadJob -ArgumentList $Store, $PSCommandPath, "http://127.0.0.1:$port/" -ScriptBlock {
    param($Store, $ModulePath, $Prefix)
    Import-Module $ModulePath
    $l = [System.Net.HttpListener]::new()
    $l.Prefixes.Add($Prefix)
    $l.Start()
    $Store.Listener = $l
    while ($l.IsListening) {
      try { $ctx = $l.GetContext() } catch { break }
      $hold = $false
      try {
        $h = @{}
        foreach ($k in $ctx.Request.Headers.AllKeys) { $h[$k] = $ctx.Request.Headers[$k] }
        $ms = [IO.MemoryStream]::new(); $ctx.Request.InputStream.CopyTo($ms)
        [void]$Store.Seen.Add(@{ Line = "$($ctx.Request.HttpMethod) $($ctx.Request.Url.AbsolutePath)"; Headers = $h })
        $r = Invoke-FakeStoreRequest -Store $Store -Method $ctx.Request.HttpMethod -Uri $ctx.Request.Url.AbsoluteUri -Headers $h -BodyBytes $ms.ToArray()
        # No answer at all: keep the connection open until the client gives up.
        if ($r.StatusCode -eq -1) { $hold = $true; [void]$Store.Held.Add($ctx); continue }
        # No answer cannot be sent reliably over HttpListener; 504 stands in.
        $ctx.Response.StatusCode = if ($r.StatusCode -eq 0) { 504 } else { $r.StatusCode }
        if ($r.Location) { $ctx.Response.RedirectLocation = $r.Location }
        $bytes = [Text.Encoding]::UTF8.GetBytes([string]$r.Body)
        if ($r.DripSeconds -gt 0 -and $bytes.Length -gt 1) {
          # The headers and the first byte after DripHeadSeconds, then a space
          # every 250 ms (JSON allows them), then the rest. Stops when the
          # client hangs up or the server is stopped.
          # Break: a Content-Length the server never reaches, so the client
          # sees the connection end before the body is complete (an aborted
          # chunked answer can end cleanly on the managed Linux listener).
          $ctx.Response.ContentType = $Store.AnswerContentType
          if ($Store.DripEnd -eq 'Break') { $ctx.Response.ContentLength64 = $bytes.Length + 65536 } else { $ctx.Response.SendChunked = $true }
          $o = $ctx.Response.OutputStream
          $sp = [byte[]]@(32)
          try {
            if ($Store.DripHeadSeconds -gt 0) { Start-Sleep -Seconds $Store.DripHeadSeconds }
            $until = [DateTime]::UtcNow.AddSeconds($r.DripSeconds)
            $o.Write($bytes, 0, 1); $o.Flush()
            while ([DateTime]::UtcNow -lt $until -and $l.IsListening) { Start-Sleep -Milliseconds 250; $o.Write($sp, 0, 1); $o.Flush() }
            if ($Store.DripEnd -eq 'Break') {
              $Store.Dripped = 'connection broken'
              $hold = $true; $ctx.Response.Abort()
            } else {
              $o.Write($bytes, 1, $bytes.Length - 1)
              $Store.Dripped = 'whole body sent'
            }
          } catch {
            $Store.Dripped = 'client hung up'
            $hold = $true; try { $ctx.Response.Abort() } catch { }
          }
        }
        elseif ($bytes.Length) { $ctx.Response.ContentType = $Store.AnswerContentType; $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length) }
      } catch {
        [void]$Store.Log.Add("SERVER ERROR $_")
        $ctx.Response.StatusCode = 500
      } finally { if (-not $hold) { $ctx.Response.Close() } }
    }
  }
  $deadline = (Get-Date).AddSeconds(20)
  while (-not $Store.ContainsKey('Listener') -and (Get-Date) -lt $deadline) {
    if ($Store.Job.State -in 'Failed', 'Completed') { throw "fake Store server did not start: $($Store.Job | Receive-Job 2>&1 | Out-String)" }
    Start-Sleep -Milliseconds 100
  }
  if (-not $Store.ContainsKey('Listener')) { throw "fake Store server did not start" }
  $Store.BaseUrl
}

function Stop-FakeStoreServer {
  param([Parameter(Mandatory)]$Store)
  foreach ($c in @($Store.Held)) { try { $c.Response.Abort() } catch { } }
  $Store.Held.Clear()
  if ($Store.ContainsKey('Listener')) { $Store.Listener.Stop(); $Store.Listener.Close() }
  if ($Store.ContainsKey('Job')) { $Store.Job | Wait-Job -Timeout 10 | Out-Null; $Store.Job | Remove-Job -Force }
}

# Entry names and bytes of the uploaded zip.
function Get-FakeUploadedZip {
  param([Parameter(Mandatory)]$Store)
  if (-not $Store.Blob) { return @() }
  $z = [IO.Compression.ZipArchive]::new([IO.MemoryStream]::new([byte[]]$Store.Blob))
  try {
    @(foreach ($e in $z.Entries) {
      $ms = [IO.MemoryStream]::new(); $s = $e.Open(); $s.CopyTo($ms); $s.Dispose()
      [pscustomobject]@{ Name = $e.FullName; Bytes = $ms.ToArray() }
    })
  } finally { $z.Dispose() }
}

Export-ModuleMember -Function New-FakeStore, Invoke-FakeStoreRequest, Get-FakeSubmission, Start-FakeStoreServer, Stop-FakeStoreServer, Get-FakeUploadedZip
