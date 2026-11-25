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
# Three markets and a sale, so a market price, a market order and the sales the
# service rewrites after a PUT (Edit-FakeFieldsOnPut) show.
$script:FieldsTemplate = @'
{
  "applicationCategory": "Productivity",
  "pricing": { "trialPeriod": "NoFreeTrial", "marketSpecificPricings": { "HK": "Tier2", "US": "Tier3", "GB": "Tier4" },
    "sales": [ { "name": "Launch sale", "basePriceId": "Tier1", "startDate": "2026-01-01T00:00:00Z", "endDate": "2026-02-01T00:00:00Z",
      "marketSpecificPricings": { "HK": "Tier1" } } ], "priceId": "Free", "isAdvancedPricingModel": false, "isAdvertisingFunded": false },
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
# Fields the service owns: a PUT cannot change them (friendlyName: the service
# rewrites it after every PUT, Edit-FakeFieldsOnPut).
$script:ServerOwned = @('id', 'status', 'statusDetails', 'fileUploadUrl', 'friendlyName')

function ConvertTo-FakeNode([string]$Json) {
  $o = [System.Text.Json.Nodes.JsonNodeOptions]::new()
  $o.PropertyNameCaseInsensitive = $true
  , [System.Text.Json.Nodes.JsonNode]::Parse($Json, $o)
}

# What the service does to the fields a PUT sent (Fields: a JsonObject without
# the server-owned fields), as the real Store did in run 45524510567: it
# rewrites friendlyName (OldFriendlyName + " (updated)"), and it rearranges
# pricing: sales emptied, isAdvancedPricingModel flipped, the pricing keys and
# the markets of marketSpecificPricings in reverse order. The price itself
# (priceId, trialPeriod, the price of each market) stays. Then Drift, a change
# the service must not make: 'Pricing' (priceId becomes Tier1), 'MarketPrice'
# (the HK price becomes Tier5), 'AddMarket' (JP is added), 'RemoveMarket' (US
# is gone), 'DropListing' (the zh-hk listing is gone); or one the docs say
# Partner Center makes itself: 'StoreSetRollout' (it sets
# packageDeliveryOptions.packageRollout.packageRolloutStatus and
# fallbackSubmissionId, which "are assigned by Partner Center"); or that one
# with a change the service must not make on top: 'RolloutPercentage'
# (packageRolloutPercentage becomes 50), 'MandatoryUpdate' (isMandatoryUpdate
# becomes true). Returns the new JSON.
function Edit-FakeFieldsOnPut([System.Text.Json.Nodes.JsonObject]$Fields, [string]$OldFriendlyName, [string]$Drift) {
  $Fields['friendlyName'] = [System.Text.Json.Nodes.JsonValue]::Create("$(if ($OldFriendlyName) { $OldFriendlyName } else { 'Submission' }) (updated)")
  $p = $Fields['pricing']
  if ($p -is [System.Text.Json.Nodes.JsonObject]) {
    $old = ConvertTo-FakeNode $p.ToJsonString()
    $new = [System.Text.Json.Nodes.JsonObject]::new()
    $keys = @(foreach ($kv in $old) { $kv.Key }); [array]::Reverse($keys)
    foreach ($k in $keys) {
      $v = $old[$k]
      $copy = if ($null -eq $v) { $null } else { ConvertTo-FakeNode $v.ToJsonString() }
      if ($k -eq 'sales') { $copy = [System.Text.Json.Nodes.JsonArray]::new() }
      elseif ($k -eq 'isAdvancedPricingModel') { $copy = [System.Text.Json.Nodes.JsonValue]::Create(-not ($null -ne $v -and $v.ToJsonString() -ceq 'true')) }
      elseif ($k -eq 'marketSpecificPricings' -and $v -is [System.Text.Json.Nodes.JsonObject]) {
        $m = [System.Text.Json.Nodes.JsonObject]::new()
        $mk = @(foreach ($kv in $v) { $kv.Key }); [array]::Reverse($mk)
        foreach ($c in $mk) { $m[$c] = if ($null -eq $v[$c]) { $null } else { ConvertTo-FakeNode $v[$c].ToJsonString() } }
        $copy = $m
      }
      $new[$k] = $copy
    }
    $Fields['pricing'] = $new
  }
  # A pricing drift needs pricing (NoPricing has none).
  if ($Drift -cin 'Pricing', 'MarketPrice', 'AddMarket', 'RemoveMarket' -and $Fields['pricing'] -isnot [System.Text.Json.Nodes.JsonObject]) { $Drift = '' }
  if ($Drift -cin 'StoreSetRollout', 'RolloutPercentage', 'MandatoryUpdate') {
    $r = $Fields['packageDeliveryOptions']['packageRollout']
    $r['packageRolloutStatus'] = [System.Text.Json.Nodes.JsonValue]::Create('PackageRolloutInProgress')
    $r['fallbackSubmissionId'] = [System.Text.Json.Nodes.JsonValue]::Create('1152921505000000042')
  }
  switch ($Drift) {
    'Pricing' { $Fields['pricing']['priceId'] = [System.Text.Json.Nodes.JsonValue]::Create('Tier1') }
    'MarketPrice' { $Fields['pricing']['marketSpecificPricings']['HK'] = [System.Text.Json.Nodes.JsonValue]::Create('Tier5') }
    'AddMarket' { $Fields['pricing']['marketSpecificPricings']['JP'] = [System.Text.Json.Nodes.JsonValue]::Create('Tier2') }
    'RemoveMarket' { [void]$Fields['pricing']['marketSpecificPricings'].AsObject().Remove('US') }
    'DropListing' { [void]$Fields['listings'].AsObject().Remove('zh-hk') }
    'RolloutPercentage' { $Fields['packageDeliveryOptions']['packageRollout']['packageRolloutPercentage'] = [System.Text.Json.Nodes.JsonValue]::Create(50.0) }
    'MandatoryUpdate' { $Fields['packageDeliveryOptions']['isMandatoryUpdate'] = [System.Text.Json.Nodes.JsonValue]::Create($true) }
  }
  $Fields.ToJsonString()
}

# Options: PendingId (a pending submission that exists before the run; a GET
# of it by id shows it with status PendingStatus, default PendingCommit, and
# the fields of a draft an earlier run updated: Edit-FakeFieldsOnPut with
# DriftOnPut; a DELETE of it by id is refused with 409 unless it is
# PendingCommit, else answered 204 and it is gone), HidePending (GET app does not show it, as if it appeared after the check),
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
# Every PUT renames the submission and rearranges its pricing, as the real
# Store does (Edit-FakeFieldsOnPut). DriftOnPut: the PUT also changes a field
# it should keep ('Pricing': priceId becomes Tier1; 'MarketPrice': the HK
# price changes; 'AddMarket': JP is added; 'RemoveMarket': US is gone;
# 'DropListing': the zh-hk listing is gone), or makes a change Partner Center
# makes itself ('StoreSetRollout': it sets the package rollout status and
# fallback submission id), alone or with one it should not make on top
# ('RolloutPercentage', 'MandatoryUpdate'; see Edit-FakeFieldsOnPut).
# GET app shows lastPublishedApplicationSubmission 1152921505000000001 (none
# with NoPublished); a GET of it by id shows it with status Published and the
# fields as they were before any PUT (friendlyName "Submission 1").
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
# FailReadOn ('AppRead' / 'SubmissionRead'): the FailReadAt-th GET of the app
# / of a submission (default the first) is answered with FailReadStatus
# instead (any status; 0: no answer, the mocked Invoke-StoreHttp throws what
# HttpClient throws; -1: no answer before the call's time limit; -2: not
# sent, nothing reaches the fake and nothing is logged), with FailReadBody as
# its body ($null: the usual body of that GET; a scriptblock: what it returns
# for the usual body). FailReadLost: its body is
# lost (the mocked Invoke-StoreHttp returns the status with the BodyLost text
# of DripEnd). For the mocked Invoke-StoreHttp only. ReadFailed: whether that
# answer was sent.
# EditAnswer: a scriptblock called as & EditAnswer <kind> <answer> for every
# answer the fake gives to a call of a known kind (Token, Create, Update,
# Commit, Upload, Delete, AppRead, SubmissionRead), after all the options
# above; it may change the answer's StatusCode and Body (PR #74 r8: planted
# credentials).
# DropOn ('Token', 'Create', 'Update', 'Commit', 'Upload', 'Delete',
# 'AppRead', 'SubmissionRead'; PR #74 r12): the first DropTimes such requests
# (default 1) get no answer at all: the server reads the whole request, then
# closes the connection cleanly (FIN) without sending a byte. The request is
# carried out first, unless DropNotDone is set. Only the TCP server
# (Start-FakeStoreServer -Tcp) closes a connection this way; the handler
# returns status -3 for it. Dropped: how many requests were dropped.
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
    [ValidateSet('', 'Pricing', 'MarketPrice', 'AddMarket', 'RemoveMarket', 'DropListing', 'StoreSetRollout', 'RolloutPercentage',
      'MandatoryUpdate')][string]$DriftOnPut = '',
    [string]$PendingStatus = 'PendingCommit',
    [switch]$NoPublished,
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
    [ValidateSet('', 'AppRead', 'SubmissionRead')][string]$FailReadOn = '',
    [ValidateRange(1, 100)][int]$FailReadAt = 1,
    [ValidateRange(-2, 599)][int]$FailReadStatus = 503,
    $FailReadBody = $null,
    [switch]$FailReadLost,
    [scriptblock]$EditAnswer = $null,
    [ValidateSet('', 'Token', 'Create', 'Update', 'Commit', 'Upload', 'Delete', 'AppRead', 'SubmissionRead')][string]$DropOn = '',
    [ValidateRange(1, 100)][int]$DropTimes = 1,
    [switch]$DropNotDone,
    [string]$AnswerContentType = 'application/json',
    [string]$BaseUrl = 'https://manage.devcenter.microsoft.com'
  )
  $f = ConvertTo-FakeNode $script:FieldsTemplate
  $f['targetPublishMode'] = [System.Text.Json.Nodes.JsonValue]::Create($TargetPublishMode)
  if ($NoPricing) { [void]$f.Remove('pricing') } else { $f['pricing']['priceId'] = [System.Text.Json.Nodes.JsonValue]::Create($PriceId) }
  $published = ConvertTo-FakeNode $f.ToJsonString()
  $published['friendlyName'] = [System.Text.Json.Nodes.JsonValue]::Create('Submission 1')
  $pendingFields = Edit-FakeFieldsOnPut (ConvertTo-FakeNode $f.ToJsonString()) 'Submission 2' $DriftOnPut
  [hashtable]::Synchronized(@{
    PresetPendingId = $PendingId; PendingStatus = $PendingStatus; PendingFields = $pendingFields
    PublishedId = $(if ($NoPublished) { '' } else { '1152921505000000001' }); PublishedFields = $published.ToJsonString()
    AppId = $AppId; AppName = ''; Version = $Version; PendingId = $PendingId; HidePending = [bool]$HidePending
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
    FailReadOn = $FailReadOn; FailReadAt = $FailReadAt; FailReadStatus = $FailReadStatus; FailReadBody = $FailReadBody
    FailReadLost = [bool]$FailReadLost; FailReadSeen = 0; ReadFailed = $false; EditAnswer = $EditAnswer
    DropOn = $DropOn; DropTimes = $DropTimes; DropNotDone = [bool]$DropNotDone; Dropped = 0
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

# A submission this run did not create (the last published one, or a pending
# one from before the run) as JSON text: Fields plus id, status,
# statusDetails, fileUploadUrl and the old packages, Uploaded.
function Get-FakeOtherSubmission($Store, [string]$Id, [string]$Status, [string]$Fields) {
  $n = ConvertTo-FakeNode $Fields
  $n['id'] = [System.Text.Json.Nodes.JsonValue]::Create($Id)
  $n['status'] = [System.Text.Json.Nodes.JsonValue]::Create($Status)
  $n['statusDetails'] = ConvertTo-FakeNode '{"errors":[],"warnings":[],"certificationReports":[]}'
  $n['fileUploadUrl'] = [System.Text.Json.Nodes.JsonValue]::Create((Get-FakeSasUrl $Store))
  $n['applicationPackages'] = ConvertTo-FakeNode ('[{"id":"p1","fileName":"Jerislink-0.3.0.0-x64.msixupload","fileStatus":"Uploaded","version":"0.3.0.0",' +
    '"minimumDirectXVersion":"None","minimumSystemRam":"None"}]')
  $n.ToJsonString()
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
  if ($Store.DropOn -and $kind -ceq $Store.DropOn -and $Store.Dropped -lt $Store.DropTimes) {
    $Store.Dropped++
    if (-not $Store.DropNotDone) { [void](Invoke-FakeStoreRoute -Store $Store -Method $Method -Uri $Uri -Headers $Headers -BodyBytes $BodyBytes) }
    return New-FakeResponse -3 ''
  }
  if ($Store.FailReadOn -and $kind -ceq $Store.FailReadOn -and -not $Store.ReadFailed) {
    $Store.FailReadSeen++
    if ($Store.FailReadSeen -eq $Store.FailReadAt) {
      $Store.ReadFailed = $true
      if ($Store.FailReadStatus -eq -2) { return New-FakeResponse -2 '' }
      $r = Invoke-FakeStoreRoute -Store $Store -Method $Method -Uri $Uri -Headers $Headers -BodyBytes $BodyBytes
      $r.StatusCode = $Store.FailReadStatus
      if ($Store.FailReadBody -is [scriptblock]) { $r.Body = [string](& $Store.FailReadBody $r.Body) }
      elseif ($null -ne $Store.FailReadBody) { $r.Body = [string]$Store.FailReadBody }
      if ($Store.FailReadLost -and $r.StatusCode -gt 0) { $r.DripSeconds = 1 }
      if ($Store.EditAnswer -and $r.StatusCode -gt 0) { & $Store.EditAnswer $kind $r }
      return $r
    }
  }
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
  if ($Store.EditAnswer -and $kind -and $r.StatusCode -gt 0) { & $Store.EditAnswer $kind $r }
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
    # AppName: the app's name, when a test sets it (else JerisLink).
    $o = [ordered]@{ id = $Store.AppId; primaryName = $(if ($Store.AppName) { $Store.AppName } else { 'JerisLink' }) }
    if ($Store.PublishedId) { $o.lastPublishedApplicationSubmission = @{ id = $Store.PublishedId; resourceLocation = 'x' } }
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
    if ((-not $Store.Sub -or $Store.Sub.id -ne $id) -and -not $commit -and $Method -eq 'GET') {
      # Read only: the last published submission, and a pending one from
      # before the run while it is still pending.
      if ($Store.PublishedId -and $id -eq $Store.PublishedId) { return New-FakeResponse 200 (Get-FakeOtherSubmission $Store $id 'Published' $Store.PublishedFields) }
      if ($Store.PresetPendingId -and $id -eq $Store.PresetPendingId -and $Store.PendingId -eq $id) {
        return New-FakeResponse 200 (Get-FakeOtherSubmission $Store $id $Store.PendingStatus $Store.PendingFields)
      }
    }
    # A DELETE by id of the pending submission from before the run, while it
    # is still pending: refused (409) unless it is PendingCommit; else it is
    # gone (a GET of it by id is 404, GET app shows none pending).
    if ((-not $Store.Sub -or $Store.Sub.id -ne $id) -and -not $commit -and $Method -eq 'DELETE' -and
      $Store.PresetPendingId -and $id -eq $Store.PresetPendingId -and $Store.PendingId -eq $id) {
      if ($Store.PendingStatus -ne 'PendingCommit') { return New-FakeResponse 409 @{ code = 'InvalidState'; message = 'not PendingCommit' } }
      $Store.PendingId = ''
      return New-FakeResponse 204 $null
    }
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
        $Store.Fields = Edit-FakeFieldsOnPut $b ([string]$old['friendlyName']) $Store.DriftOnPut
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
# Tcp (PR #74 r12): HTTP/1.1 written by hand on a TcpListener instead of
# HttpListener, one connection at a time, so the tests see exactly what goes
# over the wire: each request in Seen also has Connection (1 for the first
# connection the server accepted, 2 for the next, ...), and a request the
# handler gives no answer (status 0 or -3, DropOn) is read whole, then its
# connection is closed cleanly (FIN) without a byte of answer. Answers carry
# Content-Length and keep the connection open for the next request
# (keep-alive). Status -1 (HangOn) waits until the client hangs up; DripOn is
# not served (the whole body is sent at once). Requests must have a
# Content-Length body (no chunked request bodies).
function Start-FakeStoreServer {
  param([Parameter(Mandatory)]$Store, [switch]$Tcp)
  $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
  $probe.Start(); $port = $probe.LocalEndpoint.Port; $probe.Stop()
  $Store.BaseUrl = "http://127.0.0.1:$port"
  $Store.Served = $true
  if ($Tcp) {
    $Store.Job = Start-ThreadJob -ArgumentList $Store, $PSCommandPath, $port -ScriptBlock {
      param($Store, $ModulePath, $Port)
      Import-Module $ModulePath
      $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
      $l.Start()
      $Store.Listener = $l
      $latin = [System.Text.Encoding]::Latin1
      $chunk = [byte[]]::new(65536)
      $n = 0
      while ($true) {
        $c = $null
        try { $c = $l.AcceptTcpClient() } catch { break }
        $n++
        $Store.Conn = $c
        try {
          $s = $c.GetStream()
          $s.ReadTimeout = 30000
          $buf = [System.IO.MemoryStream]::new()
          while ($true) {
            # One request: the head up to the empty line, then Content-Length bytes.
            $head = -1
            while (($head = $latin.GetString($buf.GetBuffer(), 0, [int]$buf.Length).IndexOf("`r`n`r`n")) -lt 0) {
              $k = $s.Read($chunk, 0, $chunk.Length)
              if ($k -le 0) { break }
              $buf.Write($chunk, 0, $k)
            }
            if ($head -lt 0) { break }
            $lines = @($latin.GetString($buf.GetBuffer(), 0, $head) -split "`r`n")
            $first = @($lines[0] -split ' ')
            $method = $first[0]; $target = $first[1]
            $h = @{}
            foreach ($x in @($lines | Select-Object -Skip 1)) {
              $i = $x.IndexOf(':')
              if ($i -le 0) { continue }
              $name = $x.Substring(0, $i).Trim(); $v = $x.Substring($i + 1).Trim()
              if ($h.ContainsKey($name)) { $h[$name] = $h[$name] + ', ' + $v } else { $h[$name] = $v }
            }
            if ($h.ContainsKey('Transfer-Encoding')) { [void]$Store.Log.Add('SERVER ERROR chunked request body'); break }
            $len = if ($h.ContainsKey('Content-Length')) { [int]$h['Content-Length'] } else { 0 }
            while ($buf.Length -lt $head + 4 + $len) {
              $k = $s.Read($chunk, 0, $chunk.Length)
              if ($k -le 0) { break }
              $buf.Write($chunk, 0, $k)
            }
            if ($buf.Length -lt $head + 4 + $len) { break }
            $body = [byte[]]::new($len)
            [Array]::Copy($buf.GetBuffer(), $head + 4, $body, 0, $len)
            $rest = [System.IO.MemoryStream]::new()
            $rest.Write($buf.GetBuffer(), $head + 4 + $len, [int]$buf.Length - ($head + 4 + $len))
            $buf = $rest
            $uri = "http://127.0.0.1:$Port$target"
            [void]$Store.Seen.Add(@{ Line = "$method $(([uri]$uri).AbsolutePath)"; Headers = $h; Connection = $n })
            $r = Invoke-FakeStoreRequest -Store $Store -Method $method -Uri $uri -Headers $h -BodyBytes $body
            if ($r.StatusCode -eq -1) {
              # No answer: wait until the client hangs up.
              $s.ReadTimeout = [System.Threading.Timeout]::Infinite
              try { while ($s.Read($chunk, 0, $chunk.Length) -gt 0) { } } catch { }
              break
            }
            if ($r.StatusCode -le 0) {
              # No answer, and the connection ends cleanly: FIN, nothing sent.
              $c.Client.Shutdown([System.Net.Sockets.SocketShutdown]::Send)
              [void]$c.Client.Poll(1000000, [System.Net.Sockets.SelectMode]::SelectRead)
              break
            }
            $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$r.Body)
            $t = "HTTP/1.1 $($r.StatusCode) Fake`r`n"
            if ($bytes.Length) { $t += "Content-Type: $($Store.AnswerContentType)`r`n" }
            if ($r.Location) { $t += "Location: $($r.Location)`r`n" }
            $t += "Content-Length: $($bytes.Length)`r`n`r`n"
            $hb = $latin.GetBytes($t)
            $s.Write($hb, 0, $hb.Length)
            if ($bytes.Length) { $s.Write($bytes, 0, $bytes.Length) }
            $s.Flush()
          }
        } catch {
          [void]$Store.Log.Add("SERVER ERROR $_")
        } finally { $c.Close(); $Store.Conn = $null }
      }
    }
    return (Wait-FakeStoreServer $Store)
  }
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
  Wait-FakeStoreServer $Store
}

# Waits until the server job listens; returns $Store.BaseUrl.
function Wait-FakeStoreServer($Store) {
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
  if ($Store.ContainsKey('Listener')) {
    $Store.Listener.Stop()
    if ($Store.Listener -is [System.Net.Sockets.TcpListener]) { if ($Store.ContainsKey('Conn') -and $Store.Conn) { try { $Store.Conn.Close() } catch { } } }
    else { $Store.Listener.Close() }
  }
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

Export-ModuleMember -Function New-FakeStore, Invoke-FakeStoreRequest, Get-FakeSubmission, Start-FakeStoreServer, Stop-FakeStoreServer, Get-FakeUploadedZip, Edit-FakeFieldsOnPut
