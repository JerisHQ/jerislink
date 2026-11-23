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
# its submission), PriceId (NoPricing drops pricing), UploadStatus/UploadBody,
# UploadBase (where the SAS upload URL points), CreateWithoutId,
# KeepOldPackage (the PUT leaves the old .msix Uploaded), CommitStatus (status
# after commit), TargetPublishMode.
# DriftOnPut: the PUT changes a field it should keep ('Pricing': priceId
# becomes Tier1; 'DropListing': the zh-hk listing is gone).
# LoseResponse ('Create' or 'Commit'): that request gets no answer, either
# After the service carried it out or Before; LoseAsStatus 0 means no
# response at all (the mocked Invoke-StoreHttp throws), another value is the
# status sent instead (e.g. 504). LoseWhen Delayed (Commit only): the commit
# is still being processed; the next CommitDelayReads GETs of that submission
# still show PendingCommit, the one after shows CommitStarted, later ones
# CommitStatus. FailAfterLoss: every later API call gets 503.
# Redirect ('Token', 'Api' or 'Upload'): those requests get a 302 to
# /redirected/<kind> on the same host.
function New-FakeStore {
  param(
    [string]$AppId = '9NM3VWQ9MD7N',
    [string]$Version = '0.4.1.0',
    [string]$PendingId = '',
    [switch]$HidePending,
    [string]$OtherDraftAfterCheck = '',
    [string]$PendingAfterCreate = '',
    [string]$TargetPublishMode = 'Manual',
    [ValidateSet('Null', 'Omit')][string]$NoPendingAs = 'Null',
    [string]$PriceId = 'Free',
    [switch]$NoPricing,
    [int]$UploadStatus = 201,
    [string]$UploadBody = '',
    [string]$UploadBase = '',
    [switch]$CreateWithoutId,
    [switch]$KeepOldPackage,
    [string]$CommitStatus = 'Certification',
    [ValidateSet('', 'Pricing', 'DropListing')][string]$DriftOnPut = '',
    [ValidateSet('', 'Create', 'Commit')][string]$LoseResponse = '',
    [ValidateSet('After', 'Before', 'Delayed')][string]$LoseWhen = 'After',
    [int]$LoseAsStatus = 0,
    [int]$CommitDelayReads = 1,
    [switch]$FailAfterLoss,
    [ValidateSet('', 'Token', 'Api', 'Upload')][string]$Redirect = '',
    [string]$BaseUrl = 'https://manage.devcenter.microsoft.com'
  )
  $f = ConvertTo-FakeNode $script:FieldsTemplate
  $f['targetPublishMode'] = [System.Text.Json.Nodes.JsonValue]::Create($TargetPublishMode)
  if ($NoPricing) { [void]$f.Remove('pricing') } else { $f['pricing']['priceId'] = [System.Text.Json.Nodes.JsonValue]::Create($PriceId) }
  [hashtable]::Synchronized(@{
    AppId = $AppId; Version = $Version; PendingId = $PendingId; HidePending = [bool]$HidePending
    OtherDraftAfterCheck = $OtherDraftAfterCheck; PendingAfterCreate = $PendingAfterCreate; NoPendingAs = $NoPendingAs
    UploadStatus = $UploadStatus; UploadBody = $UploadBody; UploadBase = $UploadBase; CreateWithoutId = [bool]$CreateWithoutId
    KeepOldPackage = [bool]$KeepOldPackage; CommitStatus = $CommitStatus; BaseUrl = $BaseUrl; Served = $false
    DriftOnPut = $DriftOnPut; LoseResponse = $LoseResponse; LoseWhen = $LoseWhen; LoseAsStatus = $LoseAsStatus
    FailAfterLoss = [bool]$FailAfterLoss; Lost = $false; Redirect = $Redirect
    CommitDelayReads = $CommitDelayReads; HeldCommit = ''; FinalStatus = ''
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
  [pscustomobject]@{ StatusCode = $StatusCode; Body = $body; Location = $Location }
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

# Handles one request. Headers: a hashtable (case-insensitive keys).
function Invoke-FakeStoreRequest {
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
  $lose = ''
  if ($Method -eq 'POST' -and $Store.LoseResponse -and -not $Store.Lost) {
    if ($Store.LoseResponse -eq 'Create' -and $path -match "^/v1\.0/my/applications/$app/submissions$") { $lose = 'Create' }
    if ($Store.LoseResponse -eq 'Commit' -and $path -match "^/v1\.0/my/applications/$app/submissions/\d+/commit$") { $lose = 'Commit' }
  }
  if ($lose) {
    $Store.Lost = $true
    if ($Store.LoseWhen -eq 'Before') { return New-FakeResponse $Store.LoseAsStatus 'lost' }
    if ($Store.LoseWhen -eq 'Delayed' -and $lose -eq 'Commit') { $Store.HeldCommit = $path; return New-FakeResponse $Store.LoseAsStatus 'lost' }
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
  if ($lose) { return New-FakeResponse $Store.LoseAsStatus 'lost' }
  $r
}

function Invoke-FakeApiRoute($Store, [string]$Method, [string]$Path, [string]$Text, [string]$App) {
  if ($Path -match "^/v1\.0/my/applications/$App$" -and $Method -eq 'GET') {
    $o = [ordered]@{ id = $Store.AppId; primaryName = 'JerisLink'; lastPublishedApplicationSubmission = @{ id = '1152921505000000001'; resourceLocation = 'x' } }
    $shown = if ($Store.Sub -and $Store.PendingAfterCreate) { $Store.PendingAfterCreate } elseif ($Store.HidePending -and -not $Store.Sub) { '' } else { $Store.PendingId }
    if ($shown) { $o.pendingApplicationSubmission = @{ id = $shown; resourceLocation = 'y' } }
    elseif ($Store.NoPendingAs -eq 'Null') { $o.pendingApplicationSubmission = $null }
    # Someone else creates a draft right after this (the run's pending check).
    if ($Store.OtherDraftAfterCheck -and -not $Store.PendingId) { $Store.PendingId = $Store.OtherDraftAfterCheck }
    return New-FakeResponse 200 $o
  }
  if ($Path -match "^/v1\.0/my/applications/$App/submissions$" -and $Method -eq 'POST') {
    if ($Store.PendingId) { return New-FakeResponse 409 @{ code = 'InvalidState'; message = 'The application has a pending submission.' } }
    $Store.Sub = @{ id = $Store.NewId; status = 'PendingCommit'; applicationPackages = @(
      [ordered]@{ id = 'p1'; fileName = 'Jerislink-0.3.0.0-x64.msixupload'; fileStatus = 'Uploaded'; version = '0.3.0.0'; minimumDirectXVersion = 'None'; minimumSystemRam = 'None' }
      [ordered]@{ id = 'p2'; fileName = 'Jerislink-0.3.0.0-x64.msix'; fileStatus = 'Uploaded'; version = '0.3.0.0'; minimumDirectXVersion = 'None'; minimumSystemRam = 'None' }) }
    $Store.PendingId = $Store.NewId
    if ($Store.CreateWithoutId) { return New-FakeResponse 201 @{ status = 'PendingCommit'; fileUploadUrl = (Get-FakeSasUrl $Store) } }
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
      try {
        $h = @{}
        foreach ($k in $ctx.Request.Headers.AllKeys) { $h[$k] = $ctx.Request.Headers[$k] }
        $ms = [IO.MemoryStream]::new(); $ctx.Request.InputStream.CopyTo($ms)
        $r = Invoke-FakeStoreRequest -Store $Store -Method $ctx.Request.HttpMethod -Uri $ctx.Request.Url.AbsoluteUri -Headers $h -BodyBytes $ms.ToArray()
        # No answer cannot be sent reliably over HttpListener; 504 stands in.
        $ctx.Response.StatusCode = if ($r.StatusCode -eq 0) { 504 } else { $r.StatusCode }
        if ($r.Location) { $ctx.Response.RedirectLocation = $r.Location }
        $bytes = [Text.Encoding]::UTF8.GetBytes([string]$r.Body)
        if ($bytes.Length) { $ctx.Response.ContentType = 'application/json'; $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length) }
      } catch {
        [void]$Store.Log.Add("SERVER ERROR $_")
        $ctx.Response.StatusCode = 500
      } finally { $ctx.Response.Close() }
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
