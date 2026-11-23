# A small in-memory stand-in for the Store submission API and the SAS blob
# upload, for tests only: the Pester tests route the mocked Invoke-StoreHttp
# here, and msstore-publish-check.yml serves it over real HTTP on 127.0.0.1
# (Start-FakeStoreServer). It models only what MsStoreRunner.psm1 relies on;
# the real service's JSON shapes and status changes are not verified by it.

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:FakeSas = 'sv=2020-08-04&sr=b&sp=w&sig=FAKE+SAS%2FSIGNATURE-0123456789'

# Options: PendingId (a pending submission that exists before the run),
# HidePending (GET app does not show it, as if it appeared after the check),
# NoPendingAs ('Null' or 'Omit': how GET app shows no pending submission),
# PendingAfterCreate (GET app shows this id as pending once the run created
# its submission), PriceId (NoPricing drops pricing), UploadStatus/UploadBody,
# CreateWithoutId, KeepOldPackage (the PUT leaves the old .msix Uploaded),
# CommitStatus (status after commit), TargetPublishMode.
function New-FakeStore {
  param(
    [string]$AppId = '9NM3VWQ9MD7N',
    [string]$Version = '0.4.1.0',
    [string]$PendingId = '',
    [switch]$HidePending,
    [string]$PendingAfterCreate = '',
    [string]$TargetPublishMode = 'Manual',
    [ValidateSet('Null', 'Omit')][string]$NoPendingAs = 'Null',
    [string]$PriceId = 'Free',
    [switch]$NoPricing,
    [int]$UploadStatus = 201,
    [string]$UploadBody = '',
    [switch]$CreateWithoutId,
    [switch]$KeepOldPackage,
    [string]$CommitStatus = 'Certification',
    [string]$BaseUrl = 'https://fake-store.invalid'
  )
  [hashtable]::Synchronized(@{
    AppId = $AppId; Version = $Version; PendingId = $PendingId; HidePending = [bool]$HidePending
    PendingAfterCreate = $PendingAfterCreate; TargetPublishMode = $TargetPublishMode; NoPendingAs = $NoPendingAs; PriceId = $(if ($NoPricing) { $null } else { $PriceId })
    UploadStatus = $UploadStatus; UploadBody = $UploadBody; CreateWithoutId = [bool]$CreateWithoutId
    KeepOldPackage = [bool]$KeepOldPackage; CommitStatus = $CommitStatus; BaseUrl = $BaseUrl
    Token = 'fake-access-token-' + [guid]::NewGuid().ToString('N'); NewId = '1152921505000000099'
    Sub = $null; Log = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
    Blob = $null; BlobHeaders = $null; BlobQuery = ''; TokenRequest = ''
  })
}

function Get-FakeSasUrl($Store) { "$($Store.BaseUrl)/blob/upload.zip?$script:FakeSas" }

function New-FakeResponse([int]$StatusCode, $Object) {
  $body = if ($null -eq $Object) { '' } elseif ($Object -is [string]) { $Object } else { $Object | ConvertTo-Json -Depth 20 -Compress }
  [pscustomobject]@{ StatusCode = $StatusCode; Body = $body }
}

function Get-FakeSubmission($Store) {
  $s = $Store.Sub
  $o = [ordered]@{ id = $s.id; status = $s.status; targetPublishMode = $Store.TargetPublishMode; applicationPackages = @($s.applicationPackages)
                   fileUploadUrl = (Get-FakeSasUrl $Store); targetPublishDate = '1601-01-01T00:00:00Z' }
  if ($null -ne $Store.PriceId) { $o.pricing = [ordered]@{ trialPeriod = 'NoFreeTrial'; marketSpecificPricings = @{}; priceId = $Store.PriceId } }
  $o
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
    $Store.TokenRequest = $text
    if ($text -notmatch '(^|&)grant_type=client_credentials(&|$)' -or $text -notmatch 'scope=https%3A%2F%2Fmanage\.devcenter\.microsoft\.com%2F\.default') {
      return New-FakeResponse 400 @{ error = 'invalid_request' }
    }
    return New-FakeResponse 200 @{ token_type = 'Bearer'; expires_in = 3599; access_token = $Store.Token }
  }
  if ($Method -eq 'PUT' -and $path -eq '/blob/upload.zip') {
    $Store.Blob = $BodyBytes; $Store.BlobHeaders = $Headers; $Store.BlobQuery = $u.Query
    return New-FakeResponse $Store.UploadStatus $Store.UploadBody
  }
  if ($path -notlike '/v1.0/my/*') { return New-FakeResponse 404 @{ code = 'NotFound'; message = 'no such route' } }
  if ($Headers['Authorization'] -cne "Bearer $($Store.Token)") { return New-FakeResponse 401 @{ code = 'Unauthorized'; message = 'bad token' } }

  $app = [regex]::Escape($Store.AppId)
  if ($path -match "^/v1\.0/my/applications/$app$" -and $Method -eq 'GET') {
    $o = [ordered]@{ id = $Store.AppId; primaryName = 'JerisLink'; lastPublishedApplicationSubmission = @{ id = '1152921505000000001'; resourceLocation = 'x' } }
    $shown = if ($Store.Sub -and $Store.PendingAfterCreate) { $Store.PendingAfterCreate } elseif ($Store.HidePending -and -not $Store.Sub) { '' } else { $Store.PendingId }
    if ($shown) { $o.pendingApplicationSubmission = @{ id = $shown; resourceLocation = 'y' } }
    elseif ($Store.NoPendingAs -eq 'Null') { $o.pendingApplicationSubmission = $null }
    return New-FakeResponse 200 $o
  }
  if ($path -match "^/v1\.0/my/applications/$app/submissions$" -and $Method -eq 'POST') {
    if ($Store.PendingId) { return New-FakeResponse 409 @{ code = 'InvalidState'; message = 'The application has a pending submission.' } }
    $Store.Sub = @{ id = $Store.NewId; status = 'PendingCommit'; applicationPackages = @(
      [ordered]@{ id = 'p1'; fileName = 'Jerislink-0.3.0.0-x64.msixupload'; fileStatus = 'Uploaded'; version = '0.3.0.0' }
      [ordered]@{ id = 'p2'; fileName = 'Jerislink-0.3.0.0-x64.msix'; fileStatus = 'Uploaded'; version = '0.3.0.0' }) }
    $Store.PendingId = $Store.NewId
    if ($Store.CreateWithoutId) { return New-FakeResponse 201 @{ status = 'PendingCommit'; fileUploadUrl = (Get-FakeSasUrl $Store) } }
    return New-FakeResponse 201 (Get-FakeSubmission $Store)
  }
  if ($path -match "^/v1\.0/my/applications/$app/submissions/(\d+)(/commit)?$") {
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
        $b = $text | ConvertFrom-Json -AsHashtable
        if ($b.id -ne $id) { return New-FakeResponse 400 @{ code = 'InvalidParameterValue'; message = 'id mismatch' } }
        if (-not $b.ContainsKey('pricing') -or -not $b.pricing.priceId) { return New-FakeResponse 400 @{ code = 'InvalidParameterValue'; message = 'pricing' } }
        $pk = @(foreach ($p in @($b.applicationPackages)) { $q = [ordered]@{}; foreach ($k in $p.Keys) { $q[$k] = $p[$k] }; $q })
        if ($Store.KeepOldPackage) { foreach ($p in $pk) { if ($p.fileName -like '*.msix') { $p.fileStatus = 'Uploaded' } } }
        $Store.Sub.applicationPackages = $pk
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
# job. Sets $Store.BaseUrl and returns it.
function Start-FakeStoreServer {
  param([Parameter(Mandatory)]$Store)
  $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
  $probe.Start(); $port = $probe.LocalEndpoint.Port; $probe.Stop()
  $Store.BaseUrl = "http://127.0.0.1:$port"
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
        $ctx.Response.StatusCode = $r.StatusCode
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

Export-ModuleMember -Function New-FakeStore, Invoke-FakeStoreRequest, Start-FakeStoreServer, Stop-FakeStoreServer, Get-FakeUploadedZip
