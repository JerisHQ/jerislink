# Pester 5 tests for MsStoreRunner.psm1: the checks on submission JSON, and the
# Store submission API flow against FakeStoreApi.psm1 (an in-memory stand-in;
# Invoke-StoreHttp, the module's only network call, is mocked to reach it).
# Run: Invoke-Pester -Path .github/scripts/tests -Output Detailed
# The fixtures are made up, not captured from Partner Center. They use
# PascalCase names; the API sends camelCase, and the checks read both (PowerShell
# property lookup ignores case). Every fileUploadUrl carries a fake SAS
# signature so the tests can check it is never printed.

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '..' 'MsStoreRunner.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot 'FakeStoreApi.psm1') -Force
  $script:Fixtures = Join-Path $PSScriptRoot 'fixtures'
  function script:Fixture([string]$Name) { Get-Content -Raw -LiteralPath (Join-Path $script:Fixtures "submission-$Name.json") }
  $script:SubId = '1152921505000000004'
  $script:App = '9NM3VWQ9MD7N'
  $script:File = 'Jerislink-0.4.1.0-x64.msixupload'
  $script:Secret = 'dummy-client-secret-Zx9'
  # Never in any output: the fake SAS signature, the blob URL, the client secret.
  $script:Leak = 'FAKE\+SAS|FAKE%2BSAS|SIGNATURE-0123456789|fake-store\.invalid|/blob/|dummy-client-secret|fake-access-token'

  # Runs a command, returns its pipeline output, everything it printed
  # (Write-Host) and the error text it threw ('' if none).
  function script:Invoke-Captured([scriptblock]$Command) {
    $printed = [System.Collections.Generic.List[string]]::new(); $value = @(); $err = ''
    try {
      $value = @(& $Command 6>&1 | ForEach-Object {
        if ($_ -is [System.Management.Automation.InformationRecord]) { $printed.Add([string]$_.MessageData) } else { $_ } })
    } catch { $err = "$_" }
    [pscustomobject]@{ Value = $value; Out = ($printed -join "`n"); Err = $err; All = (($printed -join "`n") + "`n" + $err) }
  }

  # Routes the module's HTTP calls to $global:FakeStore.
  function script:Use-FakeStore([hashtable]$Store) {
    $global:FakeStore = $Store
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp {
      $h = @{}
      if ($Headers) { foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] } }
      if ($ContentType) { $h['Content-Type'] = $ContentType }
      $bytes = if ($InFile) { [IO.File]::ReadAllBytes($InFile) } elseif ($Body) { [Text.Encoding]::UTF8.GetBytes($Body) } else { [byte[]]@() }
      Invoke-FakeStoreRequest -Store $global:FakeStore -Method $Method -Uri $Uri -Headers $h -BodyBytes $bytes
    }
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost 'https://login.fake.invalid' -ApiBase 'https://fake-store.invalid' 6>$null
    $Store.Log.Clear()
  }

  function script:New-TestPackage {
    $dir = Join-Path ([IO.Path]::GetTempPath()) ('pkg-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $dir | Out-Null
    $p = Join-Path $dir $File
    [IO.File]::WriteAllBytes($p, [byte[]](0..255 + 0..255))
    $p
  }

  function script:Invoke-Publish([string]$Package) {
    Invoke-Captured { Publish-StoreSubmission -ProductId $App -PackagePath $Package -ExpectedFileName $File -ExpectedVersion '0.4.1.0' }
  }

  $script:Base = "/v1.0/my/applications/$App"
  $script:NewId = '1152921505000000099'
}

Describe 'Test-SubmissionHasPackage' {
  It 'passes when the submission holds only the new package' {
    $r = Test-SubmissionHasPackage -SubmissionJson (Fixture 'new-package-only') -ExpectedVersion '0.4.1.0' -ExpectedSubmissionId $SubId
    $r.Result | Should -Be 'Pass'
    $r.Id | Should -Be $SubId
    $r.Status | Should -Be 'PreProcessing'
    $r.TargetPublishMode | Should -Be 'Immediate'
    $r.Packages.Count | Should -Be 1
    $r.Packages[0].FileName | Should -Be 'Jerislink-0.4.1.0-x64.msix'
    $r.Packages[0].Version | Should -Be '0.4.1.0'
    $r.Packages[0].FileStatus | Should -Be 'Uploaded'
  }

  It 'fails when the old package is still Uploaded next to the new one' {
    $r = Test-SubmissionHasPackage -SubmissionJson (Fixture 'old-package-still-present') -ExpectedVersion '0.4.1.0' -ExpectedSubmissionId $SubId
    $r.Result | Should -Be 'Fail'
    $r.Reason | Should -Match '0\.3\.0\.0'
  }

  It 'fails when the only Uploaded package has another version' {
    $r = Test-SubmissionHasPackage -SubmissionJson (Fixture 'version-mismatch') -ExpectedVersion '0.4.1.0'
    $r.Result | Should -Be 'Fail'
    $r.Reason | Should -Match '0\.4\.0\.0'
  }

  It 'fails on CommitFailed' {
    $r = Test-SubmissionHasPackage -SubmissionJson (Fixture 'commit-failed') -ExpectedVersion '0.4.1.0'
    $r.Result | Should -Be 'Fail'
    $r.Reason | Should -Match 'CommitFailed'
  }

  It 'fails on any other *Failed status' {
    $json = (Fixture 'new-package-only') -replace '"Status": "PreProcessing"', '"Status": "CertificationFailed"'
    $r = Test-SubmissionHasPackage -SubmissionJson $json -ExpectedVersion '0.4.1.0'
    $r.Result | Should -Be 'Fail'
    $r.Reason | Should -Match 'CertificationFailed'
  }

  It 'is pending while the package version is not filled in' {
    $r = Test-SubmissionHasPackage -SubmissionJson (Fixture 'version-unset') -ExpectedVersion '0.4.1.0'
    $r.Result | Should -Be 'Pending'
    $r.Reason | Should -Match 'version not filled in'
  }

  It 'is pending while the commit is still CommitStarted' {
    $json = (Fixture 'version-unset') -replace '"Status": "PreProcessing"', '"Status": "CommitStarted"'
    (Test-SubmissionHasPackage -SubmissionJson $json -ExpectedVersion '0.4.1.0').Result | Should -Be 'Pending'
  }

  It 'fails when the submission has no packages' {
    $r = Test-SubmissionHasPackage -SubmissionJson (Fixture 'no-packages') -ExpectedVersion '0.4.1.0'
    $r.Result | Should -Be 'Fail'
    $r.Reason | Should -Match 'no application packages'
  }

  It 'fails when the GET returned another submission than the one this run created' {
    $r = Test-SubmissionHasPackage -SubmissionJson (Fixture 'new-package-only') -ExpectedVersion '0.4.1.0' -ExpectedSubmissionId '1152921505000000003'
    $r.Result | Should -Be 'Fail'
    $r.Reason | Should -Match 'not submission 1152921505000000003 that this run created'
  }

  # Item 1: only committed statuses pass. A submission that is still a draft,
  # was canceled, or has no status was never committed.
  It 'fails on status <Status> (not committed)' -ForEach @(
    @{ Status = 'PendingCommit' }, @{ Status = 'Canceled' }, @{ Status = '' }, @{ Status = 'None' }
  ) {
    $json = (Fixture 'new-package-only') -replace '"Status": "PreProcessing"', ('"Status": "' + $Status + '"')
    $r = Test-SubmissionHasPackage -SubmissionJson $json -ExpectedVersion '0.4.1.0' -ExpectedSubmissionId $SubId
    $r.Result | Should -Be 'Fail'
    $r.Reason | Should -Match "status is '$Status', not a committed status"
  }

  It 'fails when the Status field is missing' {
    $json = (Fixture 'new-package-only') -replace '"Status": "PreProcessing",', ''
    $r = Test-SubmissionHasPackage -SubmissionJson $json -ExpectedVersion '0.4.1.0' -ExpectedSubmissionId $SubId
    $r.Result | Should -Be 'Fail'
    $r.Reason | Should -Match 'not a committed status'
  }

  It 'passes on committed status <Status>' -ForEach @(
    @{ Status = 'Certification' }, @{ Status = 'Release' }, @{ Status = 'PendingPublication' }, @{ Status = 'Publishing' }, @{ Status = 'Published' }
  ) {
    $json = (Fixture 'new-package-only') -replace '"Status": "PreProcessing"', ('"Status": "' + $Status + '"')
    (Test-SubmissionHasPackage -SubmissionJson $json -ExpectedVersion '0.4.1.0' -ExpectedSubmissionId $SubId).Result | Should -Be 'Pass'
  }

  It 'fails when there is no JSON' {
    (Test-SubmissionHasPackage -SubmissionJson 'Error while retrieving submission.' -ExpectedVersion '0.4.1.0').Result | Should -Be 'Fail'
    (Test-SubmissionHasPackage -SubmissionJson '' -ExpectedVersion '0.4.1.0').Result | Should -Be 'Fail'
  }

  It 'never carries the upload URL in its result' {
    foreach ($name in 'new-package-only', 'old-package-still-present', 'commit-failed', 'version-unset', 'no-packages') {
      $r = Test-SubmissionHasPackage -SubmissionJson (Fixture $name) -ExpectedVersion '0.4.1.0'
      ($r | ConvertTo-Json -Depth 5) | Should -Not -Match 'sig=|blob\.core|FileUploadUrl'
    }
  }
}

Describe 'Test-DraftReadyToCommit' {
  BeforeAll { $script:NewFile = 'Jerislink-0.4.1.0-x64.msixupload' }

  It 'passes when the old package is PendingDelete and only the new one remains' {
    $r = Test-DraftReadyToCommit -SubmissionJson (Fixture 'draft-ready') -SubmissionId $SubId -ExpectedFileName $NewFile -ExpectedVersion '0.4.1.0'
    $r.Result | Should -Be 'Pass'
    $r.Reason | Should -Match 'only Jerislink-0\.4\.1\.0-x64\.msixupload would remain'
  }

  It 'fails when an old package with another extension stays Uploaded' {
    $r = Test-DraftReadyToCommit -SubmissionJson (Fixture 'draft-old-other-extension') -SubmissionId $SubId -ExpectedFileName $NewFile -ExpectedVersion '0.4.1.0'
    $r.Result | Should -Be 'Fail'
    $r.Reason | Should -Match '2 package\(s\) would remain after commit .*Jerislink-0\.3\.0\.0-x64\.msix version=0\.3\.0\.0'
  }

  It 'fails when a second old package with the same extension stays' {
    $r = Test-DraftReadyToCommit -SubmissionJson (Fixture 'draft-two-old-same-extension') -SubmissionId $SubId -ExpectedFileName $NewFile -ExpectedVersion '0.4.1.0'
    $r.Result | Should -Be 'Fail'
    $r.Reason | Should -Match '2 package\(s\) would remain after commit .*arm64'
  }

  It 'fails when the only remaining package is not the new file' {
    $r = Test-DraftReadyToCommit -SubmissionJson (Fixture 'draft-ready') -SubmissionId $SubId -ExpectedFileName 'Jerislink-0.4.2.0-x64.msixupload' -ExpectedVersion '0.4.2.0'
    $r.Result | Should -Be 'Fail'
    $r.Reason | Should -Match 'not Jerislink-0\.4\.2\.0-x64\.msixupload'
  }

  It 'fails when no package would remain' {
    $json = (Fixture 'draft-ready') -replace '"FileStatus": "PendingUpload"', '"FileStatus": "PendingDelete"'
    $r = Test-DraftReadyToCommit -SubmissionJson $json -SubmissionId $SubId -ExpectedFileName $NewFile -ExpectedVersion '0.4.1.0'
    $r.Result | Should -Be 'Fail'
    $r.Reason | Should -Match '0 package\(s\) would remain'
  }

  It 'fails when the remaining package has another version' {
    $json = (Fixture 'draft-ready') -replace '"Version": null', '"Version": "0.4.0.0"'
    (Test-DraftReadyToCommit -SubmissionJson $json -SubmissionId $SubId -ExpectedFileName $NewFile -ExpectedVersion '0.4.1.0').Reason | Should -Match 'version is 0\.4\.0\.0'
  }

  It 'fails when the draft status is <Status>, not PendingCommit' -ForEach @(@{ Status = 'PreProcessing' }, @{ Status = 'Canceled' }, @{ Status = '' }) {
    $json = (Fixture 'draft-ready') -replace '"Status": "PendingCommit"', ('"Status": "' + $Status + '"')
    $r = Test-DraftReadyToCommit -SubmissionJson $json -SubmissionId $SubId -ExpectedFileName $NewFile -ExpectedVersion '0.4.1.0'
    $r.Result | Should -Be 'Fail'
    $r.Reason | Should -Match "draft status is '$Status'"
  }

  It 'fails when the GET returned another submission than the draft' {
    $r = Test-DraftReadyToCommit -SubmissionJson (Fixture 'draft-ready') -SubmissionId '1152921505000000003' -ExpectedFileName $NewFile -ExpectedVersion '0.4.1.0'
    $r.Result | Should -Be 'Fail'
    $r.Reason | Should -Match 'not draft 1152921505000000003 that this run created'
  }

  It 'fails when there is no JSON' {
    (Test-DraftReadyToCommit -SubmissionJson 'Error' -SubmissionId $SubId -ExpectedFileName $NewFile -ExpectedVersion '0.4.1.0').Result | Should -Be 'Fail'
  }

  It 'never carries the upload URL in its result' {
    $r = Test-DraftReadyToCommit -SubmissionJson (Fixture 'draft-ready') -SubmissionId $SubId -ExpectedFileName $NewFile -ExpectedVersion '0.4.1.0'
    ($r | ConvertTo-Json -Depth 5) | Should -Not -Match 'sig=|blob\.core|FileUploadUrl'
  }
}

Describe 'Protect-StoreText' {
  It 'masks URLs, sig= values and bearer tokens' {
    $t = Protect-StoreText 'PUT https://x.blob.core.windows.net/c/u.zip?sv=1&sig=AbC%2B12 failed; sig=Zz9 Bearer eyJ0eXAi.abc.def'
    $t | Should -Not -Match 'blob\.core|AbC|Zz9|eyJ0'
    $t | Should -Match '\[url\]'
  }
  It 'masks JSON-escaped URLs' {
    Protect-StoreText '{"fileUploadUrl":"https:\/\/x.blob.core.windows.net\/c?sig=AbC"}' | Should -Not -Match 'blob\.core|AbC'
  }
}

Describe 'Connect-StoreApi' {
  It 'never prints the secret or the token, also when the token request fails' {
    $s = New-FakeStore
    $global:FakeStore = $s
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp {
      [pscustomobject]@{ StatusCode = 401; Body = '{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret dummy-client-secret-Zx9 provided. https://login.microsoftonline.com/error?code=7000215"}' }
    }
    $r = Invoke-Captured { Connect-StoreApi -TenantId 't' -ClientId 'c' -ClientSecret $Secret -AuthorityHost 'https://login.fake.invalid' }
    $r.Err | Should -Match 'could not get a Partner Center access token: HTTP 401'
    $r.All | Should -Not -Match $Leak
  }
  It 'masks a network error that names the URL' {
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp { throw "No connection could be made (https://login.fake.invalid/t/oauth2/v2.0/token?x=dummy-client-secret-Zx9)" }
    $r = Invoke-Captured { Connect-StoreApi -TenantId 't' -ClientId 'c' -ClientSecret $Secret }
    $r.Err | Should -Match 'could not get a Partner Center access token'
    $r.All | Should -Not -Match $Leak
  }
  It 'refuses an empty secret without calling out' {
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp { throw 'called' }
    { Connect-StoreApi -TenantId 't' -ClientId 'c' -ClientSecret '' } | Should -Throw '*empty*'
    Should -Invoke -ModuleName MsStoreRunner Invoke-StoreHttp -Times 0 -Exactly
  }
  It 'asks for a client-credentials token for the Store API scope' {
    $s = New-FakeStore; Use-FakeStore $s
    $s.TokenRequest | Should -Match '(^|&)grant_type=client_credentials(&|$)'
    $s.TokenRequest | Should -Match 'scope=https%3A%2F%2Fmanage\.devcenter\.microsoft\.com%2F\.default'
  }
}

Describe 'Publish-StoreSubmission (fake Store)' {
  BeforeEach { $script:Pkg = New-TestPackage }
  AfterEach { Remove-Item -LiteralPath (Split-Path $Pkg) -Recurse -Force }

  It 'creates, updates, uploads, checks and commits by the id from the create response' {
    $s = New-FakeStore; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -BeNullOrEmpty
    $r.Value | Should -Be @($NewId)
    @($s.Log) | Should -Be @(
      "GET $Base"
      "POST $Base/submissions"
      "GET $Base"
      "GET $Base/submissions/$NewId"
      "PUT $Base/submissions/$NewId"
      'PUT /blob/upload.zip'
      "GET $Base/submissions/$NewId"
      "POST $Base/submissions/$NewId/commit")
    $s.Sub.status | Should -Be 'Certification'
    $r.Out | Should -Match "created submission id=$NewId \(from the create response\)"
    $r.Out | Should -Match 'package uploaded: Jerislink-0\.4\.1\.0-x64\.msixupload in Upload\.zip \(\d+ bytes\), HTTP 201'
    $r.All | Should -Not -Match $Leak
  }

  It 'uploads a block-blob zip holding only the package, at the zip root, with + escaped in the SAS URL' {
    $s = New-FakeStore; Use-FakeStore $s
    (Invoke-Publish $Pkg).Err | Should -BeNullOrEmpty
    $s.BlobHeaders['x-ms-blob-type'] | Should -BeExactly 'BlockBlob'
    $s.BlobHeaders['Content-Type'] | Should -BeExactly 'application/zip'
    $s.BlobQuery | Should -Match 'sig=FAKE%2BSAS'
    $z = @(Get-FakeUploadedZip $s)
    $z.Count | Should -Be 1
    $z[0].Name | Should -BeExactly $File
    [Convert]::ToBase64String($z[0].Bytes) | Should -BeExactly ([Convert]::ToBase64String([IO.File]::ReadAllBytes($Pkg)))
  }

  It 'marks every old package PendingDelete in the PUT, so only the new one is left after commit' {
    $s = New-FakeStore; Use-FakeStore $s
    (Invoke-Publish $Pkg).Err | Should -BeNullOrEmpty
    @($s.Sub.applicationPackages).Count | Should -Be 1
    $s.Sub.applicationPackages[0].fileName | Should -BeExactly $File
    $s.Sub.applicationPackages[0].version | Should -Be '0.4.1.0'
  }

  It 'stops before create, and deletes nothing, when a submission is already pending' {
    $s = New-FakeStore -PendingId '1152921505000000007'; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match 'already has a pending submission 1152921505000000007'
    $r.Err | Should -Match "DELETE /v1\.0/my/applications/$App/submissions/1152921505000000007 "
    $r.Err | Should -Match "Remove-StoreDraftSubmission -ProductId $App -SubmissionId 1152921505000000007"
    @($s.Log) | Should -Be @("GET $Base")
  }

  It 'stops, and deletes nothing, when create is refused because a submission appeared after the check' {
    $s = New-FakeStore -PendingId '1152921505000000007' -HidePending; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match "POST $([regex]::Escape($Base))/submissions failed: HTTP 409"
    $r.Err | Should -Match 'No submission was created and none was deleted'
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions")
  }

  It 'treats a missing pendingApplicationSubmission field as nothing pending' {
    $s = New-FakeStore -NoPendingAs Omit; Use-FakeStore $s
    (Invoke-Publish $Pkg).Value | Should -Be @($NewId)
  }

  It 'stops before any change when the create response has no id' {
    $s = New-FakeStore -CreateWithoutId; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match 'the create response has no submission id'
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions")
  }

  It 'stops uncommitted when the app shows another pending submission after create' {
    $s = New-FakeStore -PendingAfterCreate '1152921505000000008'; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match "after create, the app's pending submission is '1152921505000000008', not $NewId"
    $r.Err | Should -Match "Not committed: draft $NewId stays uncommitted"
    $r.Err | Should -Match "DELETE /v1\.0/my/applications/$App/submissions/$NewId "
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
  }

  It 'stops uncommitted, before the PUT, when pricing is <Case>' -ForEach @(
    @{ Case = 'Base'; Opt = @{ PriceId = 'Base' }; Want = "'Base'" }, @{ Case = 'empty'; Opt = @{ PriceId = '' }; Want = 'empty' }, @{ Case = 'missing'; Opt = @{ NoPricing = $true }; Want = 'no pricing' }
  ) {
    $s = New-FakeStore @Opt; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match "price check failed: .*$Want"
    $r.Err | Should -Match "DELETE /v1\.0/my/applications/$App/submissions/$NewId "
    @($s.Log) | Should -Not -Contain "PUT $Base/submissions/$NewId"
    @($s.Log) | Should -Not -Contain "POST $Base/submissions/$NewId/commit"
  }

  It 'does not commit when an old package would remain after the PUT' {
    $s = New-FakeStore -KeepOldPackage; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match 'draft check failed: 2 package\(s\) would remain'
    $r.Err | Should -Match "DELETE /v1\.0/my/applications/$App/submissions/$NewId "
    @($s.Log) | Should -Not -Contain "POST $Base/submissions/$NewId/commit"
    $s.Sub.status | Should -Be 'PendingCommit'
  }

  It 'masks the SAS URL when the upload fails with an error body' {
    $s = New-FakeStore -UploadStatus 403 -UploadBody '<?xml version="1.0"?><Error><Code>AuthenticationFailed</Code><Message>Signature did not match. https://fake-store.invalid/blob/upload.zip?sv=2020-08-04&sig=FAKE+SAS%2FSIGNATURE-0123456789</Message></Error>'
    Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match 'package upload failed: HTTP 403 .*AuthenticationFailed'
    $r.All | Should -Not -Match $Leak
    @($s.Log) | Should -Not -Contain "POST $Base/submissions/$NewId/commit"
  }

  It 'masks the SAS URL when the upload throws an error that names it' {
    $s = New-FakeStore; Use-FakeStore $s
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp -ParameterFilter { $Uri -like '*/blob/*' } {
      throw "The SSL connection could not be established, see inner exception. ($Uri)"
    }
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match 'package upload failed: The SSL connection could not be established'
    $r.All | Should -Not -Match $Leak
    @($s.Log) | Should -Not -Contain "POST $Base/submissions/$NewId/commit"
  }

  It 'prints one fixed line for a successful upload and nothing from the URL' {
    $s = New-FakeStore; Use-FakeStore $s
    $r = Invoke-Captured { Send-StorePackage -UploadUrl "https://fake-store.invalid/blob/upload.zip?sv=1&sig=FAKE+SAS%2FSIGNATURE-0123456789" -PackagePath $Pkg }
    $r.Err | Should -BeNullOrEmpty
    $r.Out | Should -Match "^package uploaded: $([regex]::Escape($File)) in Upload\.zip \(\d+ bytes\), HTTP 201$"
  }
}

Describe 'Invoke-SubmissionCommit and Remove-StoreDraftSubmission' {
  It 'commits exactly the given submission id' {
    $s = New-FakeStore; Use-FakeStore $s
    $s.Sub = @{ id = $SubId; status = 'PendingCommit'; applicationPackages = @() }
    $r = Invoke-Captured { Invoke-SubmissionCommit -ProductId $App -SubmissionId $SubId }
    $r.Err | Should -BeNullOrEmpty
    @($s.Log) | Should -Be @("POST $Base/submissions/$SubId/commit")
    $r.Out | Should -Match "submission $SubId commit requested through the API: status=CommitStarted"
  }
  It 'fails when the commit is refused' {
    $s = New-FakeStore; Use-FakeStore $s
    $s.Sub = @{ id = $SubId; status = 'Certification'; applicationPackages = @() }
    { Invoke-SubmissionCommit -ProductId $App -SubmissionId $SubId 6>$null } | Should -Throw '*HTTP 409*'
  }
  It 'refuses a submission id that is not a number' {
    { Invoke-SubmissionCommit -ProductId $App -SubmissionId '1/../2' } | Should -Throw '*not a number*'
  }
  It 'deletes the given draft by id when it is PendingCommit' {
    $s = New-FakeStore; Use-FakeStore $s
    $s.Sub = @{ id = $SubId; status = 'PendingCommit'; applicationPackages = @() }
    Remove-StoreDraftSubmission -ProductId $App -SubmissionId $SubId 6>$null
    @($s.Log) | Should -Be @("GET $Base/submissions/$SubId", "DELETE $Base/submissions/$SubId")
  }
  It 'does not delete a submission that is no longer a draft' {
    $s = New-FakeStore; Use-FakeStore $s
    $s.Sub = @{ id = $SubId; status = 'Certification'; applicationPackages = @() }
    { Remove-StoreDraftSubmission -ProductId $App -SubmissionId $SubId 6>$null } | Should -Throw "*'Certification', not an uncommitted PendingCommit draft*"
    @($s.Log) | Should -Not -Contain "DELETE $Base/submissions/$SubId"
  }
}

Describe 'Set-SubmissionPackage and Test-SubmissionPricing' {
  It 'marks every old package PendingDelete, drops one still PendingUpload, adds the new file, and keeps other fields byte for byte' {
    $in = '{"id":"1","targetPublishDate":"1601-01-01T00:00:00Z","x":1.50,"pricing":{"priceId":"Free"},"applicationPackages":[' +
          '{"fileName":"a.msixupload","fileStatus":"Uploaded","version":"1.0.0.0"},{"fileName":"b.msix","fileStatus":"Uploaded"},' +
          '{"fileName":"c.msixupload","fileStatus":"PendingUpload"},{"fileName":"d.appx","fileStatus":"PendingDelete"}]}'
    $out = Set-SubmissionPackage -SubmissionJson $in -FileName $File
    $out | Should -BeExactly ('{"id":"1","targetPublishDate":"1601-01-01T00:00:00Z","x":1.50,"pricing":{"priceId":"Free"},"applicationPackages":[' +
          '{"fileName":"a.msixupload","fileStatus":"PendingDelete","version":"1.0.0.0"},{"fileName":"b.msix","fileStatus":"PendingDelete"},' +
          '{"fileName":"d.appx","fileStatus":"PendingDelete"},{"fileName":"' + $File + '","fileStatus":"PendingUpload"}]}')
  }
  It 'passes a priced submission and fails <Case>' -ForEach @(
    @{ Case = 'no pricing'; Json = '{"id":"1"}' }, @{ Case = 'null pricing'; Json = '{"pricing":null}' },
    @{ Case = 'empty priceId'; Json = '{"pricing":{"priceId":""}}' }, @{ Case = 'Base'; Json = '{"pricing":{"priceId":"Base"}}' },
    @{ Case = 'base (any case)'; Json = '{"pricing":{"priceId":"base"}}' }
  ) {
    (Test-SubmissionPricing -SubmissionJson '{"pricing":{"priceId":"Free"}}').Result | Should -Be 'Pass'
    (Test-SubmissionPricing -SubmissionJson $Json).Result | Should -Be 'Fail'
  }
}

Describe 'Assert-SubmissionHasPackage (fake Store)' {
  It 'reads the submission back by its id and passes' {
    $s = New-FakeStore; Use-FakeStore $s
    $s.Sub = @{ id = $SubId; status = 'Certification'; applicationPackages = @(@{ fileName = $File; fileStatus = 'Uploaded'; version = '0.4.1.0' }) }
    $r = Invoke-Captured { Assert-SubmissionHasPackage -ProductId $App -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -TimeoutMinutes 0 -IntervalSeconds 0 }
    $r.Err | Should -BeNullOrEmpty
    $r.Out | Should -Match "verified submission ${SubId}: submission holds exactly one Uploaded package, version 0\.4\.1\.0"
    $r.Out | Should -Not -Match 'Store publish mode'
    @($s.Log) | Should -Be @("GET $Base/submissions/$SubId")
    $r.All | Should -Not -Match $Leak
  }
  It 'warns when targetPublishMode is not Manual' {
    $s = New-FakeStore -TargetPublishMode Immediate; Use-FakeStore $s
    $s.Sub = @{ id = $SubId; status = 'Published'; applicationPackages = @(@{ fileName = $File; fileStatus = 'Uploaded'; version = '0.4.1.0' }) }
    (Invoke-Captured { Assert-SubmissionHasPackage -ProductId $App -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -TimeoutMinutes 0 -IntervalSeconds 0 }).Out |
      Should -Match "::warning title=Store publish mode::targetPublishMode is 'Immediate'"
  }
  It 'fails on a submission that was never committed (PendingCommit)' {
    $s = New-FakeStore; Use-FakeStore $s
    $s.Sub = @{ id = $SubId; status = 'PendingCommit'; applicationPackages = @(@{ fileName = $File; fileStatus = 'PendingUpload' }) }
    (Invoke-Captured { Assert-SubmissionHasPackage -ProductId $App -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -TimeoutMinutes 0 -IntervalSeconds 0 }).Err |
      Should -Match "status is 'PendingCommit', not a committed status"
  }
  It 'throws "not verified" while the version never gets filled in' {
    $s = New-FakeStore; Use-FakeStore $s
    $s.Sub = @{ id = $SubId; status = 'PreProcessing'; applicationPackages = @(@{ fileName = $File; fileStatus = 'Uploaded' }) }
    (Invoke-Captured { Assert-SubmissionHasPackage -ProductId $App -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -TimeoutMinutes 0 -IntervalSeconds 0 }).Err |
      Should -Match 'not verified after 0 min: package version not filled in yet'
  }
  It 'counts a failed GET as pending, and never prints the URL from it' {
    $s = New-FakeStore; Use-FakeStore $s
    (Invoke-Captured { Assert-SubmissionHasPackage -ProductId $App -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -TimeoutMinutes 0 -IntervalSeconds 0 }).Err |
      Should -Match "not verified after 0 min: Store API GET /v1\.0/my/applications/$App/submissions/$SubId failed: HTTP 404"
  }
  It 'fails when the GET returns another submission' {
    $s = New-FakeStore; Use-FakeStore $s
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp { [pscustomobject]@{ StatusCode = 200; Body = (Get-Content -Raw (Join-Path $PSScriptRoot 'fixtures/submission-new-package-only.json')) } }
    (Invoke-Captured { Assert-SubmissionHasPackage -ProductId $App -SubmissionId '1152921505000000003' -ExpectedVersion '0.4.1.0' -TimeoutMinutes 0 -IntervalSeconds 0 }).Err |
      Should -Match 'not submission 1152921505000000003 that this run created'
  }
}
