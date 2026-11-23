# Pester 5 tests for MsStoreRunner.psm1: the checks on submission JSON, and the
# Store submission API flow against FakeStoreApi.psm1 (an in-memory stand-in;
# Invoke-StoreHttp, the module's only network call, is mocked to reach it),
# and, in the last block, the real HTTP path against the same stand-in served
# on 127.0.0.1 (redirects, verbose and debug output).
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
  # Never in any output: the fake SAS signature, the blob URL, the client secret, the token.
  $script:Leak = 'FAKE\+SAS|FAKE%2BSAS|SIGNATURE-0123456789|jlfakeupload|/blob/|dummy-client-secret|fake-access-token'
  # Lines that must never be printed from API strings (workflow commands, line breaks).
  $script:Injected = '::error::|::warning::|::set-output|::add-mask|pwned'
  # Digits of other scripts (Arabic-Indic, Extended Arabic-Indic, Devanagari,
  # fullwidth): .NET \d matches them and [int] cannot convert them. None may
  # be printed.
  $script:OtherDigits = '[\u0660-\u0669\u06F0-\u06F9\u0966-\u096F\uFF10-\uFF19]'
  # A Store API error body (code ServiceError) with this target, at the top
  # level or (Nested) in an error object.
  function script:New-TargetBody($Target, [switch]$Nested) {
    $e = @{ code = 'ServiceError'; target = $Target; message = 'Internal error.' }
    if ($Nested) { @{ error = $e } | ConvertTo-Json -Compress } else { $e | ConvertTo-Json -Compress }
  }

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

  # Routes the module's HTTP calls to $global:FakeStore. Signs in with the
  # production hosts (the mock sends nothing). A request the fake answers with
  # status 0 throws what HttpClient throws when no answer comes back. Each call
  # is logged in $Store.Calls with its timeout (and printed as "[http] ..."
  # when $global:FakeTrace is set). A call that takes longer than its timeout
  # (CallSeconds, UploadSeconds; a hung one, status -1, never ends) throws what
  # the real Invoke-StoreHttp throws when its time limit is reached; with
  # $global:FakeClock set, the call moves that clock on by the time it took.
  # An answer the fake drips (DripOn Token, Create, Commit or Upload) comes
  # back with its status and its body lost, with the BodyLost text the real
  # Invoke-StoreHttp returns (time limit reached, or with DripEnd Break the
  # connection broke).
  function script:Use-FakeStore([hashtable]$Store) {
    $global:FakeStore = $Store
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp {
      $h = @{}
      if ($Headers) { foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] } }
      if ($ContentType) { $h['Content-Type'] = $ContentType }
      # A mock does not get the default of a parameter the caller left out.
      $wait = if ($TimeoutSec) { $TimeoutSec } else { 600 }
      $line = "$Method $(if ($Kind -eq 'Upload') { '(upload)' } else { ([uri]$Uri).AbsolutePath }) timeout=$wait"
      [void]$global:FakeStore.Calls.Add($line)
      if ($global:FakeTrace) { Write-Host "[http] $line" }
      $bytes = if ($InFile) { [IO.File]::ReadAllBytes($InFile) } elseif ($Body) { [Text.Encoding]::UTF8.GetBytes($Body) } else { [byte[]]@() }
      $r = Invoke-FakeStoreRequest -Store $global:FakeStore -Method $Method -Uri $Uri -Headers $h -BodyBytes $bytes
      $took = if ($r.StatusCode -eq -1) { [int]::MaxValue } elseif ($Kind -eq 'Upload') { $global:FakeStore.UploadSeconds } else { $global:FakeStore.CallSeconds }
      if ($took -gt $wait) {
        if ($null -ne $global:FakeClock) { $global:FakeClock = $global:FakeClock.AddSeconds($wait) }
        throw (& (Get-Module MsStoreRunner) { param($s) New-StoreError "no response (time limit of $s s for the whole request reached)" -OutcomeUnknown } $wait)
      }
      if ($null -ne $global:FakeClock) { $global:FakeClock = $global:FakeClock.AddSeconds($took) }
      if ($r.StatusCode -eq 0) {
        $sock = [System.Net.Sockets.SocketException]::new([int][System.Net.Sockets.SocketError]::ConnectionReset)
        $io = [System.IO.IOException]::new("Unable to read data from the transport connection ($Uri)", $sock)
        throw [System.Net.Http.HttpRequestException]::new("An error occurred while sending the request to $Uri", $io)
      }
      if ($r.DripSeconds -gt 0) {
        $lost = & (Get-Module MsStoreRunner) { param($w, $brk) if ($brk) { $script:BodyLostText.Broken } else { $script:BodyLostText.TimeLimit -f $w } } $wait ($global:FakeStore.DripEnd -eq 'Break')
        return [pscustomobject]@{ StatusCode = $r.StatusCode; Body = ''; BodyLost = $lost }
      }
      [pscustomobject]@{ StatusCode = $r.StatusCode; Body = $r.Body }
    }
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret 6>$null
    $Store.Log.Clear(); $Store.Calls.Clear()
  }

  function script:New-TestPackage {
    $dir = Join-Path ([IO.Path]::GetTempPath()) ('pkg-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $dir | Out-Null
    $p = Join-Path $dir $File
    [IO.File]::WriteAllBytes($p, [byte[]](0..255 + 0..255))
    $p
  }

  function script:Invoke-Publish([string]$Package) {
    Invoke-Captured { Publish-StoreSubmission -ProductId $App -PackagePath $Package -ExpectedFileName $File -ExpectedVersion '0.4.1.0' -CommitReadBackAttempts 3 -CommitReadBackIntervalSeconds 0 }
  }

  $script:Base = "/v1.0/my/applications/$App"
  $script:NewId = '1152921505000000099'
  # Advice that must not be given while a result is unconfirmed: delete by id
  # (Get-DeleteByIdText), or retry (re-run, commit again). "do not re-run" is
  # not advice to re-run.
  $script:DeleteAdvice = 'DELETE /v1|Remove-StoreDraftSubmission|Delete exactly'
  $script:RetryAdvice = '(?<!do not )re-run this workflow|\bretry\b|commit (it )?again'
  # A Store API error body whose message carries every kind of secret and
  # text the output must never show (a SAS URL, scheme-less query strings,
  # sig=, a bearer token, the current access token, the client secret in
  # quotes, a JWT, a long opaque key, delete and retry advice, both workflow
  # command syntaxes mid-line and after a line break), and the one line
  # Get-StoreErrorText -Detail makes of it: the code, the listed target and
  # the module's own hint. Nothing of the message is printed.
  function script:New-PlantedErrorBody([string]$Token, [string]$Target = 'applicationCategory') {
    $msg = "Bad.`n::error::injected see ##[error]injected https://jlfakeupload.blob.core.windows.net/blob/upload.zip?sv=2020-08-04&sig=FAKE+SAS%2FSIGNATURE-0123456789 " +
      "acct.blob.core.windows.net/c/x.zip?sv=2020-08-04&sp=w c/y.zip?skoid=Zq9 sv=2020-08-04&sr=b sig=FAKE+SAS%2FSIGNATURE-0123456789 Bearer abc.def-ghi " +
      "token $Token client_secret=`"$Secret`" eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl AbCdEfGh0123456789AbCdEfGh0123456789xyz " +
      "0f8fad5b-d9cb-469f-a165-70867728950e $File. Delete submission 1152921505000000007 and retry.`n##[set-output name=x;]injected"
    @{ code = 'InvalidParameterValue'; target = $Target; message = $msg; source = 'Ingestion Api' } | ConvertTo-Json -Compress
  }
  $script:PlantedText = 'HTTP 400 (InvalidParameterValue); target: applicationCategory; hint: a parameter in the request body is invalid'
  # Words of the planted message (and its source); none may be printed.
  $script:PlantedWords = 'Bad\.|injected|Ingestion|acct\.blob|skoid|Bearer|client_secret|0f8fad5b|Delete submission|retry|set-output'
  # Index of the first line from From on that matches Pattern, or -1.
  function script:Get-LineIndex([string[]]$Lines, [string]$Pattern, [int]$From = 0) {
    for ($i = $From; $i -lt $Lines.Count; $i++) { if ($Lines[$i] -match $Pattern) { return $i } }
    -1
  }
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
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp {
      [pscustomobject]@{ StatusCode = 401; Body = '{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret dummy-client-secret-Zx9 provided. https://login.microsoftonline.com/error?code=7000215","error_codes":[7000215]}' }
    }
    $r = Invoke-Captured { Connect-StoreApi -TenantId 't' -ClientId 'c' -ClientSecret $Secret }
    $r.Err | Should -BeExactly 'could not get a Partner Center access token: HTTP 401 (invalid_client, AADSTS7000215)'
    $r.All | Should -Not -Match $Leak
  }
  It 'prints only exception type names for a network error that names the URL' {
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp { throw "No connection could be made (https://login.microsoftonline.com/t/oauth2/v2.0/token?x=dummy-client-secret-Zx9)" }
    $r = Invoke-Captured { Connect-StoreApi -TenantId 't' -ClientId 'c' -ClientSecret $Secret }
    $r.Err | Should -BeExactly 'could not get a Partner Center access token: no response (RuntimeException)'
    $r.All | Should -Not -Match $Leak
  }
  It 'refuses an empty secret without calling out' {
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp { throw 'called' }
    { Connect-StoreApi -TenantId 't' -ClientId 'c' -ClientSecret '' } | Should -Throw '*empty*'
    Should -Invoke -ModuleName MsStoreRunner Invoke-StoreHttp -Times 0 -Exactly
  }
  It 'refuses <Case> before the client secret is sent' -ForEach @(
    @{ Case = 'another sign-in host'; Opt = @{ AuthorityHost = 'https://login.fake.invalid' } }
    @{ Case = 'plain-HTTP sign-in'; Opt = @{ AuthorityHost = 'http://login.microsoftonline.com' } }
    @{ Case = 'another sign-in port'; Opt = @{ AuthorityHost = 'https://login.microsoftonline.com:8443' } }
    @{ Case = 'another API host'; Opt = @{ ApiBase = 'https://evil.invalid' } }
    @{ Case = 'a look-alike API host'; Opt = @{ ApiBase = 'https://manage.devcenter.microsoft.com.evil.invalid' } }
    @{ Case = 'a loopback stand-in without -LoopbackTestServer'; Opt = @{ AuthorityHost = 'http://127.0.0.1:9'; ApiBase = 'http://127.0.0.1:9' } }
  ) {
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp { throw 'called' }
    $r = Invoke-Captured { Connect-StoreApi -TenantId 't' -ClientId 'c' -ClientSecret $Secret @Opt }
    $r.Err | Should -Match '^refused: sign-in goes only to https://login\.microsoftonline\.com and API calls only to https://manage\.devcenter\.microsoft\.com .*the client secret was not sent$'
    Should -Invoke -ModuleName MsStoreRunner Invoke-StoreHttp -Times 0 -Exactly
  }
  It 'asks for a client-credentials token for the Store API scope' {
    $s = New-FakeStore; Use-FakeStore $s
    $s.TokenRequest | Should -Match '(^|&)grant_type=client_credentials(&|$)'
    $s.TokenRequest | Should -Match 'scope=https%3A%2F%2Fmanage\.devcenter\.microsoft\.com%2F\.default'
  }
}

Describe 'Test-StoreUri and Invoke-StoreHttp (where requests may go)' {
  BeforeEach { InModuleScope MsStoreRunner { $script:LoopbackTestServer = $false } }
  AfterAll { InModuleScope MsStoreRunner { $script:LoopbackTestServer = $false } }

  It 'allows <Kind> <Uri>' -ForEach @(
    @{ Kind = 'Token'; Uri = 'https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token' }
    @{ Kind = 'Api'; Uri = 'https://manage.devcenter.microsoft.com/v1.0/my/applications/9NM3VWQ9MD7N' }
    @{ Kind = 'Api'; Uri = 'https://manage.devcenter.microsoft.com/v1.0/my/applications/9NM3VWQ9MD7N/submissions?isMinimalResponse=true' }
    @{ Kind = 'Upload'; Uri = 'https://productingestionbin1.blob.core.windows.net/ingestion/x?sv=1&sig=a' }
    @{ Kind = 'Upload'; Uri = 'HTTPS://PRODUCTINGESTIONBIN1.BLOB.CORE.WINDOWS.NET/ingestion/x' }
  ) {
    Test-StoreUri -Uri $Uri -Kind $Kind | Should -BeTrue
  }
  It 'refuses <Kind> <Uri>' -ForEach @(
    @{ Kind = 'Upload'; Uri = 'http://productingestionbin1.blob.core.windows.net/ingestion/x' }
    @{ Kind = 'Upload'; Uri = 'https://evil.invalid/ingestion/x' }
    @{ Kind = 'Upload'; Uri = 'https://acct.blob.core.windows.net.evil.invalid/x' }
    @{ Kind = 'Upload'; Uri = 'https://evil.invalid/acct.blob.core.windows.net' }
    @{ Kind = 'Upload'; Uri = 'https://a.b.blob.core.windows.net/x' }
    @{ Kind = 'Upload'; Uri = 'https://acct.blob.core.windows.net:8443/x' }
    @{ Kind = 'Upload'; Uri = 'https://user:pw@acct.blob.core.windows.net/x' }
    @{ Kind = 'Upload'; Uri = 'http://127.0.0.1:8080/blob/upload.zip' }
    @{ Kind = 'Upload'; Uri = 'https://manage.devcenter.microsoft.com/x' }
    @{ Kind = 'Api'; Uri = 'https://acct.blob.core.windows.net/x' }
    @{ Kind = 'Api'; Uri = 'http://manage.devcenter.microsoft.com/v1.0/my/' }
    @{ Kind = 'Token'; Uri = 'https://manage.devcenter.microsoft.com/t/oauth2/v2.0/token' }
    @{ Kind = 'Api'; Uri = 'file:///etc/passwd' }
    @{ Kind = 'Api'; Uri = 'not a url' }
    @{ Kind = 'Api'; Uri = '' }
  ) {
    Test-StoreUri -Uri $Uri -Kind $Kind | Should -BeFalse
  }
  It 'allows loopback only after Connect-StoreApi -LoopbackTestServer, and nothing else extra' {
    InModuleScope MsStoreRunner { $script:LoopbackTestServer = $true }
    Test-StoreUri -Uri 'http://127.0.0.1:1234/blob/upload.zip' -Kind Upload | Should -BeTrue
    Test-StoreUri -Uri 'http://localhost:1234/v1.0/my/' -Kind Api | Should -BeTrue
    Test-StoreUri -Uri 'https://evil.invalid/x' -Kind Upload | Should -BeFalse
    Test-StoreUri -Uri 'http://10.0.0.1/x' -Kind Api | Should -BeFalse
  }
  It 'refuses, before sending anything, a request to a URL that is not allowed for its kind' -ForEach @(
    @{ Kind = 'Api'; Uri = 'http://127.0.0.1:9/v1.0/my/applications' }
    @{ Kind = 'Upload'; Uri = 'https://evil.invalid/blob/upload.zip?sig=FAKE+SAS' }
    @{ Kind = 'Token'; Uri = 'https://manage.devcenter.microsoft.com/t/oauth2/v2.0/token' }
  ) {
    $r = Invoke-Captured { Invoke-StoreHttp -Method GET -Uri $Uri -Kind $Kind }
    $r.Err | Should -Match "^refused: $Kind requests go only to https://.*; nothing was sent$"
    $r.All | Should -Not -Match $Leak
  }
}

Describe 'Get-StoreErrorText (fixed diagnostics for HTTP errors)' {
  It 'returns <Want> for <Case>' -ForEach @(
    @{ Case = 'a blob storage XML error'; Code = 403; Want = 'HTTP 403 (AuthenticationFailed)'
       Body = '<?xml version="1.0"?><Error><Code>AuthenticationFailed</Code><Message>Signature did not match. https://jlfakeupload.blob.core.windows.net/blob/upload.zip?sig=FAKE+SAS%2FSIGNATURE-0123456789</Message></Error>' }
    @{ Case = 'a Store API error'; Code = 400; Want = 'HTTP 400 (InvalidParameterValue)'
       Body = '{"code":"InvalidParameterValue","message":"bad value at https://evil.invalid/?sig=FAKE+SAS","target":"applicationPackages"}' }
    @{ Case = 'a nested error object'; Code = 400; Want = 'HTTP 400 (BadRequest)'; Body = '{"error":{"code":"BadRequest","message":"see https://evil.invalid"}}' }
    @{ Case = 'a token endpoint error'; Code = 401; Want = 'HTTP 401 (invalid_client, AADSTS7000215)'
       Body = '{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret dummy-client-secret-Zx9","error_codes":[7000215]}' }
    @{ Case = 'a code with a line break and a workflow command'; Code = 500; Want = 'HTTP 500'; Body = "{`"code`":`"Bad`n::error::pwned`"}" }
    @{ Case = 'a code that is a URL'; Code = 400; Want = 'HTTP 400'; Body = '{"code":"https://evil.invalid/x?sig=FAKE+SAS"}' }
    @{ Case = 'an HTML page'; Code = 502; Want = 'HTTP 502'; Body = '<html><body>Bad gateway https://evil.invalid ::error::pwned</body></html>' }
    @{ Case = 'an empty body'; Code = 404; Want = 'HTTP 404'; Body = '' }
  ) {
    $t = Get-StoreErrorText -StatusCode $Code -Body $Body
    $t | Should -BeExactly $Want
  }
}

# The create in run 45185550541 got HTTP 400 (InvalidParameterValue) and the
# log showed nothing else. Store API errors now add the target when it is a
# documented submission field name, and a hint written in the module for the
# code or the status (Get-StoreErrorText -Detail). The API's message is never
# printed: masking it could be bypassed (Pepper, PR #74 r1). The token
# endpoint and the blob upload keep the fixed text above.
# PR #74 r5: the body of an answer is decoded from its bytes, so a charset
# .NET does not know no longer loses a body that came in (HttpContent's
# ReadAsStringAsync throws for it; Invoke-WebRequest read it as UTF-8).
Describe 'ConvertFrom-StoreBodyBytes (an answer body never lost to its charset)' {
  It 'decodes <Case>' -ForEach @(
    @{ Case = 'UTF-8 without a charset'; Bytes = [byte[]](0x7B,0x22,0x61,0x22,0x3A,0x22,0xC3,0xA9,0x22,0x7D); CharSet = ''; Want = "{`"a`":`"$([char]0xE9)`"}" }
    @{ Case = 'UTF-8 with charset utf-8'; Bytes = [byte[]](0x7B,0x22,0x61,0x22,0x3A,0x22,0xC3,0xA9,0x22,0x7D); CharSet = 'utf-8'; Want = "{`"a`":`"$([char]0xE9)`"}" }
    @{ Case = 'UTF-8 with a quoted charset'; Bytes = [byte[]](0x7B,0x22,0x61,0x22,0x3A,0x22,0xC3,0xA9,0x22,0x7D); CharSet = '"utf-8"'; Want = "{`"a`":`"$([char]0xE9)`"}" }
    @{ Case = 'ISO-8859-1 by its charset'; Bytes = [byte[]](0x7B,0x22,0x61,0x22,0x3A,0x22,0xE9,0x22,0x7D); CharSet = 'iso-8859-1'; Want = "{`"a`":`"$([char]0xE9)`"}" }
    @{ Case = 'an unknown charset as UTF-8'; Bytes = [byte[]](0x7B,0x22,0x61,0x22,0x3A,0x22,0xC3,0xA9,0x22,0x7D); CharSet = 'x-bogus-zz'; Want = "{`"a`":`"$([char]0xE9)`"}" }
    @{ Case = 'a UTF-8 byte order mark (dropped)'; Bytes = [byte[]](0xEF,0xBB,0xBF,0x7B,0x7D); CharSet = ''; Want = '{}' }
    @{ Case = 'UTF-16 by its byte order mark'; Bytes = [byte[]](0xFF,0xFE,0x7B,0x00,0x7D,0x00); CharSet = ''; Want = '{}' }
    @{ Case = 'invalid UTF-8 as U+FFFD'; Bytes = [byte[]](0x7B,0xC3,0x7D); CharSet = 'utf-8'; Want = "{$([char]0xFFFD)}" }
    @{ Case = 'no bytes'; Bytes = [byte[]]@(); CharSet = 'utf-8'; Want = '' }
  ) {
    # Not exported: called inside the module.
    InModuleScope MsStoreRunner -Parameters @{ B = $Bytes; C = $CharSet } { param($B, $C) ConvertFrom-StoreBodyBytes $B $C } | Should -BeExactly $Want
  }
}

Describe 'Get-StoreErrorText -Detail (listed target and local hint, never the API message)' {
  It 'prints the code, the listed target and the hint, and nothing of a message full of planted secrets, advice and commands' {
    $s = New-FakeStore; Use-FakeStore $s
    $t = Get-StoreErrorText -StatusCode 400 -Body (New-PlantedErrorBody $s.Token) -Detail
    $t | Should -BeExactly $PlantedText
    $t | Should -Not -Match "$Leak|$([regex]::Escape($s.Token))|$Injected|$PlantedWords|eyJ|AbCdEfGh|sv=2020|::|##\[|[\r\n]"
  }
  It 'prints nothing of the body without -Detail' {
    $s = New-FakeStore; Use-FakeStore $s
    Get-StoreErrorText -StatusCode 400 -Body (New-PlantedErrorBody $s.Token) | Should -BeExactly 'HTTP 400 (InvalidParameterValue)'
  }
  It 'never prints the message: <Case>' -ForEach @(
    @{ Case = 'delete advice'; Message = 'Delete submission 1152921505000000007 with DELETE /v1.0/my/applications/9NM3VWQ9MD7N/submissions/1152921505000000007, then create it again.' }
    @{ Case = 'retry advice'; Message = 'Try the request again, or re-run this workflow and commit it again.' }
    @{ Case = 'secrets inside quotes'; Message = 'client_secret="dummy-client-secret-Zx9" sig=''FAKE+SAS%2FSIGNATURE-0123456789'' "Bearer fake-access-token"' }
    @{ Case = 'free-form AAD diagnostic text'; Message = 'AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in the request is the client secret value, not the client secret ID, for a secret added to app ''client-1''. Trace ID: 0f8fad5b-d9cb-469f-a165-70867728950e Correlation ID: 7c9e6679-7425-40de-944b-e07fc1f90ae7' }
    @{ Case = 'workflow commands mid-line and after a line break'; Message = "see ::error::pwned and ##[error]pwned`n::add-mask::pwned`n##[set-output name=x]pwned" }
  ) {
    foreach ($body in @(
        (@{ code = 'InvalidParameterValue'; target = 'pricing'; message = $Message } | ConvertTo-Json -Compress),
        (@{ error = @{ code = 'InvalidParameterValue'; target = 'pricing'; message = $Message } } | ConvertTo-Json -Compress))) {
      $t = Get-StoreErrorText -StatusCode 400 -Body $body -Detail
      $t | Should -BeExactly 'HTTP 400 (InvalidParameterValue); target: pricing; hint: a parameter in the request body is invalid'
    }
  }

  # Allowlist: field names of the submission resource and the resources in it
  # (learn.microsoft.com "Manage app submissions"), spelled as the module has them.
  It 'target allowlist: prints the listed field name <Target> as <Want>' -ForEach @(
    @{ Target = 'applicationCategory'; Want = 'applicationCategory' }
    @{ Target = 'pricing'; Want = 'pricing' }
    @{ Target = 'listings'; Want = 'listings' }
    @{ Target = 'applicationPackages'; Want = 'applicationPackages' }
    @{ Target = 'allowTargetFutureDeviceFamilies'; Want = 'allowTargetFutureDeviceFamilies' }
    @{ Target = 'allowMicrosoftDecideAppAvailabilityToFutureDeviceFamilies'; Want = 'allowMicrosoftDecideAppAvailabilityToFutureDeviceFamilies' }
    @{ Target = 'APPLICATIONCATEGORY'; Want = 'applicationCategory' }
    @{ Target = 'Pricing.PriceId'; Want = 'pricing.priceId' }
    @{ Target = 'applicationPackages[0].fileName'; Want = 'applicationPackages[0].fileName' }
    @{ Target = 'applicationPackages[007].version'; Want = 'applicationPackages[7].version' }
    @{ Target = 'listings.baseListing.images[2].imageType'; Want = 'listings.baseListing.images[2].imageType' }
  ) {
    Get-ListedTarget $Target | Should -BeExactly $Want
    $body = @{ code = 'InvalidParameterValue'; target = $Target } | ConvertTo-Json -Compress
    Get-StoreErrorText -StatusCode 400 -Body $body -Detail | Should -BeExactly "HTTP 400 (InvalidParameterValue); target: $Want; hint: a parameter in the request body is invalid"
  }
  It 'target allowlist: prints [unlisted target] for <Case>' -ForEach @(
    @{ Case = 'a plain word that is not a submission field'; Target = 'submission' }
    @{ Case = 'a plain word that could be a value'; Target = 'Free' }
    @{ Case = 'the client secret'; Target = 'dummy-client-secret-Zx9' }
    @{ Case = 'a long opaque key'; Target = 'AbCdEfGh0123456789AbCdEfGh0123456789xyz' }
    @{ Case = 'a JWT'; Target = 'eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl' }
    @{ Case = 'a SAS URL'; Target = 'https://jlfakeupload.blob.core.windows.net/blob/upload.zip?sv=1&sig=FAKE%2BSAS' }
    @{ Case = 'delete advice'; Target = 'delete submission 1152921505000000007' }
    @{ Case = 'a listed name with a mid-line "::" command'; Target = 'applicationCategory::error::pwned' }
    @{ Case = 'a listed name with a line break and a "::" command'; Target = "applicationCategory`n::error::pwned" }
    @{ Case = 'a listed name with a mid-line "##[" command'; Target = 'applicationCategory##[error]pwned' }
    @{ Case = 'a listed name with a token appended'; Target = 'pricingeyJhbGciOi' }
    @{ Case = 'a listed name with a leading space'; Target = ' pricing' }
    @{ Case = 'a listed name with a Cyrillic look-alike letter'; Target = "applicationCategor$([char]0x0443)" }
    @{ Case = 'an empty path segment'; Target = 'pricing..priceId' }
    @{ Case = 'a trailing dot'; Target = 'pricing.' }
    @{ Case = 'an index of 5 digits'; Target = 'applicationPackages[12345]' }
    @{ Case = 'more than 8 path segments'; Target = (@('pricing') * 9) -join '.' }
  ) {
    Get-ListedTarget $Target | Should -BeExactly '[unlisted target]'
    $body = @{ code = 'InvalidParameterValue'; target = $Target } | ConvertTo-Json -Compress
    Get-StoreErrorText -StatusCode 400 -Body $body -Detail | Should -BeExactly 'HTTP 400 (InvalidParameterValue); target: [unlisted target]; hint: a parameter in the request body is invalid'
  }
  It 'target allowlist: prints [unlisted target] for a target that is not a string: <Body>' -ForEach @(
    @{ Body = '{"code":"InvalidParameterValue","target":{"name":"pricing"}}' }
    @{ Body = '{"code":"InvalidParameterValue","target":["pricing"]}' }
    @{ Body = '{"code":"InvalidParameterValue","target":42}' }
    @{ Body = '{"code":"InvalidParameterValue","target":false}' }
  ) {
    Get-StoreErrorText -StatusCode 400 -Body $Body -Detail | Should -BeExactly 'HTTP 400 (InvalidParameterValue); target: [unlisted target]; hint: a parameter in the request body is invalid'
  }
  It 'returns <Want> for <Case>' -ForEach @(
    @{ Case = 'a nested error object'; Code = 400; Want = 'HTTP 400 (BadRequest); target: pricing; hint: the request is invalid'
       Body = '{"error":{"code":"BadRequest","target":"pricing","message":"see https://evil.invalid/x?a=1 now"}}' }
    @{ Case = 'an empty target'; Code = 400; Want = 'HTTP 400 (InvalidParameterValue); hint: a parameter in the request body is invalid'
       Body = '{"code":"InvalidParameterValue","target":"","message":"bad"}' }
    @{ Case = 'a null target'; Code = 409; Want = 'HTTP 409 (InvalidState); hint: the operation is not valid for the current state of the app or submission'
       Body = '{"code":"InvalidState","target":null,"message":"The application has a pending submission."}' }
    @{ Case = 'an XML body'; Code = 403; Want = 'HTTP 403 (AuthenticationFailed); hint: the Entra app is not allowed to do this'
       Body = '<Error><Code>AuthenticationFailed</Code><Message>sig=FAKE+SAS</Message></Error>' }
    @{ Case = 'an HTML page with workflow commands'; Code = 502; Want = 'HTTP 502; hint: a gateway in front of the service reported an error'
       Body = '<html><body>Bad gateway ::error::pwned ##[error]pwned</body></html>' }
  ) {
    Get-StoreErrorText -StatusCode $Code -Body $Body -Detail | Should -BeExactly $Want
  }
  It 'picks the hint for <Case>' -ForEach @(
    @{ Case = 'code InvalidParameterValue'; Code = 400; Body = '{"code":"InvalidParameterValue"}'; Hint = 'a parameter in the request body is invalid' }
    @{ Case = 'code InvalidOperation'; Code = 400; Body = '{"code":"InvalidOperation"}'; Hint = 'the operation is not valid' }
    @{ Case = 'code InvalidState'; Code = 409; Body = '{"code":"InvalidState"}'; Hint = 'the operation is not valid for the current state of the app or submission' }
    @{ Case = 'code ResourceNotFound'; Code = 404; Body = '{"code":"ResourceNotFound"}'; Hint = 'the app or submission was not found' }
    @{ Case = 'code ServiceError'; Code = 500; Body = '{"code":"ServiceError"}'; Hint = 'the service reported an internal error' }
    @{ Case = 'code InvalidArchive'; Code = 400; Body = '{"code":"InvalidArchive"}'; Hint = 'the package ZIP archive is invalid' }
    @{ Case = 'code MissingFiles'; Code = 400; Body = '{"code":"MissingFiles"}'; Hint = 'the package ZIP archive lacks files the submission lists' }
    @{ Case = 'code PackageValidationFailed'; Code = 400; Body = '{"code":"PackageValidationFailed"}'; Hint = 'a package failed validation' }
    @{ Case = 'status 400 with a code not known here'; Code = 400; Body = '{"code":"SomethingNew"}'; Hint = 'the request is invalid' }
    @{ Case = 'status 401'; Code = 401; Body = ''; Hint = 'the access token was not accepted' }
    @{ Case = 'status 403'; Code = 403; Body = ''; Hint = 'the Entra app is not allowed to do this' }
    @{ Case = 'status 404'; Code = 404; Body = ''; Hint = 'the app or submission was not found' }
    @{ Case = 'status 408'; Code = 408; Body = ''; Hint = 'the request timed out' }
    @{ Case = 'status 409'; Code = 409; Body = ''; Hint = 'the current state of the app does not allow this, or the app uses a Partner Center feature the submission API does not support' }
    @{ Case = 'status 429'; Code = 429; Body = ''; Hint = 'too many requests' }
    @{ Case = 'status 500'; Code = 500; Body = ''; Hint = 'the service reported an internal error' }
    @{ Case = 'status 503'; Code = 503; Body = ''; Hint = 'the service reported that it is unavailable' }
    @{ Case = 'status 504'; Code = 504; Body = ''; Hint = 'a gateway in front of the service timed out' }
    @{ Case = 'an unknown code and status (fixed hint)'; Code = 418; Body = '{"code":"Teapot","message":"Delete the app and try again"}'; Hint = 'no description of this error is known here (the API''s message text is not printed)' }
    @{ Case = 'an unknown status and no body (fixed hint)'; Code = 302; Body = ''; Hint = 'no description of this error is known here (the API''s message text is not printed)' }
  ) {
    $t = Get-StoreErrorText -StatusCode $Code -Body $Body -Detail
    $t | Should -Match "^HTTP $Code(?: \([A-Za-z]+\))?; hint: $([regex]::Escape($Hint))\z"
  }
  It 'no hint written in the module advises deleting or retrying, or says whether a 408 or 5xx request was carried out' {
    $hints = InModuleScope MsStoreRunner { @($script:StoreCodeHint.Values) + @($script:StoreStatusHint.Values) + @($script:StoreUnknownHint) }
    $hints.Count | Should -Be 20
    $hints | Where-Object { $_ -match "$DeleteAdvice|$RetryAdvice|delet|again|re-?run|::|##\[" } | Should -BeNullOrEmpty
    $unknown = InModuleScope MsStoreRunner { @(408, 500, 502, 503, 504 | ForEach-Object { $script:StoreStatusHint[$_] }) + $script:StoreCodeHint['ServiceError'] }
    $unknown | Where-Object { $_ -match 'fail|stop|prevent|succe|not (been )?(carried|done|committed|created)|was (carried|done|committed|created)' } | Should -BeNullOrEmpty
  }
  It 'keeps the fixed text for a failed token request' {
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp {
      [pscustomobject]@{ StatusCode = 401; Body = '{"error":"invalid_client","target":"client","message":"Invalid client secret dummy-client-secret-Zx9 provided","error_codes":[7000215]}' }
    }
    $r = Invoke-Captured { Connect-StoreApi -TenantId 't' -ClientId 'c' -ClientSecret $Secret }
    $r.Err | Should -BeExactly 'could not get a Partner Center access token: HTTP 401 (invalid_client, AADSTS7000215)'
  }
  It 'keeps the fixed text for a failed package upload' {
    $s = New-FakeStore -UploadStatus 403 -UploadBody '{"code":"AuthenticationFailed","target":"blob","message":"denied for sig=FAKE+SAS%2FSIGNATURE-0123456789"}'
    Use-FakeStore $s
    $pkg = New-TestPackage
    try { { Send-StorePackage -UploadUrl 'https://jlfakeupload.blob.core.windows.net/blob/upload.zip?sv=1&sig=FAKE%2BSAS' -PackagePath $pkg 6>$null } | Should -Throw -ExpectedMessage 'package upload failed: HTTP 403 (AuthenticationFailed)' }
    finally { Remove-Item -LiteralPath (Split-Path $pkg) -Recurse -Force }
  }
}

# The runner reads "::name::" at the start of a line and the legacy "##[name]"
# anywhere in a line (actions/runner ActionCommand.cs). Masking only "::" left
# the legacy syntax open (Pepper, PR #74 r1).
Describe 'Protect-WorkflowCommand (both workflow command syntaxes made inert)' {
  It 'legacy-command neutralization: <Case>' -ForEach @(
    @{ Case = 'a "::" command at the start of a line'; In = '::error::pwned'; Want = ':error:pwned' }
    @{ Case = 'a "::" command mid-line'; In = 'target: x ::error::pwned'; Want = 'target: x :error:pwned' }
    @{ Case = 'a "::" command after a line break'; In = "x`n::error::pwned"; Want = 'x :error:pwned' }
    @{ Case = 'a "::" command after CR, NEL, LS or PS'; In = "a`r::error::b$([char]0x85)::warning::c$([char]0x2028)::add-mask::d$([char]0x2029)::notice::e"; Want = 'a :error:b :warning:c :add-mask:d :notice:e' }
    @{ Case = 'a legacy "##[" command mid-line'; In = 'target: x ##[error]pwned'; Want = 'target: x #[error]pwned' }
    @{ Case = 'a legacy "##[" set-output mid-line'; In = 'hint: y ##[set-output name=x;]pwned'; Want = 'hint: y #[set-output name=x;]pwned' }
    @{ Case = 'a legacy "##[" command at the start of a line'; In = '##[warning]pwned'; Want = '#[warning]pwned' }
    @{ Case = 'a legacy command with three "#"'; In = 'x ###[add-mask]pwned'; Want = 'x #[add-mask]pwned' }
    @{ Case = 'a legacy command after a line break'; In = "x`n##[warning]pwned"; Want = 'x #[warning]pwned' }
    @{ Case = 'both syntaxes mid-line in one line'; In = 'a ::error::b ##[warning]c :::d ####[e'; Want = 'a :error:b #[warning]c :d #[e' }
    @{ Case = 'a format character between the two "#"'; In = "x #$([char]0x200B)#[error]pwned"; Want = 'x # #[error]pwned' }
    @{ Case = 'a format character between the two ":"'; In = "x :$([char]0x200B):error::pwned"; Want = 'x : :error:pwned' }
    @{ Case = 'plain text (unchanged)'; In = 'HTTP 400 (InvalidParameterValue); target: applicationPackages[0].fileName; hint: x'; Want = 'HTTP 400 (InvalidParameterValue); target: applicationPackages[0].fileName; hint: x' }
    @{ Case = 'one ":" and one "#" before "[" (unchanged)'; In = 'a:b #[c] # [d] ## e'; Want = 'a:b #[c] # [d] ## e' }
  ) {
    Protect-WorkflowCommand $In | Should -BeExactly $Want
  }
  It 'legacy-command neutralization: no "::", no "##[" and no line break is left in 3000 random mixes' {
    $rng = [System.Random]::new(74)
    $parts = @(':', '#', '[', ']', 'a', ' ', '::', '##[', "`n", "`r", [string][char]0x85, [string][char]0x2028, [string][char]0x200B)
    $bad = for ($i = 0; $i -lt 3000; $i++) {
      $in = -join (1..$rng.Next(1, 25) | ForEach-Object { $parts[$rng.Next($parts.Count)] })
      if ((Protect-WorkflowCommand $in) -match '::|##\[|[\r\n\u0085  ]') { $in }
    }
    @($bad).Count | Should -Be 0
  }
  It 'legacy-command neutralization: is applied to the whole error line (a hint that carried both syntaxes prints inert)' {
    InModuleScope MsStoreRunner { $script:StoreCodeHint['TestOnlyCode'] = "x ::error::pwned ##[warning]pwned`n::add-mask::y" }
    try {
      Get-StoreErrorText -StatusCode 400 -Body '{"code":"TestOnlyCode","target":"pricing"}' -Detail |
        Should -BeExactly 'HTTP 400 (TestOnlyCode); target: pricing; hint: x :error:pwned #[warning]pwned :add-mask:y'
    } finally { InModuleScope MsStoreRunner { [void]$script:StoreCodeHint.Remove('TestOnlyCode') } }
  }
  It 'legacy-command neutralization: is applied to every value that passes Get-SafeValue (even a pattern that let both syntaxes through)' {
    InModuleScope MsStoreRunner { Get-SafeValue '1 ::error::pwned ##[warning]pwned' '^.*\z' } | Should -BeExactly '1 :error:pwned #[warning]pwned'
  }
}

Describe 'Strings from the API are printed only when they are plain values' {
  BeforeAll {
    $script:Evil = '{"Id":"1152921505000000004\n::error::pwned","Status":"Certification\r\n::warning::pwned","TargetPublishMode":"Manual\n::add-mask::x",' +
      '"ApplicationPackages":[{"FileName":"Jerislink-0.4.1.0-x64.msixupload\n::error::pwned","FileStatus":"Uploaded\n::set-output name=x::pwned","Version":"0.4.1.0\n::error::pwned"}]}'
  }
  It 'turns every field that is not a plain value into [invalid] in the check results' {
    $a = Test-SubmissionHasPackage -SubmissionJson $Evil -ExpectedVersion '0.4.1.0'
    $b = Test-DraftReadyToCommit -SubmissionJson $Evil -SubmissionId $SubId -ExpectedFileName $File -ExpectedVersion '0.4.1.0'
    foreach ($r in $a, $b) {
      $r.Result | Should -Be 'Fail'
      $r.Id | Should -BeExactly '[invalid]'
      $r.Status | Should -BeExactly '[invalid]'
      $r.TargetPublishMode | Should -BeExactly '[invalid]'
      $r.Packages[0].FileName | Should -BeExactly '[invalid]'
      $r.Packages[0].Version | Should -BeExactly '[invalid]'
      $r.Packages[0].FileStatus | Should -BeExactly '[invalid]'
      ($r | ConvertTo-Json -Depth 5) | Should -Not -Match $Injected
    }
  }
  It 'prints no injected text while checking a committed submission' {
    $s = New-FakeStore; Use-FakeStore $s
    $s.Sub = @{ id = $SubId; status = "Certification`n::error::pwned"; applicationPackages = @(@{ fileName = "$File`n::warning::pwned"; fileStatus = 'Uploaded'; version = '0.4.1.0' }) }
    $r = Invoke-Captured { Assert-SubmissionHasPackage -ProductId $App -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -TimeoutMinutes 0 -IntervalSeconds 0 }
    $r.Err | Should -Match "status is '\[invalid\]', not a committed status"
    $r.All | Should -Not -Match $Injected
    $r.Out | Should -Match 'package fileName=\[invalid\] version=0\.4\.1\.0 fileStatus=Uploaded'
  }
  It 'prints no injected commit status' {
    $s = New-FakeStore; Use-FakeStore $s
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp { [pscustomobject]@{ StatusCode = 200; Body = "{`"status`":`"CommitStarted`n::error::pwned`"}" } }
    $r = Invoke-Captured { Invoke-SubmissionCommit -ProductId $App -SubmissionId $SubId }
    $r.Out | Should -BeExactly "submission $SubId commit requested through the API: status=[invalid]"
  }
  It 'prints no injected priceId' {
    $r = Test-SubmissionPricing -SubmissionJson "{`"pricing`":{`"priceId`":`"Free`n::error::pwned`"}}"
    $r.Reason | Should -BeExactly 'pricing.priceId=[invalid] is kept as is'
  }
  It 'prints no injected pending submission id' {
    $appJson = "{`"id`":`"$App`",`"pendingApplicationSubmission`":{`"id`":`"1`n::error::pwned`"}}"
    $r = Invoke-Captured { Test-NoPendingSubmission -AppJson $appJson -ProductId $App }
    $r.Err | Should -Match 'pending submission \(no usable id\)'
    $r.All | Should -Not -Match $Injected
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
    $r.Out | Should -Match 'fields unchanged: 20 submission fields other than applicationPackages read back as before the update'
    $r.All | Should -Not -Match $Leak
  }

  # Item r3-1: the docs require these on every package object of the update.
  It 'sends minimumDirectXVersion and minimumSystemRam None on the new package entry' {
    $s = New-FakeStore; Use-FakeStore $s
    (Invoke-Publish $Pkg).Err | Should -BeNullOrEmpty
    $put = $s.LastPut | ConvertFrom-Json
    $new = @($put.applicationPackages | Where-Object { $_.fileStatus -ceq 'PendingUpload' })
    $new.Count | Should -Be 1
    $new[0].fileName | Should -BeExactly $File
    $new[0].minimumDirectXVersion | Should -BeExactly 'None'
    $new[0].minimumSystemRam | Should -BeExactly 'None'
  }

  # Item r3-2: everything but the packages must read back as it was.
  It 'stops uncommitted when the update changed <Case>' -ForEach @(
    @{ Case = 'the pricing'; Drift = 'Pricing'; Field = 'pricing' }, @{ Case = 'the listings (one dropped)'; Drift = 'DropListing'; Field = 'listings' }
  ) {
    $s = New-FakeStore -DriftOnPut $Drift; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match "submission fields changed after this run's update: $Field\. Only applicationPackages may change"
    $r.Err | Should -Match "Not committed: draft $NewId stays uncommitted"
    $r.Err | Should -Match "DELETE /v1\.0/my/applications/$App/submissions/$NewId "
    @($s.Log) | Should -Not -Contain "POST $Base/submissions/$NewId/commit"
    $s.Sub.status | Should -Be 'PendingCommit'
    $r.All | Should -Not -Match $Leak
  }

  # Item r3-3b: the upload goes only to https on a blob storage account.
  It 'does not upload, and stops uncommitted, when the upload URL is <Case>' -ForEach @(
    @{ Case = 'plain HTTP'; UploadBase = 'http://jlfakeupload.blob.core.windows.net' }
    @{ Case = 'another host'; UploadBase = 'https://evil.invalid' }
    @{ Case = 'a look-alike host'; UploadBase = 'https://jlfakeupload.blob.core.windows.net.evil.invalid' }
  ) {
    $s = New-FakeStore -UploadBase $UploadBase; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match 'package upload refused: the upload URL is not https://<account>\.blob\.core\.windows\.net; nothing was sent'
    $r.Err | Should -Match "DELETE /v1\.0/my/applications/$App/submissions/$NewId "
    @($s.Log) | Should -Not -Contain 'PUT /blob/upload.zip'
    @($s.Log) | Should -Not -Contain "POST $Base/submissions/$NewId/commit"
    $s.Blob | Should -BeNullOrEmpty
    $r.All | Should -Not -Match "$Leak|evil\.invalid"
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
    $r.Err | Should -Match "POST $([regex]::Escape($Base))/submissions\?isMinimalResponse=true failed: HTTP 409 \(InvalidState\); hint: the operation is not valid for the current state of the app or submission\. No submission was created and none was deleted"
    $r.Err | Should -Match 'Read-back of the app after the refused create \(one GET; nothing changed or deleted\): no pendingApplicationSubmission\.'
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
  }

  It 'sends the create with isMinimalResponse=true and needs only the id from its answer' {
    $s = New-FakeStore; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -BeNullOrEmpty
    $s.CreateQuery | Should -BeExactly '?isMinimalResponse=true'
    $r.Out | Should -Match "created submission id=$NewId \(from the create response\)"
    $r.Value | Should -Be @($NewId)
  }

  # Run 45185550541: the create got HTTP 400 and the log showed only the code.
  It 'create refused with HTTP 400: prints the listed target and the hint, not the message, reads the app once, deletes nothing' {
    $s = New-FakeStore -CreateErrorStatus 400; Use-FakeStore $s
    $s.CreateErrorBody = New-PlantedErrorBody $s.Token
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match ('^' + [regex]::Escape("Store API POST $Base/submissions?isMinimalResponse=true failed: $PlantedText. No submission was created and none was deleted. "))
    $r.Err | Should -Match 'Read-back of the app after the refused create \(one GET; nothing changed or deleted\): no pendingApplicationSubmission\.$'
    $r.Out | Should -Match ('(?m)^' + [regex]::Escape("create refused: Store API POST $Base/submissions?isMinimalResponse=true failed: $PlantedText. No submission was created and none was deleted.") + '$')
    $r.Err | Should -Not -Match $DeleteAdvice
    $r.All | Should -Not -Match "$Leak|$([regex]::Escape($s.Token))|$Injected|$PlantedWords|eyJ|AbCdEfGh|sv=2020|##\["
    $s.CreateQuery | Should -BeExactly '?isMinimalResponse=true'
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
    @($s.Calls)[-1] | Should -BeExactly "GET $Base timeout=30"
    $s.Sub | Should -BeNullOrEmpty
  }
  It 'create refused because another publisher made a draft after the check: the read-back logs that id only, no delete advice' {
    $other = '1152921505000000077'
    $s = New-FakeStore -OtherDraftAfterCheck $other; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match "failed: HTTP 409 \(InvalidState\);.* No submission was created and none was deleted\."
    $r.Err | Should -Match "Read-back of the app after the refused create \(one GET; nothing changed or deleted\): pendingApplicationSubmission id $other\. This run did not create it\.$"
    $r.Err | Should -Not -Match $DeleteAdvice
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
    $s.PendingId | Should -Be $other
  }
  It 'create refused and the read-back fails: says so, deletes nothing' {
    $s = New-FakeStore -CreateErrorStatus 400 -CreateErrorBody '{"code":"InvalidParameterValue","target":"submission"}' -FailAfterLoss; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match 'failed: HTTP 400 \(InvalidParameterValue\); target: \[unlisted target\]; hint: a parameter in the request body is invalid\. No submission was created'
    $r.Err | Should -Match "Read-back of the app after the refused create \(one GET; nothing changed or deleted\): failed \(Store API GET $([regex]::Escape($Base)) failed: HTTP 503 \(ServiceUnavailable\); hint: the service reported that it is unavailable\)\.$"
    $r.Out | Should -Match ('(?m)^' + [regex]::Escape('create refused: Store API POST ' + $Base + '/submissions?isMinimalResponse=true failed: HTTP 400 (InvalidParameterValue); target: [unlisted target]; hint: a parameter in the request body is invalid. No submission was created and none was deleted.') + '$')
    $r.Err | Should -Not -Match $DeleteAdvice
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
  }

  It 'create refused and the read-back reaches its time limit: the create error is printed before it, the read-back says so, no advice' {
    $s = New-FakeStore -CreateErrorStatus 400 -CallSeconds 40; Use-FakeStore $s
    $s.CreateErrorBody = New-PlantedErrorBody $s.Token
    $r = Invoke-Publish $Pkg
    $refused = "Store API POST $Base/submissions?isMinimalResponse=true failed: $PlantedText. No submission was created and none was deleted."
    $r.Out | Should -Match ('(?m)^' + [regex]::Escape("create refused: $refused") + '$')
    $r.Err | Should -Match ('^' + [regex]::Escape("$refused ") + '.*' + [regex]::Escape(
        "Read-back of the app after the refused create (one GET; nothing changed or deleted): failed (Store API GET $Base failed: no response (time limit of 30 s for the whole request reached)).") + '$')
    $r.All | Should -Not -Match "$DeleteAdvice|$RetryAdvice|$Leak|$([regex]::Escape($s.Token))|$Injected|$PlantedWords|eyJ|AbCdEfGh|sv=2020|##\["
    @($s.Calls)[-1] | Should -BeExactly "GET $Base timeout=30"
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
  }

  It 'create refused: the create error is printed before the read-back starts' {
    $s = New-FakeStore -CreateErrorStatus 400; Use-FakeStore $s
    $s.CreateErrorBody = New-PlantedErrorBody $s.Token
    Mock -ModuleName MsStoreRunner Get-RefusedCreateReadBack { Write-Host 'fake read-back started'; 'Fake read-back sentence.' }
    $r = Invoke-Captured { New-StoreSubmission -ProductId $App }
    $refused = "Store API POST $Base/submissions?isMinimalResponse=true failed: $PlantedText. No submission was created and none was deleted."
    $lines = @($r.Out -split "`n")
    $lines.IndexOf("create refused: $refused") | Should -BeGreaterOrEqual 0
    $lines.IndexOf("create refused: $refused") | Should -BeLessThan $lines.IndexOf('fake read-back started')
    $r.Err | Should -BeLike "$refused * Fake read-back sentence."
    Should -Invoke -ModuleName MsStoreRunner Get-RefusedCreateReadBack -Times 1 -Exactly -ParameterFilter { $ProductId -ceq $App -and $TimeoutSec -eq 30 }
  }

  It 'create refused and the read-back step itself throws: the create error is still printed and thrown unchanged, the throw is not shown' {
    $s = New-FakeStore -CreateErrorStatus 400; Use-FakeStore $s
    $s.CreateErrorBody = New-PlantedErrorBody $s.Token
    Mock -ModuleName MsStoreRunner Get-RefusedCreateReadBack { throw 'fake read-back step broke' }
    $r = Invoke-Captured { New-StoreSubmission -ProductId $App -ReadBackTimeoutSec 7 }
    $refused = "Store API POST $Base/submissions?isMinimalResponse=true failed: $PlantedText. No submission was created and none was deleted."
    $r.Out | Should -Match ('(?m)^' + [regex]::Escape("create refused: $refused") + '$')
    $r.Err | Should -BeExactly ("$refused HTTP 409 means the app's current state does not allow a new submission, for example because " +
      "another submission is pending; see the pending-submission check above. Read-back of the app after the refused create: not done.")
    $r.All | Should -Not -Match "broke|$DeleteAdvice|$RetryAdvice|$Leak|$([regex]::Escape($s.Token))|$PlantedWords"
    Should -Invoke -ModuleName MsStoreRunner Get-RefusedCreateReadBack -Times 1 -Exactly -ParameterFilter { $TimeoutSec -eq 7 }
    @($s.Log) | Should -Be @("POST $Base/submissions")
  }

  It 'treats a missing pendingApplicationSubmission field as nothing pending' {
    $s = New-FakeStore -NoPendingAs Omit; Use-FakeStore $s
    (Invoke-Publish $Pkg).Value | Should -Be @($NewId)
  }

  It 'stops before any change when the create response has no id: created, id unknown, the app read back once' {
    $s = New-FakeStore -CreateWithoutId; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match '^the create response \(HTTP 2xx\) has no usable submission id\. Created, id unknown: '
    $r.Err | Should -Match "Read-back of the app \(one GET\): pending submission $NewId\. Reported by id only: not updated, not committed, not deleted\."
    $r.All | Should -Not -Match "$DeleteAdvice|$RetryAdvice|$Leak"
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
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
    $s = New-FakeStore -UploadStatus 403 -UploadBody '<?xml version="1.0"?><Error><Code>AuthenticationFailed</Code><Message>Signature did not match. https://jlfakeupload.blob.core.windows.net/blob/upload.zip?sv=2020-08-04&sig=FAKE+SAS%2FSIGNATURE-0123456789</Message></Error>'
    Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match 'package upload failed: HTTP 403 \(AuthenticationFailed\)\. Not committed'
    $r.All | Should -Not -Match "$Leak|Signature did not match"
    @($s.Log) | Should -Not -Contain "POST $Base/submissions/$NewId/commit"
  }

  It 'masks the SAS URL when the upload throws an error that names it' {
    $s = New-FakeStore; Use-FakeStore $s
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp -ParameterFilter { $Kind -eq 'Upload' } {
      throw [System.Net.Http.HttpRequestException]::new("The SSL connection could not be established, see inner exception. ($Uri)")
    }
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match 'package upload failed: no response \(HttpRequestException( Unknown)?\)\. Not committed'
    $r.All | Should -Not -Match "$Leak|SSL connection"
    @($s.Log) | Should -Not -Contain "POST $Base/submissions/$NewId/commit"
  }

  It 'prints one fixed line for a successful upload and nothing from the URL' {
    $s = New-FakeStore; Use-FakeStore $s
    $r = Invoke-Captured { Send-StorePackage -UploadUrl "https://jlfakeupload.blob.core.windows.net/blob/upload.zip?sv=1&sig=FAKE+SAS%2FSIGNATURE-0123456789" -PackagePath $Pkg }
    $r.Err | Should -BeNullOrEmpty
    $r.Out | Should -Match "^package uploaded: $([regex]::Escape($File)) in Upload\.zip \(\d+ bytes\), HTTP 201$"
  }

  It 'refuses a plain-HTTP upload URL before zipping or sending anything' {
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp { throw 'called' }
    $r = Invoke-Captured { Send-StorePackage -UploadUrl "http://jlfakeupload.blob.core.windows.net/blob/upload.zip?sv=1&sig=FAKE+SAS%2FSIGNATURE-0123456789" -PackagePath $Pkg }
    $r.Err | Should -Match '^package upload refused'
    $r.All | Should -Not -Match $Leak
    Should -Invoke -ModuleName MsStoreRunner Invoke-StoreHttp -Times 0 -Exactly
  }
}

# Items r3-4 and r4: no answer to create or commit. LoseAsStatus 0 is no
# response at all (HttpRequestException), 504 a gateway timeout; either way the
# service may have carried the request out, so the run reads back and reports
# what it sees. While the result is unconfirmed it gives no delete or retry
# advice.
Describe 'No answer to create or commit (fake Store)' {
  BeforeEach { $script:Pkg = New-TestPackage }
  AfterEach { Remove-Item -LiteralPath (Split-Path $Pkg) -Recurse -Force }

  It 'create carried out, answer lost (<Lost>): reports the pending submission, origin unconfirmed, no delete advice' -ForEach @(
    @{ Lost = 0; Why = 'no response \(HttpRequestException Unknown <- IOException <- SocketException ConnectionReset\)' }, @{ Lost = 504; Why = 'HTTP 504; hint: a gateway in front of the service timed out' }
  ) {
    $s = New-FakeStore -LoseResponse Create -LoseWhen After -LoseAsStatus $Lost; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match "POST $([regex]::Escape($Base))/submissions\?isMinimalResponse=true failed: $Why\. Result unconfirmed: the create request got no answer"
    $r.Err | Should -Match "a pending submission $NewId exists, origin unconfirmed\. This run never got a submission id from a create response"
    $r.Err | Should -Not -Match $DeleteAdvice
    $r.Err | Should -Not -Match $RetryAdvice
    $r.Err | Should -Not -Match "most likely|this run's draft"
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
    $s.Sub.status | Should -Be 'PendingCommit'
    $r.All | Should -Not -Match $Leak
  }
  # Item r4-1: the pending submission on the read-back is not this run's.
  It 'another publisher creates a draft after the pending check, create gets no answer (<When>, <Lost>): origin unconfirmed, no delete advice' -ForEach @(
    @{ When = 'Before'; Lost = 0 }, @{ When = 'After'; Lost = 504 }
  ) {
    $other = '1152921505000000077'
    $s = New-FakeStore -OtherDraftAfterCheck $other -LoseResponse Create -LoseWhen $When -LoseAsStatus $Lost; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match "Result unconfirmed: the create request got no answer.* a pending submission $other exists, origin unconfirmed"
    $r.Err | Should -Match "cannot tell whether $other is its own draft or one someone else created after the pending-submission check"
    $r.Err | Should -Not -Match $DeleteAdvice
    $r.Err | Should -Not -Match $RetryAdvice
    $r.Err | Should -Not -Match "most likely|this run's draft"
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
    $s.Sub | Should -BeNullOrEmpty
    $s.PendingId | Should -Be $other
  }
  # Pepper, PR #74 r5: the Store may show a new submission only after a
  # while, so a read-back without one is not taken as "none was created", and
  # the run gives no re-run advice.
  It 'create not carried out, no answer: the read-back shows none yet, which is not taken as none created; no re-run or delete advice' {
    $s = New-FakeStore -LoseResponse Create -LoseWhen Before; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match ('Result unconfirmed: .* no pending submission yet\. That does not show none was created: the Store may take a while to show a new submission\. ' +
      "This run changes and deletes nothing\. A person needs to read GET /v1\.0/my/applications/$App later; a pending submission there is of unconfirmed origin")
    $r.Err | Should -Not -Match "$DeleteAdvice|$RetryAdvice|none had been created|nothing to clean up"
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
    $s.Sub | Should -BeNullOrEmpty
  }
  It 'create with no answer and a failing read-back: result stays unknown, no origin claim, no delete advice' {
    $s = New-FakeStore -LoseResponse Create -LoseWhen After -FailAfterLoss; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match 'Result unconfirmed: .* failed too \(Store API GET .* failed: HTTP 503 \(ServiceUnavailable\); hint: the service reported that it is unavailable\)\. The result stays unknown: do not delete anything\.'
    $r.Err | Should -Match 'a pending submission there is of unconfirmed origin'
    $r.Err | Should -Not -Match "$DeleteAdvice|$RetryAdvice"
    $r.Err | Should -Not -Match "most likely|this run's (uncommitted )?draft"
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
  }
  It 'commit carried out, answer lost (<Lost>): reads it back by id, sees it committed, and goes on' -ForEach @(@{ Lost = 0 }, @{ Lost = 504 }) {
    $s = New-FakeStore -LoseResponse Commit -LoseWhen After -LoseAsStatus $Lost; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -BeNullOrEmpty
    $r.Value | Should -Be @($NewId)
    $r.Out | Should -Match "::warning title=Store commit::The commit request for submission $NewId got no answer, but read-back 1 by id shows status Certification: it was committed"
    @($s.Log)[-2..-1] | Should -Be @("POST $Base/submissions/$NewId/commit", "GET $Base/submissions/$NewId")
    $r.All | Should -Not -Match $Leak
  }
  # Item r4-2: the commit API is asynchronous; PendingCommit on a read-back
  # does not mean the commit failed.
  It 'commit still processing when its answer was lost (<Lost>, <Delay> PendingCommit read(s)): reads again, sees CommitStarted, goes on' -ForEach @(
    @{ Lost = 0; Delay = 1 }, @{ Lost = 504; Delay = 2 }
  ) {
    $s = New-FakeStore -LoseResponse Commit -LoseWhen Delayed -LoseAsStatus $Lost -CommitDelayReads $Delay; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -BeNullOrEmpty
    $r.Value | Should -Be @($NewId)
    $r.Out | Should -Match "commit of submission $NewId not confirmed yet \(read-back 1 of 3 shows status PendingCommit\); reading it back again in 0 s"
    $r.Out | Should -Match "::warning title=Store commit::The commit request for submission $NewId got no answer, but read-back $($Delay + 1) by id shows status CommitStarted: it was committed"
    $r.All | Should -Not -Match $DeleteAdvice
    $r.All | Should -Not -Match $RetryAdvice
    $tail = @("POST $Base/submissions/$NewId/commit") + @(1..($Delay + 1) | ForEach-Object { "GET $Base/submissions/$NewId" })
    @($s.Log)[(-$tail.Count)..-1] | Should -Be $tail
    $s.Sub.status | Should -Be 'CommitStarted'
    $v = Invoke-Captured { Assert-SubmissionHasPackage -ProductId $App -SubmissionId $NewId -ExpectedVersion '0.4.1.0' -TimeoutMinutes 1 -IntervalSeconds 0 }
    $v.Err | Should -BeNullOrEmpty
    $v.Out | Should -Match "verified submission ${NewId}: submission holds exactly one Uploaded package, version 0\.4\.1\.0"
    @($s.Log) | Should -Not -Match '^DELETE '
    $r.All | Should -Not -Match $Leak
  }
  It 'commit not confirmed within the read-backs (<Case>): stays unconfirmed, a person checks the id, no delete or retry advice' -ForEach @(
    @{ Case = 'never arrived'; When = 'Before' }, @{ Case = 'still processing'; When = 'Delayed' }
  ) {
    $s = New-FakeStore -LoseResponse Commit -LoseWhen $When -CommitDelayReads 5; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match "Result unconfirmed: the commit request for submission $NewId got no answer, so it may or may not have been committed\. Read back by id 3 time\(s\), 0 s apart; last: read-back 3 of 3 shows status PendingCommit\. The commit API is asynchronous, so PendingCommit does not show the commit failed"
    $r.Err | Should -Match "A person needs to check GET /v1\.0/my/applications/$App/submissions/$NewId later"
    $r.Err | Should -Not -Match $DeleteAdvice
    $r.Err | Should -Not -Match $RetryAdvice
    $r.Err | Should -Not -Match 'so it was not committed|means it was not|was not committed'
    $r.Out | Should -Not -Match $DeleteAdvice
    @($s.Log)[-4..-1] | Should -Be @("POST $Base/submissions/$NewId/commit", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId")
    @($s.Log | Where-Object { $_ -ceq "GET $Base/submissions/$NewId" }).Count | Should -Be 5 -Because 'two GETs before the commit, then exactly 3 read-backs'
    @($s.Log) | Should -Not -Match '^DELETE '
    $s.Sub.status | Should -Be 'PendingCommit'
  }
  It 'commit with no answer and a failing read-back: result stays unconfirmed, no delete or retry advice' {
    $s = New-FakeStore -LoseResponse Commit -LoseWhen After -FailAfterLoss; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match 'Result unconfirmed: the commit request .* Read back by id 3 time\(s\), 0 s apart; last: read-back 3 of 3 failed \(Store API GET .* failed: HTTP 503 \(ServiceUnavailable\); hint: the service reported that it is unavailable\)\. .*The result stays unconfirmed'
    $r.Err | Should -Not -Match $DeleteAdvice
    $r.Err | Should -Not -Match $RetryAdvice
    $r.Err | Should -Not -Match 'means it was not'
    @($s.Log)[-4..-1] | Should -Be @("POST $Base/submissions/$NewId/commit", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId")
  }
  It 'commit with no answer and a read-back status that is neither: stops at once, no delete or retry advice' {
    $s = New-FakeStore -LoseResponse Commit -LoseWhen After -CommitStatus CommitFailed; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match "Read-back 1 by id: status is 'CommitFailed'\. Nothing is deleted or retried"
    $r.Err | Should -Not -Match $DeleteAdvice
    $r.Err | Should -Not -Match $RetryAdvice
    @($s.Log)[-2..-1] | Should -Be @("POST $Base/submissions/$NewId/commit", "GET $Base/submissions/$NewId")
  }
  It 'commit refused with an answer (HTTP 409): no read-back, says how to check and delete by id' {
    $s = New-FakeStore -LoseResponse Commit -LoseWhen Before -LoseAsStatus 409; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match "failed: HTTP 409; hint: the current state of the app does not allow this, or the app uses a Partner Center feature the submission API does not support\. Commit of submission $NewId was not accepted"
    $r.Err | Should -Not -Match 'Result unconfirmed'
    @($s.Log)[-1] | Should -Be "POST $Base/submissions/$NewId/commit"
  }
}

# PR #74 r2: an error target whose index is in the digits of another script
# (applicationPackages[\u0661]) made Get-ListedTarget throw ([int] cannot convert
# it) while the error text was formatted, before the error was built. A 5xx,
# whose result is unconfirmed, then became an ordinary error: a commit went
# down the "not accepted" path (delete advice, no read-back by id), a create
# down the "refused" path. Now the index is ASCII digits only, the formatters
# never throw (fixed text instead), and Invoke-StoreApi decides OutcomeUnknown
# before it formats anything.
Describe 'An answer whose body is lost is classified by its status (PR #74 r4, fake Store)' {
  # Pepper, PR #74 r4: the create POST got its HTTP 400 status and headers,
  # then the body did not arrive in time; the status was dropped and the
  # create counted as unanswered (result unconfirmed). Invoke-StoreHttp now
  # returns the status with a fixed BodyLost text, and the status decides.
  BeforeAll {
    $script:LostLimit = 'body not received (time limit of {0} s for the whole request reached)'
    $script:LostBroken = 'body not received (the connection broke or the body could not be read)'
    function script:Get-StatusHint([int]$Code) { & (Get-Module MsStoreRunner) { param($c) $script:StoreStatusHint[$c] } $Code }
  }
  BeforeEach { $script:Pkg = New-TestPackage }
  AfterEach { Remove-Item -LiteralPath (Split-Path $Pkg) -Recurse -Force }

  It 'create answered HTTP <Status>, body lost (<End>): refused by its status, status and fixed text printed first, read back, no retry or delete advice' -ForEach @(
    @{ Status = 400; End = 'Body' }, @{ Status = 409; End = 'Break' }, @{ Status = 403; End = 'Body' }
  ) {
    $s = New-FakeStore -CreateErrorStatus $Status -DripOn Create -DripSeconds 30 -DripEnd $End; Use-FakeStore $s
    $s.CreateErrorBody = New-PlantedErrorBody $s.Token
    $r = Invoke-Publish $Pkg
    $lost = if ($End -eq 'Break') { $LostBroken } else { $LostLimit -f 600 }
    $refused = "Store API POST $Base/submissions?isMinimalResponse=true failed: HTTP ${Status}; hint: $(Get-StatusHint $Status); $lost. No submission was created and none was deleted."
    $r.Out | Should -Match ('(?m)^' + [regex]::Escape("create refused: $refused") + '$')
    $r.Err | Should -Match ('^' + [regex]::Escape("$refused ") + '.*' + [regex]::Escape('Read-back of the app after the refused create (one GET; nothing changed or deleted): no pendingApplicationSubmission.') + '$')
    $r.All | Should -Not -Match "Result unconfirmed|$DeleteAdvice|$RetryAdvice|$Leak|$([regex]::Escape($s.Token))|$Injected|$PlantedWords"
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
    $s.Sub | Should -BeNullOrEmpty
  }
  # Carried out: the read-back finds a pending submission of unconfirmed
  # origin, no advice. Not carried out: the read-back shows none yet, which
  # (PR #74 r6) is not taken as none created: no re-run or delete advice.
  It 'create answered HTTP <Status> (<When> it was carried out), body lost: result unconfirmed by its status, the app read back, no re-run or delete advice' -ForEach @(
    @{ Status = 503; When = 'After'; Shows = "a pending submission 1152921505000000099 exists, origin unconfirmed" }
    @{ Status = 500; When = 'Before'; Shows = 'no pending submission yet. That does not show none was created' }
    @{ Status = 408; When = 'Before'; Shows = 'no pending submission yet. That does not show none was created' }
  ) {
    $s = New-FakeStore -LoseResponse Create -LoseWhen $When -LoseAsStatus $Status -LoseBody '{"code":"ServiceError"}' -DripOn Create -DripSeconds 30; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match ('^' + [regex]::Escape("Store API POST $Base/submissions?isMinimalResponse=true failed: HTTP ${Status}; hint: $(Get-StatusHint $Status); $($LostLimit -f 600). Result unconfirmed: the create request got no answer"))
    $r.Err | Should -Match ([regex]::Escape($Shows))
    $r.All | Should -Not -Match "create refused|No submission was created|none had been created|nothing to clean up|$DeleteAdvice|$RetryAdvice|$Leak"
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
  }
  It 'commit answered HTTP <Status> (carried out), body lost: unconfirmed by its status, read back by id, committed, goes on' -ForEach @(
    @{ Status = 503; Opt = @{ LoseResponse = 'Commit'; LoseWhen = 'After'; LoseAsStatus = 503; LoseBody = '{"code":"ServiceError"}' } }
    @{ Status = 200; Opt = @{} }
  ) {
    $o = $Opt.Clone(); $s = New-FakeStore @o -DripOn Commit -DripSeconds 30; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -BeNullOrEmpty
    $r.Value | Should -Be @($NewId)
    $why = if ($Status -eq 200) { 'HTTP 200' } else { "HTTP ${Status}; hint: $(Get-StatusHint $Status)" }
    $r.Out | Should -Match ([regex]::Escape("Store API POST $Base/submissions/$NewId/commit failed: $why; $($LostLimit -f 60)"))
    $got = if ($Status -eq 200) { "was accepted (HTTP 200) but its answer's body was not read;" } else { 'got no answer, but' }
    $r.Out | Should -Match ([regex]::Escape("::warning title=Store commit::The commit request for submission $NewId $got read-back 1 by id shows status Certification: it was committed"))
    $r.All | Should -Not -Match "$DeleteAdvice|was not accepted|$Leak"
    @($s.Log)[-2..-1] | Should -Be @("POST $Base/submissions/$NewId/commit", "GET $Base/submissions/$NewId")
  }
  It 'commit answered HTTP <Status> (not carried out), body lost: unconfirmed after 3 read-backs by id, no retry or delete advice' -ForEach @(@{ Status = 503 }, @{ Status = 504 }) {
    $s = New-FakeStore -LoseResponse Commit -LoseWhen Before -LoseAsStatus $Status -LoseBody '{"code":"ServiceError"}' -DripOn Commit -DripSeconds 30; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Out | Should -Match ('::warning title=Store commit::Result unconfirmed: the commit request for submission ' + $NewId + ' got no answer ' +
      [regex]::Escape("(Store API POST $Base/submissions/$NewId/commit failed: HTTP ${Status}; hint: $(Get-StatusHint $Status); $($LostLimit -f 60))"))
    $r.Err | Should -Match "Read back by id 3 time\(s\), 0 s apart; last: read-back 3 of 3 shows status PendingCommit\."
    $r.Err | Should -Not -Match $RetryAdvice
    $r.All | Should -Not -Match "$DeleteAdvice|was not accepted|$Leak"
    @($s.Log)[-4..-1] | Should -Be @("POST $Base/submissions/$NewId/commit", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId")
  }
  # PR #74 r6: an HTTP 2xx to the commit means it was accepted; the text says
  # so instead of "got no answer". The commit API is asynchronous, so a
  # submission still PendingCommit on every read-back stays unconfirmed.
  It 'commit answered HTTP 200 (accepted), body lost, still PendingCommit on 3 read-backs: unconfirmed, says accepted, no retry or delete advice' {
    $s = New-FakeStore -LoseResponse Commit -LoseWhen Delayed -LoseAsStatus 200 -LoseBody '{"status":"CommitStarted"}' -CommitDelayReads 5 -DripOn Commit -DripSeconds 30; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $fail = "Store API POST $Base/submissions/$NewId/commit failed: HTTP 200; $($LostLimit -f 60)"
    $r.Out | Should -Match ([regex]::Escape("::warning title=Store commit::Result unconfirmed: the commit request for submission $NewId was accepted (HTTP 200) but its answer's body was not read ($fail). Reading it back by id"))
    $r.Err | Should -Match ('^' + [regex]::Escape("$fail. Result unconfirmed: the commit request for submission $NewId was accepted (HTTP 200) but its answer's body was not read, so whether the commit has started is not confirmed. Read back by id 3 time(s), 0 s apart; last: read-back 3 of 3 shows status PendingCommit."))
    $r.Err | Should -Not -Match $RetryAdvice
    $r.All | Should -Not -Match "$DeleteAdvice|was not accepted|got no answer|$Leak"
    @($s.Log)[-4..-1] | Should -Be @("POST $Base/submissions/$NewId/commit", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId")
  }
  It 'commit answered HTTP 409, body lost: refused by its status (not accepted), not read back as unconfirmed' {
    $s = New-FakeStore -LoseResponse Commit -LoseWhen Before -LoseAsStatus 409 -LoseBody '{"code":"InvalidState"}' -DripOn Commit -DripSeconds 30; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match ('^' + [regex]::Escape("Store API POST $Base/submissions/$NewId/commit failed: HTTP 409; hint: $(Get-StatusHint 409); $($LostLimit -f 60). Commit of submission $NewId was not accepted."))
    $r.All | Should -Not -Match "Result unconfirmed|$Leak"
    @($s.Log)[-1] | Should -Be "POST $Base/submissions/$NewId/commit"
  }
  It 'token answered HTTP 200, body lost: not signed in, the status and the fixed text are printed' {
    $s = New-FakeStore; Use-FakeStore $s
    $s.DripOn = 'Token'; $s.DripSeconds = 30
    $r = Invoke-Captured { Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret }
    $r.Err | Should -BeExactly "could not get a Partner Center access token: HTTP 200; $($LostLimit -f 600)"
    (& (Get-Module MsStoreRunner) { $script:Token }) | Should -BeNullOrEmpty
    $r.All | Should -Not -Match $Leak
  }
  It 'package upload answered HTTP 201, body lost: the blob is stored, so the upload counts and the run goes on' {
    $s = New-FakeStore -UploadBody '<x/>' -DripOn Upload -DripSeconds 30; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -BeNullOrEmpty
    $r.Value | Should -Be @($NewId)
    $r.Out | Should -Match ([regex]::Escape("package uploaded: $File in Upload.zip (") + '\d+' + [regex]::Escape(" bytes), HTTP 201 (the answer's body was not read: $($LostLimit -f 600))"))
    $r.All | Should -Not -Match $Leak
  }
  It 'package upload answered HTTP 403, body lost: the upload failed with its status and the fixed text, not committed' {
    $s = New-FakeStore -UploadStatus 403 -UploadBody '<Error><Code>AuthenticationFailed</Code></Error>' -DripOn Upload -DripSeconds 30; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match ('^' + [regex]::Escape("package upload failed: HTTP 403; $($LostLimit -f 600). Not committed: draft $NewId stays uncommitted"))
    @($s.Log) | Should -Not -Contain "POST $Base/submissions/$NewId/commit"
    $r.All | Should -Not -Match $Leak
  }
}

# Pepper, PR #74 r5: a create answered HTTP 201 whose body was cut off went
# down the "no answer" path, and a read-back without a pending submission was
# reported as "none had been created" with advice to re-run. An HTTP 2xx means
# the Store created a submission; only its id is unknown. Now that is
# "created, id unknown": a warning first, then one read-back of the app; a
# pending submission is reported by id only; the run stops with no update,
# upload, commit or delete, and no re-run or delete advice, whatever the
# read-back shows (the Store may show a new submission only after a while).
Describe 'A create answered HTTP 2xx without a usable id: created, id unknown (PR #74 r6, fake Store)' {
  BeforeAll {
    $script:LostLimit = 'body not received (time limit of {0} s for the whole request reached)'
    $script:LostBroken = 'body not received (the connection broke or the body could not be read)'
    $script:ApiOnly = & (Get-Module MsStoreRunner) { $script:ApiOnlyNote }
    $script:NotCreated = 'Result unconfirmed|create refused|No submission was created|none had been created|nothing to clean up|origin unconfirmed|has no submission id'
    $script:Look = "A person needs to check the app's pending submission in Partner Center (look only, change nothing there) or with GET $Base (pendingApplicationSubmission.id)"
    # The error text up to the read-back result, and the text after it.
    function script:Get-CreatedText([string]$Answer, [string]$Status, [string]$Want, [string]$Pending) {
      $tail = switch ($Want) {
        'Pending' { "pending submission $Pending. Reported by id only: not updated, not committed, not deleted. A person needs to check submission $Pending in Partner Center (look only, change nothing there) or with GET $Base/submissions/$Pending. $ApiOnly" }
        'None' { "no pending submission yet. That does not mean none was created: the Store may take a while to show the new submission. $Look later. $ApiOnly" }
        'NoId' { "a pending submission without a usable id. $Look. $ApiOnly" }
        'Failed' { "failed (fake read-back broke). $Look once the API answers; the Store may take a while to show the new submission. $ApiOnly" }
      }
      ("$Answer. Created, id unknown: the Store answered the create with $Status, so it created a submission, but this run did not get the new submission's id. " +
        "This run stops: it does not update, upload to, commit or delete any submission. Read-back of the app (one GET): $tail")
    }
    function script:Get-CreatedWarning([string]$Answer, [string]$Status) {
      ("::warning title=Store create::Created, id unknown: the Store answered the create with $Status, so it created a submission, but this run did not get its id ($Answer). " +
        "The run stops; it updates, commits and deletes nothing. Reading the app back once. If this step ends before a result is printed below: $Look; the Store may take a while to show it.")
    }
  }
  BeforeEach { $script:Pkg = New-TestPackage }
  AfterEach { Remove-Item -LiteralPath (Split-Path $Pkg) -Recurse -Force }

  It 'create answered HTTP 201, body lost (<End>), the read-back shows <Case>: the run stops, nothing updated, committed or deleted, no re-run or delete advice' -ForEach @(
    @{ End = 'Body'; Case = 'the new pending submission'; Want = 'Pending'; Opt = @{} }
    @{ End = 'Break'; Case = 'the new pending submission'; Want = 'Pending'; Opt = @{} }
    @{ End = 'Body'; Case = 'no pending submission yet (the Store is slow to show it)'; Want = 'None'; Opt = @{ PendingLag = $true } }
    @{ End = 'Break'; Case = 'no pending submission yet (the Store is slow to show it)'; Want = 'None'; Opt = @{ PendingLag = $true } }
    @{ End = 'Body'; Case = 'a pending submission without a usable id'; Want = 'NoId'; Opt = @{ PendingAfterCreate = 'x1' } }
  ) {
    $o = $Opt.Clone(); $s = New-FakeStore @o -DripOn Create -DripSeconds 30 -DripEnd $End; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $lost = if ($End -eq 'Break') { $LostBroken } else { $LostLimit -f 600 }
    $answer = "Store API POST $Base/submissions?isMinimalResponse=true failed: HTTP 201; $lost"
    $r.Out | Should -Match ('(?m)^' + [regex]::Escape((Get-CreatedWarning $answer 'HTTP 201')) + '$')
    $r.Err | Should -BeExactly (Get-CreatedText $answer 'HTTP 201' $Want $NewId)
    $r.Value | Should -BeNullOrEmpty
    $r.All | Should -Not -Match "$NotCreated|$DeleteAdvice|$RetryAdvice|$Leak"
    # One read-back of the app; no PUT, upload, commit or DELETE.
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
    $s.Blob | Should -BeNullOrEmpty
    $s.Sub.id | Should -Be $NewId
    $s.Sub.status | Should -Be 'PendingCommit'
  }
  It 'create answered HTTP 201, body lost, and the read-back fails: the run stops, a person checks once the API answers, no re-run or delete advice' {
    $s = New-FakeStore -DripOn Create -DripSeconds 30; Use-FakeStore $s
    Mock -ModuleName MsStoreRunner Get-StoreApp { throw 'fake read-back broke' }
    $r = Invoke-Captured { New-StoreSubmission -ProductId $App -ReadBackTimeoutSec 7 }
    $answer = "Store API POST $Base/submissions?isMinimalResponse=true failed: HTTP 201; $($LostLimit -f 600)"
    $r.Out | Should -Match ('(?m)^' + [regex]::Escape((Get-CreatedWarning $answer 'HTTP 201')) + '$')
    $r.Err | Should -BeExactly (Get-CreatedText $answer 'HTTP 201' 'Failed')
    $r.All | Should -Not -Match "$NotCreated|$DeleteAdvice|$RetryAdvice|$Leak"
    Should -Invoke -ModuleName MsStoreRunner Get-StoreApp -Times 1 -Exactly -ParameterFilter { $ProductId -ceq $App -and $TimeoutSec -eq 7 }
    @($s.Log) | Should -Be @("POST $Base/submissions")
  }
  It 'create answered HTTP 201 with a body without a usable id (<Case>): created, id unknown, read back once, the run stops' -ForEach @(
    @{ Case = 'no id, the new submission shown'; Want = 'Pending'; Opt = @{ CreateWithoutId = $true } }
    @{ Case = 'no id, the new submission not shown yet'; Want = 'None'; Opt = @{ CreateWithoutId = $true; PendingLag = $true } }
  ) {
    $o = $Opt.Clone(); $s = New-FakeStore @o; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $answer = 'the create response (HTTP 2xx) has no usable submission id'
    $r.Out | Should -Match ('(?m)^' + [regex]::Escape((Get-CreatedWarning $answer 'HTTP 2xx')) + '$')
    $r.Err | Should -BeExactly (Get-CreatedText $answer 'HTTP 2xx' $Want $NewId)
    $r.All | Should -Not -Match "$NotCreated|$DeleteAdvice|$RetryAdvice|$Leak"
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
    $s.Sub.status | Should -Be 'PendingCommit'
  }
  # The status decides, not the body: 2xx is created; 408/5xx unconfirmed;
  # another status refused; no status (no answer) unconfirmed.
  It 'create answered HTTP <Status> with its body lost goes down the <Path> path' -ForEach @(
    @{ Status = 200; Path = 'created, id unknown'; Opt = @{ LoseResponse = 'Create'; LoseWhen = 'After'; LoseAsStatus = 200; LoseBody = '{}' }; Want = 'Created, id unknown: the Store answered the create with HTTP 200' }
    @{ Status = 202; Path = 'created, id unknown'; Opt = @{ LoseResponse = 'Create'; LoseWhen = 'After'; LoseAsStatus = 202; LoseBody = '{}' }; Want = 'Created, id unknown: the Store answered the create with HTTP 202' }
    @{ Status = 299; Path = 'created, id unknown'; Opt = @{ LoseResponse = 'Create'; LoseWhen = 'After'; LoseAsStatus = 299; LoseBody = '{}' }; Want = 'Created, id unknown: the Store answered the create with HTTP 299' }
    @{ Status = 300; Path = 'refused'; Opt = @{ LoseResponse = 'Create'; LoseWhen = 'Before'; LoseAsStatus = 300; LoseBody = '{}' }; Want = 'No submission was created and none was deleted' }
    @{ Status = 199; Path = 'refused'; Opt = @{ LoseResponse = 'Create'; LoseWhen = 'Before'; LoseAsStatus = 199; LoseBody = '{}' }; Want = 'No submission was created and none was deleted' }
    @{ Status = 409; Path = 'refused'; Opt = @{ LoseResponse = 'Create'; LoseWhen = 'Before'; LoseAsStatus = 409; LoseBody = '{}' }; Want = 'No submission was created and none was deleted' }
    @{ Status = 503; Path = 'unconfirmed'; Opt = @{ LoseResponse = 'Create'; LoseWhen = 'Before'; LoseAsStatus = 503; LoseBody = '{}' }; Want = 'Result unconfirmed: the create request got no answer' }
  ) {
    $o = $Opt.Clone(); $s = New-FakeStore @o -DripOn Create -DripSeconds 30; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match ('^' + [regex]::Escape("Store API POST $Base/submissions?isMinimalResponse=true failed: HTTP $Status") + '.*' + [regex]::Escape($Want))
    $r.All | Should -Not -Match "$DeleteAdvice|$RetryAdvice|$Leak"
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
  }
  It 'create got no answer at all (<When>): unconfirmed, never taken for created' -ForEach @(@{ When = 'After' }, @{ When = 'Before' }) {
    $s = New-FakeStore -LoseResponse Create -LoseWhen $When; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match 'Result unconfirmed: the create request got no answer'
    $r.All | Should -Not -Match "Created, id unknown|$DeleteAdvice|$RetryAdvice|$Leak"
  }
}

# Every status a call can end with (2xx with its body read or lost, 4xx, 408,
# 5xx, no answer, not sent) and the advice printed, for each call that can
# change something: no re-run or delete advice wherever the call may have
# been carried out (PR #74 r6 sweep). The pre-commit stops are this run's
# own draft (its id came from the create response), uncommitted (the commit
# was not sent): delete-by-id advice there is checked against PendingCommit
# by Remove-StoreDraftSubmission before anything is deleted.
Describe 'Advice by status for each call (PR #74 r6 sweep, fake Store)' {
  BeforeAll {
    $script:LostLimit = 'body not received (time limit of {0} s for the whole request reached)'
  }
  AfterAll { $global:FakeDeleteStatus = $null; $global:FakeDeleteSub = $null }
  BeforeEach { $script:Pkg = New-TestPackage }
  AfterEach { Remove-Item -LiteralPath (Split-Path $Pkg) -Recurse -Force }

  # The status mark is read without throwing: a record without it, or one
  # that cannot be read, is 0 (never an answered 2xx), so a caller's catch
  # still classifies the original error.
  It 'Get-StoreErrorStatus reads the status mark, and gives 0 (never throws) for <Case>' -ForEach @(
    @{ Case = 'a marked 201'; Kind = 'Marked201'; Want = 201 }
    @{ Case = 'no answer (marked 0)'; Kind = 'NoAnswer'; Want = 0 }
    @{ Case = 'an error without the mark'; Kind = 'NoMark'; Want = 0 }
    @{ Case = 'a mark that is not a number'; Kind = 'NotANumber'; Want = 0 }
    @{ Case = 'no error record at all'; Kind = 'None'; Want = 0 }
  ) {
    InModuleScope MsStoreRunner -Parameters @{ Kind = $Kind; Want = $Want } {
      param($Kind, $Want)
      $e = switch ($Kind) {
        'Marked201' { New-StoreError 'x' -OutcomeUnknown -Status 201 }
        'NoAnswer' { New-StoreError 'x' -OutcomeUnknown }
        'NoMark' { [System.InvalidOperationException]::new('x') }
        'NotANumber' { $x = [System.InvalidOperationException]::new('x'); $x.Data['StoreStatus'] = 'x'; $x }
        default { $null }
      }
      $rec = $null
      if ($e) { try { throw $e } catch { $rec = $_ } }
      if ($e) { $rec.Exception | Should -BeExactly $e }
      Get-StoreErrorStatus $rec | Should -Be $Want
      Test-Store2xx (Get-StoreErrorStatus $rec) | Should -Be ($Want -eq 201)
    }
  }

  # The PUT was carried out (HTTP 200) but its answer, with the upload URL,
  # was not read: the run stops before the upload. The draft is this run's
  # own and the commit was never sent, so the delete-by-id advice stands; it
  # deletes only while that id is still PendingCommit.
  It 'PUT of the submission answered HTTP 200 with its body lost: stops uncommitted before the upload; delete-by-id advice for this run''s own draft only' {
    $s = New-FakeStore -DripOn Update -DripSeconds 30; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match ('^' + [regex]::Escape("Store API PUT $Base/submissions/$NewId failed: HTTP 200; $($LostLimit -f 600). Not committed: draft $NewId stays uncommitted."))
    $r.Err | Should -Match ([regex]::Escape("DELETE /v1.0/my/applications/$App/submissions/$NewId (Remove-StoreDraftSubmission -ProductId $App -SubmissionId $NewId") + '.*' + [regex]::Escape('only while it is still an uncommitted PendingCommit draft'))
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base", "GET $Base/submissions/$NewId", "PUT $Base/submissions/$NewId")
    $s.Blob | Should -BeNullOrEmpty
    $s.Sub.status | Should -Be 'PendingCommit'
    $r.All | Should -Not -Match $Leak
  }

  It 'manual DELETE answered HTTP 204 with its body lost: deleted (the body is not used)' {
    $s = New-FakeStore -DripOn Delete -DripSeconds 30; Use-FakeStore $s
    $s.Sub = @{ id = $SubId; status = 'PendingCommit'; applicationPackages = @() }
    $r = Invoke-Captured { Remove-StoreDraftSubmission -ProductId $App -SubmissionId $SubId }
    $r.Err | Should -BeNullOrEmpty
    $r.Out | Should -BeExactly "deleted draft submission $SubId (HTTP 204; the answer's body was not read)"
    @($s.Log) | Should -Be @("GET $Base/submissions/$SubId", "DELETE $Base/submissions/$SubId")
    $s.Sub | Should -BeNullOrEmpty
  }
  It 'manual DELETE that fails without an answered 2xx (<Case>): the error is thrown, nothing says deleted' -ForEach @(
    @{ Case = 'no answer'; Status = 0 }, @{ Case = 'HTTP 503, body lost'; Status = 503 }, @{ Case = 'HTTP 409'; Status = 409 }
  ) {
    # No parameter filter: Pester 6 does not fall back to the real command
    # for a call that no filter matches, so both calls are mocked here.
    $global:FakeDeleteStatus = $Status
    $global:FakeDeleteSub = "{`"id`":`"$SubId`",`"status`":`"PendingCommit`"}"
    Mock -ModuleName MsStoreRunner Get-StoreSubmissionJson { $global:FakeDeleteSub }
    Mock -ModuleName MsStoreRunner Invoke-StoreApi {
      throw (& (Get-Module MsStoreRunner) { param($st) New-StoreError "fake DELETE failed with $st" -OutcomeUnknown:($st -ne 409) -Status $st } $global:FakeDeleteStatus)
    }
    $r = Invoke-Captured { Remove-StoreDraftSubmission -ProductId $App -SubmissionId $SubId }
    $r.Err | Should -BeExactly "fake DELETE failed with $Status"
    $r.Out | Should -Not -Match 'deleted draft'
    Should -Invoke -ModuleName MsStoreRunner Invoke-StoreApi -Times 1 -Exactly -ParameterFilter { $Method -eq 'DELETE' }
    Should -Invoke -ModuleName MsStoreRunner Invoke-StoreApi -Times 1 -Exactly
  }
}

Describe 'Diagnostics that cannot be formatted never change how an error is classified (PR #74 r2)' {
  BeforeAll {
    $script:UnlistedServiceError = 'target: \[unlisted target\]; hint: the service reported an internal error'
    $script:NoDiag = 'diagnostics not shown \(they could not be formatted\)'
    # Fails the way [int] fails on such digits.
    $script:CastFailure = { throw 'Cannot convert value "x" to type "System.Int32". Error: "The input string was not in a correct format."' }
  }

  It 'Get-ListedTarget prints [unlisted target] for an index in <Case>, and so does Get-StoreErrorText for a 503' -ForEach @(
    @{ Case = 'an Arabic-Indic digit'; Target = "applicationPackages[$([char]0x0661)]" }
    @{ Case = 'three Arabic-Indic digits'; Target = "applicationPackages[$([char]0x0660)$([char]0x0661)$([char]0x0662)].fileName" }
    @{ Case = 'fullwidth digits'; Target = "applicationPackages[$([char]0xFF11)$([char]0xFF12)]" }
    @{ Case = 'an ASCII digit and a Devanagari digit'; Target = "applicationPackages[1$([char]0x0967)].version" }
    @{ Case = 'an Extended Arabic-Indic digit, deeper in the path'; Target = "listings.baseListing.images[$([char]0x06F1)].imageType" }
  ) {
    Get-ListedTarget $Target | Should -BeExactly '[unlisted target]'
    foreach ($nested in $false, $true) {
      Get-StoreErrorText -StatusCode 503 -Body (New-TargetBody $Target -Nested:$nested) -Detail |
        Should -BeExactly 'HTTP 503 (ServiceError); target: [unlisted target]; hint: the service reported an internal error'
    }
  }
  It 'Get-StoreErrorText prints the status and a fixed text when <Fails> throws' -ForEach @(
    @{ Fails = 'Get-ListedTarget' }, @{ Fails = 'Protect-WorkflowCommand' }
  ) {
    Mock -ModuleName MsStoreRunner -CommandName $Fails -MockWith $CastFailure
    Get-StoreErrorText -StatusCode 503 -Body (New-TargetBody 'applicationPackages[0]') -Detail |
      Should -BeExactly 'HTTP 503; diagnostics not shown (they could not be formatted)'
  }
  It 'Get-StoreFailureText prints a fixed text for a failure it cannot format' {
    InModuleScope MsStoreRunner { Get-StoreFailureText ([pscustomobject]@{ NotAnErrorRecord = 1 }) } |
      Should -BeExactly 'no HTTP response; diagnostics not shown (they could not be formatted)'
  }
  It 'Invoke-StoreApi: HTTP <Status> with an Arabic-Indic index in the error target stays <Want>' -ForEach @(
    @{ Status = 408; Want = 'unconfirmed' }, @{ Status = 500; Want = 'unconfirmed' }, @{ Status = 502; Want = 'unconfirmed' }
    @{ Status = 503; Want = 'unconfirmed' }, @{ Status = 504; Want = 'unconfirmed' }
    @{ Status = 400; Want = 'refused' }, @{ Status = 409; Want = 'refused' }
  ) {
    $s = New-FakeStore -LoseResponse Commit -LoseWhen Before -LoseAsStatus $Status -LoseBody (New-TargetBody "applicationPackages[$([char]0x0661)]"); Use-FakeStore $s
    $e = InModuleScope MsStoreRunner -Parameters @{ P = "applications/$App/submissions/$NewId/commit" } { param($P) try { Invoke-StoreApi -Method POST -Path $P; $null } catch { $_ } }
    $e | Should -Not -BeNullOrEmpty
    InModuleScope MsStoreRunner -Parameters @{ E = $e } { param($E) Test-StoreOutcomeUnknown $E } | Should -Be ($Want -eq 'unconfirmed')
    "$e" | Should -Match ('^' + [regex]::Escape("Store API POST $Base/submissions/$NewId/commit failed: HTTP $Status (ServiceError); target: [unlisted target]; hint: the service reported an internal error") + '\z')
  }
  It 'Invoke-StoreApi: <Case> stays unconfirmed when <Fails> throws' -ForEach @(
    @{ Case = 'HTTP 503'; Lost = 503; Fails = 'Format-StoreErrorText'; Text = 'HTTP 503' }
    @{ Case = 'HTTP 503'; Lost = 503; Fails = 'Get-ListedTarget'; Text = 'HTTP 503' }
    @{ Case = 'no response'; Lost = 0; Fails = 'Format-StoreFailureText'; Text = 'no HTTP response' }
  ) {
    $s = New-FakeStore -LoseResponse Commit -LoseWhen Before -LoseAsStatus $Lost -LoseBody (New-TargetBody 'applicationPackages[0]'); Use-FakeStore $s
    Mock -ModuleName MsStoreRunner -CommandName $Fails -MockWith $CastFailure
    $e = InModuleScope MsStoreRunner -Parameters @{ P = "applications/$App/submissions/$NewId/commit" } { param($P) try { Invoke-StoreApi -Method POST -Path $P; $null } catch { $_ } }
    InModuleScope MsStoreRunner -Parameters @{ E = $e } { param($E) Test-StoreOutcomeUnknown $E } | Should -BeTrue
    "$e" | Should -BeExactly "Store API POST $Base/submissions/$NewId/commit failed: $Text; diagnostics not shown (they could not be formatted)"
  }
  It 'Invoke-StoreApi: a refusal before sending stays not sent when its text cannot be formatted' {
    $s = New-FakeStore; Use-FakeStore $s
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp { throw (& (Get-Module MsStoreRunner) { New-StoreError 'refused: nothing was sent' -NotSent }) }
    Mock -ModuleName MsStoreRunner Format-StoreFailureText $CastFailure
    $e = InModuleScope MsStoreRunner -Parameters @{ P = "applications/$App/submissions/$NewId/commit" } { param($P) try { Invoke-StoreApi -Method POST -Path $P; $null } catch { $_ } }
    InModuleScope MsStoreRunner -Parameters @{ E = $e } { param($E) Test-StoreOutcomeUnknown $E } | Should -BeFalse
    "$e" | Should -BeExactly "Store API POST $Base/submissions/$NewId/commit failed: no HTTP response; diagnostics not shown (they could not be formatted)"
  }
  It 'a submission id or version in other digits is [invalid], and no request is sent for such an id' {
    $id = -join ('1152921505000000004'.ToCharArray() | ForEach-Object { [char](0x0660 + [int]"$_") })
    $ver = -join ('0.4.1.0'.ToCharArray() | ForEach-Object { if ($_ -eq '.') { '.' } else { [char](0xFF10 + [int]"$_") } })
    $json = @{ Id = $id; Status = 'Certification'; ApplicationPackages = @(@{ FileName = $File; FileStatus = 'Uploaded'; Version = $ver }) } | ConvertTo-Json -Depth 5 -Compress
    $c = Test-SubmissionHasPackage -SubmissionJson $json -ExpectedVersion '0.4.1.0'
    $c.Result | Should -Be 'Fail'
    $c.Id | Should -BeExactly '[invalid]'
    $c.Packages[0].Version | Should -BeExactly '[invalid]'
    ($c | ConvertTo-Json -Depth 5) | Should -Not -Match $OtherDigits
    $s = New-FakeStore; Use-FakeStore $s
    $r = Invoke-Captured { Invoke-SubmissionCommit -ProductId $App -SubmissionId $id }
    $r.Err | Should -BeExactly "submission id '[invalid]' is not a number"
    @($s.Calls).Count | Should -Be 0
  }

  Context 'publish (fake Store)' {
    BeforeEach { $script:Pkg = New-TestPackage }
    AfterEach { Remove-Item -LiteralPath (Split-Path $Pkg) -Recurse -Force }

    It 'create gets HTTP <Lost> (<When> it was carried out), error target <Case>: result unconfirmed, reads the app back, no delete advice' -ForEach @(
      @{ Case = 'with an Arabic-Indic index'; Lost = 503; When = 'After'; Target = "applicationPackages[$([char]0x0661)]"; Nested = $false }
      @{ Case = 'with a fullwidth index, in an error object'; Lost = 500; When = 'Before'; Target = "applicationPackages[$([char]0xFF11)$([char]0xFF12)]"; Nested = $true }
      @{ Case = 'with a Devanagari digit in the index'; Lost = 502; When = 'After'; Target = "applicationPackages[1$([char]0x0967)].version"; Nested = $false }
      @{ Case = 'with an Extended Arabic-Indic index deeper in the path'; Lost = 504; When = 'Before'; Target = "listings.baseListing.images[$([char]0x06F1)].imageType"; Nested = $false }
      @{ Case = 'with an unclosed index'; Lost = 503; When = 'Before'; Target = 'applicationPackages[0'; Nested = $false }
      @{ Case = 'with an empty index, in an error object'; Lost = 500; When = 'After'; Target = 'applicationPackages[]'; Nested = $true }
      @{ Case = 'that is a number'; Lost = 503; When = 'After'; Target = 42; Nested = $false }
    ) {
      $s = New-FakeStore -LoseResponse Create -LoseWhen $When -LoseAsStatus $Lost -LoseBody (New-TargetBody $Target -Nested:$Nested); Use-FakeStore $s
      $r = Invoke-Publish $Pkg
      $r.Err | Should -Match ("^Store API POST $([regex]::Escape($Base))/submissions\?isMinimalResponse=true failed: HTTP $Lost \(ServiceError\); $UnlistedServiceError\. " +
        'Result unconfirmed: the create request got no answer')
      if ($When -eq 'After') {
        $r.Err | Should -Match "a pending submission $NewId exists, origin unconfirmed"
        $r.Err | Should -Not -Match $RetryAdvice
      } else {
        $r.Err | Should -Match 'no pending submission yet\. That does not show none was created'
      }
      $r.Err | Should -Not -Match $RetryAdvice
      $r.All | Should -Not -Match "$DeleteAdvice|No submission was created|none had been created|Cannot convert|$OtherDigits"
      @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
    }
    It 'commit gets HTTP <Lost>, error target <Case>, commit carried out: reads it back by id, sees it committed, goes on' -ForEach @(
      @{ Case = 'with an Arabic-Indic index'; Lost = 503; Target = "applicationPackages[$([char]0x0661)]"; Nested = $false }
      @{ Case = 'with an Extended Arabic-Indic index, in an error object'; Lost = 504; Target = "applicationPackages[$([char]0x06F1)].fileName"; Nested = $true }
      @{ Case = 'that is a number'; Lost = 500; Target = 42; Nested = $false }
    ) {
      $s = New-FakeStore -LoseResponse Commit -LoseWhen After -LoseAsStatus $Lost -LoseBody (New-TargetBody $Target -Nested:$Nested); Use-FakeStore $s
      $r = Invoke-Publish $Pkg
      $r.Err | Should -BeNullOrEmpty
      $r.Value | Should -Be @($NewId)
      $r.Out | Should -Match "::warning title=Store commit::The commit request for submission $NewId got no answer, but read-back 1 by id shows status Certification: it was committed"
      $r.All | Should -Not -Match "$DeleteAdvice|was not accepted|Cannot convert|$OtherDigits"
      @($s.Log)[-2..-1] | Should -Be @("POST $Base/submissions/$NewId/commit", "GET $Base/submissions/$NewId")
    }
    It 'commit gets HTTP <Lost>, error target <Case>, commit not carried out: unconfirmed after 3 read-backs by id, no delete or retry advice' -ForEach @(
      @{ Case = 'with a fullwidth index'; Lost = 500; Target = "applicationPackages[$([char]0xFF11)$([char]0xFF12)]"; Nested = $false }
      @{ Case = 'with a Devanagari digit in the index'; Lost = 502; Target = "applicationPackages[1$([char]0x0967)].version"; Nested = $false }
      @{ Case = 'with three Arabic-Indic digits, in an error object'; Lost = 503; Target = "applicationPackages[$([char]0x0660)$([char]0x0661)$([char]0x0662)]"; Nested = $true }
      @{ Case = 'with an unclosed index'; Lost = 504; Target = 'applicationPackages[0'; Nested = $false }
      @{ Case = 'that is an object'; Lost = 503; Target = @{ name = 'pricing' }; Nested = $false }
    ) {
      $s = New-FakeStore -LoseResponse Commit -LoseWhen Before -LoseAsStatus $Lost -LoseBody (New-TargetBody $Target -Nested:$Nested); Use-FakeStore $s
      $r = Invoke-Publish $Pkg
      $r.Out | Should -Match ("::warning title=Store commit::Result unconfirmed: the commit request for submission $NewId got no answer " +
        "\(Store API POST $([regex]::Escape($Base))/submissions/$NewId/commit failed: HTTP $Lost \(ServiceError\); $UnlistedServiceError\)")
      $r.Err | Should -Match "Result unconfirmed: the commit request for submission $NewId got no answer, so it may or may not have been committed\. Read back by id 3 time\(s\), 0 s apart; last: read-back 3 of 3 shows status PendingCommit\."
      $r.Err | Should -Match "A person needs to check GET /v1\.0/my/applications/$App/submissions/$NewId later"
      $r.Err | Should -Not -Match $RetryAdvice
      $r.All | Should -Not -Match "$DeleteAdvice|was not accepted|Cannot convert|$OtherDigits"
      @($s.Log)[-4..-1] | Should -Be @("POST $Base/submissions/$NewId/commit", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId")
      @($s.Log) | Should -Not -Match '^DELETE '
    }
    It '<Step> gets HTTP 503 (<When> it was carried out) and <Fails> throws while its error is formatted: result unconfirmed, read back, no delete advice' -ForEach @(
      @{ Step = 'Create'; When = 'After'; Fails = 'Get-ListedTarget' }, @{ Step = 'Create'; When = 'After'; Fails = 'Format-StoreErrorText' }
      @{ Step = 'Commit'; When = 'Before'; Fails = 'Get-ListedTarget' }, @{ Step = 'Commit'; When = 'Before'; Fails = 'Format-StoreErrorText' }
    ) {
      $s = New-FakeStore -LoseResponse $Step -LoseWhen $When -LoseAsStatus 503 -LoseBody (New-TargetBody 'applicationPackages[0]'); Use-FakeStore $s
      Mock -ModuleName MsStoreRunner -CommandName $Fails -MockWith $CastFailure
      $r = Invoke-Publish $Pkg
      if ($Step -eq 'Create') {
        $r.Err | Should -Match ("^Store API POST $([regex]::Escape($Base))/submissions\?isMinimalResponse=true failed: HTTP 503; $NoDiag\. " +
          "Result unconfirmed: the create request got no answer.* a pending submission $NewId exists, origin unconfirmed")
        @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
      } else {
        $r.Out | Should -Match "::warning title=Store commit::Result unconfirmed: the commit request for submission $NewId got no answer \(Store API POST $([regex]::Escape($Base))/submissions/$NewId/commit failed: HTTP 503; $NoDiag\)"
        $r.Err | Should -Match 'Read back by id 3 time\(s\), 0 s apart; last: read-back 3 of 3 shows status PendingCommit\.'
        @($s.Log)[-4..-1] | Should -Be @("POST $Base/submissions/$NewId/commit", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId")
      }
      $r.Err | Should -Not -Match $RetryAdvice
      $r.All | Should -Not -Match "$DeleteAdvice|was not accepted|No submission was created|Cannot convert"
    }
    It 'a create response whose id is in other digits: that id is not used; created, id unknown, the app read back once' {
      $s = New-FakeStore; Use-FakeStore $s
      $s.NewId = -join ('1152921505000000099'.ToCharArray() | ForEach-Object { [char](0x0660 + [int]"$_") })
      $r = Invoke-Publish $Pkg
      $r.Err | Should -Match '^the create response \(HTTP 2xx\) has no usable submission id\. Created, id unknown: '
      $r.Err | Should -Match "Read-back of the app \(one GET\): a pending submission without a usable id\. A person needs to check the app's pending submission in Partner Center \(look only, change nothing there\) or with GET /v1\.0/my/applications/$App \(pendingApplicationSubmission\.id\)\."
      $r.All | Should -Not -Match "$DeleteAdvice|$RetryAdvice|$OtherDigits"
      @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
    }
  }
}

# Item r5: the publish step has one timeout, and nothing prints once the runner
# kills it. A fake clock stands in for time: the mocked Invoke-StoreHttp moves
# it on by what each call takes (or its timeout), Start-Sleep moves it on too.
Describe 'Time budget: the commit hand-off prints before the step can time out (fake Store, fake clock)' {
  BeforeAll {
    $script:T0 = [datetime]::new(2026, 11, 23, 1, 0, 0, [DateTimeKind]::Utc)
    $script:EB = [regex]::Escape($Base)
    Mock -ModuleName MsStoreRunner Get-StoreUtcNow { $global:FakeClock }
    Mock -ModuleName MsStoreRunner Start-Sleep { $global:FakeClock = $global:FakeClock.AddSeconds($Seconds) }
    # Publish, starting at T0, with the deadline msstore-publish.yml sets (18
    # minutes) unless Set overrides it; a $null value leaves that parameter out.
    function script:Invoke-TimedPublish([string]$Package, [hashtable]$Set = @{}) {
      $global:FakeClock = $T0
      $p = @{ ProductId = $App; PackagePath = $Package; ExpectedFileName = $File; ExpectedVersion = '0.4.1.0'; DeadlineUtc = $T0.AddMinutes(18) }
      foreach ($k in $Set.Keys) { if ($null -eq $Set[$k]) { $p.Remove($k) } else { $p[$k] = $Set[$k] } }
      Invoke-Captured { Publish-StoreSubmission @p }
    }
    function script:Get-CallsAfterCommit($Store) {
      $calls = @($Store.Calls)
      $c = [array]::IndexOf($calls, "POST $Base/submissions/$NewId/commit timeout=60")
      if ($c -lt 0) { return }
      $calls | Select-Object -Skip ($c + 1)
    }
  }
  BeforeEach { $script:Pkg = New-TestPackage; $global:FakeClock = $T0; $global:FakeTrace = $true }
  AfterEach {
    Remove-Item -LiteralPath (Split-Path $Pkg) -Recurse -Force; $global:FakeTrace = $false
    InModuleScope MsStoreRunner { $script:CallDeadline = $null }
  }
  AfterAll { $global:FakeClock = $null }

  It 'prints the id and how to check it before the commit is sent, and "result unconfirmed" before the first read-back (the commit hangs)' {
    $s = New-FakeStore -HangOn Commit; Use-FakeStore $s
    $r = Invoke-TimedPublish $Pkg
    $lines = @($r.Out -split "`n")
    $pre = Get-LineIndex $lines ("^committing submission $NewId \(waiting up to 60 s for the answer\)\. If this step ends before a commit result is " +
      "printed below, the result is unconfirmed: check GET $EB/submissions/$NewId by hand \(CommitStarted or a later status means it was committed\)")
    $post = Get-LineIndex $lines "^\[http\] POST $EB/submissions/$NewId/commit timeout=60$"
    $warn = Get-LineIndex $lines ("^::warning title=Store commit::Result unconfirmed: the commit request for submission $NewId got no answer " +
      "\(Store API POST $EB/submissions/$NewId/commit failed: no response \(time limit of 60 s for the whole request reached\)\)\. Reading it back by id " +
      "for up to 300 s\. If this step ends before a result is printed below, check GET $EB/submissions/$NewId by hand")
    $read = Get-LineIndex $lines "^\[http\] GET $EB/submissions/$NewId timeout=30$"
    $pre | Should -BeGreaterOrEqual 0
    $post | Should -BeGreaterThan $pre -Because 'the hand-off text is printed before the commit request is sent'
    $warn | Should -BeGreaterThan $post
    $read | Should -BeGreaterThan $warn -Because '"result unconfirmed" is printed before the first read-back'
    Get-CallsAfterCommit $s | Should -Be @(1..10 | ForEach-Object { "GET $Base/submissions/$NewId timeout=30" })
    ($global:FakeClock - $T0).TotalSeconds | Should -Be 330 -Because 'the commit waits 60 s, then 10 read-backs 30 s apart'
    $r.Err | Should -Match "Read back by id 10 time\(s\), 30 s apart; last: read-back 10 of 10 shows status PendingCommit\."
    $r.All | Should -Not -Match $DeleteAdvice
    $r.All | Should -Not -Match $RetryAdvice
    $r.All | Should -Not -Match $Leak
    $s.Sub.status | Should -Be 'PendingCommit'
  }
  It 'read-backs that hang: each GET waits at most <T> s and they stop within the <B> s budget (<Reads> read-back(s), <Secs> s)' -ForEach @(
    @{ T = 30; B = 300; Reads = 5; Secs = 270 }, @{ T = 5; B = 20; Reads = 1; Secs = 5 }
  ) {
    $s = New-FakeStore -LoseResponse Commit -LoseWhen Before -LoseAsStatus 504 -HangOn ReadBack; Use-FakeStore $s
    $r = Invoke-TimedPublish $Pkg @{ CommitReadBackTimeoutSeconds = $T; CommitReadBackBudgetSeconds = $B }
    Get-CallsAfterCommit $s | Should -Be @(1..$Reads | ForEach-Object { "GET $Base/submissions/$NewId timeout=$T" })
    ($global:FakeClock - $T0).TotalSeconds | Should -Be $Secs
    $r.Out | Should -Match "Result unconfirmed: the commit request for submission $NewId got no answer \(Store API POST $EB/submissions/$NewId/commit failed: HTTP 504; hint: a gateway in front of the service timed out\)\. Reading it back by id for up to $B s"
    $r.Err | Should -Match ("Read back by id $Reads time\(s\), 30 s apart \(stopped: the read-back time budget of $B s is used up\); last: read-back $Reads of 10 " +
      "failed \(Store API GET $EB/submissions/$NewId failed: no response \(time limit of $T s for the whole request reached\)\)")
    $r.Err | Should -Match "A person needs to check GET $EB/submissions/$NewId later"
    $r.All | Should -Not -Match $DeleteAdvice
    $r.All | Should -Not -Match $RetryAdvice
    $r.All | Should -Not -Match $Leak
  }
  It 'read-backs stop before DeadlineUtc when it comes before the end of the budget' {
    $s = New-FakeStore -HangOn ReadBack; Use-FakeStore $s
    $s.Sub = @{ id = $NewId; status = 'PendingCommit'; applicationPackages = @() }; $s.CommitTried = $true
    $r = Invoke-Captured { & (Get-Module MsStoreRunner) { param($a, $i, $d)
      $script:CallDeadline = $d.AddHours(1)
      Resolve-UnconfirmedCommit -ProductId $a -SubmissionId $i -Failure 'Store API POST x failed: HTTP 504' -DeadlineUtc $d } $App $NewId $T0.AddSeconds(100) }
    @($s.Calls) | Should -Be @("GET $Base/submissions/$NewId timeout=30", "GET $Base/submissions/$NewId timeout=30")
    ($global:FakeClock - $T0).TotalSeconds | Should -Be 90
    $r.Err | Should -Match "Read back by id 2 time\(s\), 30 s apart \(stopped: the step's deadline 2026-11-23 01:01:40Z is near\)"
    InModuleScope MsStoreRunner { $script:CallDeadline } | Should -Be $T0.AddSeconds(3700) -Because "the caller's call deadline is put back"
  }
  It 'upload close to 10 minutes, then a commit that hangs: the commit and every read-back still end before the deadline' {
    $s = New-FakeStore -UploadSeconds 599 -HangOn Commit; Use-FakeStore $s
    $r = Invoke-TimedPublish $Pkg
    @($s.Calls) | Should -Contain 'PUT (upload) timeout=600'
    Get-CallsAfterCommit $s | Should -Be @(1..10 | ForEach-Object { "GET $Base/submissions/$NewId timeout=30" })
    ($global:FakeClock - $T0).TotalSeconds | Should -Be 929 -Because 'upload 599 s, commit 60 s, read-backs 270 s'
    $global:FakeClock | Should -BeLessOrEqual $T0.AddMinutes(18)
    $r.Out | Should -Match "::warning title=Store commit::Result unconfirmed: the commit request for submission $NewId"
    $r.Err | Should -Match 'Read back by id 10 time\(s\), 30 s apart; last: read-back 10 of 10 shows status PendingCommit\.'
  }
  It 'cuts an upload that would run into the time kept for the commit, and stops uncommitted with delete-by-id advice' {
    $s = New-FakeStore -UploadSeconds 2000; Use-FakeStore $s
    $r = Invoke-TimedPublish $Pkg @{ DeadlineUtc = $T0.AddSeconds(860) }
    @($s.Calls) | Should -Contain 'PUT (upload) timeout=500' -Because '860 s minus the 360 s kept for the commit and its read-backs'
    ($global:FakeClock - $T0).TotalSeconds | Should -Be 500
    $r.Err | Should -Match "package upload failed: no response \(time limit of 500 s for the whole request reached\)\. Not committed: draft $NewId stays uncommitted"
    $r.Err | Should -Match $DeleteAdvice
    @($s.Log) | Should -Not -Contain "POST $Base/submissions/$NewId/commit"
  }
  It 'does not send the commit once the time kept for it has started, and stops uncommitted with delete-by-id advice' {
    $s = New-FakeStore -CallSeconds 5 -UploadSeconds 470; Use-FakeStore $s
    $r = Invoke-TimedPublish $Pkg @{ DeadlineUtc = $T0.AddSeconds(860) }
    @($s.Calls)[-2..-1] | Should -Be @('PUT (upload) timeout=475', "GET $Base/submissions/$NewId timeout=5")
    ($global:FakeClock - $T0).TotalSeconds | Should -Be 500 -Because 'the last call before the commit ends exactly where the kept time starts'
    $r.Err | Should -Match ("no time left for the commit: it and its read-backs need the last 360 s before the deadline 2026-11-23 01:14:20Z, " +
      "and that time has started\. Not committed: draft $NewId stays uncommitted")
    $r.Err | Should -Match $DeleteAdvice
    $r.Out | Should -Not -Match '^committing submission'
    @($s.Log) | Should -Not -Contain "POST $Base/submissions/$NewId/commit"
  }
  It 'a commit sent just before the time kept for it still waits its full 60 s, and its read-backs end before the deadline' {
    $s = New-FakeStore -CallSeconds 5 -UploadSeconds 465 -HangOn Commit; Use-FakeStore $s
    $r = Invoke-TimedPublish $Pkg @{ DeadlineUtc = $T0.AddSeconds(860) }
    $s.Calls | Should -Contain "POST $Base/submissions/$NewId/commit timeout=60" -Because 'the commit is sent at 495 s, 5 s before the kept time starts'
    Get-CallsAfterCommit $s | Should -Be (@(1..8 | ForEach-Object { "GET $Base/submissions/$NewId timeout=30" }) + "GET $Base/submissions/$NewId timeout=20")
    ($global:FakeClock - $T0).TotalSeconds | Should -Be 840 -Because 'commit 495-555 s, then 9 read-backs (5 s each, 30 s apart) inside the 300 s budget'
    $global:FakeClock | Should -BeLessOrEqual $T0.AddSeconds(860)
    $r.Out | Should -Match "::warning title=Store commit::Result unconfirmed: the commit request for submission $NewId got no answer"
    $r.Err | Should -Match ('Read back by id 9 time\(s\), 30 s apart \(stopped: the read-back time budget of 300 s is used up\); ' +
      'last: read-back 9 of 10 shows status PendingCommit\.')
    $r.All | Should -Not -Match $DeleteAdvice
  }
  It 'sends nothing when the deadline leaves no time for the work before the commit' {
    $s = New-FakeStore; Use-FakeStore $s
    $r = Invoke-TimedPublish $Pkg @{ DeadlineUtc = $T0.AddSeconds(400) }
    $r.Err | Should -BeExactly ('not publishing: the deadline 2026-11-23 01:06:40Z leaves less than 60 s for the work before the commit ' +
      '(360 s are kept for the commit and its read-backs); nothing was sent')
    @($s.Calls).Count | Should -Be 0
  }
  It 'without DeadlineUtc, the deadline is 18 minutes from the start' {
    $s = New-FakeStore; Use-FakeStore $s
    $r = Invoke-TimedPublish $Pkg @{ DeadlineUtc = $null; CommitReadBackBudgetSeconds = 1000 }
    $r.Err | Should -BeExactly ('not publishing: the deadline 2026-11-23 01:18:00Z leaves less than 60 s for the work before the commit ' +
      '(1060 s are kept for the commit and its read-backs); nothing was sent')
    @($s.Calls).Count | Should -Be 0
  }
  It 'refuses, before sending, a call with less than a second left before the call deadline, and marks it not sent' {
    $s = New-FakeStore; Use-FakeStore $s
    $e = & (Get-Module MsStoreRunner) { param($a, $now)
      $script:CallDeadline = $now.AddMilliseconds(500)
      try { Get-StoreApp $a; $null } catch { $_ } finally { $script:CallDeadline = $null }
    } $App $global:FakeClock 6>$null
    "$e" | Should -BeExactly "Store API GET $Base failed: not sent: no time left in this step's time budget"
    $e.Exception.Data['StoreOutcomeUnknown'] | Should -BeFalse
    @($s.Calls).Count | Should -Be 0
  }
  It 'cuts a call timeout to the whole seconds left before the call deadline' {
    $s = New-FakeStore; Use-FakeStore $s
    & (Get-Module MsStoreRunner) { param($a, $now)
      $script:CallDeadline = $now.AddSeconds(42.7)
      try { $null = Get-StoreApp $a } finally { $script:CallDeadline = $null }
    } $App $global:FakeClock 6>$null
    @($s.Calls) | Should -Be @("GET $Base timeout=42")
  }
  It 'leaves no call deadline behind after a run (<Case>)' -ForEach @(
    @{ Case = 'committed'; Opt = @{} }, @{ Case = 'stopped before the commit'; Opt = @{ UploadStatus = 403 } }, @{ Case = 'commit unconfirmed'; Opt = @{ HangOn = 'Commit' } }
  ) {
    $s = New-FakeStore @Opt; Use-FakeStore $s
    $null = Invoke-TimedPublish $Pkg
    InModuleScope MsStoreRunner { $script:CallDeadline } | Should -BeNullOrEmpty
    $global:FakeClock = $T0.AddHours(1); $s.Calls.Clear(); $s.HangOn = ''
    $null = & (Get-Module MsStoreRunner) { param($a, $i) Get-StoreSubmissionJson $a $i } $App $NewId 6>$null
    @($s.Calls) | Should -Be @("GET $Base/submissions/$NewId timeout=600")
  }
}

Describe 'Compare-SubmissionFields' {
  BeforeAll {
    $s = New-FakeStore
    $s.Sub = @{ id = $SubId; status = 'PendingCommit'; applicationPackages = @(@{ fileName = 'a.msixupload'; fileStatus = 'Uploaded' }) }
    $script:Before = Get-FakeSubmission $s
    $script:Kept = Get-SubmissionComparedFields -SubmissionJson $Before
    function script:Edit-Submission([scriptblock]$Change) {
      $o = [System.Text.Json.Nodes.JsonNodeOptions]::new(); $o.PropertyNameCaseInsensitive = $true
      $n = [System.Text.Json.Nodes.JsonNode]::Parse($Before, $o)
      & $Change $n
      $n.ToJsonString()
    }
  }
  It 'keeps no upload URL' {
    $Kept | Should -Not -Match 'fileUploadUrl|sig=|blob\.core|applicationPackages'
  }
  It 'reports nothing when only id, status, statusDetails, fileUploadUrl and the packages changed' {
    $after = Edit-Submission {
      param($n)
      $n['id'] = [System.Text.Json.Nodes.JsonValue]::Create('1'); $n['status'] = [System.Text.Json.Nodes.JsonValue]::Create('CommitStarted')
      $n['statusDetails'] = [System.Text.Json.Nodes.JsonValue]::Create('x'); $n['fileUploadUrl'] = [System.Text.Json.Nodes.JsonValue]::Create('https://other')
      $n['applicationPackages'] = [System.Text.Json.Nodes.JsonArray]::new()
    }
    $d = Compare-SubmissionFields -ExpectedJson $Kept -SubmissionJson $after
    $d.Changed | Should -BeNullOrEmpty
    $d.Compared | Should -Be 20
  }
  It 'reports nothing for other key order and key case' {
    $after = '{"Trailers":[],' + $Before.Substring(1).Replace('"pricing"', '"Pricing"')
    $after = $after.Replace(',"trailers":[]', '')
    (Compare-SubmissionFields -ExpectedJson $Kept -SubmissionJson $after).Changed | Should -BeNullOrEmpty
  }
  It 'reports <Field> when <Case>' -ForEach @(
    @{ Case = 'the price changed'; Field = 'pricing'; Change = { param($n) $n['pricing']['priceId'] = [System.Text.Json.Nodes.JsonValue]::Create('Tier1') } }
    @{ Case = 'a market price changed'; Field = 'pricing'; Change = { param($n) $n['pricing']['marketSpecificPricings']['HK'] = [System.Text.Json.Nodes.JsonValue]::Create('Free') } }
    @{ Case = 'a listing was dropped'; Field = 'listings'; Change = { param($n) [void]$n['listings'].AsObject().Remove('zh-hk') } }
    @{ Case = 'a listing title changed'; Field = 'listings'; Change = { param($n) $n['listings']['en-us']['baseListing']['title'] = [System.Text.Json.Nodes.JsonValue]::Create('X') } }
    @{ Case = 'visibility is gone'; Field = 'visibility'; Change = { param($n) [void]$n.Remove('visibility') } }
    @{ Case = 'the publish mode changed'; Field = 'targetPublishMode'; Change = { param($n) $n['targetPublishMode'] = [System.Text.Json.Nodes.JsonValue]::Create('Immediate') } }
    @{ Case = 'the publish date changed'; Field = 'targetPublishDate'; Change = { param($n) $n['targetPublishDate'] = [System.Text.Json.Nodes.JsonValue]::Create('2027-01-01T00:00:00Z') } }
    @{ Case = 'a device family changed'; Field = 'allowTargetFutureDeviceFamilies'; Change = { param($n) $n['allowTargetFutureDeviceFamilies']['Xbox'] = [System.Text.Json.Nodes.JsonValue]::Create($true) } }
    @{ Case = 'a field was added'; Field = 'newSetting'; Change = { param($n) $n['newSetting'] = [System.Text.Json.Nodes.JsonValue]::Create(1) } }
    @{ Case = 'a field with an odd name was added'; Field = '[unexpected field name]'; Change = { param($n) $n["x`n::error::pwned"] = [System.Text.Json.Nodes.JsonValue]::Create(1) } }
  ) {
    $after = Edit-Submission $Change
    $d = Compare-SubmissionFields -ExpectedJson $Kept -SubmissionJson $after
    @($d.Changed) | Should -Be @($Field)
  }
  It 'throws on JSON that is not an object' {
    { Compare-SubmissionFields -ExpectedJson $Kept -SubmissionJson 'Error' } | Should -Throw '*not an object*'
    { Compare-SubmissionFields -ExpectedJson $Kept -SubmissionJson '[1]' } | Should -Throw '*not an object*'
  }
}

Describe 'Fake Store package rules' {
  # The fake must refuse what the real service refuses, or the dry run proves nothing.
  It 'refuses a PUT whose new package lacks <Field>' -ForEach @(
    @{ Field = 'minimumDirectXVersion'; Value = $null }, @{ Field = 'minimumSystemRam'; Value = $null },
    @{ Field = 'minimumDirectXVersion'; Value = 'DirectX12' }, @{ Field = 'minimumSystemRam'; Value = 'Memory4GB' }
  ) {
    $s = New-FakeStore
    $s.Sub = @{ id = $SubId; status = 'PendingCommit'; applicationPackages = @() }
    $o = [System.Text.Json.Nodes.JsonNodeOptions]::new(); $o.PropertyNameCaseInsensitive = $true
    $n = [System.Text.Json.Nodes.JsonNode]::Parse((Set-SubmissionPackage -SubmissionJson (Get-FakeSubmission $s) -FileName $File), $o)
    $last = $n['applicationPackages'][$n['applicationPackages'].Count - 1]
    if ($null -eq $Value) { [void]$last.AsObject().Remove($Field) } else { $last[$Field] = [System.Text.Json.Nodes.JsonValue]::Create($Value) }
    $r = Invoke-FakeStoreRequest -Store $s -Method PUT -Uri "https://manage.devcenter.microsoft.com$Base/submissions/$SubId" `
      -Headers @{ Authorization = "Bearer $($s.Token)" } -BodyBytes ([Text.Encoding]::UTF8.GetBytes($n.ToJsonString()))
    $r.StatusCode | Should -Be 400
    $r.Body | Should -Match 'InvalidParameterValue'
  }
  It 'accepts the PUT that Set-SubmissionPackage builds' {
    $s = New-FakeStore
    $s.Sub = @{ id = $SubId; status = 'PendingCommit'; applicationPackages = @() }
    $body = Set-SubmissionPackage -SubmissionJson (Get-FakeSubmission $s) -FileName $File
    $r = Invoke-FakeStoreRequest -Store $s -Method PUT -Uri "https://manage.devcenter.microsoft.com$Base/submissions/$SubId" `
      -Headers @{ Authorization = "Bearer $($s.Token)" } -BodyBytes ([Text.Encoding]::UTF8.GetBytes($body))
    $r.StatusCode | Should -Be 200
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
          '{"fileName":"d.appx","fileStatus":"PendingDelete"},{"fileName":"' + $File + '","fileStatus":"PendingUpload",' +
          '"minimumDirectXVersion":"None","minimumSystemRam":"None"}]}')
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

# The real HTTP path (Invoke-StoreHttp is not mocked) against the fake Store
# served on 127.0.0.1, signed in with -LoopbackTestServer.
Describe 'HTTP path (fake Store on 127.0.0.1)' {
  BeforeEach {
    $script:Pkg = New-TestPackage
    $o = if ($Opt) { $Opt } else { @{} }
    $script:Srv = New-FakeStore @o
    $script:Url = Start-FakeStoreServer $Srv
  }
  AfterEach {
    Stop-FakeStoreServer $Srv
    Remove-Item -LiteralPath (Split-Path $Pkg) -Recurse -Force
    InModuleScope MsStoreRunner { $script:LoopbackTestServer = $false; $script:Token = '' }
  }

  # Item r3-3a: PowerShell 7.6 writes request URLs, headers and bodies to the
  # debug stream, 7.4/7.5 write request lines to the verbose stream.
  It 'writes no request detail to any stream with verbose and debug output on' {
    $saved = $global:VerbosePreference, $global:DebugPreference
    $records = [System.Collections.Generic.List[object]]::new()
    $err = ''
    try {
      $global:VerbosePreference = 'Continue'; $global:DebugPreference = 'Continue'
      $all = & {
        Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer -Verbose -Debug
        $id = Publish-StoreSubmission -ProductId $App -PackagePath $Pkg -ExpectedFileName $File -ExpectedVersion '0.4.1.0'
        Assert-SubmissionHasPackage -ProductId $App -SubmissionId $id -ExpectedVersion '0.4.1.0' -TimeoutMinutes 0 -IntervalSeconds 0
      } *>&1
      foreach ($x in $all) { $records.Add($x) }
    } catch { $err = "$_" } finally { $global:VerbosePreference, $global:DebugPreference = $saved }
    $err | Should -BeNullOrEmpty
    $text = ($records | ForEach-Object { if ($_ -is [System.Management.Automation.InformationRecord]) { [string]$_.MessageData } else { "$_" } }) -join "`n"
    $text | Should -Match "verified submission ${NewId}"
    $text | Should -Not -Match "$Leak|$([regex]::Escape($Srv.Token))|$([regex]::Escape($Url))"
    $noisy = @($records | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] -or $_ -is [System.Management.Automation.DebugRecord] } |
      Where-Object { "$_" -match 'HTTP/|payload|https?://|Bearer|client_secret|sig=' })
    $sample = @($noisy | Select-Object -First 3 | ForEach-Object { $t = ("$_" -replace '[^ -~]', '?'); $t.Substring(0, [Math]::Min(80, $t.Length)) }) -join ' | '
    $noisy.Count | Should -Be 0 -Because "no verbose or debug record may describe a request ($sample)"
  }

  # Item r3-3b: no redirect is followed (it could carry the secret, the token
  # or the package to another host).
  It 'does not follow a redirect of the token request' -ForEach @(@{ Opt = @{ Redirect = 'Token' } }) {
    $r = Invoke-Captured { Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer }
    $r.Err | Should -BeExactly 'could not get a Partner Center access token: HTTP 302'
    @($Srv.Log) | Should -Be @('POST /tenant-1/oauth2/v2.0/token')
  }
  It 'does not follow a redirect of the package upload' -ForEach @(@{ Opt = @{ Redirect = 'Upload' } }) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match 'package upload failed: HTTP 302\. Not committed'
    @($Srv.Log) | Should -Not -Match '/redirected/'
    @($Srv.Log) | Should -Not -Contain "POST $Base/submissions/$NewId/commit"
  }
  It 'does not follow a redirect of an API call' -ForEach @(@{ Opt = @{ Redirect = 'Api' } }) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match "GET $([regex]::Escape($Base)) failed: HTTP 302"
    @($Srv.Log) | Should -Not -Match '/redirected/'
  }
  # Run 45185550541 over HTTP: the create gets a 400 whose message carries secrets, advice and commands.
  It 'prints the listed target and the hint, not the message, of a create refused with HTTP 400, sends the query, deletes nothing' -ForEach @(@{ Opt = @{ CreateErrorStatus = 400 } }) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $Srv.CreateErrorBody = New-PlantedErrorBody $Srv.Token
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match ('^' + [regex]::Escape("Store API POST $Base/submissions?isMinimalResponse=true failed: $PlantedText. No submission was created and none was deleted. ") + '.*' + [regex]::Escape(': no pendingApplicationSubmission.') + '$')
    $r.All | Should -Not -Match "$Leak|$([regex]::Escape($Srv.Token))|$([regex]::Escape($Url))|$Injected|$PlantedWords|eyJ|AbCdEfGh|sv=2020|##\["
    $Srv.CreateQuery | Should -BeExactly '?isMinimalResponse=true'
    @($Srv.Log) | Should -Be @("POST /tenant-1/oauth2/v2.0/token", "GET $Base", "POST $Base/submissions", "GET $Base")
  }
  # Item r4-2 over HTTP: the commit gets a 504 while it is still processing.
  It 'reads a commit that got a 504 back by id until it shows CommitStarted, then goes on' -ForEach @(@{ Opt = @{ LoseResponse = 'Commit'; LoseWhen = 'Delayed'; LoseAsStatus = 504; CommitDelayReads = 1 } }) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $r = Invoke-Publish $Pkg
    $r.Err | Should -BeNullOrEmpty
    $r.Value | Should -Be @($NewId)
    $r.Out | Should -Match "not confirmed yet \(read-back 1 of 3 shows status PendingCommit\)"
    $r.Out | Should -Match "read-back 2 by id shows status CommitStarted: it was committed"
    $r.All | Should -Not -Match "$DeleteAdvice|$Leak"
    @($Srv.Log)[-3..-1] | Should -Be @("POST $Base/submissions/$NewId/commit", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId")
  }
  # Item r5 over HTTP: real HttpClient timeouts on calls that never get an answer.
  It 'commit that never answers: prints the hand-off first, gives up after its timeout, says "result unconfirmed", then reads back' -ForEach @(@{ Opt = @{ HangOn = 'Commit' } }) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-Captured { Publish-StoreSubmission -ProductId $App -PackagePath $Pkg -ExpectedFileName $File -ExpectedVersion '0.4.1.0' -CommitTimeoutSeconds 2 -CommitReadBackAttempts 2 -CommitReadBackIntervalSeconds 1 -CommitReadBackTimeoutSeconds 5 -CommitReadBackBudgetSeconds 20 }
    $sw.Stop()
    $lines = @($r.Out -split "`n")
    $pre = Get-LineIndex $lines "^committing submission $NewId \(waiting up to 2 s for the answer\)\. If this step ends before a commit result is printed below, the result is unconfirmed"
    $warn = Get-LineIndex $lines "^::warning title=Store commit::Result unconfirmed: the commit request for submission $NewId got no answer \(Store API POST $([regex]::Escape($Base))/submissions/$NewId/commit failed: no response \("
    $pre | Should -BeGreaterOrEqual 0
    $warn | Should -BeGreaterThan $pre
    $r.Err | Should -Match "Read back by id 2 time\(s\), 1 s apart; last: read-back 2 of 2 shows status PendingCommit\."
    $sw.Elapsed.TotalSeconds | Should -BeLessThan 20
    @($Srv.Log)[-3..-1] | Should -Be @("POST $Base/submissions/$NewId/commit", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId")
    $r.All | Should -Not -Match "$DeleteAdvice|$Leak|$([regex]::Escape($Url))"
    $seen = [regex]::Match($r.Out, 'commit failed: (no response \([^()]*\))').Groups[1].Value
    Write-Host "    commit timeout reported as: $seen"
  }
  It 'read-backs that never answer: each GET gives up after its timeout and they stop within the budget' -ForEach @(@{ Opt = @{ LoseResponse = 'Commit'; LoseWhen = 'Before'; LoseAsStatus = 504; HangOn = 'ReadBack' } }) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-Captured { Publish-StoreSubmission -ProductId $App -PackagePath $Pkg -ExpectedFileName $File -ExpectedVersion '0.4.1.0' -CommitReadBackIntervalSeconds 1 -CommitReadBackTimeoutSeconds 1 -CommitReadBackBudgetSeconds 4 }
    $sw.Stop()
    $log = @($Srv.Log)
    $reads = @($log | Select-Object -Skip ([array]::IndexOf($log, "POST $Base/submissions/$NewId/commit") + 1))
    $reads.Count | Should -BeGreaterOrEqual 1
    $reads.Count | Should -BeLessOrEqual 3
    $reads | Should -Be @(1..$reads.Count | ForEach-Object { "GET $Base/submissions/$NewId" })
    $r.Out | Should -Match "::warning title=Store commit::Result unconfirmed: the commit request for submission $NewId got no answer \(.*HTTP 504; hint: a gateway in front of the service timed out\)"
    $r.Err | Should -Match "Read back by id $($reads.Count) time\(s\), 1 s apart \(stopped: the read-back time budget of 4 s is used up\); last: read-back $($reads.Count) of 10 failed \(Store API GET .* failed: no response \("
    $sw.Elapsed.TotalSeconds | Should -BeLessThan 15
    $r.All | Should -Not -Match "$DeleteAdvice|$Leak|$([regex]::Escape($Url))"
  }
  # PR #74 r2 over HTTP: a 5xx whose error target has an index in other digits
  # (sent as JSON \u escapes, so the test does not depend on the charset).
  It 'commit that gets HTTP 503 with an Arabic-Indic index in the error target: result unconfirmed, read back by id, no delete advice' -ForEach @(
    @{ Opt = @{ LoseResponse = 'Commit'; LoseWhen = 'Before'; LoseAsStatus = 503; LoseBody = '{"code":"ServiceError","target":"applicationPackages[\u0661]","message":"x"}' } }
  ) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $r = Invoke-Publish $Pkg
    $r.Out | Should -Match ("::warning title=Store commit::Result unconfirmed: the commit request for submission $NewId got no answer \(Store API POST $([regex]::Escape($Base))/submissions/$NewId/commit " +
      'failed: HTTP 503 \(ServiceError\); target: \[unlisted target\]; hint: the service reported an internal error\)')
    $r.Err | Should -Match 'Read back by id 3 time\(s\), 0 s apart; last: read-back 3 of 3 shows status PendingCommit\.'
    $r.Err | Should -Not -Match $RetryAdvice
    $r.All | Should -Not -Match "$DeleteAdvice|was not accepted|Cannot convert|$OtherDigits|$Leak|$([regex]::Escape($Url))"
    @($Srv.Log)[-4..-1] | Should -Be @("POST $Base/submissions/$NewId/commit", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId")
  }
  It 'create that gets HTTP 502 with a fullwidth index in the error target: result unconfirmed, reads the app back, no delete advice' -ForEach @(
    @{ Opt = @{ LoseResponse = 'Create'; LoseWhen = 'After'; LoseAsStatus = 502; LoseBody = '{"error":{"code":"ServiceError","target":"applicationPackages[\uFF11\uFF12]","message":"x"}}' } }
  ) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match ('^' + [regex]::Escape("Store API POST $Base/submissions?isMinimalResponse=true failed: HTTP 502 (ServiceError); target: [unlisted target]; " +
      'hint: the service reported an internal error. Result unconfirmed: the create request got no answer'))
    $r.Err | Should -Match "a pending submission $NewId exists, origin unconfirmed"
    $r.Err | Should -Not -Match $RetryAdvice
    $r.All | Should -Not -Match "$DeleteAdvice|No submission was created|Cannot convert|$OtherDigits|$Leak|$([regex]::Escape($Url))"
    @($Srv.Log) | Should -Be @('POST /tenant-1/oauth2/v2.0/token', "GET $Base", "POST $Base/submissions", "GET $Base")
  }
  # PR #74 r3 (Pepper): Invoke-WebRequest -TimeoutSec bounds only the wait for
  # the headers (PowerShell 7.4+); a server that answers in time and then
  # drips its body held a GET with a 2 s limit for about 4.85 s. The limit now
  # covers the whole call. PR #74 r4: the status that came in is kept and the
  # body is marked lost with a fixed text (the caller classifies by status).
  It 'total time limit: a GET whose answer drips its body for 15 s gives up at its 2 s limit, keeping the status' -ForEach @(@{ Opt = @{ DripOn = 'AppRead'; DripSeconds = 15 } }) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-Captured { Invoke-StoreHttp -Method GET -Uri "$Url$Base" -Kind Api -Headers @{ Authorization = "Bearer $($Srv.Token)" } -TimeoutSec 2 }
    $sw.Stop()
    Write-Host "    GET with a 2 s limit and a 15 s body returned after $([Math]::Round($sw.Elapsed.TotalSeconds, 2)) s"
    $r.Err | Should -BeExactly ''
    $r.Value[0].StatusCode | Should -Be 200
    $r.Value[0].Body | Should -BeExactly ''
    $r.Value[0].BodyLost | Should -BeExactly 'body not received (time limit of 2 s for the whole request reached)'
    $sw.Elapsed.TotalSeconds | Should -BeLessThan 5
    @($Srv.Log) | Should -Be @('POST /tenant-1/oauth2/v2.0/token', "GET $Base")
  }
  It 'total time limit: one limit for headers and body together (headers after 3 s, then a 15 s body, 4 s limit: gives up at 4 s, not 3 + 4, keeping the status)' -ForEach @(@{ Opt = @{ DripOn = 'AppRead'; DripSeconds = 15; DripHeadSeconds = 3 } }) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-Captured { Invoke-StoreHttp -Method GET -Uri "$Url$Base" -Kind Api -Headers @{ Authorization = "Bearer $($Srv.Token)" } -TimeoutSec 4 }
    $sw.Stop()
    Write-Host "    GET with a 4 s limit, headers after 3 s and a 15 s body returned after $([Math]::Round($sw.Elapsed.TotalSeconds, 2)) s"
    $r.Err | Should -BeExactly ''
    $r.Value[0].StatusCode | Should -Be 200
    $r.Value[0].BodyLost | Should -BeExactly 'body not received (time limit of 4 s for the whole request reached)'
    $sw.Elapsed.TotalSeconds | Should -BeGreaterThan 3.5
    $sw.Elapsed.TotalSeconds | Should -BeLessThan 6
  }
  It 'total time limit: a GET whose body drips for 1 s, inside its 8 s limit, returns the whole body' -ForEach @(@{ Opt = @{ DripOn = 'AppRead'; DripSeconds = 1 } }) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $r = Invoke-StoreHttp -Method GET -Uri "$Url$Base" -Kind Api -Headers @{ Authorization = "Bearer $($Srv.Token)" } -TimeoutSec 8
    $r.StatusCode | Should -Be 200
    ($r.Body | ConvertFrom-Json).id | Should -BeExactly $App
    $Srv.Dripped | Should -BeExactly 'whole body sent'
  }
  It 'total time limit: create refused with HTTP 400, then the app read-back drips its body: the create error prints first, the read-back gives up at its limit, no advice, nothing secret' -ForEach @(
    @{ Opt = @{ CreateErrorStatus = 400; DripOn = 'AppReadAfterCreate'; DripSeconds = 15 } }
  ) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $Srv.CreateErrorBody = New-PlantedErrorBody $Srv.Token
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-Captured { New-StoreSubmission -ProductId $App -ReadBackTimeoutSec 2 }
    $sw.Stop()
    Write-Host "    refused create with a dripping read-back (2 s limit, 15 s body) returned after $([Math]::Round($sw.Elapsed.TotalSeconds, 2)) s"
    $refused = "Store API POST $Base/submissions?isMinimalResponse=true failed: $PlantedText. No submission was created and none was deleted."
    @($r.Out -split "`n")[0] | Should -BeExactly "create refused: $refused"
    $r.Err | Should -Match ('^' + [regex]::Escape("$refused ") + '.*' + [regex]::Escape(
        "Read-back of the app after the refused create (one GET; nothing changed or deleted): failed (Store API GET $Base failed: HTTP 200; body not received (time limit of 2 s for the whole request reached)).") + '$')
    $sw.Elapsed.TotalSeconds | Should -BeLessThan 6
    $r.All | Should -Not -Match "$DeleteAdvice|$RetryAdvice|$Leak|$([regex]::Escape($Srv.Token))|$([regex]::Escape($Url))|$Injected|$PlantedWords|eyJ|AbCdEfGh|sv=2020|##\["
    @($Srv.Log) | Should -Be @('POST /tenant-1/oauth2/v2.0/token', "POST $Base/submissions", "GET $Base")
  }
  # A failed step must throw the exception it failed with (not the
  # AggregateException around it), so the printed type chain stays as before.
  It 'a network failure (nothing listens on the port) throws the HttpRequestException itself; the text is the type chain only' {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0); $l.Start(); $port = $l.LocalEndpoint.Port; $l.Stop()
    $caught = $null
    try { $null = Invoke-StoreHttp -Method GET -Uri "http://127.0.0.1:$port$Base" -Kind Api -Headers @{ Authorization = "Bearer $($Srv.Token)" } -TimeoutSec 20 } catch { $caught = $_ }
    $caught | Should -Not -BeNullOrEmpty
    $caught.Exception.GetType().FullName | Should -BeExactly 'System.Net.Http.HttpRequestException'
    $text = & (Get-Module MsStoreRunner) { param($e) Get-StoreFailureText $e } $caught
    Write-Host "    nothing listening: $text"
    $text | Should -Match '^no response \(HttpRequestException( [A-Za-z]+)? <- SocketException [A-Za-z]+\)$'
    @($Srv.Log).Count | Should -Be 1
  }
  # Azure Blob Put Blob needs Content-Length (no chunked upload); the bearer
  # token never goes to the blob host.
  It 'the package upload carries Content-Length (not chunked), the block-blob headers, a User-Agent and no Authorization header' {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $r = Invoke-Captured { Publish-StoreSubmission -ProductId $App -PackagePath $Pkg -ExpectedFileName $File -ExpectedVersion '0.4.1.0' }
    $r.Err | Should -BeNullOrEmpty
    $Srv.Blob.Length | Should -BeGreaterThan 0
    $Srv.BlobHeaders['Content-Length'] | Should -BeExactly ([string]$Srv.Blob.Length)
    $Srv.BlobHeaders['Transfer-Encoding'] | Should -BeNullOrEmpty
    $Srv.BlobHeaders['Expect'] | Should -BeNullOrEmpty
    $Srv.BlobHeaders['Authorization'] | Should -BeNullOrEmpty
    $Srv.BlobHeaders['x-ms-blob-type'] | Should -BeExactly 'BlockBlob'
    $Srv.BlobHeaders['Content-Type'] | Should -BeExactly 'application/zip'
    $Srv.BlobHeaders['User-Agent'] | Should -BeExactly 'JerisLink-msstore-publish/1.0'
    @(Get-FakeUploadedZip $Srv)[0].Name | Should -BeExactly $File
  }
  # PR #74 r5: what differs from Invoke-WebRequest on the wire is checked in
  # the PR. These pin the parts that matter: a create or commit POST has no
  # body and no Content-Type (as the msstore CLI sends them; Invoke-WebRequest
  # added application/x-www-form-urlencoded), every request asks for gzip,
  # deflate or br as Invoke-WebRequest did, and an answer with an unknown
  # charset is read as UTF-8 (as Invoke-WebRequest read it), not lost.
  It 'create and commit POSTs carry no body and no Content-Type; every request asks for gzip, deflate, br' {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $r = Invoke-Captured { Publish-StoreSubmission -ProductId $App -PackagePath $Pkg -ExpectedFileName $File -ExpectedVersion '0.4.1.0' }
    $r.Err | Should -BeNullOrEmpty
    $posts = @($Srv.Seen | Where-Object { $_.Line -cmatch '^POST .*/submissions(/\d+/commit)?$' })
    @($posts | ForEach-Object { $_.Line }) | Should -Be @("POST $Base/submissions", "POST $Base/submissions/$($Srv.NewId)/commit")
    foreach ($p in $posts) {
      $p.Headers['Content-Length'] | Should -BeExactly '0'
      $p.Headers['Content-Type'] | Should -BeNullOrEmpty
    }
    @($Srv.Seen).Count | Should -BeGreaterThan 5
    foreach ($s in $Srv.Seen) { $s.Headers['Accept-Encoding'] | Should -BeExactly 'gzip, deflate, br' }
  }
  It 'an answer with the charset <CharSet> is read (<Why>), its body not lost' -ForEach @(
    @{ CharSet = 'x-bogus-zz'; Why = 'unknown: as UTF-8, as Invoke-WebRequest read it'; Opt = @{ AnswerContentType = 'application/json; charset=x-bogus-zz' } }
    @{ CharSet = 'utf-8'; Why = 'as UTF-8'; Opt = @{ AnswerContentType = 'application/json; charset=utf-8' } }
  ) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $r = Invoke-StoreHttp -Method GET -Uri "$Url$Base" -Kind Api -Headers @{ Authorization = "Bearer $($Srv.Token)" } -TimeoutSec 20
    $r.StatusCode | Should -Be 200
    $r.BodyLost | Should -BeExactly ''
    ($r.Body | ConvertFrom-Json).id | Should -BeExactly $App
    $r = Invoke-Captured { Assert-NoPendingSubmission -ProductId $App }
    $r.Err | Should -BeNullOrEmpty
  }
  # Pepper, PR #74 r4, over HTTP: the answer's status and headers arrive, then
  # its body drips past the call's time limit (or the connection breaks). The
  # status decides: 400 refused, 5xx unconfirmed; a 2xx is unconfirmed too.
  It 'create answered HTTP 400, body dripping past its 2 s limit: refused by its status, printed first, read back, no retry or delete advice, nothing secret' -ForEach @(
    @{ Opt = @{ CreateErrorStatus = 400; DripOn = 'Create'; DripSeconds = 15 } }
  ) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $Srv.CreateErrorBody = New-PlantedErrorBody $Srv.Token
    Mock -ModuleName MsStoreRunner Get-CallTimeout { [Math]::Min($Requested, 2) }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-Captured { New-StoreSubmission -ProductId $App }
    $sw.Stop()
    Write-Host "    create 400 with a dripping body (2 s limit, 15 s body) returned after $([Math]::Round($sw.Elapsed.TotalSeconds, 2)) s"
    $refused = "Store API POST $Base/submissions?isMinimalResponse=true failed: HTTP 400; hint: the request is invalid; " +
      'body not received (time limit of 2 s for the whole request reached). No submission was created and none was deleted.'
    @($r.Out -split "`n")[0] | Should -BeExactly "create refused: $refused"
    $r.Err | Should -Match ('^' + [regex]::Escape("$refused ") + '.*' + [regex]::Escape('Read-back of the app after the refused create (one GET; nothing changed or deleted): no pendingApplicationSubmission.') + '$')
    $sw.Elapsed.TotalSeconds | Should -BeLessThan 6
    $r.All | Should -Not -Match "Result unconfirmed|$DeleteAdvice|$RetryAdvice|$Leak|$([regex]::Escape($Srv.Token))|$([regex]::Escape($Url))|$Injected|$PlantedWords|eyJ|AbCdEfGh|sv=2020|##\["
    @($Srv.Log) | Should -Be @('POST /tenant-1/oauth2/v2.0/token', "POST $Base/submissions", "GET $Base")
  }
  It 'create answered HTTP 400, connection broken while the body is read: refused by its status, the fixed text says the connection broke' -ForEach @(
    @{ Opt = @{ CreateErrorStatus = 400; DripOn = 'Create'; DripSeconds = 1; DripEnd = 'Break' } }
  ) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $Srv.CreateErrorBody = New-PlantedErrorBody $Srv.Token
    Mock -ModuleName MsStoreRunner Get-CallTimeout { [Math]::Min($Requested, 20) }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-Captured { New-StoreSubmission -ProductId $App }
    $sw.Stop()
    @($r.Out -split "`n")[0] | Should -BeExactly ("create refused: Store API POST $Base/submissions?isMinimalResponse=true failed: HTTP 400; hint: the request is invalid; " +
      'body not received (the connection broke or the body could not be read). No submission was created and none was deleted.')
    $sw.Elapsed.TotalSeconds | Should -BeLessThan 15
    $Srv.Dripped | Should -BeExactly 'connection broken'
    $r.All | Should -Not -Match "Result unconfirmed|$DeleteAdvice|$RetryAdvice|$Leak|$Injected|$PlantedWords"
  }
  It 'create answered HTTP <Status>, body dripping past its 2 s limit: result unconfirmed by its status, the app read back, no retry or delete advice' -ForEach @(
    @{ Status = 503; Why = 'HTTP 503; hint: the service reported that it is unavailable'; Opt = @{ LoseResponse = 'Create'; LoseWhen = 'After'; LoseAsStatus = 503; LoseBody = '{"code":"ServiceUnavailable"}'; DripOn = 'Create'; DripSeconds = 15 } }
  ) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    Mock -ModuleName MsStoreRunner Get-CallTimeout { [Math]::Min($Requested, 2) }
    $r = Invoke-Captured { New-StoreSubmission -ProductId $App }
    $r.Err | Should -Match ('^' + [regex]::Escape("Store API POST $Base/submissions?isMinimalResponse=true failed: $Why; body not received (time limit of 2 s for the whole request reached). " +
      'Result unconfirmed: the create request got no answer'))
    $r.Err | Should -Match "a pending submission $NewId exists, origin unconfirmed"
    $r.All | Should -Not -Match "create refused|No submission was created|$DeleteAdvice|$RetryAdvice|$Leak|$([regex]::Escape($Url))"
    @($Srv.Log) | Should -Be @('POST /tenant-1/oauth2/v2.0/token', "POST $Base/submissions", "GET $Base")
  }
  # PR #74 r6: over real HTTP, a create answered HTTP 201 whose body never
  # arrives is "created, id unknown", never "not created".
  It 'create answered HTTP 201, body <How>, the read-back shows <Case>: created, id unknown, the run stops, no re-run or delete advice' -ForEach @(
    @{ How = 'dripping past its 2 s limit'; Case = 'the new pending submission'; Opt = @{ DripOn = 'Create'; DripSeconds = 15 } }
    @{ How = 'cut off'; Case = 'no pending submission yet'; Opt = @{ DripOn = 'Create'; DripSeconds = 1; DripEnd = 'Break'; PendingLag = $true } }
  ) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    Mock -ModuleName MsStoreRunner Get-CallTimeout { [Math]::Min($Requested, 2) }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-Captured { Publish-StoreSubmission -ProductId $App -PackagePath $Pkg -ExpectedFileName $File -ExpectedVersion '0.4.1.0' }
    $sw.Stop()
    $lost = if ($Opt.DripEnd -eq 'Break') { 'body not received (the connection broke or the body could not be read)' } else { 'body not received (time limit of 2 s for the whole request reached)' }
    $r.Out | Should -Match ('(?m)^' + [regex]::Escape("::warning title=Store create::Created, id unknown: the Store answered the create with HTTP 201, so it created a submission, but this run did not get its id (Store API POST $Base/submissions?isMinimalResponse=true failed: HTTP 201; $lost)."))
    $r.Err | Should -Match ('^' + [regex]::Escape("Store API POST $Base/submissions?isMinimalResponse=true failed: HTTP 201; $lost. Created, id unknown: the Store answered the create with HTTP 201"))
    if ($Opt.PendingLag) {
      $r.Err | Should -Match 'Read-back of the app \(one GET\): no pending submission yet\. That does not mean none was created'
    } else {
      $r.Err | Should -Match "Read-back of the app \(one GET\): pending submission $NewId\. Reported by id only: not updated, not committed, not deleted\."
    }
    $r.Value | Should -BeNullOrEmpty
    $sw.Elapsed.TotalSeconds | Should -BeLessThan 12
    $r.All | Should -Not -Match "Result unconfirmed|create refused|No submission was created|none had been created|nothing to clean up|$DeleteAdvice|$RetryAdvice|$Leak|$([regex]::Escape($Url))"
    @($Srv.Log) | Should -Be @('POST /tenant-1/oauth2/v2.0/token', "GET $Base", "POST $Base/submissions", "GET $Base")
    $Srv.Sub.status | Should -Be 'PendingCommit'
  }
  It 'commit answered HTTP <Status> (<Case>), body dripping past its 2 s limit: unconfirmed by its status, read back by id' -ForEach @(
    @{ Status = 503; Case = 'carried out'; Done = $true; Opt = @{ LoseResponse = 'Commit'; LoseWhen = 'After'; LoseAsStatus = 503; LoseBody = '{"code":"ServiceUnavailable"}'; DripOn = 'Commit'; DripSeconds = 15 } }
    @{ Status = 503; Case = 'not carried out'; Done = $false; Opt = @{ LoseResponse = 'Commit'; LoseWhen = 'Before'; LoseAsStatus = 503; LoseBody = '{"code":"ServiceUnavailable"}'; DripOn = 'Commit'; DripSeconds = 15 } }
    @{ Status = 200; Case = 'carried out'; Done = $true; Opt = @{ DripOn = 'Commit'; DripSeconds = 15 } }
  ) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $r = Invoke-Captured { Publish-StoreSubmission -ProductId $App -PackagePath $Pkg -ExpectedFileName $File -ExpectedVersion '0.4.1.0' -CommitTimeoutSeconds 2 -CommitReadBackAttempts 3 -CommitReadBackIntervalSeconds 0 }
    $why = if ($Status -eq 200) { 'HTTP 200' } else { 'HTTP 503; hint: the service reported that it is unavailable' }
    $r.Out | Should -Match ([regex]::Escape("Store API POST $Base/submissions/$NewId/commit failed: $why; body not received (time limit of 2 s for the whole request reached)"))
    if ($Done) {
      $r.Err | Should -BeNullOrEmpty
      $r.Value | Should -Be @($NewId)
      $got = if ($Status -eq 200) { "was accepted (HTTP 200) but its answer's body was not read;" } else { 'got no answer, but' }
      $r.Out | Should -Match ([regex]::Escape("::warning title=Store commit::The commit request for submission $NewId $got read-back 1 by id shows status Certification: it was committed"))
      @($Srv.Log)[-2..-1] | Should -Be @("POST $Base/submissions/$NewId/commit", "GET $Base/submissions/$NewId")
    } else {
      $r.Out | Should -Match "::warning title=Store commit::Result unconfirmed: the commit request for submission $NewId got no answer"
      $r.Err | Should -Match 'Read back by id 3 time\(s\), 0 s apart; last: read-back 3 of 3 shows status PendingCommit\.'
      $r.Err | Should -Not -Match $RetryAdvice
      @($Srv.Log)[-4..-1] | Should -Be @("POST $Base/submissions/$NewId/commit", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId")
    }
    $r.All | Should -Not -Match "$DeleteAdvice|was not accepted|$Leak|$([regex]::Escape($Url))"
  }
  # Pepper, PR #74 r4: the header values Invoke-WebRequest checked (through
  # HttpHeaders.Add) are checked again, and more strictly, before anything is
  # sent. The error names the header, never its value.
  It 'refuses an Authorization value with <Case> before sending; the error does not print the value' -ForEach @(
    @{ Case = 'CR LF and a second header'; V = "Bearer Zq7abc`r`nX-Zq7: 1" }, @{ Case = 'LF'; V = "Bearer Zq7abc`nX-Zq7: 1" }, @{ Case = 'CR'; V = "Bearer Zq7abc`rX-Zq7: 1" }
    @{ Case = 'NUL'; V = "Bearer Zq7abc$([char]0)Zq7" }, @{ Case = 'SOH'; V = "Bearer Zq7abc$([char]1)Zq7" }, @{ Case = 'TAB'; V = "Bearer Zq7abc`tZq7" }
    @{ Case = 'DEL'; V = "Bearer Zq7abc$([char]0x7F)Zq7" }, @{ Case = 'NEL'; V = "Bearer Zq7abc$([char]0x85)Zq7" }, @{ Case = 'a non-ASCII letter'; V = "Bearer Zq7abc$([char]0xE9)Zq7" }
    @{ Case = 'nothing (empty)'; V = '' }, @{ Case = 'only spaces'; V = '   ' }, @{ Case = 'a leading space'; V = ' Bearer Zq7abc' }, @{ Case = 'a trailing space'; V = 'Bearer Zq7abc ' }
    @{ Case = 'a comma (HttpHeaders.Add refuses it)'; V = 'Bearer Zq7abc,Zq7' }, @{ Case = 'an unclosed quote (HttpHeaders.Add refuses it)'; V = 'Bearer "Zq7abc' }
  ) {
    InModuleScope MsStoreRunner { $script:LoopbackTestServer = $true }
    $caught = $null
    try { $null = Invoke-StoreHttp -Method GET -Uri "$Url$Base" -Kind Api -Headers @{ Authorization = $V } -TimeoutSec 5 } catch { $caught = $_ }
    "$caught" | Should -BeExactly 'refused: request header Authorization has an invalid value (not printed); nothing was sent'
    $caught.Exception.Data['StoreNotSent'] | Should -BeTrue
    @($Srv.Log).Count | Should -Be 0
  }
  It 'refuses <Case> before sending' -ForEach @(
    @{ Case = 'an x-ms-blob-type value with CR LF'; Kind = 'Upload'; Path = '/blob/upload.zip'; H = @{ 'x-ms-blob-type' = "BlockBlob`r`nX-Zq7: 1" }; Text = 'refused: request header x-ms-blob-type has an invalid value (not printed); nothing was sent' }
    @{ Case = 'a Date value HttpHeaders.Add does not parse'; Kind = 'Api'; Path = ''; H = @{ Date = 'not a date' }; Text = 'refused: request header Date has an invalid value (not printed); nothing was sent' }
    @{ Case = 'a header name with a space'; Kind = 'Api'; Path = ''; H = @{ 'X Zq7' = 'v' }; Text = 'refused: a request header name is not valid; nothing was sent' }
  ) {
    InModuleScope MsStoreRunner { $script:LoopbackTestServer = $true }
    $caught = $null
    $u = if ($Path) { "$Url$Path" } else { "$Url$Base" }
    try { $null = Invoke-StoreHttp -Method PUT -Uri $u -Kind $Kind -Headers $H -Body 'x' -TimeoutSec 5 } catch { $caught = $_ }
    "$caught" | Should -BeExactly $Text
    $caught.Exception.Data['StoreNotSent'] | Should -BeTrue
    @($Srv.Log).Count | Should -Be 0
  }
  It 'refuses an access_token with <Case> from the token endpoint: not signed in, the token is not printed, no API call' -ForEach @(
    @{ Case = 'CR LF'; T = "Zq7abc`r`nX-Zq7: 1" }, @{ Case = 'a space'; T = 'Zq7abc Zq7' }, @{ Case = 'SOH'; T = "Zq7abc$([char]1)Zq7" }
    @{ Case = 'a quote'; T = 'Zq7abc"Zq7' }, @{ Case = 'a comma'; T = 'Zq7abc,Zq7' }, @{ Case = 'a non-ASCII letter'; T = "Zq7abc$([char]0xE9)Zq7" }
    @{ Case = '= before the end'; T = 'Zq7abc=Zq7' }, @{ Case = 'a trailing LF'; T = "Zq7abc`n" }
  ) {
    $Srv.Token = $T
    $r = Invoke-Captured { Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer }
    $r.Err | Should -BeExactly "the token response's access_token is not a valid bearer token (it is not printed); not signed in"
    (& (Get-Module MsStoreRunner) { $script:Token }) | Should -BeNullOrEmpty
    $r.All | Should -Not -Match 'Zq7'
    @($Srv.Log) | Should -Be @('POST /tenant-1/oauth2/v2.0/token')
  }
  It 'accepts a JWT-shaped access token (letters, digits, - . _ ~ + / and = padding) and uses it' {
    $Srv.Token = 'eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiJ4In0.c2ln-_~+/x=='
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $r = Invoke-Captured { Assert-NoPendingSubmission -ProductId $App }
    $r.Err | Should -BeNullOrEmpty
    @($Srv.Log) | Should -Be @('POST /tenant-1/oauth2/v2.0/token', "GET $Base")
  }
  It 'does not send an API call when the token in memory is not a valid bearer token (<Case>): fixed text, nothing printed of it' -ForEach @(
    @{ Case = 'CR LF'; T = "Zq7abc`r`nX-Zq7: 1" }, @{ Case = 'a space'; T = 'Zq7abc Zq7' }, @{ Case = 'DEL'; T = "Zq7abc$([char]0x7F)" }
  ) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    & (Get-Module MsStoreRunner) { param($t) $script:Token = $t } $T
    $r = Invoke-Captured { New-StoreSubmission -ProductId $App }
    $r.Err | Should -Match ('^' + [regex]::Escape("Store API POST $Base/submissions?isMinimalResponse=true failed: not sent: the access token is not a valid bearer token (it is not printed). No submission was created and none was deleted."))
    $r.All | Should -Not -Match 'Zq7'
    @($Srv.Log) | Should -Be @('POST /tenant-1/oauth2/v2.0/token')
  }
  It 'sends nothing to a loopback stand-in without -LoopbackTestServer' {
    $r = Invoke-Captured { Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url }
    $r.Err | Should -Match '^refused: '
    @($Srv.Log).Count | Should -Be 0
  }
}
