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
  # status 0 throws what HttpClient throws when no answer comes back; status
  # -2 throws the module's "not sent" error. Each call
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
      if ($r.StatusCode -eq -2) { throw (& (Get-Module MsStoreRunner) { New-StoreError "not sent: no time left in this step's time budget" -NotSent }) }
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
    Reset-StoreSecrets
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret 6>$null
    $Store.Log.Clear(); $Store.Calls.Clear()
  }

  # Each fake Store run is one workflow step, a new PowerShell session: it
  # starts with no known credentials (the module keeps them for the whole
  # session, so without this they would pile up across tests).
  # The memo of registered texts (SecretInputs) is cleared too, where the
  # module has one (the r9 module has none, and the r10 tests run on it too).
  function script:Reset-StoreSecrets {
    & (Get-Module MsStoreRunner) {
      $script:KnownSecrets.Clear(); $script:SecretPattern = $null
      if (Get-Variable -Name SecretInputs -Scope Script -ErrorAction Ignore) { $script:SecretInputs.Clear() }
      if (Get-Variable -Name ConfirmedSecrets -Scope Script -ErrorAction Ignore) { $script:ConfirmedSecrets.Clear(); $script:ConfirmedPattern = $null }
    }
  }

  function script:New-TestPackage {
    $dir = Join-Path ([IO.Path]::GetTempPath()) ('pkg-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $dir | Out-Null
    $p = Join-Path $dir $File
    [IO.File]::WriteAllBytes($p, [byte[]](0..255 + 0..255))
    $p
  }

  # Prices: the fake's priceId, trialPeriod, market and sale prices, and the
  # ones tests set. None may be printed, by any publish run (Pepper, PR #75
  # r1: run 45524510567 printed "pricing.priceId=Free is kept as is").
  # Matched in this case only, so fixed text such as "make the product free"
  # does not count.
  $script:PriceValues = '\bFree\b|\bBase\b|\bNotAvailable\b|Tier[0-9]|NoFreeTrial|OneWeek|Launch sale'
  # Every publish run through this helper, whatever it ends with, is checked
  # for prices.
  function script:Invoke-Publish([string]$Package) {
    $r = Invoke-Captured { Publish-StoreSubmission -ProductId $App -PackagePath $Package -ExpectedFileName $File -ExpectedVersion '0.4.1.0' -CommitReadBackAttempts 3 -CommitReadBackIntervalSeconds 0 }
    $r.All | Should -Not -MatchExactly $PriceValues -Because 'a publish run never prints a price (Pepper, PR #75 r1)'
    $r
  }

  $script:Base = "/v1.0/my/applications/$App"
  $script:NewId = '1152921505000000099'
  # Advice that must not be given while a result is unconfirmed: delete by id
  # (Get-DeleteByIdText), or retry (re-run, commit again). "do not re-run" is
  # not advice to re-run.
  $script:DeleteAdvice = 'DELETE /v1|Remove-StoreDraftSubmission|Delete exactly'
  $script:RetryAdvice = '(?<!do not )re-run this workflow|\bretry\b|commit (it )?again'
  # What a stop says of a Store answer that is not read (Pepper, PR #74 r10:
  # an answer is read only as one complete JSON object with each key once).
  $script:UnreadAnswer = 'no JSON object that can be read (an answer is read only as one complete JSON object with each key once)'
  $script:UnreadSubmission = ('no submission JSON that can be read (an answer is read only as one complete JSON object with each key once, ' +
    'and applicationPackages, when given, as a list of objects)')
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
    $r = Test-SubmissionHasPackage -SubmissionJson (Fixture 'new-package-only') -ExpectedVersion '0.4.1.0' -ExpectedSubmissionId $SubId -ExpectedFileName 'Jerislink-0.4.1.0-x64.msix'
    $r.Result | Should -Be 'Pass'
    $r.Id | Should -Be $SubId
    $r.Status | Should -Be 'PreProcessing'
    $r.TargetPublishMode | Should -Be 'Immediate'
    $r.Packages.Count | Should -Be 1
    $r.Packages[0].FileName | Should -BeExactly 'Jerislink-0.4.1.0-x64.msix'
    $r.Packages[0].Version | Should -Be '0.4.1.0'
    $r.Packages[0].FileStatus | Should -Be 'Uploaded'
  }
  # Pepper, PR #74 r8: a file name from the API is shown only when it is
  # exactly this run's file; any other name, or no expected name, is
  # "[file name not shown]".
  It 'does not show a file name that is not this run''s file (<Case>)' -ForEach @(
    @{ Case = 'no expected name'; Expected = '' }
    @{ Case = 'another expected name'; Expected = 'Jerislink-0.4.2.0-x64.msix' }
    @{ Case = 'the expected name in another case'; Expected = 'JERISLINK-0.4.1.0-X64.MSIX' }
  ) {
    $r = Test-SubmissionHasPackage -SubmissionJson (Fixture 'new-package-only') -ExpectedVersion '0.4.1.0' -ExpectedSubmissionId $SubId -ExpectedFileName $Expected
    $r.Result | Should -Be 'Pass'
    $r.Packages[0].FileName | Should -BeExactly '[file name not shown]'
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
    $r.Reason | Should -Match '2 package\(s\) would remain after commit \(\[file name not shown\] version=0\.3\.0\.0 fileStatus=Uploaded; Jerislink-0\.4\.1\.0-x64\.msixupload version= fileStatus=PendingUpload\)'
  }

  It 'fails when a second old package with the same extension stays' {
    $r = Test-DraftReadyToCommit -SubmissionJson (Fixture 'draft-two-old-same-extension') -SubmissionId $SubId -ExpectedFileName $NewFile -ExpectedVersion '0.4.1.0'
    $r.Result | Should -Be 'Fail'
    $r.Reason | Should -Match '2 package\(s\) would remain after commit \(\[file name not shown\] version=0\.3\.0\.0 fileStatus=Uploaded; '
    $r.Reason | Should -Not -Match 'arm64'
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
    @{ Case = 'a code with a line break and a workflow command'; Code = 500; Want = 'HTTP 500 ([unlisted code])'; Body = '{"code":"Bad\n::error::pwned"}' }
    @{ Case = 'a code with an unescaped line break (not JSON that can be read)'; Code = 500; Want = 'HTTP 500'; Body = "{`"code`":`"Bad`n::error::pwned`"}" }
    @{ Case = 'a code that is a URL'; Code = 400; Want = 'HTTP 400 ([unlisted code])'; Body = '{"code":"https://evil.invalid/x?sig=FAKE+SAS"}' }
    @{ Case = 'an HTML page'; Code = 502; Want = 'HTTP 502'; Body = '<html><body>Bad gateway https://evil.invalid ::error::pwned</body></html>' }
    @{ Case = 'an empty body'; Code = 404; Want = 'HTTP 404'; Body = '' }
    # Pepper, PR #74 r10: each field only in its own JSON type (the 127f676
    # module read a code in a list as its text, and error_codes as text or in
    # a nested list as numbers).
    @{ Case = 'error.code in a list'; Code = 400; Want = 'HTTP 400 ([unlisted code])'; Body = '{"error":{"code":["InvalidParameterValue"]}}' }
    @{ Case = 'error.code an object'; Code = 400; Want = 'HTTP 400 ([unlisted code])'; Body = '{"error":{"code":{"code":"InvalidParameterValue"}}}' }
    @{ Case = 'code in a list'; Code = 400; Want = 'HTTP 400'; Body = '{"code":["InvalidParameterValue"]}' }
    @{ Case = 'error_codes as text, not a list'; Code = 401; Want = 'HTTP 401 (invalid_client)'; Body = '{"error":"invalid_client","error_codes":"7000215"}' }
    @{ Case = 'error_codes a number, not a list'; Code = 401; Want = 'HTTP 401 (invalid_client)'; Body = '{"error":"invalid_client","error_codes":7000215}' }
    @{ Case = 'error_codes, a number as text'; Code = 401; Want = 'HTTP 401 (invalid_client)'; Body = '{"error":"invalid_client","error_codes":["7000215"]}' }
    @{ Case = 'error_codes, a number in a nested list'; Code = 401; Want = 'HTTP 401 (invalid_client)'; Body = '{"error":"invalid_client","error_codes":[[7000215]]}' }
    @{ Case = 'error_codes, an object'; Code = 401; Want = 'HTTP 401 (invalid_client)'; Body = '{"error":"invalid_client","error_codes":{"c":7000215}}' }
    @{ Case = 'error_codes, a number with a fraction'; Code = 401; Want = 'HTTP 401 (invalid_client)'; Body = '{"error":"invalid_client","error_codes":[7000215.0]}' }
    @{ Case = 'error_codes given twice'; Code = 401; Want = 'HTTP 401'; Body = '{"error":"invalid_client","error_codes":[],"error_codes":[7000215]}' }
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
    $t | Should -Match "^HTTP $Code(?: \((?:[A-Za-z]+|\[unlisted code\])\))?; hint: $([regex]::Escape($Hint))\z"
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
  It 'turns every field that is not a listed or plain value into a fixed mark in the check results' {
    $a = Test-SubmissionHasPackage -SubmissionJson $Evil -ExpectedVersion '0.4.1.0' -ExpectedFileName $File
    $b = Test-DraftReadyToCommit -SubmissionJson $Evil -SubmissionId $SubId -ExpectedFileName $File -ExpectedVersion '0.4.1.0'
    foreach ($r in $a, $b) {
      $r.Result | Should -Be 'Fail'
      $r.Id | Should -BeExactly '[invalid]'
      $r.Status | Should -BeExactly '[unlisted]'
      $r.TargetPublishMode | Should -BeExactly '[unlisted]'
      $r.Packages[0].FileName | Should -BeExactly '[file name not shown]'
      $r.Packages[0].Version | Should -BeExactly '[invalid]'
      $r.Packages[0].FileStatus | Should -BeExactly '[unlisted]'
      ($r | ConvertTo-Json -Depth 5) | Should -Not -Match $Injected
    }
  }
  It 'prints no injected text while checking a committed submission' {
    $s = New-FakeStore; Use-FakeStore $s
    $s.Sub = @{ id = $SubId; status = "Certification`n::error::pwned"; applicationPackages = @(@{ fileName = "$File`n::warning::pwned"; fileStatus = 'Uploaded'; version = '0.4.1.0' }) }
    $r = Invoke-Captured { Assert-SubmissionHasPackage -ProductId $App -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -TimeoutMinutes 0 -IntervalSeconds 0 }
    $r.Err | Should -Match "status is '\[unlisted\]', not a committed status"
    $r.All | Should -Not -Match $Injected
    $r.Out | Should -Match 'package fileName=\[file name not shown\] version=0\.4\.1\.0 fileStatus=Uploaded'
  }
  It 'prints no injected commit status' {
    $s = New-FakeStore; Use-FakeStore $s
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp { [pscustomobject]@{ StatusCode = 200; Body = '{"status":"CommitStarted\n::error::pwned"}' } }
    $r = Invoke-Captured { Invoke-SubmissionCommit -ProductId $App -SubmissionId $SubId }
    $r.Out | Should -BeExactly "submission $SubId commit requested through the API: status=[unlisted]"
  }
  It 'prints no injected priceId' {
    $r = Test-SubmissionPricing -SubmissionJson '{"pricing":{"priceId":"Free\n::error::pwned"}}'
    $r.Reason | Should -BeExactly 'pricing.priceId is set and is kept as is (the price is not printed)'
  }
  It 'prints no injected pending submission id' {
    $appJson = "{`"id`":`"$App`",`"pendingApplicationSubmission`":{`"id`":`"1\n::error::pwned`"}}"
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
    $r.Out | Should -Match ([regex]::Escape('fields unchanged: 19 submission fields other than applicationPackages and friendlyName read back as before the update (pricing: priceId, trialPeriod and the market prices; packageDeliveryOptions: all but the package rollout status and fallback submission id Partner Center sets)'))
    $r.All | Should -Not -Match $Leak
  }

  # Run 45524510567: after the PUT the real Store gave the draft a new
  # friendlyName and rearranged pricing (sales emptied, isAdvancedPricingModel
  # changed, the markets in another order), with the price itself unchanged.
  # The fake does the same on every PUT; the run must still commit.
  It 'commits when the Store only renamed the draft and rearranged its pricing after the update (run 45524510567)' {
    $s = New-FakeStore; Use-FakeStore $s
    $before = ConvertFrom-Json $s.Fields -AsHashtable
    @($before.pricing.sales).Count | Should -Be 1
    $before.pricing.isAdvancedPricingModel | Should -BeFalse
    @($before.pricing.marketSpecificPricings.Keys) | Should -Be @('HK', 'US', 'GB')
    $r = Invoke-Publish $Pkg
    $r.Err | Should -BeNullOrEmpty
    @($s.Log) | Should -Contain "POST $Base/submissions/$NewId/commit"
    $s.Sub.status | Should -Be 'Certification'
    # What the fake did to the fields on the PUT.
    $after = ConvertFrom-Json $s.Fields -AsHashtable
    $after.friendlyName | Should -BeExactly 'Submission 2 (updated)'
    @($after.pricing.sales).Count | Should -Be 0
    $after.pricing.isAdvancedPricingModel | Should -BeTrue
    @($after.pricing.marketSpecificPricings.Keys) | Should -Be @('GB', 'US', 'HK')
    $after.pricing.priceId | Should -BeExactly 'Free'
    $after.pricing.trialPeriod | Should -BeExactly 'NoFreeTrial'
    $after.pricing.marketSpecificPricings.HK | Should -BeExactly 'Tier2'
    $r.All | Should -Not -Match $Leak
    $r.All | Should -Not -MatchExactly 'Tier\d|Launch sale|Submission 2'
  }

  # Pepper, PR #75 r1: the price check printed the priceId. It prints fixed
  # text now, and no price (priceId, trialPeriod, a market or sale price) is
  # printed anywhere in the run (Invoke-Publish checks that for every run).
  It 'prints no price anywhere in a publish run; the price check line is fixed text (priceId <PriceId>)' -ForEach @(
    @{ PriceId = 'Free' }, @{ PriceId = 'Tier7' }, @{ PriceId = 'NotAvailable' }
  ) {
    $s = New-FakeStore -PriceId $PriceId; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -BeNullOrEmpty
    @($s.Log) | Should -Contain "POST $Base/submissions/$NewId/commit"
    $r.Out | Should -Match '(?m)^price check: pricing\.priceId is set and is kept as is \(the price is not printed\)$'
    $r.All | Should -Not -MatchExactly ([regex]::Escape($PriceId))
    $r.All | Should -Not -MatchExactly $PriceValues
  }

  # Partner Center sets packageDeliveryOptions.packageRollout.packageRolloutStatus
  # and fallbackSubmissionId itself ("Manage app submissions", Package rollout
  # resource: "assigned by Partner Center, and are not intended to be set by
  # the developer"). A change of them after the PUT does not stop the run.
  It 'commits when Partner Center only set its own package rollout fields after the update (packageRolloutStatus, fallbackSubmissionId)' {
    $s = New-FakeStore -DriftOnPut StoreSetRollout; Use-FakeStore $s
    $before = ConvertFrom-Json $s.Fields -AsHashtable
    $before.packageDeliveryOptions.packageRollout.packageRolloutStatus | Should -BeExactly 'PackageRolloutNotStarted'
    $before.packageDeliveryOptions.packageRollout.fallbackSubmissionId | Should -BeExactly '0'
    $r = Invoke-Publish $Pkg
    $r.Err | Should -BeNullOrEmpty
    @($s.Log) | Should -Contain "POST $Base/submissions/$NewId/commit"
    $s.Sub.status | Should -Be 'Certification'
    $after = ConvertFrom-Json $s.Fields -AsHashtable
    $after.packageDeliveryOptions.packageRollout.packageRolloutStatus | Should -BeExactly 'PackageRolloutInProgress'
    $after.packageDeliveryOptions.packageRollout.fallbackSubmissionId | Should -BeExactly '1152921505000000042'
    $after.packageDeliveryOptions.packageRollout.packageRolloutPercentage | Should -Be 0
    $after.packageDeliveryOptions.isMandatoryUpdate | Should -BeFalse
    $r.Out | Should -Match 'fields unchanged: 19 submission fields'
    $r.All | Should -Not -MatchExactly 'PackageRollout(NotStarted|InProgress)|1152921505000000042'
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

  # Item r3-2: everything but the packages, friendlyName and the pricing
  # fields the Store rewrites must read back as it was. Each drift comes on
  # top of the rename and the rearranged pricing (which alone pass).
  It 'stops uncommitted when the update changed <Case>, and names the path, not the values' -ForEach @(
    @{ Case = 'the price (priceId)'; Drift = 'Pricing'; Field = 'pricing'; Path = 'pricing.priceId' }
    @{ Case = 'a market price'; Drift = 'MarketPrice'; Field = 'pricing'; Path = 'pricing.marketSpecificPricings.HK' }
    @{ Case = 'the markets (one added)'; Drift = 'AddMarket'; Field = 'pricing'; Path = 'pricing.marketSpecificPricings.JP' }
    @{ Case = 'the markets (one removed)'; Drift = 'RemoveMarket'; Field = 'pricing'; Path = 'pricing.marketSpecificPricings.US' }
    @{ Case = 'the listings (one dropped)'; Drift = 'DropListing'; Field = 'listings'; Path = 'listings.zh-hk' }
    # Partner Center also set its own rollout fields; only the field this run
    # controls is named.
    @{ Case = 'the package rollout percentage, with the rollout fields Partner Center sets'; Drift = 'RolloutPercentage'; Field = 'packageDeliveryOptions'; Path = 'packageDeliveryOptions.packageRollout.packageRolloutPercentage' }
    @{ Case = 'the mandatory update setting, with the rollout fields Partner Center sets'; Drift = 'MandatoryUpdate'; Field = 'packageDeliveryOptions'; Path = 'packageDeliveryOptions.isMandatoryUpdate' }
  ) {
    $s = New-FakeStore -DriftOnPut $Drift; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match ("submission fields changed after this run's update: $Field\. Paths that differ \(values not printed\): " +
      [regex]::Escape($Path) + '\. Only applicationPackages, friendlyName, the pricing fields other than priceId, trialPeriod and the market ' +
      'prices, and the package rollout status and fallback submission id Partner Center sets may change')
    $r.All | Should -Not -MatchExactly 'Tier\d|Launch sale|Submission 2|NoFreeTrial|PackageRollout(NotStarted|InProgress)|1152921505000000042'
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

  # Run 45524510567 left draft 1152921505702498903 PendingCommit. Step 1 still
  # stops on such a draft and sends nothing to it; it reads its status by id
  # (one GET) and says a person decides, with the draft id.
  It 'stops before create on an existing PendingCommit draft: names the draft, says a person decides, sends nothing to it' {
    $s = New-FakeStore -PendingId '1152921505000000007'; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match ([regex]::Escape("Partner Center already has a pending submission 1152921505000000007 for ${App}: an uncommitted draft (status PendingCommit). " +
      'This run did not create it, so it stops and touches nothing: it does not delete, change or commit draft 1152921505000000007. ' +
      'A person decides what happens to draft 1152921505000000007. To look at it without changing anything, run this workflow with mode=diagnose ' +
      'and submission_id=1152921505000000007 (GET calls only).'))
    $r.Err | Should -Match "If the person decides to discard it: .*DELETE /v1\.0/my/applications/$App/submissions/1152921505000000007 "
    $r.Err | Should -Match "Remove-StoreDraftSubmission -ProductId $App -SubmissionId 1152921505000000007"
    @($s.Log) | Should -Be @("GET $Base", "GET $Base/submissions/1152921505000000007")
    $s.PendingId | Should -BeExactly '1152921505000000007'
    $r.All | Should -Not -Match $Leak
    $r.All | Should -Not -MatchExactly 'Tier\d|Launch sale|Submission 2'
  }

  It 'stops before create on a pending submission <Case>: no delete advice, a person decides, sends nothing to it' -ForEach @(
    @{ Case = 'in certification'; Status = 'Certification'; Shown = 'Certification' }
    @{ Case = 'in a status not listed'; Status = "Odd`n::error::pwned"; Shown = '[unlisted]' }
  ) {
    $s = New-FakeStore -PendingId '1152921505000000007' -PendingStatus $Status; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match ([regex]::Escape("Partner Center already has a pending submission 1152921505000000007 for $App (status $Shown, not an uncommitted PendingCommit draft). " +
      'This run did not create it, so it stops and touches nothing (it never deletes, changes or commits a submission it did not create). ' +
      'A person decides what happens to submission 1152921505000000007; if it is in certification, let certification finish. ' +
      'To look at it without changing anything, run this workflow with mode=diagnose and submission_id=1152921505000000007 (GET calls only).'))
    $r.Err | Should -Not -Match $DeleteAdvice
    @($s.Log) | Should -Be @("GET $Base", "GET $Base/submissions/1152921505000000007")
    $r.All | Should -Not -Match "$Leak|$Injected"
  }

  It 'stops before create on a pending submission whose status cannot be read: both cases, a person decides, sends nothing to it' {
    $s = New-FakeStore -PendingId '1152921505000000007'; $s.PresetPendingId = ''; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Out | Should -Match 'the status of pending submission 1152921505000000007 was not read: .*HTTP 404'
    $r.Err | Should -Match ([regex]::Escape("Partner Center already has a pending submission 1152921505000000007 for $App (its status was not read). " +
      'This run did not create it, so it stops and touches nothing (it never deletes, changes or commits a submission it did not create). ' +
      'A person decides what happens to submission 1152921505000000007. To look at it without changing anything'))
    $r.Err | Should -Match 'If it is in certification, let certification finish\. If it is an uncommitted draft: '
    @($s.Log) | Should -Be @("GET $Base", "GET $Base/submissions/1152921505000000007")
    $r.All | Should -Not -Match $Leak
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
    $r.Err | Should -Match '^the create response \(HTTP 200, 201 or 204\) has no usable submission id\. Created, id unknown: the Store answered the create with HTTP 200, 201 or 204, '
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
    @{ Case = 'Base'; Opt = @{ PriceId = 'Base' }; Want = 'pricing\.priceId is one the service rejects on PUT \(the price is not printed\)' }
    @{ Case = 'base'; Opt = @{ PriceId = 'base' }; Want = 'pricing\.priceId is one the service rejects on PUT \(the price is not printed\)' }
    @{ Case = 'empty'; Opt = @{ PriceId = '' }; Want = 'pricing\.priceId is empty' }, @{ Case = 'missing'; Opt = @{ NoPricing = $true }; Want = 'submission has no pricing' }
  ) {
    $s = New-FakeStore @Opt; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match "price check failed: $Want"
    $r.All | Should -Not -Match "'base'|\bbase\b"
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
# reported as "none had been created" with advice to re-run. An HTTP 200,
# 201 or 204 means the Store created a submission; only its id is unknown
# (r7: an HTTP 202 or another 2xx only says the create was accepted, see the
# next block). Now that is
# "created, id unknown": a warning first, then one read-back of the app; a
# pending submission is reported by id only; the run stops with no update,
# upload, commit or delete, and no re-run or delete advice, whatever the
# read-back shows (the Store may show a new submission only after a while).
Describe 'A create answered HTTP 200, 201 or 204 without a usable id: created, id unknown (PR #74 r6, fake Store)' {
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
    $answer = 'the create response (HTTP 200, 201 or 204) has no usable submission id'
    $r.Out | Should -Match ('(?m)^' + [regex]::Escape((Get-CreatedWarning $answer 'HTTP 200, 201 or 204')) + '$')
    $r.Err | Should -BeExactly (Get-CreatedText $answer 'HTTP 200, 201 or 204' $Want $NewId)
    $r.All | Should -Not -Match "$NotCreated|$DeleteAdvice|$RetryAdvice|$Leak"
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
    $s.Sub.status | Should -Be 'PendingCommit'
  }
  # The status decides, not the body: 200, 201 or 204 is created; 202 and
  # every other 2xx accepted, completion unconfirmed (PR #74 r7); 408/5xx
  # unconfirmed; another status refused; no status (no answer) unconfirmed.
  It 'create answered HTTP <Status> with its body lost goes down the <Path> path' -ForEach @(
    @{ Status = 200; Path = 'created, id unknown'; Opt = @{ LoseResponse = 'Create'; LoseWhen = 'After'; LoseAsStatus = 200; LoseBody = '{}' }; Want = 'Created, id unknown: the Store answered the create with HTTP 200' }
    @{ Status = 201; Path = 'created, id unknown'; Opt = @{ LoseResponse = 'Create'; LoseWhen = 'After'; LoseAsStatus = 201; LoseBody = '{}' }; Want = 'Created, id unknown: the Store answered the create with HTTP 201' }
    @{ Status = 204; Path = 'created, id unknown'; Opt = @{ LoseResponse = 'Create'; LoseWhen = 'After'; LoseAsStatus = 204; LoseBody = '{}' }; Want = 'Created, id unknown: the Store answered the create with HTTP 204' }
    @{ Status = 202; Path = 'accepted, completion unconfirmed'; Opt = @{ LoseResponse = 'Create'; LoseWhen = 'After'; LoseAsStatus = 202; LoseBody = '{}' }; Want = 'Accepted, completion unconfirmed: the Store answered the create with HTTP 202: it accepted the request but has not confirmed' }
    @{ Status = 203; Path = 'accepted, completion unconfirmed'; Opt = @{ LoseResponse = 'Create'; LoseWhen = 'After'; LoseAsStatus = 203; LoseBody = '{}' }; Want = 'Accepted, completion unconfirmed: the Store answered the create with HTTP 203: it accepted the request but has not confirmed' }
    @{ Status = 299; Path = 'accepted, completion unconfirmed'; Opt = @{ LoseResponse = 'Create'; LoseWhen = 'After'; LoseAsStatus = 299; LoseBody = '{}' }; Want = 'Accepted, completion unconfirmed: the Store answered the create with HTTP 299: it accepted the request but has not confirmed' }
    @{ Status = 300; Path = 'refused'; Opt = @{ LoseResponse = 'Create'; LoseWhen = 'Before'; LoseAsStatus = 300; LoseBody = '{}' }; Want = 'No submission was created and none was deleted' }
    @{ Status = 199; Path = 'refused'; Opt = @{ LoseResponse = 'Create'; LoseWhen = 'Before'; LoseAsStatus = 199; LoseBody = '{}' }; Want = 'No submission was created and none was deleted' }
    @{ Status = 409; Path = 'refused'; Opt = @{ LoseResponse = 'Create'; LoseWhen = 'Before'; LoseAsStatus = 409; LoseBody = '{}' }; Want = 'No submission was created and none was deleted' }
    @{ Status = 503; Path = 'unconfirmed'; Opt = @{ LoseResponse = 'Create'; LoseWhen = 'Before'; LoseAsStatus = 503; LoseBody = '{}' }; Want = 'Result unconfirmed: the create request got no answer' }
  ) {
    $o = $Opt.Clone(); $s = New-FakeStore @o -DripOn Create -DripSeconds 30; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $how = if ($Path -like 'accepted*') { "answered HTTP ${Status}: accepted, completion unconfirmed" } else { "failed: HTTP $Status" }
    $r.Err | Should -Match ('^' + [regex]::Escape("Store API POST $Base/submissions?isMinimalResponse=true $how") + '.*' + [regex]::Escape($Want))
    $r.All | Should -Not -Match "$DeleteAdvice|$RetryAdvice|$Leak"
    if ($Path -like 'accepted*') { $r.All | Should -Not -Match 'Created, id unknown|so it created a submission' }
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
  }
  It 'create got no answer at all (<When>): unconfirmed, never taken for created' -ForEach @(@{ When = 'After' }, @{ When = 'Before' }) {
    $s = New-FakeStore -LoseResponse Create -LoseWhen $When; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match 'Result unconfirmed: the create request got no answer'
    $r.All | Should -Not -Match "Created, id unknown|$DeleteAdvice|$RetryAdvice|$Leak"
  }
}

# Pepper, PR #74 r7: HTTP 202 Accepted means the service took the request but
# has not finished it (RFC 9110, 15.3.3). It was handled as done: a create
# answered 202 went on as created, a DELETE answered 202 printed "deleted".
# Now a change (create, PUT, upload, commit, DELETE) counts as done only on
# HTTP 200, 201 or 204; HTTP 202 and every other 2xx is "accepted, completion
# unconfirmed": checked once by id where there is one, never committed after,
# no re-run or delete advice. A GET is a usable read only on HTTP 200, the
# token only on HTTP 200. Each change is tested with its body read and with
# its body lost (time limit, broken connection), carried out by the Store
# (Done) and not (AcceptNotDone).
Describe 'HTTP 202 and other 2xx: accepted, completion unconfirmed (PR #74 r7, fake Store)' {
  BeforeAll {
    $script:LostLimit = 'body not received (time limit of {0} s for the whole request reached)'
    $script:LostBroken = 'body not received (the connection broke or the body could not be read)'
    $script:ApiOnly = & (Get-Module MsStoreRunner) { $script:ApiOnlyNote }
    # The old packages' names come from the API and are not this run's file:
    # not shown (Pepper, PR #74 r8). This run's file is shown.
    $script:OldPkgs = '[file name not shown] Uploaded, [file name not shown] Uploaded'
    $script:PutPkgs = "[file name not shown] PendingDelete, [file name not shown] PendingDelete, $File PendingUpload"
    $script:LookApp = "A person needs to check the app's pending submission later in Partner Center (look only, change nothing there) or with GET $Base (pendingApplicationSubmission.id)"
    $script:ReadOnly200 = '(a read is used only when answered HTTP 200)'
    # Text that says a change was done; never printed for an accepted one
    # (the create adds 'created submission id=').
    $script:SaysDone = 'Created, id unknown|so it created a submission|deleted draft|package uploaded|updated: old packages|commit requested through the API'
    # '' when the body is read; else the BodyLost text, with its leading "; ".
    function script:Get-LostPart([string]$End, [int]$Sec) {
      if (-not $End) { return '' }
      if ($End -eq 'Break') { "; $LostBroken" } else { "; $($LostLimit -f $Sec)" }
    }
    # Fake Store options: the first On request answered with Status, carried
    # out (Done) or not, its body read (End '') or lost (Body, Break).
    function script:Get-AcceptOpt([string]$On, [int]$Status, [bool]$Done, [string]$End) {
      $o = @{ AcceptOn = $On; AcceptStatus = $Status; AcceptNotDone = (-not $Done) }
      if ($End) { $o.DripOn = $On; $o.DripSeconds = 30; $o.DripEnd = $End }
      $o
    }
    function script:Get-Case([bool]$Done) { if ($Done) { 'carried out' } else { 'not carried out' } }
  }
  AfterAll { $global:FakeAnswer = $null }
  BeforeEach { $script:Pkg = New-TestPackage }
  AfterEach { Remove-Item -LiteralPath (Split-Path $Pkg) -Recurse -Force }

  It 'HTTP <Status>: done <Done>, accepted <Acc>' -ForEach @(
    @{ Status = 0; Done = $false; Acc = $false }, @{ Status = 199; Done = $false; Acc = $false }
    @{ Status = 200; Done = $true; Acc = $false }, @{ Status = 201; Done = $true; Acc = $false }
    @{ Status = 202; Done = $false; Acc = $true }, @{ Status = 203; Done = $false; Acc = $true }
    @{ Status = 204; Done = $true; Acc = $false }, @{ Status = 205; Done = $false; Acc = $true }
    @{ Status = 206; Done = $false; Acc = $true }, @{ Status = 226; Done = $false; Acc = $true }
    @{ Status = 299; Done = $false; Acc = $true }, @{ Status = 300; Done = $false; Acc = $false }
    @{ Status = 404; Done = $false; Acc = $false }, @{ Status = 503; Done = $false; Acc = $false }
  ) {
    InModuleScope MsStoreRunner -Parameters @{ S = $Status; D = $Done; A = $Acc } {
      param($S, $D, $A)
      Test-StoreDone $S | Should -Be $D
      Test-StoreAccepted $S | Should -Be $A
    }
  }

  # Pepper, PR #74 r8: every 2xx code on its own, 200 through 299, one case
  # each. A GET is used only on 200; a POST, PUT, DELETE or the package upload
  # is done on 200, 201 or 204 and accepted, completion unconfirmed, on every
  # other 2xx.
  It 'HTTP <Status>, each 2xx on its own: GET <Get>, change <Change>' -ForEach @(
    foreach ($c in 200..299) {
      @{ Status = $c; Get = $(if ($c -eq 200) { 'used' } else { 'failed read' }); Change = $(if ($c -in 200, 201, 204) { 'done' } else { 'accepted' }) }
    }
  ) {
    InModuleScope MsStoreRunner -Parameters @{ S = $Status; D = ($Change -eq 'done') } {
      param($S, $D)
      Test-StoreDone $S | Should -Be $D
      Test-StoreAccepted $S | Should -Be (-not $D)
    }
    $s = New-FakeStore; Use-FakeStore $s
    $global:FakeAnswer = @{ S = $Status; Body = '{"id":"1152921505000000099","status":"PendingCommit"}' }
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp { [pscustomobject]@{ StatusCode = $global:FakeAnswer.S; Body = $global:FakeAnswer.Body } }
    $path = "applications/$App/submissions/$NewId"
    foreach ($m in 'GET', 'POST', 'PUT', 'DELETE') {
      $rec = $null; $v = $null
      try { $v = & (Get-Module MsStoreRunner) { param($m, $p) Invoke-StoreApi -Method $m -Path $p } $m $path } catch { $rec = $_ }
      $used = if ($m -eq 'GET') { $Get -eq 'used' } else { $Change -eq 'done' }
      if ($used) {
        $rec | Should -BeNullOrEmpty
        $v | Should -BeExactly $global:FakeAnswer.Body
        continue
      }
      $what = "Store API $m /v1.0/my/$path"
      $want = if ($m -eq 'GET') { "$what failed: HTTP $Status $ReadOnly200" } else { "$what answered HTTP ${Status}: accepted, completion unconfirmed" }
      "$rec" | Should -BeExactly $want
      $v | Should -BeNullOrEmpty
      & (Get-Module MsStoreRunner) { param($r) Get-StoreErrorStatus $r } $rec | Should -Be $Status
    }
    $r = Invoke-Captured { Send-StorePackage -UploadUrl 'https://jlfakeupload.blob.core.windows.net/blob/upload.zip?sv=1&sig=FAKE%2BSAS' -PackagePath $Pkg }
    if ($Change -eq 'done') {
      $r.Err | Should -BeNullOrEmpty
      $r.Out | Should -Match "^package uploaded: .*, HTTP $Status$"
    } else {
      $r.Err | Should -BeExactly "package upload answered HTTP ${Status}: accepted, completion unconfirmed (not confirmed stored)"
      $r.Out | Should -BeNullOrEmpty
    }
  }

  # Invoke-StoreApi decides once for every caller: a GET is used only on 200,
  # a POST, PUT or DELETE only on 200, 201 or 204; 202 and other 2xx are
  # thrown as accepted, with only a plain-number id kept from the body.
  It 'Invoke-StoreApi <Method> answered HTTP <Status> (<How>): <Want>' -ForEach @(
    @{ Method = 'GET'; Status = 200; How = 'body read'; Want = 'Return' }
    @{ Method = 'GET'; Status = 201; How = 'body read'; Want = 'ReadFailed' }
    @{ Method = 'GET'; Status = 202; How = 'body read'; Want = 'ReadFailed' }
    @{ Method = 'GET'; Status = 203; How = 'body read'; Want = 'ReadFailed' }
    @{ Method = 'GET'; Status = 204; How = 'body read'; Want = 'ReadFailed' }
    @{ Method = 'GET'; Status = 206; How = 'body read'; Want = 'ReadFailed' }
    @{ Method = 'GET'; Status = 202; How = 'body lost'; Want = 'ReadFailed' }
    @{ Method = 'POST'; Status = 200; How = 'body read'; Want = 'Return' }
    @{ Method = 'POST'; Status = 201; How = 'body read'; Want = 'Return' }
    @{ Method = 'POST'; Status = 204; How = 'body read'; Want = 'Return' }
    @{ Method = 'PUT'; Status = 200; How = 'body read'; Want = 'Return' }
    @{ Method = 'PUT'; Status = 201; How = 'body read'; Want = 'Return' }
    @{ Method = 'PUT'; Status = 204; How = 'body read'; Want = 'Return' }
    @{ Method = 'DELETE'; Status = 200; How = 'body read'; Want = 'Return' }
    @{ Method = 'DELETE'; Status = 201; How = 'body read'; Want = 'Return' }
    @{ Method = 'DELETE'; Status = 204; How = 'body read'; Want = 'Return' }
    @{ Method = 'POST'; Status = 202; How = 'body read'; Want = 'Accepted' }
    @{ Method = 'POST'; Status = 203; How = 'body read'; Want = 'Accepted' }
    @{ Method = 'POST'; Status = 205; How = 'body read'; Want = 'Accepted' }
    @{ Method = 'POST'; Status = 299; How = 'body read'; Want = 'Accepted' }
    @{ Method = 'PUT'; Status = 202; How = 'body read'; Want = 'Accepted' }
    @{ Method = 'PUT'; Status = 226; How = 'body read'; Want = 'Accepted' }
    @{ Method = 'DELETE'; Status = 202; How = 'body read'; Want = 'Accepted' }
    @{ Method = 'DELETE'; Status = 206; How = 'body read'; Want = 'Accepted' }
    @{ Method = 'POST'; Status = 202; How = 'body read, id in other digits'; Want = 'Accepted' }
    @{ Method = 'POST'; Status = 202; How = 'body read, not JSON'; Want = 'Accepted' }
    @{ Method = 'POST'; Status = 202; How = 'body lost'; Want = 'Accepted' }
    @{ Method = 'DELETE'; Status = 202; How = 'body lost'; Want = 'Accepted' }
    @{ Method = 'POST'; Status = 201; How = 'body lost'; Want = 'DoneBodyLost' }
  ) {
    $s = New-FakeStore; Use-FakeStore $s
    $body = switch ($How) {
      'body read, id in other digits' { '{"id":"' + (-join ('1152921505000000099'.ToCharArray() | ForEach-Object { [char](0x0660 + [int]"$_") })) + '","status":"PendingCommit"}' }
      'body read, not JSON' { 'id=1152921505000000099' }
      default { '{"id":"1152921505000000099","status":"PendingCommit"}' }
    }
    $global:FakeAnswer = @{ S = $Status; Lost = ($How -eq 'body lost'); Body = $body }
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp {
      $a = $global:FakeAnswer
      if ($a.Lost) { return [pscustomobject]@{ StatusCode = $a.S; Body = ''; BodyLost = 'body not received (the connection broke or the body could not be read)' } }
      [pscustomobject]@{ StatusCode = $a.S; Body = $a.Body }
    }
    $path = "applications/$App/submissions/$NewId"
    $rec = $null; $v = $null
    try { $v = & (Get-Module MsStoreRunner) { param($m, $p) Invoke-StoreApi -Method $m -Path $p } $Method $path } catch { $rec = $_ }
    $lost = if ($How -eq 'body lost') { "; $LostBroken" } else { '' }
    $what = "Store API $Method /v1.0/my/$path"
    if ($Want -eq 'Return') {
      $rec | Should -BeNullOrEmpty
      $v | Should -BeExactly $body
      return
    }
    $got = & (Get-Module MsStoreRunner) { param($r) @((Test-StoreOutcomeUnknown $r), (Get-StoreErrorStatus $r), (Get-StoreAcceptedId $r)) } $rec
    $got[0] | Should -BeTrue
    $got[1] | Should -Be $Status
    switch ($Want) {
      'ReadFailed' { "$rec" | Should -BeExactly "$what failed: HTTP $Status $ReadOnly200$lost"; $got[2] | Should -BeExactly '' }
      'DoneBodyLost' { "$rec" | Should -BeExactly "$what failed: HTTP $Status$lost"; $got[2] | Should -BeExactly '' }
      'Accepted' {
        "$rec" | Should -BeExactly "$what answered HTTP ${Status}: accepted, completion unconfirmed$lost"
        $id = if ($How -eq 'body read') { $NewId } else { '' }
        $got[2] | Should -BeExactly $id
      }
    }
    "$rec" | Should -Not -Match $OtherDigits
  }
  It 'Get-StoreAcceptedId gives '''' (never throws) for <Case>' -ForEach @(
    @{ Case = 'no error record' }, @{ Case = 'an error without the mark' }, @{ Case = 'a mark that is not a plain number' }, @{ Case = 'a mark in other digits' }
  ) {
    InModuleScope MsStoreRunner -Parameters @{ Case = $Case } {
      param($Case)
      $e = switch ($Case) {
        'no error record' { $null }
        'an error without the mark' { New-StoreError 'x' -OutcomeUnknown -Status 202 }
        'a mark that is not a plain number' { $x = New-StoreError 'x' -OutcomeUnknown -Status 202; $x.Data['StoreAcceptedId'] = '1/../2'; $x }
        default { $x = New-StoreError 'x' -OutcomeUnknown -Status 202; $x.Data['StoreAcceptedId'] = [string][char]0x0661; $x }
      }
      $rec = $null
      if ($e) { try { throw $e } catch { $rec = $_ } }
      Get-StoreAcceptedId $rec | Should -BeExactly ''
    }
  }

  It 'create answered HTTP <Status> naming its id, body read (<Case>): accepted, completion unconfirmed, checked once by that id, the run stops, no advice' -ForEach @(
    @{ Status = 202; Done = $true; Case = 'carried out' }, @{ Status = 202; Done = $false; Case = 'not carried out' }
    @{ Status = 203; Done = $true; Case = 'carried out' }, @{ Status = 299; Done = $false; Case = 'not carried out' }
  ) {
    $o = Get-AcceptOpt 'Create' $Status $Done ''; $s = New-FakeStore @o; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $answer = "Store API POST $Base/submissions?isMinimalResponse=true answered HTTP ${Status}: accepted, completion unconfirmed"
    $what = "the Store answered the create with HTTP ${Status}: it accepted the request but has not confirmed that a submission was created"
    $look = "A person needs to check submission $NewId later in Partner Center (look only, change nothing there) or with GET $Base/submissions/$NewId"
    $r.Out | Should -Match ('(?m)^' + [regex]::Escape("::warning title=Store create::Accepted, completion unconfirmed: $what ($answer). The run stops; it updates, uploads to, commits and deletes nothing. Checking submission $NewId (the id in the answer) once by id. If this step ends before a result is printed below: $look.") + '$')
    $head = "$answer. Accepted, completion unconfirmed: $what. This run stops: it does not update, upload to, commit or delete any submission. Read-back of submission $NewId by id (one GET; nothing changed): "
    if ($Done) {
      $r.Err | Should -BeExactly "${head}status PendingCommit; packages: $OldPkgs. $look. $ApiOnly"
      $s.Sub.status | Should -Be 'PendingCommit'
    } else {
      $r.Err | Should -BeExactly "${head}failed (Store API GET $Base/submissions/$NewId failed: HTTP 404 (NotFound); hint: the app or submission was not found). $look. $ApiOnly"
      $s.Sub | Should -BeNullOrEmpty
    }
    $r.Value | Should -BeNullOrEmpty
    $r.All | Should -Not -Match "created submission id=|$SaysDone|Result unconfirmed|$DeleteAdvice|$RetryAdvice|$Leak"
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base/submissions/$NewId")
    $s.Blob | Should -BeNullOrEmpty
  }
  It 'create answered HTTP <Status>, <How> (<Case>): accepted, completion unconfirmed, the app read back once, the run stops, no advice' -ForEach @(
    @{ Status = 202; How = 'body lost (time limit)'; End = 'Body'; Done = $true; Case = 'carried out'; Opt = @{}; Want = 'Pending' }
    @{ Status = 202; How = 'body lost (connection broken)'; End = 'Break'; Done = $true; Case = 'carried out'; Opt = @{}; Want = 'Pending' }
    @{ Status = 202; How = 'body lost (time limit)'; End = 'Body'; Done = $false; Case = 'not carried out'; Opt = @{}; Want = 'None' }
    @{ Status = 202; How = 'body lost (connection broken)'; End = 'Break'; Done = $false; Case = 'not carried out'; Opt = @{}; Want = 'None' }
    @{ Status = 202; How = 'body read without an id'; End = ''; Done = $true; Case = 'carried out'; Opt = @{ CreateWithoutId = $true }; Want = 'Pending' }
    @{ Status = 202; How = 'body read without an id'; End = ''; Done = $false; Case = 'not carried out'; Opt = @{ CreateWithoutId = $true }; Want = 'None' }
    @{ Status = 299; How = 'body lost (time limit)'; End = 'Body'; Done = $true; Case = 'carried out, shown without a usable id'; Opt = @{ PendingAfterCreate = 'x1' }; Want = 'NoId' }
    @{ Status = 205; How = 'body read without an id'; End = ''; Done = $true; Case = 'carried out, not shown yet'; Opt = @{ CreateWithoutId = $true; PendingLag = $true }; Want = 'None' }
  ) {
    $o = Get-AcceptOpt 'Create' $Status $Done $End; foreach ($k in $Opt.Keys) { $o[$k] = $Opt[$k] }
    $s = New-FakeStore @o; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $answer = "Store API POST $Base/submissions?isMinimalResponse=true answered HTTP ${Status}: accepted, completion unconfirmed$(Get-LostPart $End 600)"
    $what = "the Store answered the create with HTTP ${Status}: it accepted the request but has not confirmed that a submission was created"
    $r.Out | Should -Match ('(?m)^' + [regex]::Escape("::warning title=Store create::Accepted, completion unconfirmed: $what ($answer). The run stops; it updates, uploads to, commits and deletes nothing. The answer named no usable id; reading the app back once. If this step ends before a result is printed below: $LookApp.") + '$')
    $tail = switch ($Want) {
      'Pending' { "pending submission $NewId. Reported by id only: not updated, not committed, not deleted. A person needs to check submission $NewId later in Partner Center (look only, change nothing there) or with GET $Base/submissions/$NewId. $ApiOnly" }
      'None' { "no pending submission yet. That does not mean none will be created: the Store may still be processing the request. $LookApp. $ApiOnly" }
      'NoId' { "a pending submission without a usable id. $LookApp. $ApiOnly" }
    }
    $r.Err | Should -BeExactly "$answer. Accepted, completion unconfirmed: $what. This run stops: it does not update, upload to, commit or delete any submission. Read-back of the app (one GET; nothing changed): $tail"
    $r.Value | Should -BeNullOrEmpty
    $r.All | Should -Not -Match "created submission id=|$SaysDone|Result unconfirmed|$DeleteAdvice|$RetryAdvice|$Leak"
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
    $s.Blob | Should -BeNullOrEmpty
    if ($Done) { $s.Sub.status | Should -Be 'PendingCommit' } else { $s.Sub | Should -BeNullOrEmpty }
  }
  It 'create answered HTTP 202 and its check fails (<Case>): reported in the text, a person checks once the API answers, no advice' -ForEach @(
    @{ Case = 'by the id in the answer'; End = '' }, @{ Case = 'reading the app back'; End = 'Body' }
  ) {
    $o = Get-AcceptOpt 'Create' 202 $true $End; $s = New-FakeStore @o; Use-FakeStore $s
    Mock -ModuleName MsStoreRunner Get-StoreSubmissionJson { throw 'fake read-back broke' }
    Mock -ModuleName MsStoreRunner Get-StoreApp { throw 'fake read-back broke' }
    $r = Invoke-Captured { New-StoreSubmission -ProductId $App -ReadBackTimeoutSec 7 }
    if ($End) {
      $r.Err | Should -Match ([regex]::Escape("Read-back of the app (one GET; nothing changed): failed (fake read-back broke). $LookApp once the API answers. $ApiOnly") + '$')
      Should -Invoke -ModuleName MsStoreRunner Get-StoreApp -Times 1 -Exactly -ParameterFilter { $ProductId -ceq $App -and $TimeoutSec -eq 7 }
      Should -Invoke -ModuleName MsStoreRunner Get-StoreSubmissionJson -Times 0 -Exactly
    } else {
      $r.Err | Should -Match ([regex]::Escape("Read-back of submission $NewId by id (one GET; nothing changed): failed (fake read-back broke). A person needs to check submission $NewId later") )
      Should -Invoke -ModuleName MsStoreRunner Get-StoreSubmissionJson -Times 1 -Exactly -ParameterFilter { $ProductId -ceq $App -and $SubmissionId -ceq $NewId -and $TimeoutSec -eq 7 }
      Should -Invoke -ModuleName MsStoreRunner Get-StoreApp -Times 0 -Exactly
    }
    $r.Err | Should -Match '^Store API POST .* answered HTTP 202: accepted, completion unconfirmed'
    $r.All | Should -Not -Match "created submission id=|$SaysDone|$DeleteAdvice|$RetryAdvice|$Leak"
    @($s.Log) | Should -Be @("POST $Base/submissions")
  }
  It 'create answered HTTP 202 naming its id, and the GET by that id returns another submission: says so, prints nothing of that submission' {
    $o = Get-AcceptOpt 'Create' 202 $true ''; $s = New-FakeStore @o; Use-FakeStore $s
    Mock -ModuleName MsStoreRunner Get-StoreSubmissionJson { '{"id":"1152921505000000004","status":"Certification","applicationPackages":[]}' }
    $r = Invoke-Captured { New-StoreSubmission -ProductId $App }
    $r.Err | Should -Match ([regex]::Escape("Read-back of submission $NewId by id (one GET; nothing changed): it did not return that submission. A person needs to check submission $NewId later"))
    $r.All | Should -Not -MatchExactly 'Certification|1152921505000000004'
    $r.All | Should -Not -Match "created submission id=|$SaysDone|$DeleteAdvice|$RetryAdvice"
    Should -Invoke -ModuleName MsStoreRunner Get-StoreSubmissionJson -Times 1 -Exactly -ParameterFilter { $SubmissionId -ceq $NewId }
  }

  It 'PUT of the submission answered HTTP <Status>, body <Body> (<Case>): accepted, completion unconfirmed, read back once by id, stops uncommitted before the upload, no delete or re-run advice' -ForEach @(
    @{ Status = 202; End = ''; Body = 'read'; Done = $true; Case = 'carried out' }
    @{ Status = 202; End = ''; Body = 'read'; Done = $false; Case = 'not carried out' }
    @{ Status = 202; End = 'Body'; Body = 'lost (time limit)'; Done = $true; Case = 'carried out' }
    @{ Status = 202; End = 'Break'; Body = 'lost (connection broken)'; Done = $false; Case = 'not carried out' }
    @{ Status = 203; End = ''; Body = 'read'; Done = $true; Case = 'carried out' }
    @{ Status = 299; End = 'Body'; Body = 'lost (time limit)'; Done = $false; Case = 'not carried out' }
  ) {
    $o = Get-AcceptOpt 'Update' $Status $Done $End; $s = New-FakeStore @o; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $answer = "Store API PUT $Base/submissions/$NewId answered HTTP ${Status}: accepted, completion unconfirmed$(Get-LostPart $End 600)"
    $look = "A person needs to check submission $NewId later (look only, change nothing in Partner Center) with GET $Base/submissions/$NewId"
    $shows = if ($Done) { $PutPkgs } else { $OldPkgs }
    $r.Out | Should -Match ('(?m)^' + [regex]::Escape("::warning title=Store update::Accepted, completion unconfirmed: $answer. The run stops; draft $NewId stays uncommitted and nothing more is sent to it. Reading it back once by id. If this step ends before a result is printed below: $look.") + '$')
    $r.Err | Should -BeExactly ("$answer. Accepted, completion unconfirmed: the Store accepted the update of submission $NewId but has not confirmed it is done. " +
      "Not committed: this run stops, draft $NewId stays uncommitted and nothing more is sent to it. Read-back of submission $NewId by id (one GET; nothing changed): " +
      "status PendingCommit; packages: $shows. $look. $ApiOnly")
    $r.Value | Should -BeNullOrEmpty
    $r.All | Should -Not -Match "$SaysDone|$DeleteAdvice|$RetryAdvice|$Leak"
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base", "GET $Base/submissions/$NewId", "PUT $Base/submissions/$NewId", "GET $Base/submissions/$NewId")
    $s.Blob | Should -BeNullOrEmpty
    $s.Sub.status | Should -Be 'PendingCommit'
  }
  It 'package upload answered HTTP <Status>, body <Body> (<Case>): accepted, completion unconfirmed, read back once by id, not committed, no delete or re-run advice' -ForEach @(
    @{ Status = 202; End = ''; Body = 'read'; Done = $true; Case = 'stored' }
    @{ Status = 202; End = ''; Body = 'read'; Done = $false; Case = 'not stored' }
    @{ Status = 202; End = 'Body'; Body = 'lost (time limit)'; Done = $true; Case = 'stored' }
    @{ Status = 202; End = 'Break'; Body = 'lost (connection broken)'; Done = $false; Case = 'not stored' }
    @{ Status = 203; End = ''; Body = 'read'; Done = $true; Case = 'stored' }
    @{ Status = 299; End = 'Break'; Body = 'lost (connection broken)'; Done = $true; Case = 'stored' }
  ) {
    $o = Get-AcceptOpt 'Upload' $Status $Done $End; $s = New-FakeStore @o -UploadBody '<x/>'; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $answer = "package upload answered HTTP ${Status}: accepted, completion unconfirmed (not confirmed stored)$(Get-LostPart $End 600)"
    $look = "A person needs to check submission $NewId later (look only, change nothing in Partner Center) with GET $Base/submissions/$NewId"
    $r.Out | Should -Match ('(?m)^' + [regex]::Escape("::warning title=Store package upload::Accepted, completion unconfirmed: $answer. The run stops; draft $NewId stays uncommitted and nothing more is sent to it. Reading it back once by id. If this step ends before a result is printed below: $look.") + '$')
    $r.Err | Should -BeExactly ("$answer. Accepted, completion unconfirmed: the Store accepted the package upload of submission $NewId but has not confirmed it is done. " +
      "Not committed: this run stops, draft $NewId stays uncommitted and nothing more is sent to it. Read-back of submission $NewId by id (one GET; nothing changed): " +
      "status PendingCommit; packages: $PutPkgs. $look. $ApiOnly")
    $r.Value | Should -BeNullOrEmpty
    # The PUT before it was done ("updated: old packages" is printed); nothing after it.
    $r.All | Should -Not -Match "package uploaded|draft verified|commit requested through the API|deleted draft|$DeleteAdvice|$RetryAdvice|$Leak"
    @($s.Log)[-3..-1] | Should -Be @("PUT $Base/submissions/$NewId", "PUT /blob/upload.zip", "GET $Base/submissions/$NewId")
    @($s.Log) | Should -Not -Contain "POST $Base/submissions/$NewId/commit"
    if ($Done) { $s.Blob | Should -Not -BeNullOrEmpty } else { $s.Blob | Should -BeNullOrEmpty }
    $s.Sub.status | Should -Be 'PendingCommit'
  }
  It 'commit answered HTTP <Status>, body <Body> (<Case>): accepted, completion unconfirmed, read back by id, <Then>' -ForEach @(
    @{ Status = 202; End = ''; Body = 'read'; Done = $true; Case = 'carried out'; Then = 'committed, goes on' }
    @{ Status = 202; End = ''; Body = 'read'; Done = $false; Case = 'not carried out'; Then = 'unconfirmed after 3 read-backs, no retry or delete advice' }
    @{ Status = 202; End = 'Body'; Body = 'lost (time limit)'; Done = $true; Case = 'carried out'; Then = 'committed, goes on' }
    @{ Status = 202; End = 'Break'; Body = 'lost (connection broken)'; Done = $false; Case = 'not carried out'; Then = 'unconfirmed after 3 read-backs, no retry or delete advice' }
    @{ Status = 203; End = ''; Body = 'read'; Done = $true; Case = 'carried out'; Then = 'committed, goes on' }
    @{ Status = 299; End = 'Body'; Body = 'lost (time limit)'; Done = $false; Case = 'not carried out'; Then = 'unconfirmed after 3 read-backs, no retry or delete advice' }
  ) {
    $o = Get-AcceptOpt 'Commit' $Status $Done $End; $s = New-FakeStore @o; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $failure = "Store API POST $Base/submissions/$NewId/commit answered HTTP ${Status}: accepted, completion unconfirmed$(Get-LostPart $End 60)"
    $got = "was accepted (HTTP $Status) but the Store has not confirmed it is done"
    $r.Out | Should -Match ('(?m)^' + [regex]::Escape("::warning title=Store commit::Accepted, completion unconfirmed: the commit request for submission $NewId $got ($failure). Reading it back by id for up to 300 s."))
    if ($Done) {
      $r.Err | Should -BeNullOrEmpty
      $r.Value | Should -Be @($NewId)
      $r.Out | Should -Match ('(?m)^' + [regex]::Escape("::warning title=Store commit::The commit request for submission $NewId $got; read-back 1 by id shows status Certification: it was committed. The next step checks its package.") + '$')
      @($s.Log)[-2..-1] | Should -Be @("POST $Base/submissions/$NewId/commit", "GET $Base/submissions/$NewId")
    } else {
      $r.Err | Should -Match ('^' + [regex]::Escape("$failure. Accepted, completion unconfirmed: the commit request for submission $NewId $got, so whether the commit has started is not confirmed. Read back by id 3 time(s), 0 s apart; last: read-back 3 of 3 shows status PendingCommit."))
      $r.Err | Should -Not -Match $RetryAdvice
      $r.Value | Should -BeNullOrEmpty
      @($s.Log)[-4..-1] | Should -Be @("POST $Base/submissions/$NewId/commit", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId", "GET $Base/submissions/$NewId")
      $s.Sub.status | Should -Be 'PendingCommit'
    }
    @($s.Log | Where-Object { $_ -like 'POST */commit' }).Count | Should -Be 1
    $r.All | Should -Not -Match "commit requested through the API|Result unconfirmed|was not accepted|$DeleteAdvice|$Leak"
  }
  It 'commit answered HTTP 202, still PendingCommit on the first read-back: read back by id until CommitStarted, then goes on' {
    $s = New-FakeStore -LoseResponse Commit -LoseWhen Delayed -LoseAsStatus 202 -LoseBody '{"status":"CommitStarted"}' -CommitDelayReads 1; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -BeNullOrEmpty
    $r.Value | Should -Be @($NewId)
    $r.Out | Should -Match 'not confirmed yet \(read-back 1 of 3 shows status PendingCommit\)'
    $r.Out | Should -Match ([regex]::Escape("was accepted (HTTP 202) but the Store has not confirmed it is done; read-back 2 by id shows status CommitStarted: it was committed"))
    $r.All | Should -Not -Match "$DeleteAdvice|$RetryAdvice|$Leak"
  }
  It 'manual DELETE answered HTTP <Status>, body <Body> (<Case>): accepted, completion unconfirmed, never "deleted", read back once by id, nothing more sent' -ForEach @(
    @{ Status = 202; End = ''; Body = 'read'; Done = $true; Case = 'carried out' }
    @{ Status = 202; End = ''; Body = 'read'; Done = $false; Case = 'not carried out' }
    @{ Status = 202; End = 'Body'; Body = 'lost (time limit)'; Done = $true; Case = 'carried out' }
    @{ Status = 202; End = 'Break'; Body = 'lost (connection broken)'; Done = $false; Case = 'not carried out' }
    @{ Status = 203; End = ''; Body = 'read'; Done = $false; Case = 'not carried out' }
    @{ Status = 299; End = 'Body'; Body = 'lost (time limit)'; Done = $true; Case = 'carried out' }
  ) {
    $o = Get-AcceptOpt 'Delete' $Status $Done $End; $s = New-FakeStore @o; Use-FakeStore $s
    $s.Sub = @{ id = $SubId; status = 'PendingCommit'; applicationPackages = @() }
    $r = Invoke-Captured { Remove-StoreDraftSubmission -ProductId $App -SubmissionId $SubId }
    $failure = "Store API DELETE $Base/submissions/$SubId answered HTTP ${Status}: accepted, completion unconfirmed$(Get-LostPart $End 600)"
    $head = ("$failure. Accepted, completion unconfirmed: the Store accepted the delete of submission $SubId but has not confirmed it is done, so it is not " +
      "reported as deleted; nothing more is sent. Read-back of submission $SubId by id (one GET; nothing changed): ")
    $end = " A person needs to check GET $Base/submissions/$SubId later: HTTP 404 there means it is gone."
    if ($Done) {
      $r.Err | Should -BeExactly "${head}failed (Store API GET $Base/submissions/$SubId failed: HTTP 404 (NotFound); hint: the app or submission was not found).$end"
      $s.Sub | Should -BeNullOrEmpty
    } else {
      $r.Err | Should -BeExactly "${head}status PendingCommit; packages: none.$end"
      $s.Sub.status | Should -Be 'PendingCommit'
    }
    $r.Out | Should -Not -Match 'deleted draft'
    $r.All | Should -Not -Match "Delete exactly|Remove-StoreDraftSubmission|$RetryAdvice|$Leak"
    @($s.Log) | Should -Be @("GET $Base/submissions/$SubId", "DELETE $Base/submissions/$SubId", "GET $Base/submissions/$SubId")
  }
  It 'manual DELETE answered HTTP <Status>, body read: deleted' -ForEach @(@{ Status = 200 }, @{ Status = 201 }, @{ Status = 204 }) {
    $o = Get-AcceptOpt 'Delete' $Status $true ''; $s = New-FakeStore @o; Use-FakeStore $s
    $s.Sub = @{ id = $SubId; status = 'PendingCommit'; applicationPackages = @() }
    $r = Invoke-Captured { Remove-StoreDraftSubmission -ProductId $App -SubmissionId $SubId }
    $r.Err | Should -BeNullOrEmpty
    $r.Out | Should -BeExactly "deleted draft submission $SubId"
    @($s.Log) | Should -Be @("GET $Base/submissions/$SubId", "DELETE $Base/submissions/$SubId")
  }
  It 'token answered HTTP <Status>, body <Body>: not signed in, the status printed, the token never' -ForEach @(
    @{ Status = 201; End = ''; Body = 'read' }, @{ Status = 202; End = ''; Body = 'read' }, @{ Status = 203; End = ''; Body = 'read' }
    @{ Status = 204; End = ''; Body = 'read' }, @{ Status = 202; End = 'Body'; Body = 'lost (time limit)' }, @{ Status = 202; End = 'Break'; Body = 'lost (connection broken)' }
  ) {
    $s = New-FakeStore; Use-FakeStore $s
    $s.AcceptOn = 'Token'; $s.AcceptStatus = $Status
    if ($End) { $s.DripOn = 'Token'; $s.DripSeconds = 30; $s.DripEnd = $End }
    $r = Invoke-Captured { Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret }
    $r.Err | Should -BeExactly "could not get a Partner Center access token: HTTP $Status$(Get-LostPart $End 600)"
    (& (Get-Module MsStoreRunner) { $script:Token }) | Should -BeNullOrEmpty
    $r.All | Should -Not -Match "$Leak|$([regex]::Escape($s.Token))|signed in to"
  }

  # A GET answered with any 2xx but 200 is a failed read, wherever it is.
  It 'the pending check (GET app) answered HTTP <Status>: a failed read, not publishing, nothing created' -ForEach @(@{ Status = 201 }, @{ Status = 202 }, @{ Status = 204 }, @{ Status = 299 }) {
    $s = New-FakeStore -AcceptOn AppRead -AcceptStatus $Status; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -BeExactly "Store API GET $Base failed: HTTP $Status $ReadOnly200; cannot check for a pending submission; not publishing"
    @($s.Log) | Should -Be @("GET $Base")
  }
  # Pepper, PR #74 r8: such a read cannot verify the draft: "Could not
  # verify", no delete or re-run advice (every outcome: the Describe after
  # the r6 sweep).
  It '<Read> answered HTTP 202: a failed read; this run''s own draft (created with its id, <Sent>) stays uncommitted, could not verify, no delete or re-run advice' -ForEach @(
    @{ Read = 'the pending check after create (GET app)'; On = 'AppRead'; At = 2; Path = ''; Sent = 'nothing sent to it' }
    @{ Read = 'GET of the new submission'; On = 'SubmissionRead'; At = 1; Path = '/submissions/1152921505000000099'; Sent = 'nothing sent to it' }
    @{ Read = 'the draft check (GET of the submission after the upload)'; On = 'SubmissionRead'; At = 2; Path = '/submissions/1152921505000000099'; Sent = 'updated and uploaded to, not committed' }
  ) {
    $s = New-FakeStore -AcceptOn $On -AcceptAt $At; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match ('^' + [regex]::Escape("Store API GET $Base$Path failed: HTTP 202 $ReadOnly200. Could not verify: ") + '.*' +
      [regex]::Escape(" Not committed: this run stops, draft $NewId stays uncommitted and nothing more is sent to it. A person needs to check submission $NewId (look only, change nothing in Partner Center) with GET $Base/submissions/$NewId. $ApiOnly") + '\z')
    @($s.Log)[-1] | Should -Be "GET $Base$Path"
    @($s.Log) | Should -Not -Contain "POST $Base/submissions/$NewId/commit"
    $s.Sub.status | Should -Be 'PendingCommit'
    $r.All | Should -Not -Match "Accepted, completion unconfirmed|$DeleteAdvice|$RetryAdvice|$Leak"
  }
  It 'a commit read-back answered HTTP 202 counts as a failed read-back; the next one decides' {
    $s = New-FakeStore -LoseResponse Commit -LoseWhen After -LoseAsStatus 503 -LoseBody '{"code":"ServiceUnavailable"}' -AcceptOn SubmissionRead -AcceptAt 3; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -BeNullOrEmpty
    $r.Value | Should -Be @($NewId)
    $r.Out | Should -Match ([regex]::Escape("not confirmed yet (read-back 1 of 3 failed (Store API GET $Base/submissions/$NewId failed: HTTP 202 $ReadOnly200))"))
    $r.Out | Should -Match 'read-back 2 by id shows status Certification: it was committed'
  }
  It 'the package check after the commit (Assert-SubmissionHasPackage) answered HTTP <Status>: not verified' -ForEach @(@{ Status = 201 }, @{ Status = 202 }, @{ Status = 204 }) {
    $s = New-FakeStore -AcceptOn SubmissionRead -AcceptStatus $Status; Use-FakeStore $s
    $s.Sub = @{ id = $SubId; status = 'Certification'; applicationPackages = @(@{ fileName = $File; fileStatus = 'Uploaded'; version = '0.4.1.0' }) }
    $r = Invoke-Captured { Assert-SubmissionHasPackage -ProductId $App -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -TimeoutMinutes 0 -IntervalSeconds 0 }
    $r.Err | Should -Match ([regex]::Escape("not verified after 0 min: Store API GET $Base/submissions/$SubId failed: HTTP $Status $ReadOnly200"))
    $r.Out | Should -Not -Match 'verified submission'
  }
  It 'the diagnostic read-back after <After> answered HTTP 202: reported as a failed read-back, nothing more' -ForEach @(
    @{ After = 'a refused create'; Opt = @{ CreateErrorStatus = 400 }; Want = 'Read-back of the app after the refused create (one GET; nothing changed or deleted): failed (Store API GET {B} failed: HTTP 202 (a read is used only when answered HTTP 200)).' }
    @{ After = 'a create without a usable id'; Opt = @{ CreateWithoutId = $true }; Want = 'Read-back of the app (one GET): failed (Store API GET {B} failed: HTTP 202 (a read is used only when answered HTTP 200)).' }
    @{ After = 'a create without an answer'; Opt = @{ LoseResponse = 'Create'; LoseWhen = 'After' }; Want = 'Read-back of the app: failed too (Store API GET {B} failed: HTTP 202 (a read is used only when answered HTTP 200)).' }
  ) {
    $o = $Opt.Clone(); $s = New-FakeStore @o -AcceptOn AppRead -AcceptAt 2; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match ([regex]::Escape($Want.Replace('{B}', $Base)))
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base")
    $r.All | Should -Not -Match "$DeleteAdvice|$RetryAdvice|$Leak"
  }
  It 'manual DELETE: the GET before it answered HTTP 202: a failed read, nothing deleted' {
    $s = New-FakeStore -AcceptOn SubmissionRead; Use-FakeStore $s
    $s.Sub = @{ id = $SubId; status = 'PendingCommit'; applicationPackages = @() }
    $r = Invoke-Captured { Remove-StoreDraftSubmission -ProductId $App -SubmissionId $SubId }
    $r.Err | Should -BeExactly "Store API GET $Base/submissions/$SubId failed: HTTP 202 $ReadOnly200"
    @($s.Log) | Should -Be @("GET $Base/submissions/$SubId")
    $s.Sub.status | Should -Be 'PendingCommit'
  }
}

# Pepper, PR #74 r8: a read before the commit that gave no usable answer (a
# 202 or another 2xx but 200, its body read or lost) stopped the run and
# advised deleting the draft and re-running. Such a read cannot verify what
# the draft holds: the run stops with "Could not verify", keeps the draft
# uncommitted, sends nothing more and says only how to look at it by id.
# Each of the three reads (the app after create, the new submission before
# the PUT, the draft after the upload) gets every outcome: each 2xx but 200
# with its body read, 2xx bodies lost (time limit, broken connection), 200
# with its body lost, 4xx and 5xx error bodies read and lost, no answer, no
# answer before the time limit, not sent, and HTTP 200 bodies that cannot be
# used (not JSON, an invalid literal, keys that differ only in case, a key
# twice, another app or submission, a pending submission without a usable
# id). Every string the API sends here carries a planted token, client
# secret and SAS URL; none is printed.
Describe 'A read before the commit that gives no usable answer: could not verify, no delete or re-run advice (PR #74 r8, fake Store)' {
  BeforeAll {
    $script:ApiOnly = & (Get-Module MsStoreRunner) { $script:ApiOnlyNote }
    $script:ReadOnly200 = '(a read is used only when answered HTTP 200)'
    $script:LostText = @{
      Body = 'body not received (time limit of 600 s for the whole request reached)'
      Break = 'body not received (the connection broke or the body could not be read)'
    }
    $script:PlantedJwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJwbGFudGVkIn0.cGxhbnRlZC1zaWduYXR1cmU'
    $script:PlantedSecret = 'planted-client-secret-Qw7~x'
    $script:PlantedSas = 'https://plantedacct.blob.core.windows.net/c/p.zip?sv=2022-11-02&sig=PLANTED%2BSAS%3D'
    $script:PlantedAny = 'eyJhbGciOiJSUzI1NiJ9|eyJzdWIiOiJwbGFudGVk|cGxhbnRlZC1zaWduYXR1cmU|planted-client-secret|plantedacct|PLANTED|PlantedCode'
    $script:ReadErrBody = @{ code = 'PlantedCodeAbcDef'; target = $PlantedJwt; message = "$PlantedSecret $PlantedSas"; error = @{ code = $PlantedJwt; message = $PlantedSas } } | ConvertTo-Json -Compress
    $script:Reads = @{
      App = @{ On = 'AppRead'; At = 2; Path = $Base; Read = 'the read of the app after create (GET application)'; Log = 3 }
      Sub = @{ On = 'SubmissionRead'; At = 1; Path = "$Base/submissions/$NewId"; Read = "the read of submission $NewId before the update (GET submission)"; Log = 4 }
      Draft = @{ On = 'SubmissionRead'; At = 2; Path = "$Base/submissions/$NewId"; Read = "the draft check's read of submission $NewId after the upload (GET submission)"; Log = 7 }
    }
    $script:FullLog = @("GET $Base", "POST $Base/submissions", "GET $Base", "GET $Base/submissions/$NewId", "PUT $Base/submissions/$NewId", 'PUT /blob/upload.zip', "GET $Base/submissions/$NewId")
    # A body for FailReadBody, by name: a string, or a scriptblock that edits
    # the usual body of that GET.
    function script:Get-ReadBody([string]$Name) {
      $j = $PlantedJwt; $sas = $PlantedSas; $sec = $PlantedSecret
      switch ($Name) {
        'Error' { $ReadErrBody }
        'Html' { "<html><body>$sec $sas ::error::pwned</body></html>" }
        'NotJson' { "$j $sas" }
        'BadLiteral' { { param($b) $b.Replace('"status":"PendingCommit"', "`"status`":tru,`"x`":`"$j`"") }.GetNewClosure() }
        'CaseKeys' { { param($b) $b.Replace('"status":', "`"Status`":`"$j`",`"status`":") }.GetNewClosure() }
        'TopDup' { { param($b) $b.Replace('"status":', "`"$j`":1,`"$j`":2,`"status`":") }.GetNewClosure() }
        'NestedDup' { { param($b) $b.Replace('"priceId":"Free"', "`"priceId`":`"Free`",`"priceId`":`"$j`"") }.GetNewClosure() }
        'PackageDup' { { param($b) $b.Replace('"fileStatus":', "`"$j`":1,`"$j`":2,`"fileStatus`":") }.GetNewClosure() }
        'OtherSub' { { param($b) $b.Replace('"id":"1152921505000000099"', "`"id`":`"$j`"") }.GetNewClosure() }
        'OtherSubNumber' { { param($b) $b.Replace('"id":"1152921505000000099"', '"id":"1152921505000000123"') } }
        'OtherApp' { "{`"id`":`"$j`",`"pendingApplicationSubmission`":{`"id`":`"1152921505000000099`"}}" }
        'PendingNoId' { "{`"id`":`"9NM3VWQ9MD7N`",`"pendingApplicationSubmission`":{`"id`":`"$j`",`"resourceLocation`":`"$sas`"}}" }
        default { $null }
      }
    }
  }
  BeforeEach { $script:Pkg = New-TestPackage }
  AfterEach { Remove-Item -LiteralPath (Split-Path $Pkg) -Recurse -Force }

  It '<Step>: <Case>: could not verify; the draft stays uncommitted, look by id only, no delete or re-run advice' -ForEach @(
    foreach ($step in 'App', 'Sub', 'Draft') {
      foreach ($st in 201, 202, 203, 204, 205, 206, 207, 208, 226, 250, 299) {
        @{ Step = $step; Case = "HTTP $st, body read"; Status = $st; Fail = "HTTP $st {R}" }
      }
      @{ Step = $step; Case = 'HTTP 202 with an error body carrying the planted strings'; Status = 202; Body = 'Error'; Fail = 'HTTP 202 {R}' }
      @{ Step = $step; Case = 'HTTP 206 with an HTML page'; Status = 206; Body = 'Html'; Fail = 'HTTP 206 {R}' }
      @{ Step = $step; Case = 'HTTP 202, body lost (time limit)'; Status = 202; Lost = 'Body'; Fail = 'HTTP 202 {R}; {L}' }
      @{ Step = $step; Case = 'HTTP 203, body lost (connection broken)'; Status = 203; Lost = 'Break'; Fail = 'HTTP 203 {R}; {L}' }
      @{ Step = $step; Case = 'HTTP 206, body lost (time limit)'; Status = 206; Lost = 'Body'; Fail = 'HTTP 206 {R}; {L}' }
      @{ Step = $step; Case = 'HTTP 299, body lost (connection broken)'; Status = 299; Lost = 'Break'; Fail = 'HTTP 299 {R}; {L}' }
      @{ Step = $step; Case = 'HTTP 200, body lost (time limit)'; Status = 200; Lost = 'Body'; Fail = 'HTTP 200; {L}' }
      @{ Step = $step; Case = 'HTTP 200, body lost (connection broken)'; Status = 200; Lost = 'Break'; Fail = 'HTTP 200; {L}' }
      @{ Step = $step; Case = 'HTTP 401 with planted strings'; Status = 401; Body = 'Error'; Fail = 'HTTP 401 ([unlisted code]); target: [unlisted target]; hint: the access token was not accepted' }
      @{ Step = $step; Case = 'HTTP 404 with planted strings'; Status = 404; Body = 'Error'; Fail = 'HTTP 404 ([unlisted code]); target: [unlisted target]; hint: the app or submission was not found' }
      @{ Step = $step; Case = 'HTTP 409 with planted strings, body lost'; Status = 409; Body = 'Error'; Lost = 'Break'; Fail = 'HTTP 409; hint: the current state of the app does not allow this, or the app uses a Partner Center feature the submission API does not support; {L}' }
      @{ Step = $step; Case = 'HTTP 500 with planted strings'; Status = 500; Body = 'Error'; Fail = 'HTTP 500 ([unlisted code]); target: [unlisted target]; hint: the service reported an internal error' }
      @{ Step = $step; Case = 'HTTP 503 with planted strings'; Status = 503; Body = 'Error'; Fail = 'HTTP 503 ([unlisted code]); target: [unlisted target]; hint: the service reported that it is unavailable' }
      @{ Step = $step; Case = 'HTTP 503 with planted strings, body lost'; Status = 503; Body = 'Error'; Lost = 'Body'; Fail = 'HTTP 503; hint: the service reported that it is unavailable; {L}' }
      @{ Step = $step; Case = 'HTTP 502 with an HTML page'; Status = 502; Body = 'Html'; Fail = 'HTTP 502; hint: a gateway in front of the service reported an error' }
      @{ Step = $step; Case = 'HTTP 302'; Status = 302; Body = 'Error'; Fail = "HTTP 302 ([unlisted code]); target: [unlisted target]; hint: no description of this error is known here (the API's message text is not printed)" }
      @{ Step = $step; Case = 'no answer'; Status = 0; Fail = 'no response (HttpRequestException Unknown <- IOException <- SocketException ConnectionReset)' }
      @{ Step = $step; Case = 'no answer before the time limit'; Status = -1; Fail = 'no response (time limit of 600 s for the whole request reached)' }
      @{ Step = $step; Case = 'not sent'; Status = -2; Fail = "not sent: no time left in this step's time budget" }
      @{ Step = $step; Case = 'HTTP 200, not JSON'; Status = 200; Body = 'NotJson'; Fail = $(if ($step -eq 'App') { "=GET application returned {UA}" } else { "=GET submission {Id} returned {US}" }) }
    }
    @{ Step = 'App'; Case = 'HTTP 200, another app'; Status = 200; Body = 'OtherApp'; Fail = '=GET application returned a different or empty application id' }
    @{ Step = 'App'; Case = 'HTTP 200, a pending submission without a usable id'; Status = 200; Body = 'PendingNoId'; Fail = "=after create, the app's pending submission has no usable id" }
    foreach ($step in 'Sub', 'Draft') {
      @{ Step = $step; Case = 'HTTP 200, an invalid literal'; Status = 200; Body = 'BadLiteral'; Fail = "=GET submission {Id} returned {US}" }
      @{ Step = $step; Case = 'HTTP 200, keys that differ only in case'; Status = 200; Body = 'CaseKeys'; Fail = "=GET submission {Id} returned {US}" }
      @{ Step = $step; Case = 'HTTP 200, another submission (a planted id)'; Status = 200; Body = 'OtherSub'; Fail = '=GET submission {Id} returned another submission' }
      @{ Step = $step; Case = 'HTTP 200, another submission (another number)'; Status = 200; Body = 'OtherSubNumber'; Fail = '=GET submission {Id} returned another submission' }
    }
    # ConvertFrom-Json takes a key given twice in the same case; the strict
    # read (Pepper, PR #74 r10) refuses it at any depth, before anything is
    # read from the answer.
    foreach ($step in 'Sub', 'Draft') {
      @{ Step = $step; Case = 'HTTP 200, a top-level key twice'; Status = 200; Body = 'TopDup'; Fail = "=GET submission {Id} returned {US}" }
      @{ Step = $step; Case = 'HTTP 200, a key twice in a compared field'; Status = 200; Body = 'NestedDup'; Fail = "=GET submission {Id} returned {US}" }
      @{ Step = $step; Case = 'HTTP 200, a key twice in a package object'; Status = 200; Body = 'PackageDup'; Fail = "=GET submission {Id} returned {US}" }
    }
  ) {
    $d = $Reads[$Step]
    $o = @{ FailReadOn = $d.On; FailReadAt = $d.At; FailReadStatus = $Status }
    if ($Body) { $o.FailReadBody = Get-ReadBody $Body }
    if ($Lost) { $o.FailReadLost = $true; $o.DripEnd = $Lost }
    $s = New-FakeStore @o; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $f = $Fail.Replace('{R}', $ReadOnly200).Replace('{Id}', $NewId).Replace('{UA}', $UnreadAnswer).Replace('{US}', $UnreadSubmission)
    if ($Lost) { $f = $f.Replace('{L}', $LostText[$Lost]) }
    $f = if ($f.StartsWith('=')) { $f.Substring(1) } else { "Store API GET $($d.Path) failed: $f" }
    $r.Err | Should -BeExactly ("$f. Could not verify: $($d.Read) gave no usable answer, so this run does not know what draft $NewId holds now. " +
      "Not committed: this run stops, draft $NewId stays uncommitted and nothing more is sent to it. " +
      "A person needs to check submission $NewId (look only, change nothing in Partner Center) with GET $Base/submissions/$NewId. $ApiOnly")
    $r.Value | Should -BeNullOrEmpty
    $r.All | Should -Not -Match "$DeleteAdvice|$RetryAdvice|$Leak|$Injected|$PlantedAny"
    $r.All | Should -Not -Match 'draft verified|commit requested through the API|deleted draft'
    $s.ReadFailed | Should -BeTrue
    # Nothing is sent after the failed read (a read not sent is not logged).
    $n = if ($Status -eq -2) { $d.Log - 1 } else { $d.Log }
    @($s.Log) | Should -Be @($FullLog[0..($n - 1)])
    $s.Sub.status | Should -Be 'PendingCommit'
  }

  # The readable answers that still give delete-by-id advice for this run's
  # own draft: they are not failed reads (Remove-StoreDraftSubmission deletes
  # only while it is PendingCommit).
  It 'after create, a readable answer (HTTP 200) shows <Case>: delete-by-id advice for this run''s own draft stays' -ForEach @(
    @{ Case = 'another pending id'; Opt = @{ PendingAfterCreate = '1152921505000000008' }; Want = "after create, the app's pending submission is '1152921505000000008', not 1152921505000000099" }
    @{ Case = 'no pending submission'; Opt = @{ PendingLag = $true }; Want = "after create, the app's pending submission is '', not 1152921505000000099" }
  ) {
    $o = $Opt.Clone(); $s = New-FakeStore @o; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -Match ('^' + [regex]::Escape("$Want. Not committed: draft $NewId stays uncommitted. $ApiOnly Delete exactly this submission through the API: DELETE $Base/submissions/$NewId "))
    $r.Err | Should -Not -Match 'Could not verify'
    @($s.Log) | Should -Be @($FullLog[0..2])
  }
}

# Pepper, PR #74 r8, point 1: no API content is printed raw. A synthetic token
# (a JWT), a client secret, a SAS URL, and all three in one string, are each
# planted at every spot of an answer, one spot at a time: the whole body, each
# value at any depth (text, number, true, false, null, object or array, so a
# field of an unexpected type too) and each property name. The run may stop
# or go on; nothing it prints, returns for printing or throws may show any of
# the planted text.
Describe 'Credentials planted at every spot of every API answer are never printed (PR #74 r8)' {
  BeforeAll {
    $script:PlantedJwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJwbGFudGVkIn0.cGxhbnRlZC1zaWduYXR1cmU'
    $script:PlantedSecret = 'planted-client-secret-Qw7~x'
    $script:PlantedSas = 'https://plantedacct.blob.core.windows.net/c/p.zip?sv=2022-11-02&sig=PLANTED%2BSAS%3D'
    $script:PlantedAny = 'eyJhbGciOiJSUzI1NiJ9|eyJzdWIiOiJwbGFudGVk|cGxhbnRlZC1zaWduYXR1cmU|planted-client-secret|plantedacct|PLANTED'
    $script:Plants = [ordered]@{ Jwt = $PlantedJwt; Secret = $PlantedSecret; Sas = $PlantedSas; All = "$PlantedJwt $PlantedSecret $PlantedSas" }

    # Every spot of a body: the whole body (Root), and when it is a JSON
    # object or array, each value at any depth (Key: property name or array
    # index of the node at Path) and each property name (Name).
    function script:Get-PlantSpots([AllowEmptyString()][string]$Json) {
      $spots = [System.Collections.Generic.List[hashtable]]::new()
      $spots.Add(@{ Root = $true })
      $root = $null
      try { $root = [System.Text.Json.Nodes.JsonNode]::Parse($Json) } catch { }
      $walk = {
        param($Node, [object[]]$Path)
        if ($Node -is [System.Text.Json.Nodes.JsonObject]) {
          foreach ($kv in @($Node)) {
            $spots.Add(@{ Path = $Path; Key = $kv.Key; Name = $true })
            $spots.Add(@{ Path = $Path; Key = $kv.Key; Name = $false })
            & $walk $kv.Value ($Path + @($kv.Key))
          }
        } elseif ($Node -is [System.Text.Json.Nodes.JsonArray]) {
          for ($i = 0; $i -lt $Node.Count; $i++) {
            $spots.Add(@{ Path = $Path; Key = $i; Name = $false })
            & $walk $Node[$i] ($Path + @($i))
          }
        }
      }
      & $walk $root @()
      , $spots
    }
    # Json with Value planted at Spot.
    function script:Set-Plant([AllowEmptyString()][string]$Json, [hashtable]$Spot, [string]$Value) {
      if ($Spot.Root) { return $Value }
      $root = [System.Text.Json.Nodes.JsonNode]::Parse($Json)
      $p = $root
      foreach ($k in $Spot.Path) { $p = $p[$k] }
      if ($Spot.Name) {
        $o = $p.AsObject(); $v = $o[$Spot.Key]; [void]$o.Remove($Spot.Key); $o.Add($Value, $v)
      } else {
        $p[$Spot.Key] = [System.Text.Json.Nodes.JsonValue]::Create($Value)
      }
      $root.ToJsonString()
    }
    # The first planted text in Text, with some context, or ''.
    function script:Get-PlantLeak([AllowEmptyString()][string]$Text, [string]$Pattern = $PlantedAny) {
      $m = [regex]::Match($Text, "(?is).{0,60}(?:$Pattern).{0,30}")
      if ($m.Success) { $m.Value -replace '\s+', ' ' } else { '' }
    }
    # Fills the lists the fake leaves empty (statusDetails) and adds app
    # fields the fake leaves out, so those have spots too.
    function script:Add-PlantFill([string]$Kind, [AllowEmptyString()][string]$Body) {
      if (-not $Body) { return $Body }
      $Body = $Body.Replace('"statusDetails":{"errors":[],"warnings":[],"certificationReports":[]}',
        '"statusDetails":{"errors":[{"code":"InvalidParameterValue","details":"x"}],"warnings":[{"code":"SalesUnsupportedWarning","details":"y"}],"certificationReports":[{"date":"2026-01-01T00:00:00Z","reportUrl":"https://example.invalid/r"}]}')
      if ($Kind -ceq 'AppRead' -and $Body.StartsWith('{')) { $Body = '{"packageFamilyName":"JerisHQ.JerisLink_0abc","firstPublishedDate":"2026-01-01T00:00:00Z",' + $Body.Substring(1) }
      $Body
    }
    # The fake's EditAnswer: fills the answer (Add-PlantFill), makes Sig (when
    # set) the signature of every SAS upload URL the fake hands out, then for
    # an answer of the kind $global:PlantState.Kind makes it the planted error
    # body (when Status is set) and plants Value at spot K.
    $script:PlantSpotCache = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    $script:PlantHook = {
      param([string]$Kind, $R)
      $p = $global:PlantState
      if ($null -eq $p) { return }
      if ($Kind -ceq $p.Kind -and $p.Status) { $R.StatusCode = $p.Status; $R.Body = $p.ErrorBody }
      $R.Body = Add-PlantFill $Kind ([string]$R.Body)
      if ($p.Sig) { $R.Body = $R.Body.Replace('FAKE\u002BSAS%2FSIGNATURE-0123456789', $p.Sig).Replace('FAKE+SAS%2FSIGNATURE-0123456789', $p.Sig) }
      if ($Kind -cne $p.Kind) { return }
      $spots = $null
      if (-not $PlantSpotCache.TryGetValue($R.Body, [ref]$spots)) { $spots = Get-PlantSpots $R.Body; $PlantSpotCache[$R.Body] = $spots }
      if ($spots.Count -gt $p.Max) { $p.Max = $spots.Count }
      if ($p.K -lt $spots.Count) { $R.Body = Set-Plant $R.Body $spots[$p.K] $p.Value; $p.Planted++ }
    }
    # Runs Action (given a new fake Store made with Options, after signing in)
    # once for each spot K = 0, 1, ... with Value planted at spot K of every
    # answer of kind Kind (made the error body ErrorBody with HTTP Status
    # first, when Status is set), until K has passed every spot any such
    # answer had. Token, ClientSecret and Sig (when set) are this session's
    # access token, client secret and SAS signature; a leak is any text
    # matching LeakPattern (default: the planted texts). Returns the leaks
    # (run and planted text shown), the number of runs and how many answers
    # were planted.
    function script:Invoke-PlantRuns {
      param([string]$Kind, [string]$Value, [hashtable]$Options = @{}, [scriptblock]$Action, [int]$Status = 0, [string]$ErrorBody = '',
            [string]$Token = '', [string]$ClientSecret = $Secret, [string]$Sig = '', [string]$LeakPattern = $PlantedAny)
      Use-FakeStore (New-FakeStore)
      $leaks = [System.Collections.Generic.List[string]]::new()
      $global:PlantState = @{ Kind = $Kind; K = 0; Max = 0; Value = $Value; Planted = 0; Status = $Status; ErrorBody = $ErrorBody; Sig = $Sig }
      $k = 0; $planted = 0
      try {
        do {
          $global:PlantState.K = $k; $global:PlantState.Planted = 0
          $s = New-FakeStore @Options -EditAnswer $PlantHook
          if ($Token) { $s.Token = $Token }
          $global:FakeStore = $s
          Reset-StoreSecrets
          $r = Invoke-Captured { Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $ClientSecret; & $Action $s }
          $planted += $global:PlantState.Planted
          $leak = Get-PlantLeak (($r.Value | ForEach-Object { "$_" }) -join "`n") $LeakPattern
          if (-not $leak) { $leak = Get-PlantLeak $r.All $LeakPattern }
          if ($leak) { $leaks.Add("$Kind spot ${k}: $leak") }
          $k++
        } while ($k -lt $global:PlantState.Max)
      } finally { $global:PlantState = $null }
      [pscustomobject]@{ Leaks = $leaks; Runs = $k; Planted = $planted }
    }
    # Error bodies with every field the module reads (code, error, error
    # object, error_codes, target) or could read (message, details,
    # innererror, the token endpoint's fields).
    $script:StoreErrorTemplate = '{"code":"InvalidParameterValue","message":"m","target":"applicationCategory","source":"Ingestion Api",' +
      '"details":[{"code":"InvalidState","message":"m","target":"pricing"}],"innererror":{"code":"InvalidState","message":"m","innererror":{"code":"x"}},' +
      '"error":{"code":"InvalidParameterValue","message":"m","target":"pricing","details":[{"code":"InvalidState","message":"m"}],"innererror":{"code":"x"}},' +
      '"statusCode":400,"requestId":"0f8fad5b-d9cb-469f-a165-70867728950e"}'
    $script:OAuthErrorTemplate = '{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided.","error_codes":[7000215],' +
      '"timestamp":"2026-11-24 00:00:00Z","trace_id":"0f8fad5b-d9cb-469f-a165-70867728950e","correlation_id":"0f8fad5b-d9cb-469f-a165-70867728950f",' +
      '"error_uri":"https://login.microsoftonline.com/error?code=7000215"}'
    $script:BlobErrorTemplate = '<?xml version="1.0" encoding="utf-8"?><Error><Code>AuthenticationFailed</Code><Message>Server failed to authenticate the request.</Message>' +
      '<AuthenticationErrorDetail>Signature did not match.</AuthenticationErrorDetail></Error>'
    # Each text of the blob error XML replaced with Value, each element name,
    # and Value as the whole body.
    function script:Get-BlobErrorPlants([string]$Value) {
      $t = $BlobErrorTemplate
      $esc = [Security.SecurityElement]::Escape($Value)
      @(
        $t.Replace('>AuthenticationFailed<', ">$esc<"), $t.Replace('>Server failed to authenticate the request.<', ">$esc<"),
        $t.Replace('>Signature did not match.<', ">$esc<"), $t.Replace('Code>', "Code>$esc "), $t.Replace('<Code>AuthenticationFailed</Code>', "<Code>$esc</Code><Code>$esc</Code>"),
        $Value, "<html><head><title>$esc</title></head><body>$esc</body></html>", "<Code>$Value</Code>"
      )
    }
    # A submission as Partner Center returns it after this run's update: two
    # old packages PendingDelete, this run's PendingUpload, statusDetails
    # filled.
    $s0 = New-FakeStore
    $s0.Sub = @{ id = $NewId; status = 'PendingCommit'; applicationPackages = @(
      [ordered]@{ id = 'p1'; fileName = 'Jerislink-0.3.0.0-x64.msixupload'; fileStatus = 'PendingDelete'; version = '0.3.0.0'; minimumDirectXVersion = 'None'; minimumSystemRam = 'None' }
      [ordered]@{ id = 'p2'; fileName = 'Jerislink-0.3.0.0-x64.msix'; fileStatus = 'PendingDelete'; version = '0.3.0.0'; minimumDirectXVersion = 'None'; minimumSystemRam = 'None' }
      [ordered]@{ fileName = $File; fileStatus = 'PendingUpload'; minimumDirectXVersion = 'None'; minimumSystemRam = 'None' }) }
    $script:PlantSub = Add-PlantFill 'SubmissionRead' (Get-FakeSubmission $s0)
    $script:PlantApp = '{"id":"9NM3VWQ9MD7N","primaryName":"JerisLink","packageFamilyName":"JerisHQ.JerisLink_0abc","firstPublishedDate":"2026-01-01T00:00:00Z",' +
      '"lastPublishedApplicationSubmission":{"id":"1152921505000000001","resourceLocation":"applications/9NM3VWQ9MD7N/submissions/1152921505000000001"},' +
      '"pendingApplicationSubmission":{"id":"1152921505000000099","resourceLocation":"applications/9NM3VWQ9MD7N/submissions/1152921505000000099"}}'
    # What an end-to-end run does once signed in (S: its fake Store).
    $script:PlantPublish = {
      param($S)
      Publish-StoreSubmission -ProductId $App -PackagePath $Pkg -ExpectedFileName $File -ExpectedVersion '0.4.1.0' -CommitReadBackAttempts 2 -CommitReadBackIntervalSeconds 0
    }
    $script:PlantVerify = {
      param($S)
      $S.Sub = @{ id = $SubId; status = 'Certification'; applicationPackages = @(
        [ordered]@{ id = 'p3'; fileName = $File; fileStatus = 'Uploaded'; version = '0.4.1.0'; minimumDirectXVersion = 'None'; minimumSystemRam = 'None' }) }
      Assert-SubmissionHasPackage -ProductId $App -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -ExpectedFileName $File -TimeoutMinutes 0 -IntervalSeconds 0
    }
    $script:PlantDelete = {
      param($S)
      $S.Sub = @{ id = $SubId; status = 'PendingCommit'; applicationPackages = @(
        [ordered]@{ id = 'p1'; fileName = 'Jerislink-0.3.0.0-x64.msixupload'; fileStatus = 'Uploaded'; version = '0.3.0.0'; minimumDirectXVersion = 'None'; minimumSystemRam = 'None' }) }
      Remove-StoreDraftSubmission -ProductId $App -SubmissionId $SubId
    }
  }
  AfterAll { $global:PlantState = $null }
  BeforeEach { $script:Pkg = New-TestPackage }
  AfterEach { Remove-Item -LiteralPath (Split-Path $Pkg) -Recurse -Force }

  It 'finds every spot: the whole body, each value at any depth and each property name' {
    $spots = Get-PlantSpots '{"a":"x","b":{"c":1,"d":["y",{"e":null}]}}'
    $spots.Count | Should -Be 13
    $all = @(foreach ($sp in $spots) { Set-Plant '{"a":"x","b":{"c":1,"d":["y",{"e":null}]}}' $sp 'P' })
    $all | Should -Be @('P', '{"b":{"c":1,"d":["y",{"e":null}]},"P":"x"}', '{"a":"P","b":{"c":1,"d":["y",{"e":null}]}}',
      '{"a":"x","P":{"c":1,"d":["y",{"e":null}]}}', '{"a":"x","b":"P"}', '{"a":"x","b":{"d":["y",{"e":null}],"P":1}}', '{"a":"x","b":{"c":"P","d":["y",{"e":null}]}}',
      '{"a":"x","b":{"c":1,"P":["y",{"e":null}]}}', '{"a":"x","b":{"c":1,"d":"P"}}', '{"a":"x","b":{"c":1,"d":["P",{"e":null}]}}', '{"a":"x","b":{"c":1,"d":["y","P"]}}',
      '{"a":"x","b":{"c":1,"d":["y",{"P":null}]}}', '{"a":"x","b":{"c":1,"d":["y",{"e":"P"}]}}')
    (Get-PlantSpots 'not json').Count | Should -Be 1
    (Get-PlantSpots $PlantSub).Count | Should -BeGreaterThan 150
  }

  It 'Get-StoreErrorText prints only the status, listed codes, a listed target and fixed hints (HTTP <Status>, <Plant>)' -ForEach @(
    foreach ($st in 400, 401, 403, 404, 409, 412, 429, 500, 502, 503, 504) { foreach ($pl in 'Jwt', 'Secret', 'Sas', 'All') { @{ Status = $st; Plant = $pl } } }
  ) {
    $v = $Plants[$Plant]
    $bodies = [System.Collections.Generic.List[string]]::new()
    foreach ($t in $StoreErrorTemplate, $OAuthErrorTemplate) { foreach ($sp in (Get-PlantSpots $t)) { $bodies.Add((Set-Plant $t $sp $v)) } }
    foreach ($b in (Get-BlobErrorPlants $v)) { $bodies.Add($b) }
    $bodies.Count | Should -Be 75
    $leaks = @(foreach ($b in $bodies) {
      foreach ($d in $false, $true) {
        $t = Get-StoreErrorText -StatusCode $Status -Body $b -Detail:$d
        if ($t -notmatch "^HTTP $Status\b") { "not a status line: $t" }
        $l = Get-PlantLeak $t
        if ($l) { $l }
      }
    })
    $leaks | Should -BeNullOrEmpty
  }

  # The fallback when the text cannot be formatted: a planted body (and a
  # planted value in the failure's own message) never reaches it.
  It 'Get-StoreErrorText, when <Fails> throws, prints the status and a fixed text, never the body (<Plant>)' -ForEach @(
    foreach ($f in 'Format-StoreErrorText', 'Get-ListedCode', 'Get-ListedTarget', 'Protect-WorkflowCommand') { foreach ($pl in 'Jwt', 'Secret', 'Sas', 'All') { @{ Fails = $f; Plant = $pl } } }
  ) {
    $v = $Plants[$Plant]
    $script:MockPlant = $v
    Mock -ModuleName MsStoreRunner -CommandName $Fails -MockWith { throw "Cannot convert value `"$script:MockPlant`" to type `"System.Int32`"." }
    $bodies = [System.Collections.Generic.List[string]]::new()
    foreach ($t in $StoreErrorTemplate, $OAuthErrorTemplate) { foreach ($sp in (Get-PlantSpots $t)) { $bodies.Add((Set-Plant $t $sp $v)) } }
    foreach ($b in (Get-BlobErrorPlants $v)) { $bodies.Add($b) }
    $bodies.Count | Should -Be 75
    $fellBack = 0
    $leaks = @(foreach ($b in $bodies) {
      foreach ($st in 400, 503) {
        foreach ($d in $false, $true) {
          $t = Get-StoreErrorText -StatusCode $st -Body $b -Detail:$d
          if ($t -notmatch "^HTTP $st\b") { "not a status line: $t" }
          if ($t -ceq "HTTP $st; diagnostics not shown (they could not be formatted)") { $fellBack++ }
          $l = Get-PlantLeak $t
          if ($l) { $l }
        }
      }
    })
    $leaks | Should -BeNullOrEmpty
    $fellBack | Should -BeGreaterThan 0
  }

  It 'checks of a submission (read, package, draft, price, compare, summary) show none of it (<Plant>)' -ForEach @(
    @{ Plant = 'Jwt' }, @{ Plant = 'Secret' }, @{ Plant = 'Sas' }, @{ Plant = 'All' }
  ) {
    $v = $Plants[$Plant]
    $kept = Get-SubmissionComparedFields -SubmissionJson $PlantSub
    $spots = Get-PlantSpots $PlantSub
    $leaks = [System.Collections.Generic.List[string]]::new()
    for ($k = 0; $k -lt $spots.Count; $k++) {
      $j = Set-Plant $PlantSub $spots[$k] $v
      $r = Invoke-Captured {
        $out = [System.Collections.Generic.List[string]]::new()
        $safe = & (Get-Module MsStoreRunner) { param($j, $f) Read-SubmissionSafe -SubmissionJson $j -ExpectedFileName $f } $j $File
        $out.Add(($safe | ConvertTo-Json -Depth 6 -Compress))
        $out.Add((Test-SubmissionHasPackage -SubmissionJson $j -ExpectedVersion '0.4.1.0' -ExpectedFileName $File | ConvertTo-Json -Depth 6 -Compress))
        $ready = Test-DraftReadyToCommit -SubmissionJson $j -SubmissionId $NewId -ExpectedFileName $File -ExpectedVersion '0.4.1.0'
        $out.Add(($ready | ConvertTo-Json -Depth 6 -Compress))
        & (Get-Module MsStoreRunner) { param($c) Write-SubmissionSummary -Check $c } $ready
        $out.Add((Test-SubmissionPricing -SubmissionJson $j | ConvertTo-Json -Compress))
        foreach ($c in { Compare-SubmissionFields -ExpectedJson $kept -SubmissionJson $j }, { Compare-SubmissionFields -ExpectedJson $j -SubmissionJson $PlantSub },
                       { Get-SubmissionComparedFields -SubmissionJson $j | Out-Null }, { Set-SubmissionPackage -SubmissionJson $j -FileName $File | Out-Null },
                       { & (Get-Module MsStoreRunner) { param($j) Get-SubmissionUploadUrl $j | Out-Null } $j }) {
          try { $x = & $c; if ($null -ne $x) { $out.Add(($x | ConvertTo-Json -Depth 6 -Compress)) } } catch { $out.Add("$_") }
        }
        $out -join "`n"
      }
      $leak = Get-PlantLeak $r.All
      if ($leak) { $leaks.Add("spot ${k}: $leak") }
    }
    $spots.Count | Should -BeGreaterThan 150
    $leaks | Should -BeNullOrEmpty
  }

  # System.Text.Json refuses a key given twice (also in another case, with
  # PropertyNameCaseInsensitive) when the object is first read, and its
  # message quotes the key; ConvertFrom-Json refuses keys that differ only in
  # case, and takes the same key twice. Every check gets each, with the
  # planted value as the key, at the top level, in a compared field (pricing)
  # and in a package object.
  It 'a planted key given twice at the top level, in pricing or in a package object: no parser message is shown (<Plant>)' -ForEach @(
    @{ Plant = 'Jwt' }, @{ Plant = 'Secret' }, @{ Plant = 'Sas' }, @{ Plant = 'All' }
  ) {
    $v = $Plants[$Plant]
    $kept = Get-SubmissionComparedFields -SubmissionJson $PlantSub
    $q = $v | ConvertTo-Json; $qu = $v.ToUpperInvariant() | ConvertTo-Json
    $variants = [ordered]@{}
    foreach ($dup in @{ Same = "$($q):1,$($q):2"; Case = "$($qu):1,$($q):2" }.GetEnumerator()) {
      foreach ($at in @{ Top = '^\{'; Pricing = '"pricing":\{'; Package = '"applicationPackages":\[\{' }.GetEnumerator()) {
        $m = [regex]::Matches($PlantSub, $at.Value)
        $m.Count | Should -BeGreaterThan 0
        $variants["$($at.Key) $($dup.Key)"] = $PlantSub.Substring(0, $m[0].Index + $m[0].Length) + $dup.Value + ',' + $PlantSub.Substring($m[0].Index + $m[0].Length)
      }
    }
    $variants.Count | Should -Be 6
    $leaks = [System.Collections.Generic.List[string]]::new()
    $thrown = @{}
    foreach ($e in $variants.GetEnumerator()) {
      $j = $e.Value
      $r = Invoke-Captured {
        $out = [System.Collections.Generic.List[string]]::new()
        $safe = & (Get-Module MsStoreRunner) { param($j, $f) Read-SubmissionSafe -SubmissionJson $j -ExpectedFileName $f } $j $File
        $out.Add(($safe | ConvertTo-Json -Depth 6 -Compress))
        $out.Add((Test-SubmissionHasPackage -SubmissionJson $j -ExpectedVersion '0.4.1.0' -ExpectedFileName $File | ConvertTo-Json -Depth 6 -Compress))
        $ready = Test-DraftReadyToCommit -SubmissionJson $j -SubmissionId $NewId -ExpectedFileName $File -ExpectedVersion '0.4.1.0'
        $out.Add(($ready | ConvertTo-Json -Depth 6 -Compress))
        & (Get-Module MsStoreRunner) { param($c) Write-SubmissionSummary -Check $c } $ready
        $out.Add((Test-SubmissionPricing -SubmissionJson $j | ConvertTo-Json -Compress))
        $n = 0
        foreach ($c in { Compare-SubmissionFields -ExpectedJson $kept -SubmissionJson $j }, { Compare-SubmissionFields -ExpectedJson $j -SubmissionJson $PlantSub },
                       { Get-SubmissionComparedFields -SubmissionJson $j | Out-Null }, { Set-SubmissionPackage -SubmissionJson $j -FileName $File | Out-Null },
                       { & (Get-Module MsStoreRunner) { param($j) Get-SubmissionUploadUrl $j | Out-Null } $j }) {
          $n++
          try { $x = & $c; if ($null -ne $x) { $out.Add(($x | ConvertTo-Json -Depth 6 -Compress)) } } catch { $out.Add("$_"); $thrown["$($e.Key) $n"] = "$_" }
        }
        $out -join "`n"
      }
      $leak = Get-PlantLeak $r.All
      if ($leak) { $leaks.Add("$($e.Key): $leak") }
    }
    $leaks | Should -BeNullOrEmpty
    # The parser refused each where expected, and only fixed text came out.
    $thrown['Package Same 4'] | Should -BeExactly "the submission JSON could not be read to set the packages (the parser's message is not printed)"
    $thrown['Pricing Same 1'] | Should -BeExactly "submission JSON is not an object that can be read (the parser's message is not printed)"
    $thrown['Top Same 3'] | Should -BeExactly "submission JSON is not an object that can be read (the parser's message is not printed)"
    $thrown['Top Case 4'] | Should -BeExactly "the submission JSON could not be read to set the packages (the parser's message is not printed)"
  }

  It 'reads of the app (pending submission id, pending check) show none of it (<Plant>)' -ForEach @(
    @{ Plant = 'Jwt' }, @{ Plant = 'Secret' }, @{ Plant = 'Sas' }, @{ Plant = 'All' }
  ) {
    $v = $Plants[$Plant]
    $spots = Get-PlantSpots $PlantApp
    $leaks = @(for ($k = 0; $k -lt $spots.Count; $k++) {
      $j = Set-Plant $PlantApp $spots[$k] $v
      $r = Invoke-Captured {
        try { Read-AppPendingSubmissionId -AppJson $j -ProductId $App } catch { "$_" }
        Test-NoPendingSubmission -AppJson $j -ProductId $App
      }
      $l = Get-PlantLeak (($r.Value -join "`n") + "`n" + $r.All)
      if ($l) { "spot ${k}: $l" }
    })
    $spots.Count | Should -BeGreaterThan 15
    $leaks | Should -BeNullOrEmpty
  }

  # End to end on the fake Store: every answer of each kind the scenario
  # reads, planted at each of its spots in turn, through the whole run as the
  # workflow makes it (publish, verify, manual delete).
  It 'end to end: <Name>, planted in every <Kind> answer (<Plant>)' -ForEach @(
    foreach ($kd in 'Token', 'AppRead', 'Create', 'Upload', 'Commit') { foreach ($pl in 'Jwt', 'Secret', 'Sas', 'All') { @{ Name = 'publish'; Kind = $kd; Plant = $pl } } }
    foreach ($kd in 'SubmissionRead', 'Update') { @{ Name = 'publish'; Kind = $kd; Plant = 'All' } }
    @{ Name = 'verify after commit'; Kind = 'SubmissionRead'; Plant = 'All' }
    foreach ($kd in 'AppRead', 'Create', 'SubmissionRead') { @{ Name = 'publish, create accepted (HTTP 202)'; Kind = $kd; Plant = 'All' } }
    foreach ($kd in 'AppRead', 'Create') { @{ Name = 'publish, create accepted (HTTP 202), not carried out'; Kind = $kd; Plant = 'All' } }
    foreach ($kd in 'SubmissionRead', 'Update') { @{ Name = 'publish, update accepted (HTTP 202)'; Kind = $kd; Plant = 'All' } }
    foreach ($kd in 'SubmissionRead', 'Upload') { @{ Name = 'publish, upload accepted (HTTP 202)'; Kind = $kd; Plant = 'All' } }
    foreach ($kd in 'SubmissionRead', 'Commit') { @{ Name = 'publish, commit accepted (HTTP 202)'; Kind = $kd; Plant = 'All' } }
    @{ Name = 'publish, commit answer lost'; Kind = 'SubmissionRead'; Plant = 'All' }
    @{ Name = 'publish, create answer lost'; Kind = 'AppRead'; Plant = 'All' }
    foreach ($kd in 'AppRead', 'Create') { @{ Name = 'publish, create refused (HTTP 409)'; Kind = $kd; Plant = 'All' } }
    foreach ($kd in 'AppRead', 'Create') { @{ Name = 'publish, create answered without an id'; Kind = $kd; Plant = 'All' } }
    @{ Name = 'publish, another pending submission'; Kind = 'AppRead'; Plant = 'All' }
    foreach ($kd in 'SubmissionRead', 'Delete') { @{ Name = 'manual delete'; Kind = $kd; Plant = 'All' } }
    foreach ($kd in 'SubmissionRead', 'Delete') { @{ Name = 'manual delete accepted (HTTP 202)'; Kind = $kd; Plant = 'All' } }
  ) {
    $opt = switch ($Name) {
      'publish, create accepted (HTTP 202)' { @{ AcceptOn = 'Create' } }
      'publish, create accepted (HTTP 202), not carried out' { @{ AcceptOn = 'Create'; AcceptNotDone = $true } }
      'publish, update accepted (HTTP 202)' { @{ AcceptOn = 'Update' } }
      'publish, upload accepted (HTTP 202)' { @{ AcceptOn = 'Upload' } }
      'publish, commit accepted (HTTP 202)' { @{ AcceptOn = 'Commit' } }
      'publish, commit answer lost' { @{ LoseResponse = 'Commit' } }
      'publish, create answer lost' { @{ LoseResponse = 'Create' } }
      'publish, create refused (HTTP 409)' { @{ CreateErrorStatus = 409; CreateErrorBody = $StoreErrorTemplate } }
      'publish, create answered without an id' { @{ CreateWithoutId = $true } }
      'publish, another pending submission' { @{ PendingId = '1152921505000000007' } }
      'manual delete accepted (HTTP 202)' { @{ AcceptOn = 'Delete' } }
      default { @{} }
    }
    $act = switch -Wildcard ($Name) {
      'publish*' { $PlantPublish }
      'verify after commit' { $PlantVerify }
      'manual delete*' { $PlantDelete }
    }
    $res = Invoke-PlantRuns -Kind $Kind -Value $Plants[$Plant] -Options $opt -Action $act
    $res.Planted | Should -BeGreaterThan 0 -Because "the scenario reaches a $Kind answer"
    $res.Leaks | Should -BeNullOrEmpty
  }

  # Error answers on the fake Store: each kind answered with an error status
  # and an error body planted at each of its spots in turn (the token
  # endpoint with its own fields, the blob upload with blob storage XML).
  It 'end to end: <Name>, every <Kind> answered HTTP <Status> with a planted error body (<Plant>)' -ForEach @(
    foreach ($st in 400, 503) {
      foreach ($kd in 'Token', 'AppRead', 'Create', 'SubmissionRead', 'Update', 'Upload', 'Commit') { foreach ($pl in 'Jwt', 'All') { @{ Name = 'publish'; Kind = $kd; Status = $st; Plant = $pl } } }
    }
    foreach ($st in 400, 409, 503) { foreach ($pl in 'Jwt', 'All') { @{ Name = 'manual delete'; Kind = 'Delete'; Status = $st; Plant = $pl } } }
    foreach ($st in 404, 503) { @{ Name = 'verify after commit'; Kind = 'SubmissionRead'; Status = $st; Plant = 'All' } }
  ) {
    $body = switch ($Kind) { 'Token' { $OAuthErrorTemplate } 'Upload' { $BlobErrorTemplate } default { $StoreErrorTemplate } }
    $act = switch ($Name) { 'publish' { $PlantPublish } 'manual delete' { $PlantDelete } default { $PlantVerify } }
    $res = Invoke-PlantRuns -Kind $Kind -Value $Plants[$Plant] -Status $Status -ErrorBody $body -Action $act
    $res.Planted | Should -BeGreaterThan 0
    $res.Leaks | Should -BeNullOrEmpty
  }

  # Pepper, PR #74 r9, point 1: masking must not rest on a field's format
  # check. The access token, client secret and SAS signature are made values
  # that fit the fields an answer has (a submission id or a number: digits;
  # a package version: dotted numbers), and each is planted in turn at every
  # spot of every answer of a kind; none may come out. The token and secret
  # are known from the sign-in on; the SAS signature from the first answer
  # that holds the upload URL (the GET before the PUT: the create asks for
  # the minimal answer, id and status only), so it is planted in the answers
  # from then on (an answer before that cannot hold a signature not yet
  # issued to this run, and a value seen before it is not a known credential).
  It 'end to end, credentials that fit a field''s format (<Form>): <Name>, the <Cred> planted in every <Kind> answer' -ForEach @(
    foreach ($fm in 'digits', 'dotted') {
      foreach ($cr in 'access token', 'client secret', 'SAS signature') {
        $kinds = if ($cr -eq 'SAS signature') { 'Upload', 'Commit' } else { 'Token', 'AppRead', 'Create', 'Upload', 'Commit' }
        foreach ($kd in $kinds) { @{ Form = $fm; Cred = $cr; Name = 'publish'; Kind = $kd } }
        @{ Form = $fm; Cred = $cr; Name = 'verify after commit'; Kind = 'SubmissionRead' }
        foreach ($kd in 'SubmissionRead', 'Delete') { @{ Form = $fm; Cred = $cr; Name = 'manual delete'; Kind = $kd } }
        if ($cr -ne 'SAS signature') { @{ Form = $fm; Cred = $cr; Name = 'publish, create accepted (HTTP 202)'; Kind = 'Create' } }
        @{ Form = $fm; Cred = $cr; Name = 'publish, commit accepted (HTTP 202)'; Kind = 'Commit' }
      }
    }
    # The submission reads and the PUT answer have the most spots: the SAS
    # signature (registered from the URL) and one sign-in credential each.
    @{ Form = 'digits'; Cred = 'access token'; Name = 'publish'; Kind = 'SubmissionRead' }
    @{ Form = 'dotted'; Cred = 'SAS signature'; Name = 'publish'; Kind = 'SubmissionRead' }
    @{ Form = 'digits'; Cred = 'SAS signature'; Name = 'publish'; Kind = 'Update' }
    @{ Form = 'dotted'; Cred = 'client secret'; Name = 'publish'; Kind = 'Update' }
  ) {
    $c = if ($Form -eq 'digits') { @{ Token = '1152921505000000123'; Secret = '1152921505000000456'; Sig = '1152921505000000789' } }
         else { @{ Token = '7.7.7.7'; Secret = '8.8.8.8'; Sig = '9.9.9.9' } }
    $v = switch ($Cred) { 'access token' { $c.Token } 'client secret' { $c.Secret } default { $c.Sig } }
    $opt = switch ($Name) {
      'publish, create accepted (HTTP 202)' { @{ AcceptOn = 'Create' } }
      'publish, commit accepted (HTTP 202)' { @{ AcceptOn = 'Commit' } }
      default { @{} }
    }
    $act = switch -Wildcard ($Name) { 'publish*' { $PlantPublish } 'verify after commit' { $PlantVerify } 'manual delete' { $PlantDelete } }
    $pattern = (@($c.Token, $c.Secret, $c.Sig) | ForEach-Object { [regex]::Escape($_) }) -join '|'
    $res = Invoke-PlantRuns -Kind $Kind -Value $v -Options $opt -Action $act -Token $c.Token -ClientSecret $c.Secret -Sig $c.Sig -LeakPattern $pattern
    $res.Planted | Should -BeGreaterThan 0 -Because "the scenario reaches a $Kind answer"
    $res.Leaks | Should -BeNullOrEmpty
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
  # No answer, 408 or 5xx (PR #74 r12): result unconfirmed, read back once by
  # id, not sent again; any other error is thrown as it is.
  It 'manual DELETE that fails without an answered 2xx (<Case>): the error is thrown, nothing says deleted' -ForEach @(
    @{ Case = 'no answer'; Status = 0; Unconfirmed = $true }, @{ Case = 'HTTP 503, body lost'; Status = 503; Unconfirmed = $true }
    @{ Case = 'HTTP 409'; Status = 409; Unconfirmed = $false }
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
    if ($Unconfirmed) {
      $r.Err | Should -BeExactly ("fake DELETE failed with $Status. Result unconfirmed: the delete request for submission $SubId got no answer " +
        "that says what happened, so it may or may not have been deleted; it is not sent again. Read-back of submission $SubId by id " +
        "(one GET; nothing changed): status PendingCommit; packages: none. A person needs to check " +
        "GET /v1.0/my/applications/$App/submissions/$SubId later: HTTP 404 there means it is gone.")
      Should -Invoke -ModuleName MsStoreRunner Get-StoreSubmissionJson -Times 2 -Exactly
    } else {
      $r.Err | Should -BeExactly "fake DELETE failed with $Status"
      Should -Invoke -ModuleName MsStoreRunner Get-StoreSubmissionJson -Times 1 -Exactly
    }
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
      $r.Err | Should -Match '^the create response \(HTTP 200, 201 or 204\) has no usable submission id\. Created, id unknown: the Store answered the create with HTTP 200, 201 or 204, '
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
    $d.Paths | Should -BeNullOrEmpty
    $d.Compared | Should -Be 19
  }

  # Run 45524510567: what the real Store did to the draft after the PUT. None
  # of it is a change this run must stop on.
  It 'reports nothing when the Store only <Case>' -ForEach @(
    @{ Case = 'renamed the draft (friendlyName)'; Change = { param($n) $n['friendlyName'] = [System.Text.Json.Nodes.JsonValue]::Create('Submission 2 (updated)') } }
    @{ Case = 'dropped friendlyName'; Change = { param($n) [void]$n.Remove('friendlyName') } }
    @{ Case = 'emptied pricing.sales'; Change = { param($n) $n['pricing']['sales'] = [System.Text.Json.Nodes.JsonArray]::new() } }
    @{ Case = 'dropped pricing.sales'; Change = { param($n) [void]$n['pricing'].AsObject().Remove('sales') } }
    @{ Case = 'changed pricing.isAdvancedPricingModel'; Change = { param($n) $n['pricing']['isAdvancedPricingModel'] = [System.Text.Json.Nodes.JsonValue]::Create($true) } }
    @{ Case = 'dropped pricing.isAdvancedPricingModel'; Change = { param($n) [void]$n['pricing'].AsObject().Remove('isAdvancedPricingModel') } }
    @{ Case = 'put the markets in another order'; Change = {
        param($n)
        $m = [System.Text.Json.Nodes.JsonObject]::new()
        foreach ($c in 'US', 'GB', 'HK') { $m[$c] = [System.Text.Json.Nodes.JsonValue]::Create([string]$n['pricing']['marketSpecificPricings'][$c]) }
        $n['pricing']['marketSpecificPricings'] = $m
      } }
    @{ Case = 'put the pricing fields in another order'; Change = {
        param($n)
        $old = $n['pricing'].ToJsonString() | ConvertFrom-Json -AsHashtable
        $p = [System.Text.Json.Nodes.JsonObject]::new()
        foreach ($k in @($old.Keys | Sort-Object -Descending)) { $p[$k] = [System.Text.Json.Nodes.JsonNode]::Parse((ConvertTo-Json -Compress -Depth 9 -InputObject $old[$k])) }
        $n['pricing'] = $p
      } }
    # Partner Center sets these two itself ("Manage app submissions", Package
    # rollout resource).
    @{ Case = 'set packageDeliveryOptions.packageRollout.packageRolloutStatus'; Change = { param($n) $n['packageDeliveryOptions']['packageRollout']['packageRolloutStatus'] = [System.Text.Json.Nodes.JsonValue]::Create('PackageRolloutInProgress') } }
    @{ Case = 'set packageDeliveryOptions.packageRollout.fallbackSubmissionId'; Change = { param($n) $n['packageDeliveryOptions']['packageRollout']['fallbackSubmissionId'] = [System.Text.Json.Nodes.JsonValue]::Create('1152921505000000042') } }
    @{ Case = 'dropped both package rollout fields Partner Center sets'; Change = { param($n) foreach ($k in 'packageRolloutStatus', 'fallbackSubmissionId') { [void]$n['packageDeliveryOptions']['packageRollout'].AsObject().Remove($k) } } }
    @{ Case = 'set both package rollout fields, as the fake Store does with StoreSetRollout'; Change = {
        param($n)
        $o = [System.Text.Json.Nodes.JsonNodeOptions]::new(); $o.PropertyNameCaseInsensitive = $true
        $f = [System.Text.Json.Nodes.JsonNode]::Parse((Edit-FakeFieldsOnPut ([System.Text.Json.Nodes.JsonNode]::Parse($n.ToJsonString(), $o)) 'Submission 2' 'StoreSetRollout'), $o)
        $n['packageDeliveryOptions'] = [System.Text.Json.Nodes.JsonNode]::Parse($f['packageDeliveryOptions'].ToJsonString())
      } }
    @{ Case = 'renamed the draft and rearranged pricing, as the fake Store does on every PUT'; Change = {
        param($n)
        $o = [System.Text.Json.Nodes.JsonNodeOptions]::new(); $o.PropertyNameCaseInsensitive = $true
        $f = [System.Text.Json.Nodes.JsonNode]::Parse((Edit-FakeFieldsOnPut ([System.Text.Json.Nodes.JsonNode]::Parse($n.ToJsonString(), $o)) 'Submission 2' ''), $o)
        foreach ($k in 'friendlyName', 'pricing') { $n[$k] = [System.Text.Json.Nodes.JsonNode]::Parse($f[$k].ToJsonString()) }
      } }
  ) {
    $after = Edit-Submission $Change
    $after | Should -Not -BeExactly $Before
    $d = Compare-SubmissionFields -ExpectedJson $Kept -SubmissionJson $after
    $d.Changed | Should -BeNullOrEmpty
    $d.Paths | Should -BeNullOrEmpty
  }

  # A real change of the price still stops the run, by path, never by value;
  # each also with the Store's rename and rearranged pricing on top.
  It 'reports pricing at <Path> when <Case> (<Rearranged>)' -ForEach @(
    foreach ($re in 'as sent', 'renamed and rearranged too') {
      @{ Case = 'priceId changed'; Path = 'pricing.priceId'; Rearranged = $re; Change = { param($n) $n['pricing']['priceId'] = [System.Text.Json.Nodes.JsonValue]::Create('Tier1') } }
      @{ Case = 'priceId is gone'; Path = 'pricing.priceId'; Rearranged = $re; Change = { param($n) [void]$n['pricing'].AsObject().Remove('priceId') } }
      @{ Case = 'trialPeriod changed'; Path = 'pricing.trialPeriod'; Rearranged = $re; Change = { param($n) $n['pricing']['trialPeriod'] = [System.Text.Json.Nodes.JsonValue]::Create('OneWeek') } }
      @{ Case = 'a market price changed'; Path = 'pricing.marketSpecificPricings.HK'; Rearranged = $re; Change = { param($n) $n['pricing']['marketSpecificPricings']['HK'] = [System.Text.Json.Nodes.JsonValue]::Create('Free') } }
      @{ Case = 'a market was added'; Path = 'pricing.marketSpecificPricings.JP'; Rearranged = $re; Change = { param($n) $n['pricing']['marketSpecificPricings']['JP'] = [System.Text.Json.Nodes.JsonValue]::Create('Tier2') } }
      @{ Case = 'a market was removed'; Path = 'pricing.marketSpecificPricings.US'; Rearranged = $re; Change = { param($n) [void]$n['pricing']['marketSpecificPricings'].AsObject().Remove('US') } }
      @{ Case = 'the market prices are not an object'; Path = 'pricing.marketSpecificPricings'; Rearranged = $re; Change = { param($n) $n['pricing']['marketSpecificPricings'] = [System.Text.Json.Nodes.JsonArray]::new() } }
      @{ Case = 'the market prices are gone'; Path = 'pricing.marketSpecificPricings'; Rearranged = $re; Change = { param($n) [void]$n['pricing'].AsObject().Remove('marketSpecificPricings') } }
    }
  ) {
    $re = $Rearranged; $edit = $Change
    $after = Edit-Submission {
      param($n)
      if ($re -ceq 'renamed and rearranged too') {
        $o = [System.Text.Json.Nodes.JsonNodeOptions]::new(); $o.PropertyNameCaseInsensitive = $true
        $f = [System.Text.Json.Nodes.JsonNode]::Parse((Edit-FakeFieldsOnPut ([System.Text.Json.Nodes.JsonNode]::Parse($n.ToJsonString(), $o)) 'Submission 2' ''), $o)
        foreach ($k in 'friendlyName', 'pricing') { $n[$k] = [System.Text.Json.Nodes.JsonNode]::Parse($f[$k].ToJsonString()) }
      }
      & $edit $n
    }.GetNewClosure()
    $d = Compare-SubmissionFields -ExpectedJson $Kept -SubmissionJson $after
    @($d.Changed) | Should -Be @('pricing')
    @($d.Paths) | Should -Be @($Path)
  }

  It 'reports pricing when pricing is <Case>' -ForEach @(
    @{ Case = 'null'; Change = { param($n) $n['pricing'] = $null } }
    @{ Case = 'gone'; Change = { param($n) [void]$n.Remove('pricing') } }
    @{ Case = 'a list'; Change = { param($n) $n['pricing'] = [System.Text.Json.Nodes.JsonNode]::Parse('[{"priceId":"Free"}]') } }
  ) {
    $d = Compare-SubmissionFields -ExpectedJson $Kept -SubmissionJson (Edit-Submission $Change)
    @($d.Changed) | Should -Be @('pricing')
    @($d.Paths) | Should -Be @('pricing')
  }

  It 'names every path that differs, values never (several changes at once)' {
    $after = Edit-Submission {
      param($n)
      $n['pricing']['priceId'] = [System.Text.Json.Nodes.JsonValue]::Create('Tier7')
      $n['pricing']['marketSpecificPricings']['GB'] = [System.Text.Json.Nodes.JsonValue]::Create('Tier9')
      $n['listings']['en-us']['baseListing']['title'] = [System.Text.Json.Nodes.JsonValue]::Create('Planted title value')
      $n['targetPublishMode'] = [System.Text.Json.Nodes.JsonValue]::Create('Immediate')
    }
    $d = Compare-SubmissionFields -ExpectedJson $Kept -SubmissionJson $after
    @($d.Changed | Sort-Object) | Should -Be @('listings', 'pricing', 'targetPublishMode')
    @($d.Paths | Sort-Object) | Should -Be @('listings.en-us.baseListing.title', 'pricing.marketSpecificPricings.GB', 'pricing.priceId', 'targetPublishMode')
    ($d.Paths -join ' ') | Should -Not -Match 'Tier|Planted|Immediate|Free|Manual'
  }
  It 'reports nothing for other key order and key case' {
    $after = '{"Trailers":[],' + $Before.Substring(1).Replace('"pricing"', '"Pricing"')
    $after = $after.Replace(',"trailers":[]', '')
    (Compare-SubmissionFields -ExpectedJson $Kept -SubmissionJson $after).Changed | Should -BeNullOrEmpty
  }
  It 'reports <Field> at <Path> when <Case>' -ForEach @(
    @{ Case = 'the price changed'; Field = 'pricing'; Path = 'pricing.priceId'; Change = { param($n) $n['pricing']['priceId'] = [System.Text.Json.Nodes.JsonValue]::Create('Tier1') } }
    @{ Case = 'a market price changed'; Field = 'pricing'; Path = 'pricing.marketSpecificPricings.HK'; Change = { param($n) $n['pricing']['marketSpecificPricings']['HK'] = [System.Text.Json.Nodes.JsonValue]::Create('Free') } }
    @{ Case = 'a listing was dropped'; Field = 'listings'; Path = 'listings.zh-hk'; Change = { param($n) [void]$n['listings'].AsObject().Remove('zh-hk') } }
    @{ Case = 'a listing title changed'; Field = 'listings'; Path = 'listings.en-us.baseListing.title'; Change = { param($n) $n['listings']['en-us']['baseListing']['title'] = [System.Text.Json.Nodes.JsonValue]::Create('X') } }
    @{ Case = 'visibility is gone'; Field = 'visibility'; Path = 'visibility'; Change = { param($n) [void]$n.Remove('visibility') } }
    @{ Case = 'the publish mode changed'; Field = 'targetPublishMode'; Path = 'targetPublishMode'; Change = { param($n) $n['targetPublishMode'] = [System.Text.Json.Nodes.JsonValue]::Create('Immediate') } }
    @{ Case = 'the publish date changed'; Field = 'targetPublishDate'; Path = 'targetPublishDate'; Change = { param($n) $n['targetPublishDate'] = [System.Text.Json.Nodes.JsonValue]::Create('2027-01-01T00:00:00Z') } }
    @{ Case = 'a device family changed'; Field = 'allowTargetFutureDeviceFamilies'; Path = 'allowTargetFutureDeviceFamilies.[unlisted field name]'; Change = { param($n) $n['allowTargetFutureDeviceFamilies']['Xbox'] = [System.Text.Json.Nodes.JsonValue]::Create($true) } }
    # packageDeliveryOptions is what the PUT sends: all of it but the two
    # rollout fields Partner Center sets is compared, and only where the docs
    # put those two.
    @{ Case = 'isPackageRollout changed'; Field = 'packageDeliveryOptions'; Path = 'packageDeliveryOptions.packageRollout.isPackageRollout'; Change = { param($n) $n['packageDeliveryOptions']['packageRollout']['isPackageRollout'] = [System.Text.Json.Nodes.JsonValue]::Create($true) } }
    @{ Case = 'packageRolloutPercentage changed'; Field = 'packageDeliveryOptions'; Path = 'packageDeliveryOptions.packageRollout.packageRolloutPercentage'; Change = { param($n) $n['packageDeliveryOptions']['packageRollout']['packageRolloutPercentage'] = [System.Text.Json.Nodes.JsonValue]::Create(50.0) } }
    @{ Case = 'packageRolloutPercentage changed, and Partner Center set its rollout fields too'; Field = 'packageDeliveryOptions'; Path = 'packageDeliveryOptions.packageRollout.packageRolloutPercentage'; Change = {
        param($n)
        $r = $n['packageDeliveryOptions']['packageRollout']
        $r['packageRolloutPercentage'] = [System.Text.Json.Nodes.JsonValue]::Create(50.0); $r['packageRolloutStatus'] = [System.Text.Json.Nodes.JsonValue]::Create('PackageRolloutInProgress'); $r['fallbackSubmissionId'] = [System.Text.Json.Nodes.JsonValue]::Create('1152921505000000042')
      } }
    @{ Case = 'isMandatoryUpdate changed'; Field = 'packageDeliveryOptions'; Path = 'packageDeliveryOptions.isMandatoryUpdate'; Change = { param($n) $n['packageDeliveryOptions']['isMandatoryUpdate'] = [System.Text.Json.Nodes.JsonValue]::Create($true) } }
    @{ Case = 'mandatoryUpdateEffectiveDate changed'; Field = 'packageDeliveryOptions'; Path = 'packageDeliveryOptions.mandatoryUpdateEffectiveDate'; Change = { param($n) $n['packageDeliveryOptions']['mandatoryUpdateEffectiveDate'] = [System.Text.Json.Nodes.JsonValue]::Create('2027-01-01T00:00:00.0000000Z') } }
    @{ Case = 'packageRollout is gone'; Field = 'packageDeliveryOptions'; Path = 'packageDeliveryOptions.packageRollout'; Change = { param($n) [void]$n['packageDeliveryOptions'].AsObject().Remove('packageRollout') } }
    @{ Case = 'packageRollout is not an object'; Field = 'packageDeliveryOptions'; Path = 'packageDeliveryOptions.packageRollout'; Change = { param($n) $n['packageDeliveryOptions']['packageRollout'] = [System.Text.Json.Nodes.JsonArray]::new() } }
    @{ Case = 'packageRolloutStatus was added outside packageRollout'; Field = 'packageDeliveryOptions'; Path = 'packageDeliveryOptions.packageRolloutStatus'; Change = { param($n) $n['packageDeliveryOptions']['packageRolloutStatus'] = [System.Text.Json.Nodes.JsonValue]::Create('PackageRolloutInProgress') } }
    @{ Case = 'a listed field was added'; Field = 'fallbackSubmissionId'; Path = 'fallbackSubmissionId'; Change = { param($n) $n['fallbackSubmissionId'] = [System.Text.Json.Nodes.JsonValue]::Create('x') } }
    @{ Case = 'a listed field was added in another case'; Field = 'fallbackSubmissionId'; Path = 'fallbackSubmissionId'; Change = { param($n) $n['FALLBACKSUBMISSIONID'] = [System.Text.Json.Nodes.JsonValue]::Create('x') } }
    @{ Case = 'a field not listed here was added'; Field = '[unlisted field name]'; Path = '[unlisted field name]'; Change = { param($n) $n['newSetting'] = [System.Text.Json.Nodes.JsonValue]::Create(1) } }
    @{ Case = 'a field named like a token was added'; Field = '[unlisted field name]'; Path = '[unlisted field name]'; Change = { param($n) $n['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl'] = [System.Text.Json.Nodes.JsonValue]::Create(1) } }
    @{ Case = 'a field with an odd name was added'; Field = '[unlisted field name]'; Path = '[unlisted field name]'; Change = { param($n) $n["x`n::error::pwned"] = [System.Text.Json.Nodes.JsonValue]::Create(1) } }
  ) {
    $after = Edit-Submission $Change
    $d = Compare-SubmissionFields -ExpectedJson $Kept -SubmissionJson $after
    @($d.Changed) | Should -Be @($Field)
    @($d.Paths) | Should -Be @($Path)
  }
  It 'throws on JSON that is not an object' {
    { Compare-SubmissionFields -ExpectedJson $Kept -SubmissionJson 'Error' } | Should -Throw '*not an object*'
    { Compare-SubmissionFields -ExpectedJson $Kept -SubmissionJson '[1]' } | Should -Throw '*not an object*'
  }
}

# mode=diagnose (msstore-publish.yml): Show-StoreSubmissionDiagnosis reads the
# app, the named submission and the last published submission, by GET only,
# and prints which friendlyName and pricing sub-fields (and other fields)
# differ, as paths, never values.
Describe 'Show-StoreSubmissionDiagnosis (mode=diagnose, read-only)' {
  BeforeAll {
    $script:Mod = Get-Module MsStoreRunner
    $script:Draft = '1152921505000000007'
    $script:Published = '1152921505000000001'
    # Values in the fake's fields; none may be printed.
    $script:Values = 'Tier\d|Launch sale|Submission [12]|NoFreeTrial|"Free"|JerisLink remote desktop|PackageRollout(NotStarted|InProgress)|1152921505000000042'
  }
  AfterEach { & $Mod { $script:ReadOnlyCalls = $false }; Remove-Variable -Name DiagWrite -Scope Global -ErrorAction Ignore }

  # The proof that diagnose is read-only: every call it makes, in every case
  # (it passes, it finds drift, there is nothing published, a read fails), is
  # a GET to the Store API; no POST, PUT or DELETE reaches Invoke-StoreHttp,
  # and the fake Store is left exactly as it was.
  It 'sends only GET calls to the Store API, never a write (<Case>)' -ForEach @(
    @{ Case = 'the draft run 45524510567 left: renamed, pricing rearranged'; Opt = @{ PendingId = '1152921505000000007' }; Id = '1152921505000000007'; Fails = $false }
    @{ Case = 'a draft whose price changed'; Opt = @{ PendingId = '1152921505000000007'; DriftOnPut = 'Pricing' }; Id = '1152921505000000007'; Fails = $false }
    @{ Case = 'a draft that lost a market'; Opt = @{ PendingId = '1152921505000000007'; DriftOnPut = 'RemoveMarket' }; Id = '1152921505000000007'; Fails = $false }
    @{ Case = 'a pending submission in certification'; Opt = @{ PendingId = '1152921505000000007'; PendingStatus = 'Certification' }; Id = '1152921505000000007'; Fails = $false }
    @{ Case = 'nothing published yet'; Opt = @{ PendingId = '1152921505000000007'; NoPublished = $true }; Id = '1152921505000000007'; Fails = $false }
    @{ Case = 'the last published submission itself'; Opt = @{}; Id = '1152921505000000001'; Fails = $false }
    @{ Case = 'a submission that does not exist'; Opt = @{ PendingId = '1152921505000000007' }; Id = '1152921505000000555'; Fails = $true }
    @{ Case = 'the app read fails'; Opt = @{ PendingId = '1152921505000000007'; FailReadOn = 'AppRead'; FailReadStatus = 500 }; Id = '1152921505000000007'; Fails = $true }
    @{ Case = 'the read of the last published submission fails'; Opt = @{ PendingId = '1152921505000000007'; FailReadOn = 'SubmissionRead'; FailReadAt = 2; FailReadStatus = 503 }; Id = '1152921505000000007'; Fails = $true }
  ) {
    $s = New-FakeStore @Opt; Use-FakeStore $s
    $fields = $s.Fields; $pending = $s.PendingId
    $r = Invoke-Captured { Show-StoreSubmissionDiagnosis -ProductId $App -SubmissionId $Id }
    if ($Fails) { $r.Err | Should -Not -BeNullOrEmpty } else { $r.Err | Should -BeNullOrEmpty }
    @($s.Calls).Count | Should -BeGreaterThan 0
    foreach ($c in @($s.Calls)) { $c | Should -Match '^GET /v1\.0/my/applications/9NM3VWQ9MD7N(/submissions/\d+)? timeout=\d+$' }
    foreach ($l in @($s.Log)) { $l | Should -Match '^GET ' }
    # The one sign-in is the test's own (Use-FakeStore), before diagnose runs.
    Should -Invoke Invoke-StoreHttp -ModuleName MsStoreRunner -Times 1 -Exactly -ParameterFilter { $Kind -ceq 'Token' }
    Should -Invoke Invoke-StoreHttp -ModuleName MsStoreRunner -Times 0 -Exactly -ParameterFilter { $Kind -cne 'Token' -and ($Method -cne 'GET' -or $Kind -cne 'Api') }
    $s.Sub | Should -BeNullOrEmpty
    $s.Fields | Should -BeExactly $fields
    $s.PendingId | Should -BeExactly $pending
    $s.Blob | Should -BeNullOrEmpty
    & $Mod { $script:ReadOnlyCalls } | Should -BeFalse
    $r.All | Should -Not -Match $Leak
    $r.All | Should -Not -MatchExactly $Values
  }

  # The guard behind that proof: while diagnose runs, a write is refused
  # before it is sent, even if a later change made diagnose ask for one.
  It 'refuses a <Method> that diagnose asks for, before it is sent, and touches nothing' -ForEach @(
    @{ Method = 'POST'; Path = 'applications/9NM3VWQ9MD7N/submissions/1152921505000000007/commit' }
    @{ Method = 'PUT'; Path = 'applications/9NM3VWQ9MD7N/submissions/1152921505000000007' }
    @{ Method = 'DELETE'; Path = 'applications/9NM3VWQ9MD7N/submissions/1152921505000000007' }
  ) {
    $s = New-FakeStore -PendingId $Draft; Use-FakeStore $s
    $global:DiagWrite = @{ Method = $Method; Path = $Path }
    Mock -ModuleName MsStoreRunner Get-DiagnosedSubmission {
      & (Get-Module MsStoreRunner) { param($m, $p) Invoke-StoreApi -Method $m -Path $p -Body '{}' } $global:DiagWrite.Method $global:DiagWrite.Path
    }
    $r = Invoke-Captured { Show-StoreSubmissionDiagnosis -ProductId $App -SubmissionId $Draft }
    $r.Err | Should -BeExactly "Store API $Method /v1.0/my/$Path refused: this is a read-only run (GET calls only); nothing was sent"
    @($s.Calls) | Should -Be @("GET $Base timeout=60")
    Should -Invoke Invoke-StoreHttp -ModuleName MsStoreRunner -Times 0 -Exactly -ParameterFilter { $Kind -cne 'Token' -and $Method -cne 'GET' }
    $s.PendingId | Should -BeExactly $Draft
    & $Mod { $script:ReadOnlyCalls } | Should -BeFalse
  }

  # The second guard, in the real Invoke-StoreHttp (no mock): in a read-only
  # run only a GET to the Store API goes out; anything else is refused before
  # a connection is made.
  It 'the real Invoke-StoreHttp refuses <Method> <Kind> in a read-only run, before anything is sent' -ForEach @(
    @{ Method = 'POST'; Kind = 'Api'; Uri = 'https://manage.devcenter.microsoft.com/v1.0/my/applications/9NM3VWQ9MD7N/submissions' }
    @{ Method = 'PUT'; Kind = 'Api'; Uri = 'https://manage.devcenter.microsoft.com/v1.0/my/applications/9NM3VWQ9MD7N/submissions/1152921505000000007' }
    @{ Method = 'DELETE'; Kind = 'Api'; Uri = 'https://manage.devcenter.microsoft.com/v1.0/my/applications/9NM3VWQ9MD7N/submissions/1152921505000000007' }
    @{ Method = 'POST'; Kind = 'Token'; Uri = 'https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token' }
    @{ Method = 'PUT'; Kind = 'Upload'; Uri = 'https://jlfakeupload.blob.core.windows.net/c/upload.zip' }
    @{ Method = 'GET'; Kind = 'Upload'; Uri = 'https://jlfakeupload.blob.core.windows.net/c/upload.zip' }
  ) {
    $e = $null
    try { & $Mod { param($m, $k, $u) $script:ReadOnlyCalls = $true; try { Invoke-StoreHttp -Method $m -Uri $u -Kind $k -TimeoutSec 1 } finally { $script:ReadOnlyCalls = $false } } $Method $Kind $Uri }
    catch { $e = $_ }
    "$e" | Should -BeExactly 'refused: this is a read-only run (GET calls to the Store API only); nothing was sent'
    $e.Exception.Data['StoreNotSent'] | Should -BeTrue
  }

  It 'leaves the read-only guard off after it ends, so a publish run is not changed by it' {
    $s = New-FakeStore -PendingId $Draft; Use-FakeStore $s
    (Invoke-Captured { Show-StoreSubmissionDiagnosis -ProductId $App -SubmissionId '1152921505000000555' }).Err | Should -Match 'HTTP 404'
    & $Mod { $script:ReadOnlyCalls } | Should -BeFalse
    $s.Sub = @{ id = $SubId; status = 'PendingCommit'; applicationPackages = @() }
    (Invoke-Captured { Invoke-SubmissionCommit -ProductId $App -SubmissionId $SubId }).Err | Should -BeNullOrEmpty
    @($s.Log) | Should -Contain "POST $Base/submissions/$SubId/commit"
  }

  It 'prints which friendlyName and pricing sub-fields differ, by path, never the values (<Case>)' -ForEach @(
    @{ Case = 'the draft run 45524510567 left: renamed, pricing rearranged'; Drift = ''; Pricing = 'pricing.sales, pricing.isAdvancedPricingModel'; Other = 'none'; Check = 'would pass' }
    @{ Case = 'and its price changed'; Drift = 'Pricing'; Pricing = 'pricing.sales, pricing.priceId, pricing.isAdvancedPricingModel'; Other = 'none'; Check = 'would stop on pricing.priceId' }
    @{ Case = 'and a market price changed'; Drift = 'MarketPrice'; Pricing = 'pricing.marketSpecificPricings.HK, pricing.sales, pricing.isAdvancedPricingModel'; Other = 'none'; Check = 'would stop on pricing.marketSpecificPricings.HK' }
    @{ Case = 'and a market was added'; Drift = 'AddMarket'; Pricing = 'pricing.marketSpecificPricings.JP, pricing.sales, pricing.isAdvancedPricingModel'; Other = 'none'; Check = 'would stop on pricing.marketSpecificPricings.JP' }
    @{ Case = 'and a market was removed'; Drift = 'RemoveMarket'; Pricing = 'pricing.marketSpecificPricings.US, pricing.sales, pricing.isAdvancedPricingModel'; Other = 'none'; Check = 'would stop on pricing.marketSpecificPricings.US' }
    @{ Case = 'and a listing was dropped'; Drift = 'DropListing'; Pricing = 'pricing.sales, pricing.isAdvancedPricingModel'; Other = 'listings.zh-hk'; Check = 'would stop on listings.zh-hk' }
    # Diagnose shows the rollout fields Partner Center sets; the publish run's
    # check does not stop on them.
    @{ Case = 'and Partner Center set its package rollout fields'; Drift = 'StoreSetRollout'; Pricing = 'pricing.sales, pricing.isAdvancedPricingModel'
      Other = 'packageDeliveryOptions.packageRollout.packageRolloutStatus, packageDeliveryOptions.packageRollout.fallbackSubmissionId'; Check = 'would pass' }
    @{ Case = 'and the rollout percentage changed too'; Drift = 'RolloutPercentage'; Pricing = 'pricing.sales, pricing.isAdvancedPricingModel'
      Other = 'packageDeliveryOptions.packageRollout.packageRolloutPercentage, packageDeliveryOptions.packageRollout.packageRolloutStatus, packageDeliveryOptions.packageRollout.fallbackSubmissionId'
      Check = 'would stop on packageDeliveryOptions.packageRollout.packageRolloutPercentage' }
  ) {
    $s = New-FakeStore -PendingId $Draft -DriftOnPut $Drift; Use-FakeStore $s
    $r = Invoke-Captured { Show-StoreSubmissionDiagnosis -ProductId $App -SubmissionId $Draft }
    $r.Err | Should -BeNullOrEmpty
    $r.Out | Should -BeExactly (@(
      'diagnose (read-only): GET calls only; nothing is created, changed, committed or deleted'
      "app ${App}: pending submission $Draft, last published submission $Published"
      "submission ${Draft}: status PendingCommit"
      "last published submission ${Published}: status Published"
      "compared last published submission $Published with submission $Draft (field paths only, values not printed)"
      'friendlyName: differs'
      "pricing sub-fields that differ: $Pricing"
      "other fields that differ (applicationPackages not compared): $Other"
      "the publish run's field check (Compare-SubmissionFields; last published as before, submission $Draft as after): $Check"
      'diagnose done: GET calls only; nothing was created, changed, committed or deleted') -join "`n")
    @($s.Log) | Should -Be @("GET $Base", "GET $Base/submissions/$Draft", "GET $Base/submissions/$Published")
    $r.All | Should -Not -Match $Leak
    $r.All | Should -Not -MatchExactly $Values
  }

  It 'says friendlyName is the same and nothing differs for the last published submission itself, and notes it is not pending' {
    $s = New-FakeStore; Use-FakeStore $s
    $r = Invoke-Captured { Show-StoreSubmissionDiagnosis -ProductId $App -SubmissionId $Published }
    $r.Err | Should -BeNullOrEmpty
    $r.Out | Should -Match "app ${App}: pending submission \[none\], last published submission $Published"
    $r.Out | Should -Match "note: submission $Published is not the app's pending submission"
    $r.Out | Should -Match '(?m)^friendlyName: same$'
    $r.Out | Should -Match '(?m)^pricing sub-fields that differ: none$'
    $r.Out | Should -Match '(?m)^other fields that differ \(applicationPackages not compared\): none$'
    $r.Out | Should -Match '(?m)would pass$'
  }

  It 'reads the draft and says there is nothing to compare with when nothing is published' {
    $s = New-FakeStore -PendingId $Draft -NoPublished; Use-FakeStore $s
    $r = Invoke-Captured { Show-StoreSubmissionDiagnosis -ProductId $App -SubmissionId $Draft }
    $r.Err | Should -BeNullOrEmpty
    $r.Out | Should -Match "pending submission $Draft, last published submission \[none\]"
    $r.Out | Should -Match 'no last published submission with a usable id: nothing to compare submission fields with'
    @($s.Log) | Should -Be @("GET $Base", "GET $Base/submissions/$Draft")
  }

  It 'stops with fixed text, and sends nothing, for a submission id that is not a number' {
    $s = New-FakeStore -PendingId $Draft; Use-FakeStore $s
    $r = Invoke-Captured { Show-StoreSubmissionDiagnosis -ProductId $App -SubmissionId "1/../2`n::error::pwned" }
    $r.Err | Should -Match 'not a number'
    @($s.Calls) | Should -BeNullOrEmpty
    $r.All | Should -Not -Match $Injected
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
  BeforeAll {
    # The run script of the diagnose job's step (id: diagnose) in
    # msstore-publish.yml, dedented, exactly as the job runs it.
    $lines = @(Get-Content -LiteralPath (Join-Path $PSScriptRoot '..' '..' 'workflows' 'msstore-publish.yml'))
    $at = [array]::IndexOf($lines, '        id: diagnose')
    if ($at -lt 0) { throw 'msstore-publish.yml has no step with id diagnose' }
    while ($lines[$at] -cne '        run: |') { $at++ }
    $body = [System.Collections.Generic.List[string]]::new()
    for ($i = $at + 1; $i -lt $lines.Count; $i++) {
      $l = $lines[$i]
      if ($l.Trim() -and -not $l.StartsWith('          ')) { break }
      $body.Add($(if ($l.Length -ge 10) { $l.Substring(10) } else { '' }))
    }
    $script:DiagnoseStep = $body -join "`n"
    # Runs that script as GitHub's pwsh shell does ($ErrorActionPreference
    # Stop), from the repository root, with the step's environment variables.
    # The one change: its Connect-StoreApi call also gets this server as the
    # sign-in and API host (-LoopbackTestServer); every other call is as written.
    function script:Invoke-DiagnoseJobStep([string]$SubmissionId) {
      $names = 'SUBMISSION_ID', 'STORE_PRODUCT_ID', 'PC_TENANT_ID', 'PC_CLIENT_ID', 'PC_CLIENT_SECRET'
      $saved = @{}; foreach ($n in $names) { $saved[$n] = [Environment]::GetEnvironmentVariable($n) }
      $global:DiagnoseUrl = $Url; $global:DiagnoseStepScript = $DiagnoseStep
      Push-Location (Join-Path $PSScriptRoot '..' '..' '..')
      try {
        [Environment]::SetEnvironmentVariable('SUBMISSION_ID', $SubmissionId)
        [Environment]::SetEnvironmentVariable('STORE_PRODUCT_ID', $App)
        [Environment]::SetEnvironmentVariable('PC_TENANT_ID', 'tenant-1')
        [Environment]::SetEnvironmentVariable('PC_CLIENT_ID', 'client-1')
        [Environment]::SetEnvironmentVariable('PC_CLIENT_SECRET', $Secret)
        Invoke-Captured {
          & {
            $ErrorActionPreference = 'Stop'
            function Connect-StoreApi([string]$TenantId, [string]$ClientId, [string]$ClientSecret) {
              MsStoreRunner\Connect-StoreApi -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -AuthorityHost $global:DiagnoseUrl -ApiBase $global:DiagnoseUrl -LoopbackTestServer
            }
            . ([scriptblock]::Create($global:DiagnoseStepScript))
          }
        }
      } finally {
        Pop-Location
        foreach ($n in $names) { [Environment]::SetEnvironmentVariable($n, $saved[$n]) }
        Remove-Variable -Name DiagnoseUrl, DiagnoseStepScript -Scope Global -ErrorAction SilentlyContinue
      }
    }
  }
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
  # mode=diagnose over real HTTP: what reached the server is the sign-in and
  # GET requests only (the server's own log of every request it read).
  It 'diagnose sends only GET requests over HTTP after the sign-in, and the server is left as it was' -ForEach @(@{ Opt = @{ PendingId = '1152921505000000007'; DriftOnPut = 'MarketPrice' } }) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $fields = $Srv.Fields
    $r = Invoke-Captured { Show-StoreSubmissionDiagnosis -ProductId $App -SubmissionId '1152921505000000007' }
    $r.Err | Should -BeNullOrEmpty
    $want = @('POST /tenant-1/oauth2/v2.0/token', "GET $Base", "GET $Base/submissions/1152921505000000007", "GET $Base/submissions/1152921505000000001")
    @($Srv.Log) | Should -Be $want
    @($Srv.Seen | ForEach-Object { $_.Line }) | Should -Be $want
    $r.Out | Should -Match '(?m)^pricing sub-fields that differ: pricing\.marketSpecificPricings\.HK, pricing\.sales, pricing\.isAdvancedPricingModel$'
    $r.Out | Should -Match '(?m)would stop on pricing\.marketSpecificPricings\.HK$'
    $Srv.PendingId | Should -BeExactly '1152921505000000007'
    $Srv.Fields | Should -BeExactly $fields
    $r.All | Should -Not -Match "$Leak|$([regex]::Escape($Srv.Token))|$([regex]::Escape($Url))"
    $r.All | Should -Not -MatchExactly 'Tier\d|Launch sale|Submission [12]|NoFreeTrial'
  }
  # The diagnose job's own step script (msstore-publish.yml), run as written
  # against this server: after the sign-in, GET requests only.
  It 'the diagnose job of msstore-publish.yml, its step run as written, sends only GET requests after the sign-in and changes nothing' -ForEach @(@{ Opt = @{ PendingId = '1152921505000000007'; DriftOnPut = 'MarketPrice' } }) {
    $fields = $Srv.PendingFields
    $r = Invoke-DiagnoseJobStep '1152921505000000007'
    $r.Err | Should -BeNullOrEmpty
    $want = @('POST /tenant-1/oauth2/v2.0/token', "GET $Base", "GET $Base/submissions/1152921505000000007", "GET $Base/submissions/1152921505000000001")
    @($Srv.Log) | Should -Be $want
    @($Srv.Seen | ForEach-Object { $_.Line }) | Should -Be $want
    $r.Out | Should -Match '(?m)^diagnose \(read-only\): GET calls only; nothing is created, changed, committed or deleted$'
    $r.Out | Should -Match '(?m)^submission 1152921505000000007: status PendingCommit$'
    $r.Out | Should -Match '(?m)would stop on pricing\.marketSpecificPricings\.HK$'
    $r.Out | Should -Match '(?m)^diagnose done: GET calls only; nothing was created, changed, committed or deleted$'
    $Srv.PendingId | Should -BeExactly '1152921505000000007'
    $Srv.PendingFields | Should -BeExactly $fields
    $Srv.Sub | Should -BeNullOrEmpty
    $Srv.Blob | Should -BeNullOrEmpty
    $r.All | Should -Not -Match "$Leak|$([regex]::Escape($Srv.Token))|$([regex]::Escape($Url))"
    $r.All | Should -Not -MatchExactly 'Tier\d|Launch sale|Submission [12]|NoFreeTrial'
  }
  It 'the diagnose job of msstore-publish.yml stops before the sign-in, sending nothing, when submission_id is <Case>' -ForEach @(
    @{ Case = 'empty'; Id = '' }
    @{ Case = 'not digits'; Id = '1152921505000000007; Remove-Item x' }
    @{ Case = 'more than 20 digits'; Id = '1' * 21 }
    @{ Case = 'digits and a newline'; Id = "1152921505000000007`n" }
    @{ Case = 'digits in another script'; Id = '١١٥٢' }
  ) {
    $r = Invoke-DiagnoseJobStep $Id
    $r.Err | Should -BeExactly 'submission_id must be a number'
    $r.Out | Should -BeNullOrEmpty
    @($Srv.Log).Count | Should -Be 0
    @($Srv.Seen).Count | Should -Be 0
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

# PR #74 r7 over real HTTP: a 202 (or other non-200/201/204 2xx) answer read
# by the real client, its body read, dripping past the time limit or cut off.
Describe 'HTTP 202 Accepted over real HTTP: accepted, completion unconfirmed (PR #74 r7, fake Store on 127.0.0.1)' {
  BeforeAll {
    $script:ApiOnly = & (Get-Module MsStoreRunner) { $script:ApiOnlyNote }
    $script:Broken = 'body not received (the connection broke or the body could not be read)'
    $script:Limit2 = 'body not received (time limit of 2 s for the whole request reached)'
    $script:Token1 = 'POST /tenant-1/oauth2/v2.0/token'
  }
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

  It 'create answered HTTP 202, body <How>: accepted, completion unconfirmed, <Check>, the run stops, no advice' -ForEach @(
    @{ How = 'read'; Check = 'checked once by the id in the answer'; Opt = @{ AcceptOn = 'Create' } }
    @{ How = 'cut off'; Check = 'the app read back once'; Opt = @{ AcceptOn = 'Create'; DripOn = 'Create'; DripSeconds = 1; DripEnd = 'Break' } }
    @{ How = 'dripping past its 2 s limit'; Check = 'the app read back once'; Opt = @{ AcceptOn = 'Create'; AcceptNotDone = $true; DripOn = 'Create'; DripSeconds = 15 } }
  ) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    Mock -ModuleName MsStoreRunner Get-CallTimeout { [Math]::Min($Requested, 2) }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-Captured { Publish-StoreSubmission -ProductId $App -PackagePath $Pkg -ExpectedFileName $File -ExpectedVersion '0.4.1.0' }
    $sw.Stop()
    $lost = switch ($How) { 'read' { '' } 'cut off' { "; $Broken" } default { "; $Limit2" } }
    $answer = "Store API POST $Base/submissions?isMinimalResponse=true answered HTTP 202: accepted, completion unconfirmed$lost"
    $head = ("$answer. Accepted, completion unconfirmed: the Store answered the create with HTTP 202: it accepted the request but has not confirmed that a submission " +
      "was created. This run stops: it does not update, upload to, commit or delete any submission. ")
    $r.Out | Should -Match ('(?m)^' + [regex]::Escape("::warning title=Store create::Accepted, completion unconfirmed: the Store answered the create with HTTP 202"))
    switch ($How) {
      'read' {
        $r.Err | Should -BeExactly ("${head}Read-back of submission $NewId by id (one GET; nothing changed): status PendingCommit; packages: " +
          "[file name not shown] Uploaded, [file name not shown] Uploaded. A person needs to check submission $NewId later in Partner Center " +
          "(look only, change nothing there) or with GET $Base/submissions/$NewId. $ApiOnly")
        @($Srv.Log) | Should -Be @($Token1, "GET $Base", "POST $Base/submissions", "GET $Base/submissions/$NewId")
      }
      'cut off' {
        $r.Err | Should -BeExactly ("${head}Read-back of the app (one GET; nothing changed): pending submission $NewId. Reported by id only: not updated, not committed, " +
          "not deleted. A person needs to check submission $NewId later in Partner Center (look only, change nothing there) or with GET $Base/submissions/$NewId. $ApiOnly")
        @($Srv.Log) | Should -Be @($Token1, "GET $Base", "POST $Base/submissions", "GET $Base")
      }
      default {
        $r.Err | Should -Match ('^' + [regex]::Escape("${head}Read-back of the app (one GET; nothing changed): no pending submission yet. That does not mean none will be created"))
        @($Srv.Log) | Should -Be @($Token1, "GET $Base", "POST $Base/submissions", "GET $Base")
        $Srv.Sub | Should -BeNullOrEmpty
      }
    }
    $r.Value | Should -BeNullOrEmpty
    $sw.Elapsed.TotalSeconds | Should -BeLessThan 12
    $r.All | Should -Not -Match "created submission id=|Created, id unknown|Result unconfirmed|$DeleteAdvice|$RetryAdvice|$Leak|$([regex]::Escape($Url))"
  }
  It 'PUT of the submission answered HTTP 202, body dripping past its 2 s limit: accepted, completion unconfirmed, read back once by id, not committed' -ForEach @(
    @{ Opt = @{ AcceptOn = 'Update'; DripOn = 'Update'; DripSeconds = 15 } }
  ) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    Mock -ModuleName MsStoreRunner Get-CallTimeout { [Math]::Min($Requested, 2) }
    $r = Invoke-Captured { Publish-StoreSubmission -ProductId $App -PackagePath $Pkg -ExpectedFileName $File -ExpectedVersion '0.4.1.0' }
    $r.Err | Should -Match ('^' + [regex]::Escape("Store API PUT $Base/submissions/$NewId answered HTTP 202: accepted, completion unconfirmed; $Limit2. Accepted, completion unconfirmed: the Store accepted the update of submission $NewId but has not confirmed it is done. Not committed: this run stops, draft $NewId stays uncommitted and nothing more is sent to it. Read-back of submission $NewId by id (one GET; nothing changed): status PendingCommit; packages: "))
    @($Srv.Log)[-2..-1] | Should -Be @("PUT $Base/submissions/$NewId", "GET $Base/submissions/$NewId")
    $r.All | Should -Not -Match "updated: old packages|$DeleteAdvice|$RetryAdvice|$Leak|$([regex]::Escape($Url))"
    $Srv.Blob | Should -BeNullOrEmpty
  }
  It 'package upload answered HTTP 202, body read, not stored: accepted, completion unconfirmed, read back once by id, not committed' -ForEach @(
    @{ Opt = @{ AcceptOn = 'Upload'; AcceptNotDone = $true; UploadBody = '<x/>' } }
  ) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $r = Invoke-Captured { Publish-StoreSubmission -ProductId $App -PackagePath $Pkg -ExpectedFileName $File -ExpectedVersion '0.4.1.0' }
    $r.Err | Should -Match ('^' + [regex]::Escape("package upload answered HTTP 202: accepted, completion unconfirmed (not confirmed stored). Accepted, completion unconfirmed: the Store accepted the package upload of submission $NewId but has not confirmed it is done. Not committed: this run stops"))
    @($Srv.Log)[-2..-1] | Should -Be @('PUT /blob/upload.zip', "GET $Base/submissions/$NewId")
    $r.All | Should -Not -Match "package uploaded|draft verified|$DeleteAdvice|$RetryAdvice|$Leak|$([regex]::Escape($Url))"
    $Srv.Blob | Should -BeNullOrEmpty
  }
  It 'commit answered HTTP 202, body <How> (<Case>): accepted, completion unconfirmed, read back by id' -ForEach @(
    @{ How = 'cut off'; Case = 'carried out'; Done = $true; Opt = @{ AcceptOn = 'Commit'; DripOn = 'Commit'; DripSeconds = 1; DripEnd = 'Break' } }
    @{ How = 'read'; Case = 'not carried out'; Done = $false; Opt = @{ AcceptOn = 'Commit'; AcceptNotDone = $true } }
  ) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $r = Invoke-Captured { Publish-StoreSubmission -ProductId $App -PackagePath $Pkg -ExpectedFileName $File -ExpectedVersion '0.4.1.0' -CommitTimeoutSeconds 2 -CommitReadBackAttempts 3 -CommitReadBackIntervalSeconds 0 }
    $lost = if ($How -eq 'cut off') { "; $Broken" } else { '' }
    $failure = "Store API POST $Base/submissions/$NewId/commit answered HTTP 202: accepted, completion unconfirmed$lost"
    $got = 'was accepted (HTTP 202) but the Store has not confirmed it is done'
    $r.Out | Should -Match ('(?m)^' + [regex]::Escape("::warning title=Store commit::Accepted, completion unconfirmed: the commit request for submission $NewId $got ($failure)."))
    if ($Done) {
      $r.Err | Should -BeNullOrEmpty
      $r.Value | Should -Be @($NewId)
      $r.Out | Should -Match ([regex]::Escape("::warning title=Store commit::The commit request for submission $NewId $got; read-back 1 by id shows status Certification: it was committed"))
    } else {
      $r.Err | Should -Match ('^' + [regex]::Escape("$failure. Accepted, completion unconfirmed: the commit request for submission $NewId $got, so whether the commit has started is not confirmed. Read back by id 3 time(s), 0 s apart; last: read-back 3 of 3 shows status PendingCommit."))
      $r.Value | Should -BeNullOrEmpty
    }
    @($Srv.Log | Where-Object { $_ -like 'POST */commit' }).Count | Should -Be 1
    $r.All | Should -Not -Match "commit requested through the API|Result unconfirmed|$DeleteAdvice|$RetryAdvice|$Leak|$([regex]::Escape($Url))"
  }
  It 'manual DELETE answered HTTP 202, <Case>: never "deleted", read back once by id, nothing more sent' -ForEach @(
    @{ Case = 'carried out'; Done = $true; Opt = @{ AcceptOn = 'Delete' } }
    @{ Case = 'not carried out'; Done = $false; Opt = @{ AcceptOn = 'Delete'; AcceptNotDone = $true } }
  ) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $Srv.Sub = @{ id = $SubId; status = 'PendingCommit'; applicationPackages = @() }
    $r = Invoke-Captured { Remove-StoreDraftSubmission -ProductId $App -SubmissionId $SubId }
    $r.Err | Should -Match ('^' + [regex]::Escape("Store API DELETE $Base/submissions/$SubId answered HTTP 202: accepted, completion unconfirmed. Accepted, completion unconfirmed: the Store accepted the delete of submission $SubId but has not confirmed it is done, so it is not reported as deleted; nothing more is sent. Read-back of submission $SubId by id (one GET; nothing changed): "))
    $tail = if ($Done) { "failed (Store API GET $Base/submissions/$SubId failed: HTTP 404 (NotFound); hint: the app or submission was not found)." } else { 'status PendingCommit; packages: none.' }
    $r.Err | Should -Match ([regex]::Escape(" $tail A person needs to check GET $Base/submissions/$SubId later: HTTP 404 there means it is gone.") + '$')
    $r.Out | Should -Not -Match 'deleted draft'
    @($Srv.Log) | Should -Be @($Token1, "GET $Base/submissions/$SubId", "DELETE $Base/submissions/$SubId", "GET $Base/submissions/$SubId")
  }
  It 'token answered HTTP 202, body read: not signed in, the token is not printed, no API call' -ForEach @(@{ Opt = @{ AcceptOn = 'Token' } }) {
    $r = Invoke-Captured { Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer }
    $r.Err | Should -BeExactly 'could not get a Partner Center access token: HTTP 202'
    (& (Get-Module MsStoreRunner) { $script:Token }) | Should -BeNullOrEmpty
    $r.All | Should -Not -Match "$Leak|$([regex]::Escape($Srv.Token))"
    @($Srv.Log) | Should -Be @($Token1)
  }
  It 'the pending check answered HTTP 202 over HTTP: a failed read, not publishing, nothing created' -ForEach @(@{ Opt = @{ AcceptOn = 'AppRead' } }) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $r = Invoke-Captured { Publish-StoreSubmission -ProductId $App -PackagePath $Pkg -ExpectedFileName $File -ExpectedVersion '0.4.1.0' }
    $r.Err | Should -BeExactly "Store API GET $Base failed: HTTP 202 (a read is used only when answered HTTP 200); cannot check for a pending submission; not publishing"
    @($Srv.Log) | Should -Be @($Token1, "GET $Base")
  }
}

# Pepper, PR #74 r9, point 1: every credential this session has seen (the
# client secret, the access token, every SAS upload URL, its query and its
# signature) is masked in every line printed and every error thrown, also
# when it fits the format of the field it is in (an id of digits, a version
# of digits and dots), so the mask does not rely on the field checks.
Describe 'Every known credential is masked in every line printed and every error thrown (PR #74 r9)' {
  BeforeAll {
    $script:Mod = Get-Module MsStoreRunner
    $script:ModulePath = Join-Path $PSScriptRoot '..' 'MsStoreRunner.psm1'
  }
  BeforeEach { Reset-StoreSecrets }
  AfterAll { Reset-StoreSecrets }

  It 'masks a registered value in each form a URL escapes or unescapes it to, and not a part of it' {
    & $Mod { Register-StoreSecret 'Ab+c/d=e%3F' }
    foreach ($f in 'Ab+c/d=e%3F', 'Ab%2Bc/d=e%3F', 'Ab c/d=e%3F', 'Ab+c/d=e?', 'Ab%2Bc%2Fd%3De%253F') {
      & $Mod { param($f) Hide-StoreSecret "x $f y" } $f | Should -BeExactly 'x [redacted] y'
    }
    & $Mod { Hide-StoreSecret 'x Ab+c y' } | Should -BeExactly 'x Ab+c y'
  }

  It 'masks the longer of two credentials whole when it holds the other' {
    & $Mod { Register-StoreSecret '1152921505000000123'; Register-StoreSecret '1152921505000000123456' }
    & $Mod { Hide-StoreSecret 'a 1152921505000000123456 b 1152921505000000123 c' } | Should -BeExactly 'a [redacted] b [redacted] c'
  }

  It 'registers nothing for an empty value, $null or the not-text mark' {
    & $Mod { Register-StoreSecret ''; Register-StoreSecret $null; Register-StoreSecret $script:NotText; $script:KnownSecrets.Count } | Should -Be 0
    & $Mod { Hide-StoreSecret '[not text] x' } | Should -BeExactly '[not text] x'
  }

  It 'masks a SAS upload URL, its query with and without "?", and its signature alone, in each form' {
    $u = 'https://acct.blob.core.windows.net/c/u.zip?sv=2020-08-04&sr=b&SIG=Ab+Cd%2F9&sp=w'
    & $Mod { param($u) Register-StoreUploadUrl $u } $u
    foreach ($t in $u, '?sv=2020-08-04&sr=b&SIG=Ab+Cd%2F9&sp=w', 'sv=2020-08-04&sr=b&SIG=Ab+Cd%2F9&sp=w', 'Ab+Cd%2F9', 'Ab%2BCd%2F9', 'Ab+Cd/9', 'Ab Cd%2F9') {
      & $Mod { param($t) Hide-StoreSecret "<$t>" } $t | Should -BeExactly '<[redacted]>'
    }
  }

  It 'New-StoreError, Write-StoreHost and Protect-StoreText mask a credential of digits and one of digits and dots' {
    & $Mod { Register-StoreSecret '1152921505000000456'; Register-StoreSecret '8.8.8.8' }
    $e = & $Mod { New-StoreError 'submission 1152921505000000456 version 8.8.8.8' -OutcomeUnknown -Status 503 }
    $e.Message | Should -BeExactly 'submission [redacted] version [redacted]'
    $e.Data['StoreText'] | Should -BeExactly 'submission [redacted] version [redacted]'
    $r = Invoke-Captured { & (Get-Module MsStoreRunner) { Write-StoreHost 'id 1152921505000000456 v 8.8.8.8' } }
    $r.Out | Should -BeExactly 'id [redacted] v [redacted]'
    Protect-StoreText 'id 1152921505000000456 v 8.8.8.8' | Should -BeExactly 'id [redacted] v [redacted]'
  }

  It 'never uses a value that fits the id or version format but holds a credential as an id or a version' {
    & $Mod { Register-StoreSecret '1152921505000000456'; Register-StoreSecret '8.8.8.8' }
    & $Mod { Test-StoreId '1152921505000000456' } | Should -BeFalse
    & $Mod { Test-StoreId '11529215050000004561' } | Should -BeFalse
    & $Mod { Test-StoreId '1152921505000000004' } | Should -BeTrue
    & $Mod { Get-SafeValue '1152921505000000456' $script:SafeId } | Should -BeExactly '[invalid]'
    & $Mod { Get-SafeValue '8.8.8.8' $script:SafeVersion } | Should -BeExactly '[invalid]'
    & $Mod { Get-SafeValue '0.4.1.0' $script:SafeVersion } | Should -BeExactly '0.4.1.0'
    $ex = [System.InvalidOperationException]::new('x'); $ex.Data['StoreAcceptedId'] = '1152921505000000456'
    $rec = [System.Management.Automation.ErrorRecord]::new($ex, 'x', 'NotSpecified', $null)
    & $Mod { param($r) Get-StoreAcceptedId $r } $rec | Should -BeExactly ''
    $ex.Data['StoreAcceptedId'] = '1152921505000000004'
    & $Mod { param($r) Get-StoreAcceptedId $r } $rec | Should -BeExactly '1152921505000000004'
    foreach ($c in { Invoke-SubmissionCommit -ProductId $App -SubmissionId '1152921505000000456' },
                   { Remove-StoreDraftSubmission -ProductId $App -SubmissionId '1152921505000000456' },
                   { Assert-SubmissionHasPackage -ProductId $App -SubmissionId '1152921505000000456' -ExpectedVersion '0.4.1.0' -TimeoutMinutes 0 }) {
      $r = Invoke-Captured $c
      $r.Err | Should -BeExactly "submission id '[invalid]' is not a number"
      $r.All | Should -Not -Match '1152921505000000456'
    }
  }

  It 'Connect-StoreApi masks the client secret before its first check, and an access token it refuses' {
    $r = Invoke-Captured { Connect-StoreApi -TenantId 'bad tenant' -ClientId 'client-1' -ClientSecret '1152921505000000456' }
    $r.Err | Should -BeExactly 'tenant id has unexpected characters'
    & $Mod { Hide-StoreSecret 'x 1152921505000000456' } | Should -BeExactly 'x [redacted]'
    Use-FakeStore (New-FakeStore)
    $FakeStore.Token = '7.7.7.7 x'
    Reset-StoreSecrets
    $r = Invoke-Captured { Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret }
    $r.Err | Should -BeExactly "the token response's access_token is not a valid bearer token (it is not printed); not signed in"
    & $Mod { Hide-StoreSecret 'x 7.7.7.7 x' } | Should -BeExactly 'x [redacted]'
  }

  It 'Invoke-StoreApi masks the fileUploadUrl of an answer from the moment it arrives (<Method> HTTP <Status>)' -ForEach @(
    @{ Method = 'GET'; Status = 200 }, @{ Method = 'GET'; Status = 202 }, @{ Method = 'GET'; Status = 404 }, @{ Method = 'POST'; Status = 201 },
    @{ Method = 'POST'; Status = 202 }, @{ Method = 'POST'; Status = 503 }, @{ Method = 'PUT'; Status = 200 }, @{ Method = 'PUT'; Status = 400 }
  ) {
    Use-FakeStore (New-FakeStore)
    $u = 'https://plantedacct.blob.core.windows.net/c/p.zip?sv=2022-11-02&sig=1152921505000000789'
    $global:R9Answer = [pscustomobject]@{ StatusCode = $Status; Body = (@{ id = $SubId; fileUploadUrl = $u } | ConvertTo-Json -Compress) }
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp { $global:R9Answer }
    $r = Invoke-Captured { & (Get-Module MsStoreRunner) { param($m) Invoke-StoreApi -Method $m -Path 'applications/9NM3VWQ9MD7N' } $Method }
    $r.All | Should -Not -Match 'plantedacct|1152921505000000789'
    & $Mod { Hide-StoreSecret 'a 1152921505000000789 b' } | Should -BeExactly 'a [redacted] b'
    & $Mod { param($u) Hide-StoreSecret "a $u b" } $u | Should -BeExactly 'a [redacted] b'
  }

  # Each function that reads an upload URL masks it on its own, so a URL that
  # did not come through Invoke-StoreApi is masked too.
  It '<Fn> masks the upload URL it is given on its own, before it uses it' -ForEach @(
    @{ Fn = 'Get-SubmissionUploadUrl' }, @{ Fn = 'Read-SubmissionSafe' }, @{ Fn = 'Send-StorePackage' }
  ) {
    $sig = '1152921505000000456'
    $u = "https://jlr9layer.blob.core.windows.net/c/u.zip?sv=2022-11-02&sig=$sig"
    $json = '{"id":"1152921505000000099","status":"PendingCommit","fileUploadUrl":"' + $u + '"}'
    & $Mod {
      param($Fn, $Json, $U)
      switch ($Fn) {
        'Get-SubmissionUploadUrl' { [void](Get-SubmissionUploadUrl $Json) }
        'Read-SubmissionSafe' { [void](Read-SubmissionSafe -SubmissionJson $Json) }
        # No such file: it throws before zipping or sending anything.
        'Send-StorePackage' { try { Send-StorePackage -UploadUrl $U -PackagePath (Join-Path ([IO.Path]::GetTempPath()) 'jl-r9-none/none.msix') } catch { } }
      }
    } $Fn $json $u
    & $Mod { param($s) Hide-StoreSecret "a $s b" } $sig | Should -BeExactly 'a [redacted] b'
    & $Mod { param($u) Hide-StoreSecret "a $u b" } $u | Should -BeExactly 'a [redacted] b'
  }

  It 'Invoke-StoreApi registers nothing from an answer without a text fileUploadUrl (<Case>)' -ForEach @(
    @{ Case = 'a number'; Body = '{"fileUploadUrl":1152921505000000789}'; Lost = $false }
    @{ Case = 'not JSON, no signature'; Body = 'id=1152921505000000789'; Lost = $false }
    @{ Case = 'body lost'; Body = ''; Lost = $true }
  ) {
    Use-FakeStore (New-FakeStore)
    $before = & $Mod { $script:KnownSecrets.Count }
    $global:R9Answer = [pscustomobject]@{ StatusCode = 200; Body = $Body }
    if ($Lost) { $global:R9Answer | Add-Member BodyLost 'the answer body was not read (the connection broke)' }
    Mock -ModuleName MsStoreRunner Invoke-StoreHttp { $global:R9Answer }
    $null = Invoke-Captured { & (Get-Module MsStoreRunner) { Invoke-StoreApi -Method GET -Path 'applications/9NM3VWQ9MD7N' } }
    & $Mod { $script:KnownSecrets.Count } | Should -Be $before
  }

  # The rule the masking rests on, checked on the module's source: every
  # throw is fixed text through Hide-StoreSecret or New-StoreError, a rethrow
  # (bare throw) of one of those, Invoke-StoreApi's own New-StoreError ($e),
  # or Wait-StoreHttpTask's network exception (its callers print only its
  # type names, Get-StoreFailureText); the only Write-Host is Write-StoreHost;
  # nothing else writes to a stream that reaches the log.
  It 'every throw of the module is masked, and Write-StoreHost is its only output' {
    $tokens = $null; $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $ModulePath).Path, [ref]$tokens, [ref]$errs)
    $errs | Should -BeNullOrEmpty
    $fnOf = { param($a) $f = $a.Parent; while ($f -and $f -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $f = $f.Parent }; if ($f) { $f.Name } else { '' } }
    $throws = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.ThrowStatementAst] }, $true))
    $bad = @(foreach ($t in $throws) {
      $fn = & $fnOf $t
      $p = if ($t.Pipeline) { $t.Pipeline.Extent.Text } else { '' }
      $ok = (-not $t.Pipeline) -or $p -cmatch '^\((Hide-StoreSecret|New-StoreError) ' -or
        ($fn -ceq 'Wait-StoreHttpTask' -and $p -ceq '$Task.Exception.InnerException') -or ($fn -ceq 'Invoke-StoreApi' -and $p -ceq '$e')
      if (-not $ok) { "line $($t.Extent.StartLineNumber) in ${fn}: $($t.Extent.Text)" }
    })
    $bad | Should -BeNullOrEmpty
    $throws.Count | Should -BeGreaterThan 50
    $inv = $ast.Find({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -ceq 'Invoke-StoreApi' }, $true)
    $sets = @($inv.FindAll({ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and $args[0].Left.Extent.Text -ceq '$e' }, $true))
    $sets.Count | Should -Be 1
    $sets[0].Right.Extent.Text | Should -Match '^New-StoreError '
    $out = @(foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
      $n = $c.GetCommandName()
      if ($n -in 'Write-Warning', 'Write-Verbose', 'Write-Debug', 'Write-Information', 'Write-Error', 'Write-Progress', 'Write-Output', 'Out-Host', 'Out-Default', 'echo') { "line $($c.Extent.StartLineNumber): $n" }
      if ($n -eq 'Write-Host' -and (& $fnOf $c) -cne 'Write-StoreHost') { "line $($c.Extent.StartLineNumber): Write-Host outside Write-StoreHost" }
    })
    $out | Should -BeNullOrEmpty
    @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] -and $args[0].GetCommandName() -eq 'Write-Host' }, $true)).Count | Should -Be 1
    @($ast.FindAll({ ($args[0] -is [System.Management.Automation.Language.TypeExpressionAst] -and $args[0].TypeName.FullName -match '^(System\.)?Console\z') -or
      ($args[0] -is [System.Management.Automation.Language.VariableExpressionAst] -and $args[0].VariablePath.UserPath -ieq 'Host') }, $true)) | Should -BeNullOrEmpty
  }
}

# Pepper, PR #74 r9, point 3: nothing is sent to the draft (the PUT, the
# upload, the commit) unless the read before it shows the draft with status
# PendingCommit: the GET before the PUT, the PUT's own answer (before the
# upload) and the draft check's GET after the upload (before the commit). A
# status that is missing, empty, null, not text, not listed or another listed
# one stops with "Could not verify": look by id only, no delete or re-run
# advice. So does a PUT answer that is not one strict JSON object (r10),
# names another submission or has no upload URL as text.
Describe 'Nothing is sent to the draft unless the read before it shows it PendingCommit (PR #74 r9, fake Store)' {
  BeforeAll {
    $script:Mod = Get-Module MsStoreRunner
    # The fake's EditAnswer: the At-th answer of kind Kind becomes what Map
    # makes of its body.
    $script:R9Edit = {
      param([string]$Kind, $R)
      $e = $global:R9EditState
      if ($null -eq $e -or $Kind -cne $e.Kind) { return }
      $e.Seen++
      if ($e.Seen -eq $e.At) { $R.Body = & $e.Map ([string]$R.Body); $e.Done = $true }
    }
    # A Map that runs Edit on the body's top-level JSON object.
    function script:New-R9JsonMap([scriptblock]$Edit) {
      { param($b) $n = [System.Text.Json.Nodes.JsonNode]::Parse($b); & $Edit $n.AsObject(); $n.ToJsonString() }.GetNewClosure()
    }
    # Status values a read can show, what this module makes of each, and
    # how to set it.
    $script:R9Statuses = [ordered]@{
      'missing' = @{ Shown = '[none]'; Edit = { param($o) [void]$o.Remove('status') } }
      'empty' = @{ Shown = '[none]'; Edit = { param($o) $o['status'] = [System.Text.Json.Nodes.JsonValue]::Create('') } }
      'null' = @{ Shown = '[none]'; Edit = { param($o) $o['status'] = $null } }
      'Published' = @{ Shown = 'Published'; Edit = { param($o) $o['status'] = [System.Text.Json.Nodes.JsonValue]::Create('Published') } }
      'CommitStarted' = @{ Shown = 'CommitStarted'; Edit = { param($o) $o['status'] = [System.Text.Json.Nodes.JsonValue]::Create('CommitStarted') } }
      'pendingcommit (other case)' = @{ Shown = '[unlisted]'; Edit = { param($o) $o['status'] = [System.Text.Json.Nodes.JsonValue]::Create('pendingcommit') } }
      'an array' = @{ Shown = '[unlisted]'; Edit = { param($o) $o['status'] = [System.Text.Json.Nodes.JsonNode]::Parse('["PendingCommit"]') } }
      'an object' = @{ Shown = '[unlisted]'; Edit = { param($o) $o['status'] = [System.Text.Json.Nodes.JsonNode]::Parse('{"value":"PendingCommit"}') } }
      'a number' = @{ Shown = '[unlisted]'; Edit = { param($o) $o['status'] = [System.Text.Json.Nodes.JsonNode]::Parse('1') } }
      'true' = @{ Shown = '[unlisted]'; Edit = { param($o) $o['status'] = [System.Text.Json.Nodes.JsonNode]::Parse('true') } }
    }
    $script:R9Reads = @{
      'GET before the PUT' = @{ Kind = 'SubmissionRead'; At = 1; Call = 'GET'; Read = "the read of submission $NewId before the update (GET submission)"; Sent = @() }
      'PUT answer' = @{ Kind = 'Update'; At = 1; Call = 'PUT'; Read = "the answer to the update of submission $NewId (PUT submission)"; Sent = @("PUT $Base/submissions/$NewId") }
      'GET after the upload' = @{ Kind = 'SubmissionRead'; At = 2; Call = 'GET'; Read = "the draft check's read of submission $NewId after the upload (GET submission)"; Sent = @("PUT $Base/submissions/$NewId", 'PUT /blob/upload.zip') }
    }
    # Runs the publish with Map on the At-th answer of kind Kind.
    function script:Invoke-R9Publish([string]$Kind, [int]$At, [scriptblock]$Map) {
      $s = New-FakeStore -EditAnswer $R9Edit
      Use-FakeStore $s
      $global:R9EditState = @{ Kind = $Kind; At = $At; Seen = 0; Done = $false; Map = $Map }
      try { $r = Invoke-Publish $Pkg } finally { $done = $global:R9EditState.Done; $global:R9EditState = $null }
      $done | Should -BeTrue -Because "the run reaches answer $At of kind $Kind"
      [pscustomobject]@{ R = $r; Log = @($s.Log); Store = $s }
    }
    function script:Get-R9Unverified([string]$Failure, [string]$Read) {
      & $Mod { param($a, $b, $c, $d) Get-UnverifiedDraftText $a $b $c $d } $App $NewId $Failure $Read
    }
  }
  AfterAll { $global:R9EditState = $null }
  BeforeEach { $script:Pkg = New-TestPackage }
  AfterEach { Remove-Item -LiteralPath (Split-Path $Pkg) -Recurse -Force }

  It '<Step> with status <Case>: Could not verify, nothing more sent, no delete or re-run advice' -ForEach @(
    foreach ($st in 'GET before the PUT', 'PUT answer', 'GET after the upload') { foreach ($c in 'missing', 'empty', 'null', 'Published', 'CommitStarted', 'pendingcommit (other case)', 'an array', 'an object', 'a number', 'true') { @{ Step = $st; Case = $c } } }
  ) {
    $rd = $R9Reads[$Step]; $v = $R9Statuses[$Case]
    $x = Invoke-R9Publish $rd.Kind $rd.At (New-R9JsonMap $v.Edit)
    $x.R.Err | Should -BeExactly (Get-R9Unverified "$($rd.Call) submission $NewId showed status $($v.Shown), not PendingCommit" $rd.Read)
    $x.R.Value | Should -BeNullOrEmpty
    # Sent to the draft: only what came before this read.
    (@($x.Log | Where-Object { $_ -cmatch '^(PUT|POST|DELETE) ' -and $_ -cne "POST $Base/submissions" }) -join ' | ') | Should -BeExactly ($rd.Sent -join ' | ')
    $x.R.All | Should -Not -Match $DeleteAdvice
    $x.R.All | Should -Not -Match $RetryAdvice
    $x.R.All | Should -Not -Match $Leak
  }

  It '<Step> with status PendingCommit (the control): the run goes on and commits' -ForEach @(
    @{ Step = 'GET before the PUT' }, @{ Step = 'PUT answer' }, @{ Step = 'GET after the upload' }
  ) {
    $rd = $R9Reads[$Step]
    $x = Invoke-R9Publish $rd.Kind $rd.At (New-R9JsonMap { param($o) $o['status'] = [System.Text.Json.Nodes.JsonValue]::Create('PendingCommit') })
    $x.R.Err | Should -BeNullOrEmpty
    $x.R.Value | Should -Be @($NewId)
    $x.Log | Should -Contain "POST $Base/submissions/$NewId/commit"
  }

  It 'PUT answer <Case>: Could not verify, no upload, no commit, no delete or re-run advice' -ForEach @(
    @{ Case = 'that is not JSON'; Map = { param($b) 'not json' }; Fail = "PUT submission <id> answered {US}" }
    @{ Case = 'that is a JSON array'; Map = { param($b) "[$b]" }; Fail = "PUT submission <id> answered {US}" }
    @{ Case = 'naming another submission'; Edit = { param($o) $o['id'] = [System.Text.Json.Nodes.JsonValue]::Create('1152921505000000007') }; Fail = 'PUT submission <id> returned another submission' }
    @{ Case = 'without an id'; Edit = { param($o) [void]$o.Remove('id') }; Fail = 'PUT submission <id> returned another submission' }
    @{ Case = 'with the id as a number'; Edit = { param($o) $o['id'] = [System.Text.Json.Nodes.JsonNode]::Parse('1152921505000000099') }; Fail = 'PUT submission <id> returned another submission' }
    @{ Case = 'without a fileUploadUrl'; Edit = { param($o) [void]$o.Remove('fileUploadUrl') }; Fail = 'the submission has no fileUploadUrl' }
    @{ Case = 'with a null fileUploadUrl'; Edit = { param($o) $o['fileUploadUrl'] = $null }; Fail = 'the submission has no fileUploadUrl' }
    @{ Case = 'with an empty fileUploadUrl'; Edit = { param($o) $o['fileUploadUrl'] = [System.Text.Json.Nodes.JsonValue]::Create('') }; Fail = 'the submission has no fileUploadUrl' }
    @{ Case = 'with a fileUploadUrl that is a number'; Edit = { param($o) $o['fileUploadUrl'] = [System.Text.Json.Nodes.JsonNode]::Parse('7') }; Fail = "the submission's fileUploadUrl is not text" }
    @{ Case = 'with a fileUploadUrl that is an array'; Edit = { param($o) $o['fileUploadUrl'] = [System.Text.Json.Nodes.JsonNode]::Parse('["https://jlfakeupload.blob.core.windows.net/blob/upload.zip?sig=FAKE"]') }; Fail = "the submission's fileUploadUrl is not text" }
  ) {
    $map = if ($Map) { $Map } else { New-R9JsonMap $Edit }
    $x = Invoke-R9Publish 'Update' 1 $map
    $x.R.Err | Should -BeExactly (Get-R9Unverified $Fail.Replace('<id>', $NewId).Replace('{US}', $UnreadSubmission) $R9Reads['PUT answer'].Read)
    $x.Log | Should -Not -Contain 'PUT /blob/upload.zip'
    $x.Log | Should -Not -Contain "POST $Base/submissions/$NewId/commit"
    $x.R.All | Should -Not -Match $DeleteAdvice
    $x.R.All | Should -Not -Match $RetryAdvice
    $x.R.All | Should -Not -Match $Leak
  }

  # HTTP 204 is "done" for a PUT, but it carries no body, so nothing shows
  # the draft PendingCommit with its upload URL: Could not verify, not a
  # pre-commit stop with delete advice.
  It 'PUT answered HTTP 204 with no body: Could not verify, no upload, no commit, no delete or re-run advice' {
    $s = New-FakeStore -AcceptOn Update -AcceptStatus 204; Use-FakeStore $s
    $r = Invoke-Publish $Pkg
    $r.Err | Should -BeExactly (Get-R9Unverified "PUT submission $NewId answered $UnreadSubmission" $R9Reads['PUT answer'].Read)
    $r.Value | Should -BeNullOrEmpty
    @($s.Log) | Should -Be @("GET $Base", "POST $Base/submissions", "GET $Base", "GET $Base/submissions/$NewId", "PUT $Base/submissions/$NewId")
    $r.All | Should -Not -Match 'accepted, completion unconfirmed'
    $r.All | Should -Not -Match $DeleteAdvice
    $r.All | Should -Not -Match $RetryAdvice
    $r.All | Should -Not -Match $Leak
  }

  # Success-condition matrix (Pepper, PR #74 r9): each field a decision to go
  # on rests on, read back missing and with another value. Status and the
  # PUT answer are above; these are the ids of the reads before the commit.
  It '<Step> with the id <Case>: Could not verify, nothing more sent' -ForEach @(
    foreach ($st in 'GET before the PUT', 'GET after the upload') {
      @{ Step = $st; Case = 'missing'; Edit = { param($o) [void]$o.Remove('id') } }
      @{ Step = $st; Case = 'another number'; Edit = { param($o) $o['id'] = [System.Text.Json.Nodes.JsonValue]::Create('1152921505000000007') } }
      @{ Step = $st; Case = 'a JSON number'; Edit = { param($o) $o['id'] = [System.Text.Json.Nodes.JsonNode]::Parse('1152921505000000099') } }
    }
  ) {
    $rd = $R9Reads[$Step]
    $x = Invoke-R9Publish $rd.Kind $rd.At (New-R9JsonMap $Edit)
    $x.R.Err | Should -BeExactly (Get-R9Unverified "GET submission $NewId returned another submission" $rd.Read)
    (@($x.Log | Where-Object { $_ -cmatch '^(PUT|POST|DELETE) ' -and $_ -cne "POST $Base/submissions" }) -join ' | ') | Should -BeExactly ($rd.Sent -join ' | ')
    $x.R.All | Should -Not -Match $DeleteAdvice
    $x.R.All | Should -Not -Match $RetryAdvice
  }
}

# Pepper, PR #74 r9, point 4: after the commit, a package whose fileStatus is
# missing, not text or not a documented value could be an Uploaded package
# the check cannot see, so the submission cannot be verified; it is verified
# only with exactly one Uploaded package, of the expected version.
Describe 'After the commit, verified only when every fileStatus is documented and exactly one package is Uploaded (PR #74 r9)' {
  BeforeAll {
    $script:Mod = Get-Module MsStoreRunner
    $script:UpJson = '{"fileName":"' + $File + '","fileStatus":"Uploaded","version":"0.4.1.0"}'
    function script:New-R9Sub([string[]]$Packages, [string]$Id = ('"' + $SubId + '"')) {
      '{"id":' + $Id + ',"status":"Certification","targetPublishMode":"Manual","applicationPackages":[' + ($Packages -join ',') + ']}'
    }
    $script:CannotTell = 'not one of None, PendingUpload, Uploaded, PendingDelete, so this check cannot tell which packages are Uploaded'
  }
  BeforeEach { Reset-StoreSecrets }
  AfterAll { Reset-StoreSecrets }

  It 'another package with fileStatus <Case>: Fail, could not verify' -ForEach @(
    @{ Case = 'missing'; Status = $null; Shown = '[none]' }
    @{ Case = 'empty'; Status = '""'; Shown = '[none]' }
    @{ Case = 'null'; Status = 'null'; Shown = '[none]' }
    @{ Case = 'uploaded (other case)'; Status = '"uploaded"'; Shown = '[unlisted]' }
    @{ Case = 'an unknown value'; Status = '"Processing"'; Shown = '[unlisted]' }
    @{ Case = 'an array'; Status = '["Uploaded"]'; Shown = '[unlisted]' }
    @{ Case = 'an object'; Status = '{"value":"Uploaded"}'; Shown = '[unlisted]' }
    @{ Case = 'a number'; Status = '1'; Shown = '[unlisted]' }
    @{ Case = 'true'; Status = 'true'; Shown = '[unlisted]' }
  ) {
    $other = if ($null -eq $Status) { '{"fileName":"Jerislink-0.4.1.0-x64.msix","version":"0.4.1.0"}' } else { '{"fileName":"Jerislink-0.4.1.0-x64.msix","fileStatus":' + $Status + ',"version":"0.4.1.0"}' }
    foreach ($pk in @(@($UpJson, $other), @($other, $UpJson), @($other))) {
      $r = Test-SubmissionHasPackage -SubmissionJson (New-R9Sub $pk) -ExpectedVersion '0.4.1.0' -ExpectedFileName $File
      $r.Result | Should -Be 'Fail'
      $r.Reason | Should -BeExactly "could not verify: 1 package(s) have fileStatus $Shown, $CannotTell"
    }
  }

  It 'the submission id <Case>: Fail' -ForEach @(
    @{ Case = 'letters'; Id = '"abc"' }
    @{ Case = 'a JSON number'; Id = '1152921505000000004' }
    @{ Case = 'a known credential of digits'; Id = '"1152921505000000456"'; Secret = '1152921505000000456' }
  ) {
    if ($Secret) { & $Mod { param($v) Register-StoreSecret $v } $Secret }
    $r = Test-SubmissionHasPackage -SubmissionJson (New-R9Sub @($UpJson) $Id) -ExpectedVersion '0.4.1.0' -ExpectedFileName $File
    $r.Result | Should -Be 'Fail'
    $r.Reason | Should -BeExactly 'the submission GET returned submission id [invalid]'
  }

  It 'counts Uploaded packages: <Case>' -ForEach @(
    @{ Case = 'exactly one, of the expected version'; Pk = @('U'); Result = 'Pass'; Reason = 'submission holds exactly one Uploaded package, version 0.4.1.0' }
    @{ Case = 'one, and an old one PendingDelete'; Pk = @('U', '{"fileName":"a.msix","fileStatus":"PendingDelete","version":"0.3.0.0"}'); Result = 'Pass'; Reason = 'submission holds exactly one Uploaded package, version 0.4.1.0' }
    @{ Case = 'two of the expected version'; Pk = @('U', 'U'); Result = 'Fail'; Reason = 'submission has 2 Uploaded packages with version 0.4.1.0; expected exactly one' }
    @{ Case = 'one, and one whose version is not filled in'; Pk = @('U', '{"fileName":"a.msix","fileStatus":"Uploaded"}'); Result = 'Pending'; Reason = 'package version not filled in yet' }
    @{ Case = 'one, and one of another version'; Pk = @('U', '{"fileName":"a.msix","fileStatus":"Uploaded","version":"0.3.0.0"}'); Result = 'Fail'; Reason = 'submission still has Uploaded package(s) with version 0.3.0.0; expected only 0.4.1.0' }
    @{ Case = 'one whose version holds a known credential'; Pk = @('{"fileName":"a.msix","fileStatus":"Uploaded","version":"8.8.8.8"}'); Secret = '8.8.8.8'; Result = 'Fail'; Reason = 'submission still has Uploaded package(s) with version [invalid]; expected only 0.4.1.0' }
    @{ Case = 'one, and one still PendingUpload'; Pk = @('U', '{"fileName":"a.msix","fileStatus":"PendingUpload"}'); Result = 'Pending'; Reason = 'package still PendingUpload' }
    @{ Case = 'none, and one still PendingUpload'; Pk = @('{"fileName":"a.msix","fileStatus":"PendingUpload"}'); Result = 'Pending'; Reason = 'package still PendingUpload' }
    @{ Case = 'none'; Pk = @('{"fileName":"a.msix","fileStatus":"PendingDelete","version":"0.3.0.0"}'); Result = 'Fail'; Reason = 'submission has no Uploaded package with version 0.4.1.0' }
  ) {
    if ($Secret) { & $Mod { param($v) Register-StoreSecret $v } $Secret }
    $pk = @($Pk | ForEach-Object { if ($_ -ceq 'U') { $UpJson } else { $_ } })
    $r = Test-SubmissionHasPackage -SubmissionJson (New-R9Sub $pk) -ExpectedVersion '0.4.1.0' -ExpectedFileName $File
    $r.Result | Should -Be $Result
    $r.Reason | Should -BeExactly $Reason
  }

  It 'Assert-SubmissionHasPackage (fake Store): <Case>, never "verified"' -ForEach @(
    @{ Case = 'a package without fileStatus'; Extra = [ordered]@{ id = 'p4'; fileName = 'Jerislink-0.4.1.0-x64.msix'; version = '0.4.1.0' }
       Err = "submission check failed: could not verify: 1 package(s) have fileStatus [none], not one of None, PendingUpload, Uploaded, PendingDelete, so this check cannot tell which packages are Uploaded" }
    @{ Case = 'a package with fileStatus uploaded'; Extra = [ordered]@{ id = 'p4'; fileName = 'Jerislink-0.4.1.0-x64.msix'; fileStatus = 'uploaded'; version = '0.4.1.0' }
       Err = "submission check failed: could not verify: 1 package(s) have fileStatus [unlisted], not one of None, PendingUpload, Uploaded, PendingDelete, so this check cannot tell which packages are Uploaded" }
    @{ Case = 'two Uploaded packages'; Extra = [ordered]@{ id = 'p4'; fileName = 'Jerislink-0.4.1.0-x64.msixupload'; fileStatus = 'Uploaded'; version = '0.4.1.0' }
       Err = 'submission check failed: submission has 2 Uploaded packages with version 0.4.1.0; expected exactly one' }
    @{ Case = 'an Uploaded package whose version is not filled in'; Extra = [ordered]@{ id = 'p4'; fileName = 'a.msix'; fileStatus = 'Uploaded' }
       Err = 'submission not verified after 0 min: package version not filled in yet' }
  ) {
    $s = New-FakeStore; Use-FakeStore $s
    $s.Sub = @{ id = $SubId; status = 'Certification'; applicationPackages = @(
      [ordered]@{ id = 'p3'; fileName = $File; fileStatus = 'Uploaded'; version = '0.4.1.0' }, $Extra) }
    $r = Invoke-Captured { Assert-SubmissionHasPackage -ProductId $App -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -ExpectedFileName $File -TimeoutMinutes 0 -IntervalSeconds 0 }
    $r.Err | Should -BeExactly $Err
    $r.Out | Should -Not -Match 'verified submission'
  }
}

# K17 (Pepper, PR #74 r8 and r9): JSON that parses but holds a lone UTF-16
# surrogate ("\ud800") cannot be written back (JsonNode.ToJsonString throws,
# and its message is .NET's, not this module's). Each function that writes a
# submission back throws its own fixed text instead, and the publish stops
# with "Could not verify".
Describe 'A submission JSON that parses but cannot be written back: fixed text only (K17, PR #74 r9)' {
  BeforeAll {
    $s0 = New-FakeStore
    $s0.Sub = @{ id = $NewId; status = 'PendingCommit'; applicationPackages = @(
      [ordered]@{ fileName = $File; fileStatus = 'PendingUpload'; minimumDirectXVersion = 'None'; minimumSystemRam = 'None' }) }
    $script:K17Good = Get-FakeSubmission $s0
    $script:K17Bad = $K17Good.Replace('"title":"JerisLink"', '"title":"\ud800"')
    $script:K17Map = { param($b) $b.Replace('"title":"JerisLink"', '"title":"\ud800"') }
    $script:Mod = Get-Module MsStoreRunner
    function script:Get-K17Err([scriptblock]$Command) { try { & $Command | Out-Null; '' } catch { "$_" } }
  }
  BeforeEach { $script:Pkg = New-TestPackage }
  AfterEach { Remove-Item -LiteralPath (Split-Path $Pkg) -Recurse -Force }

  It 'the surrogate JSON parses, and writing it back throws .NET''s own message' {
    $K17Bad | Should -Not -BeExactly $K17Good
    ($K17Bad | ConvertFrom-Json).listings.'en-us'.baseListing.title.Length | Should -Be 1
    $n = [System.Text.Json.Nodes.JsonNode]::Parse($K17Bad)
    { $n.ToJsonString() } | Should -Throw
  }

  It 'Get-SubmissionComparedFields, Set-SubmissionPackage and Compare-SubmissionFields throw their own fixed text' {
    $kept = Get-SubmissionComparedFields -SubmissionJson $K17Good
    Get-K17Err { Get-SubmissionComparedFields -SubmissionJson $K17Bad } | Should -BeExactly "the submission JSON could not be read to keep its fields (the parser's message is not printed)"
    Get-K17Err { Set-SubmissionPackage -SubmissionJson $K17Bad -FileName $File } | Should -BeExactly "the submission JSON could not be read to set the packages (the parser's message is not printed)"
    Get-K17Err { Compare-SubmissionFields -ExpectedJson $kept -SubmissionJson $K17Bad } | Should -BeExactly "the submission fields could not be compared (the parser's message is not printed)"
    Get-K17Err { Compare-SubmissionFields -ExpectedJson $K17Bad -SubmissionJson $K17Bad } | Should -BeExactly "the submission fields could not be compared (the parser's message is not printed)"
    # Either side holding it gives the same fixed text on every runtime
    # (.NET 9 and 10 can compare it without throwing; .NET 8 throws).
    Get-K17Err { Compare-SubmissionFields -ExpectedJson $K17Bad -SubmissionJson $K17Good } | Should -BeExactly "the submission fields could not be compared (the parser's message is not printed)"
    (Compare-SubmissionFields -ExpectedJson $kept -SubmissionJson $K17Good).Changed | Should -BeNullOrEmpty
  }

  It 'publish, the <Step> holds it: Could not verify with the fixed text, nothing more sent' -ForEach @(
    @{ Step = 'GET before the PUT'; At = 1; Fail = "the submission JSON could not be read to keep its fields (the parser's message is not printed)"
       Read = 'the read of submission <id> before the update (GET submission)'; Sent = @() }
    @{ Step = 'GET after the upload'; At = 2; Fail = "the submission fields could not be compared (the parser's message is not printed)"
       Read = "the draft check's read of submission <id> after the upload (GET submission)"; Sent = @('PUT <base>/submissions/<id>', 'PUT /blob/upload.zip') }
  ) {
    $global:K17State = @{ At = $At; Seen = 0; Map = $K17Map }
    $s = New-FakeStore -EditAnswer { param($Kind, $R) if ($Kind -ceq 'SubmissionRead' -and ++$global:K17State.Seen -eq $global:K17State.At) { $R.Body = & $global:K17State.Map ([string]$R.Body) } }
    Use-FakeStore $s
    try { $r = Invoke-Publish $Pkg } finally { $global:K17State = $null }
    $want = & $Mod { param($a, $b, $c, $d) Get-UnverifiedDraftText $a $b $c $d } $App $NewId $Fail $Read.Replace('<id>', $NewId)
    $Sent = @($Sent | ForEach-Object { $_.Replace('<base>', $Base).Replace('<id>', $NewId) })
    $r.Err | Should -BeExactly $want
    (@($s.Log | Where-Object { $_ -cmatch '^(PUT|POST|DELETE) ' -and $_ -cne "POST $Base/submissions" }) -join ' | ') | Should -BeExactly ($Sent -join ' | ')
    $r.All | Should -Not -Match 'ToJsonString|surrogate|UTF-16'
  }
}

# K22 (Pepper, PR #74 r8 and r9): an accepted commit (HTTP 202) keeps the id
# its answer names (Exception.Data StoreAcceptedId) only when it is a plain
# number that holds no known credential; anything else is never kept, so it
# is never checked, returned or printed.
Describe 'An accepted commit keeps the id its answer names only when it is a usable id (K22, PR #74 r9, fake Store)' {
  BeforeAll {
    function script:Invoke-K22Commit([string]$IdJson) {
      $global:K22Body = '{"id":' + $IdJson + ',"status":"CommitStarted"}'
      $s = New-FakeStore -AcceptOn Commit -EditAnswer { param($Kind, $R) if ($Kind -ceq 'Commit') { $R.Body = $global:K22Body } }
      $s.Token = '1152921505000000123'
      Use-FakeStore $s
      Reset-StoreSecrets
      Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret '1152921505000000456' 6>$null
      $s.Sub = @{ id = $SubId; status = 'PendingCommit'; applicationPackages = @() }
      $rec = $null
      try { Invoke-SubmissionCommit -ProductId $App -SubmissionId $SubId 6>$null } catch { $rec = $_ }
      $global:K22Body = $null
      $rec
    }
  }

  It 'an id that is <Case>: not kept' -ForEach @(
    @{ Case = 'letters'; Id = '"abc"'; Raw = 'abc' }
    @{ Case = 'the access token (digits)'; Id = '"1152921505000000123"'; Raw = '1152921505000000123' }
    @{ Case = 'the client secret (digits)'; Id = '"1152921505000000456"'; Raw = '1152921505000000456' }
    @{ Case = 'a JSON number'; Id = '1152921505000000004'; Raw = '[not text]' }
    @{ Case = 'an array'; Id = '["1152921505000000004"]'; Raw = '[not text]' }
    @{ Case = 'digits of another script'; Id = '"١١٥٢٩٢١٥٠٥٠٠٠٠٠٠٠٠٤"'; Raw = '١١٥٢٩٢١٥٠٥٠٠٠٠٠٠٠٠٤' }
    @{ Case = 'empty'; Id = '""'; Raw = '' }
  ) {
    $rec = Invoke-K22Commit $Id
    $rec | Should -Not -BeNullOrEmpty
    "$rec" | Should -BeExactly "Store API POST /v1.0/my/applications/$App/submissions/$SubId/commit answered HTTP 202: accepted, completion unconfirmed"
    $rec.Exception.Data['StoreStatus'] | Should -Be 202
    $rec.Exception.Data.Contains('StoreAcceptedId') | Should -BeFalse
    if ($Raw) { @($rec.Exception.Data.Values | ForEach-Object { "$_" }) | Should -Not -Contain $Raw }
    & (Get-Module MsStoreRunner) { param($r) Get-StoreAcceptedId $r } $rec | Should -BeExactly ''
  }

  It 'a plain id that holds no credential (the control): kept' {
    $rec = Invoke-K22Commit ('"' + $SubId + '"')
    $rec.Exception.Data['StoreAcceptedId'] | Should -BeExactly $SubId
    & (Get-Module MsStoreRunner) { param($r) Get-StoreAcceptedId $r } $rec | Should -BeExactly $SubId
  }
}

# Pepper, PR #74 r10. Every Store answer is read only as exactly one complete
# JSON object with each key once, at any depth and in any case
# (ConvertFrom-StoreJson), and every signature in it is masked before any
# field of it is read: a sig parameter whose name is percent-encoded (once or
# twice), one before or in a fragment, after a ";", in a nested fileUploadUrl,
# in another field, or in an answer that is not JSON that can be read.
# Point 1: masking. Point 2: each read of the publish (and of every read-back
# and check) given each answer shape (an array in place of the object, an
# object in place of a list, a key twice, text before or after it, two
# objects, a comment, single quotes, a trailing comma, NaN) stops safely:
# nothing more is sent, no delete or re-run advice, nothing of it printed.
# Point 3: the check after the commit is never "verified" on such an answer.
# The 127f676 module fails these tests (the controls aside).
Describe 'Store answers are read only as one strict JSON object, every signature masked first (PR #74 r10, fake Store)' {
  BeforeAll {
    $script:Mod = Get-Module MsStoreRunner
    # A synthetic signature that is also a usable submission id: the pending
    # id the app read shows in Pepper's repro.
    $script:R10Sig = '1152921505000000123'
    $script:R10Url = 'https://jlfakeupload.blob.core.windows.net/blob/upload.zip?sv=2020-08-04&sr=b&sp=w'
    $script:R10Leak = "$Leak|$R10Sig|r10-planted"
    $script:ApiNote = & $Mod { $script:ApiOnlyNote }
    # Text as the Store sends it (no & for "&").
    $script:R10Out = [System.Text.Json.JsonSerializerOptions]::new()
    $R10Out.Encoder = [System.Text.Encodings.Web.JavaScriptEncoder]::UnsafeRelaxedJsonEscaping
    # A Map that runs Edit on the body's top-level JSON object.
    function script:New-R10JsonMap([scriptblock]$Edit) {
      $opt = $R10Out
      { param($b) $n = [System.Text.Json.Nodes.JsonNode]::Parse($b); & $Edit $n.AsObject(); $n.ToJsonString($opt) }.GetNewClosure()
    }
    # The fake's EditAnswer: for each edit @{ Kind; At; Map }, the At-th
    # answer of kind Kind becomes what Map makes of its body.
    $script:R10Edit = {
      param([string]$Kind, $R)
      foreach ($e in @($global:R10EditState)) {
        if ($null -eq $e -or $Kind -cne $e.Kind) { continue }
        $e.Seen++
        if ($e.Seen -eq $e.At) { $R.Body = [string](& $e.Map ([string]$R.Body)); $e.Done = $true }
      }
    }
    # Runs Command (default: the publish) against a fake Store made with
    # Options, with Edits on its answers.
    function script:Invoke-R10Run([hashtable[]]$Edits, [hashtable]$Options = @{}, [scriptblock]$Command = $null, [scriptblock]$Setup = $null) {
      $s = New-FakeStore -EditAnswer $R10Edit @Options
      Use-FakeStore $s
      if ($Setup) { & $Setup $s }
      $global:R10EditState = @(foreach ($e in $Edits) { @{ Kind = $e.Kind; At = $e.At; Map = $e.Map; Seen = 0; Done = $false } })
      try { $r = if ($Command) { Invoke-Captured $Command } else { Invoke-Publish $Pkg } } finally { $st = @($global:R10EditState); $global:R10EditState = $null }
      foreach ($e in $st) { $e.Done | Should -BeTrue -Because "the run reaches answer $($e.At) of kind $($e.Kind)" }
      [pscustomobject]@{ R = $r; Log = @($s.Log); Sent = (@($s.Log | Where-Object { $_ -cmatch '^(PUT|POST|DELETE) ' }) -join ' | '); Store = $s
        Committed = [bool]@($s.Log | Where-Object { $_ -cmatch '^POST .*/commit$' }) }
    }
    function script:Get-R10Unverified([string]$Failure, [string]$Read) {
      & $Mod { param($a, $b, $c, $d) Get-UnverifiedDraftText $a $b $c $d } $App $NewId $Failure $Read
    }
    function script:Assert-R10Safe($X) {
      $X.R.All | Should -Not -Match $DeleteAdvice -Because '[delete advice]'
      $X.R.All | Should -Not -Match $RetryAdvice -Because '[re-run advice]'
      $X.R.All | Should -Not -Match $R10Leak -Because '[printed]'
      $X.R.Out | Should -Not -Match 'verified submission' -Because '[verified]'
    }

    # The shapes of an answer (Body: one JSON object, as the fake sends it).
    $script:R10Shapes = [ordered]@{
      'an array holding it' = { param($b) "[$b]" }
      'text before it' = { param($b) "Answer: $b" }
      'text after it' = { param($b) "$b (r10)" }
      'two JSON objects' = { param($b) "$b`n$b" }
      'a comment in it' = { param($b) '{/* r10 */' + $b.Substring(1) }
      'a key in single quotes' = { param($b) $b -creplace '^\{"([^"]+)"', '{''$1''' }
      'a trailing comma' = { param($b) $b.Substring(0, $b.Length - 1) + ',}' }
      'NaN in it' = { param($b) '{"r10":NaN,' + $b.Substring(1) }
      'its first key twice, a planted value first' = { param($b) $b -creplace '^\{"([^"]+)":', '{"$1":"r10-planted","$1":' }
      'its first key twice, in another case' = { param($b) '{"' + [regex]::Match($b, '^\{"([^"]+)"').Groups[1].Value.ToUpperInvariant() + '":"r10-planted",' + $b.Substring(1) }
      'a nested key twice' = { param($b) if ($b -cmatch '":\{"') { $b -creplace '":\{"([^"]+)":', '":{"$1":"r10-planted","$1":' } else { '{"r10":{"k":"r10-planted","k":1},' + $b.Substring(1) } }
      # Submission answers only.
      'applicationPackages one object, not a list' = New-R10JsonMap { param($o) $p = $o['applicationPackages'].AsArray(); $last = $p[$p.Count - 1]; $p.RemoveAt($p.Count - 1); $o['applicationPackages'] = $last }
      'status twice, a planted value first' = { param($b) $b.Replace('"status":"', '"status":"Published","status":"') }
      'status twice, PendingCommit first' = { param($b) $b.Replace('"status":"', '"status":"PendingCommit","status":"') }
      'status twice, in another case' = { param($b) $b.Replace('"status":"', '"Status":"Published","status":"') }
      'applicationPackages twice, an empty list first' = { param($b) $b.Replace('"applicationPackages":', '"applicationPackages":[],"applicationPackages":') }
      'a package''s fileStatus twice' = { param($b) $b.Replace('"fileStatus":"', '"fileStatus":"Uploaded","fileStatus":"') }
    }

    $s0 = New-FakeStore
    $script:R10Read1 = "the read of submission $NewId before the update (GET submission)"
    $script:R10ReadPut = "the answer to the update of submission $NewId (PUT submission)"
    $script:R10Read2 = "the draft check's read of submission $NewId after the upload (GET submission)"
    $script:R10ReadApp = 'the read of the app after create (GET application)'
    $create = "POST $Base/submissions"
    $put = "PUT $Base/submissions/$NewId"
    $commit = "POST $Base/submissions/$NewId/commit"
    # Where each read is, what its stop says (Err exactly, or ErrLike each
    # matched), and every PUT, POST and DELETE sent in the run.
    $script:R10Points = @{
      'GET application, the pending check' = @{ Edits = @(@{ Kind = 'AppRead'; At = 1 }); Err = "GET application returned $UnreadAnswer"; Sent = '' }
      'POST create' = @{ Edits = @(@{ Kind = 'Create'; At = 1 }); Sent = $create
        ErrLike = @('Created, id unknown', [regex]::Escape("Read-back of the app (one GET): pending submission $NewId. Reported by id only")) }
      'GET application after the create' = @{ Edits = @(@{ Kind = 'AppRead'; At = 2 }); Err = (Get-R10Unverified "GET application returned $UnreadAnswer" $R10ReadApp); Sent = $create }
      'GET submission before the PUT' = @{ Edits = @(@{ Kind = 'SubmissionRead'; At = 1 }); Err = (Get-R10Unverified "GET submission $NewId returned $UnreadSubmission" $R10Read1); Sent = $create }
      'PUT submission' = @{ Edits = @(@{ Kind = 'Update'; At = 1 }); Err = (Get-R10Unverified "PUT submission $NewId answered $UnreadSubmission" $R10ReadPut); Sent = "$create | $put" }
      'GET submission after the upload' = @{ Edits = @(@{ Kind = 'SubmissionRead'; At = 2 }); Err = (Get-R10Unverified "GET submission $NewId returned $UnreadSubmission" $R10Read2); Sent = "$create | $put | PUT /blob/upload.zip" }
      # The commit answer is shown, not used: the next step checks the
      # submission by id (below).
      'POST commit' = @{ Edits = @(@{ Kind = 'Commit'; At = 1 }); Value = $NewId; Sent = "$create | $put | PUT /blob/upload.zip | $commit"
        OutLike = [regex]::Escape("submission $NewId commit requested through the API: status=[answer not read]") }
      'GET submission, read-backs of a commit with no answer' = @{ Options = @{ LoseResponse = 'Commit' }; Sent = "$create | $put | PUT /blob/upload.zip | $commit"
        Edits = @(@{ Kind = 'SubmissionRead'; At = 3 }, @{ Kind = 'SubmissionRead'; At = 4 }, @{ Kind = 'SubmissionRead'; At = 5 })
        ErrLike = @('Result unconfirmed', [regex]::Escape('last: read-back 3 of 3 did not return that submission')); NotLike = 'by id shows status' }
      'GET submission, read-back of an accepted PUT' = @{ Options = @{ AcceptOn = 'Update' }; Edits = @(@{ Kind = 'SubmissionRead'; At = 2 }); Sent = "$create | $put"
        ErrLike = @([regex]::Escape("Read-back of submission $NewId by id (one GET; nothing changed): it did not return that submission.")) }
      'GET application, read-back of a refused create' = @{ Options = @{ CreateErrorStatus = 400; CreateErrorBody = '{"code":"InvalidParameterValue"}' }; Edits = @(@{ Kind = 'AppRead'; At = 2 }); Sent = $create
        ErrLike = @([regex]::Escape("Read-back of the app after the refused create (one GET; nothing changed or deleted): failed (GET application returned $UnreadAnswer).")) }
      'GET application, read-back of a create without an id' = @{ Options = @{ CreateWithoutId = $true }; Edits = @(@{ Kind = 'AppRead'; At = 2 }); Sent = $create
        ErrLike = @('Created, id unknown', [regex]::Escape("Read-back of the app (one GET): failed (GET application returned $UnreadAnswer).")) }
      'GET application, read-back of a create with no answer' = @{ Options = @{ LoseResponse = 'Create' }; Edits = @(@{ Kind = 'AppRead'; At = 2 }); Sent = $create
        ErrLike = @([regex]::Escape("Read-back of the app: failed too (GET application returned $UnreadAnswer).")) }
      'POST create answered HTTP 202' = @{ Options = @{ AcceptOn = 'Create' }; Edits = @(@{ Kind = 'Create'; At = 1 }); Sent = $create
        ErrLike = @('Accepted, completion unconfirmed', [regex]::Escape("Read-back of the app (one GET; nothing changed): pending submission $NewId. Reported by id only")) }
    }
  }
  AfterAll { $global:R10EditState = $null; Reset-StoreSecrets }
  BeforeEach { $script:Pkg = New-TestPackage }
  AfterEach { Remove-Item -LiteralPath (Split-Path $Pkg) -Recurse -Force }

  # Discovery-time lists (-ForEach is built before BeforeAll runs).
  $shapes = @('an array holding it', 'text before it', 'text after it', 'two JSON objects', 'a comment in it', 'a key in single quotes',
    'a trailing comma', 'NaN in it', 'its first key twice, a planted value first', 'its first key twice, in another case', 'a nested key twice')
  $subShapes = @('applicationPackages one object, not a list', 'status twice, a planted value first', 'status twice, PendingCommit first', 'status twice, in another case',
    'applicationPackages twice, an empty list first', 'a package''s fileStatus twice')
  $urlCases = @(
    @{ Case = 'a percent-encoded name (%73ig)'; Query = '&%73ig=' }
    @{ Case = 'a percent-encoded name (s%69g)'; Query = '&s%69g=' }
    @{ Case = 'a name encoded twice (%2573ig)'; Query = '&%2573ig=' }
    @{ Case = 'a name with a space before it (%20sig)'; Query = '&%20sig=' }
    @{ Case = 'a name with + after it (sig+, a space once decoded)'; Query = '&sig+=' }
    @{ Case = 'a fragment after the signature'; Query = '&sig='; After = '#r10' }
    @{ Case = 'the signature in the fragment'; Query = '#sig=' }
    @{ Case = 'a ; before the signature'; Query = ';sig=' }
    @{ Case = 'SIG in capitals (the control)'; Query = '&SIG=' }
  )

  # Point 2 (and the self-check): every read, every shape.
  It '<Point>, the answer <Shape>: stops safely, nothing more sent, no delete or re-run advice, nothing of it printed' -ForEach @(
    foreach ($p in 'GET application, the pending check', 'POST create', 'GET application after the create', 'POST commit',
      'GET application, read-back of a refused create', 'GET application, read-back of a create without an id',
      'GET application, read-back of a create with no answer', 'POST create answered HTTP 202') { foreach ($sh in $shapes) { @{ Point = $p; Shape = $sh } } }
    foreach ($p in 'GET submission before the PUT', 'PUT submission', 'GET submission after the upload',
      'GET submission, read-backs of a commit with no answer', 'GET submission, read-back of an accepted PUT') { foreach ($sh in $shapes + $subShapes) { @{ Point = $p; Shape = $sh } } }
  ) {
    $pt = $R10Points[$Point]
    $o = if ($pt.Options) { $pt.Options } else { @{} }
    $x = Invoke-R10Run @(foreach ($e in $pt.Edits) { @{ Kind = $e.Kind; At = $e.At; Map = $R10Shapes[$Shape] } }) $o
    if ($pt.Err) { $x.R.Err | Should -BeExactly $pt.Err }
    foreach ($l in @($pt.ErrLike)) { if ($l) { $x.R.Err | Should -Match $l } }
    if ($pt.OutLike) { $x.R.Err | Should -BeNullOrEmpty; $x.R.Out | Should -Match $pt.OutLike }
    if ($pt.NotLike) { $x.R.All | Should -Not -Match $pt.NotLike }
    if ($pt.Value) { $x.R.Value | Should -Be @($pt.Value) -Because '[result]' } else { $x.R.Value | Should -BeNullOrEmpty -Because '[result]' }
    if ($pt.Sent -notmatch '/commit') { $x.Committed | Should -BeFalse -Because '[commit sent]' }
    $x.Sent | Should -BeExactly $pt.Sent -Because '[sent]'
    Assert-R10Safe $x
  }

  It 'the token answer <Shape>: not signed in, nothing of it printed' -ForEach @(foreach ($sh in $shapes) { @{ Shape = $sh } }) {
    $x = Invoke-R10Run @(@{ Kind = 'Token'; At = 1; Map = $R10Shapes[$Shape] }) @{} { Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret }
    $x.R.Err | Should -BeExactly "the token request returned $UnreadAnswer; not signed in"
    $x.R.Out | Should -Not -Match 'signed in to the Store'
    Assert-R10Safe $x
  }

  It 'a delete by hand, its GET answer <Shape>: nothing deleted' -ForEach @(foreach ($sh in $shapes + $subShapes) { @{ Shape = $sh } }) {
    $x = Invoke-R10Run @(@{ Kind = 'SubmissionRead'; At = 1; Map = $R10Shapes[$Shape] }) @{} { Remove-StoreDraftSubmission -ProductId $App -SubmissionId $NewId } {
      param($s) $s.Sub = @{ id = $NewId; status = 'PendingCommit'; applicationPackages = @(
        [ordered]@{ id = 'p1'; fileName = $File; fileStatus = 'PendingUpload'; minimumDirectXVersion = 'None'; minimumSystemRam = 'None' }) }; $s.PendingId = $NewId }
    $x.R.Err | Should -BeExactly "GET submission $NewId did not return that submission; not deleting"
    $x.Sent | Should -BeExactly '' -Because '[sent]'
    Assert-R10Safe $x
  }

  # Point 3: the check after the commit (the next workflow step).
  It 'the check after the commit, the answer <Shape>: failed, never "verified"' -ForEach @(foreach ($sh in $shapes + $subShapes) { @{ Shape = $sh } }) {
    $x = Invoke-R10Run @(@{ Kind = 'SubmissionRead'; At = 1; Map = $R10Shapes[$Shape] }) @{} {
      Assert-SubmissionHasPackage -ProductId $App -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -ExpectedFileName $File -TimeoutMinutes 0 -IntervalSeconds 0 } {
      param($s) $s.Sub = @{ id = $SubId; status = 'Certification'; applicationPackages = @(
        [ordered]@{ id = 'p3'; fileName = $File; fileStatus = 'Uploaded'; version = '0.4.1.0' }) } }
    $x.R.Err | Should -BeExactly "submission check failed: the submission GET returned $UnreadSubmission"
    $x.Sent | Should -BeExactly '' -Because '[sent]'
    Assert-R10Safe $x
  }

  It 'the check after the commit, the same answer as one JSON object (the control): verified' {
    $x = Invoke-R10Run @() @{} {
      Assert-SubmissionHasPackage -ProductId $App -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -ExpectedFileName $File -TimeoutMinutes 0 -IntervalSeconds 0 } {
      param($s) $s.Sub = @{ id = $SubId; status = 'Certification'; applicationPackages = @(
        [ordered]@{ id = 'p3'; fileName = $File; fileStatus = 'Uploaded'; version = '0.4.1.0' }) } }
    $x.R.Err | Should -BeNullOrEmpty
    $x.R.Out | Should -Match "verified submission ${SubId}: submission holds exactly one Uploaded package, version 0\.4\.1\.0"
  }

  # Pepper's repros of point 3, as pure checks: a package object in place of
  # the list, and status twice (PendingCommit, then Published) were verified.
  It 'Test-SubmissionHasPackage and Test-DraftReadyToCommit, <Case>: Fail, the answer is not read' -ForEach @(
    @{ Case = 'applicationPackages one object'; Pk = '{"fileName":"<f>","fileStatus":"Uploaded","version":"0.4.1.0"}'; Status = '"status":"<s>"' }
    @{ Case = 'status twice, PendingCommit then the status checked'; Pk = '[{"fileName":"<f>","fileStatus":"Uploaded","version":"0.4.1.0"}]'; Status = '"status":"PendingCommit","status":"<s>"' }
    @{ Case = 'status twice, the status checked then Published'; Pk = '[{"fileName":"<f>","fileStatus":"Uploaded","version":"0.4.1.0"}]'; Status = '"status":"<s>","status":"Published"' }
    @{ Case = 'status twice, in another case'; Pk = '[{"fileName":"<f>","fileStatus":"Uploaded","version":"0.4.1.0"}]'; Status = '"Status":"PendingCommit","status":"<s>"' }
    @{ Case = 'a package''s fileStatus twice'; Pk = '[{"fileName":"<f>","fileStatus":"PendingDelete","fileStatus":"Uploaded","version":"0.4.1.0"}]'; Status = '"status":"<s>"' }
    @{ Case = 'applicationPackages twice'; Pk = '[],"applicationPackages":[{"fileName":"<f>","fileStatus":"Uploaded","version":"0.4.1.0"}]'; Status = '"status":"<s>"' }
  ) {
    foreach ($w in @(@{ S = 'Published'; Fn = 'Has' }, @{ S = 'PendingCommit'; Fn = 'Ready' })) {
      $json = '{"id":"' + $SubId + '",' + $Status.Replace('<s>', $w.S) + ',"targetPublishMode":"Manual","applicationPackages":' + $Pk.Replace('<f>', $File) + '}'
      $r = if ($w.Fn -eq 'Has') { Test-SubmissionHasPackage -SubmissionJson $json -ExpectedVersion '0.4.1.0' -ExpectedSubmissionId $SubId -ExpectedFileName $File }
           else { Test-DraftReadyToCommit -SubmissionJson $json -SubmissionId $SubId -ExpectedFileName $File -ExpectedVersion '0.4.1.0' }
      $r.Result | Should -Be 'Fail' -Because "[result] $($w.Fn)"
      $r.Reason | Should -BeExactly "the submission GET returned $UnreadSubmission" -Because $w.Fn
    }
    # The control: the same answer with the list and one status.
    $ok = '{"id":"' + $SubId + '","status":"Published","targetPublishMode":"Manual","applicationPackages":[{"fileName":"' + $File + '","fileStatus":"Uploaded","version":"0.4.1.0"}]}'
    (Test-SubmissionHasPackage -SubmissionJson $ok -ExpectedVersion '0.4.1.0' -ExpectedSubmissionId $SubId -ExpectedFileName $File).Result | Should -Be 'Pass'
  }

  # Point 3: one strict rule for every read, the price check among them.
  It 'Test-SubmissionPricing, <Case>: <Result>' -ForEach @(
    @{ Case = 'pricing as a list'; Json = '{"pricing":[{"priceId":"Tier1"}]}'; Result = 'Unread'; Reason = 'pricing is not a JSON object; this run does not send a price it cannot read' }
    @{ Case = 'priceId as a list'; Json = '{"pricing":{"priceId":["Tier1"]}}'; Result = 'Unread'; Reason = 'pricing.priceId is not text; this run does not send a price it cannot read' }
    @{ Case = 'pricing twice'; Json = '{"pricing":{"priceId":"Base"},"pricing":{"priceId":"Tier1"}}'; Result = 'Unread'; Reason = '<unread>' }
    @{ Case = 'priceId twice'; Json = '{"pricing":{"priceId":"Base","priceId":"Tier1"}}'; Result = 'Unread'; Reason = '<unread>' }
    @{ Case = 'priceId twice, in another case'; Json = '{"pricing":{"PriceId":"Base","priceId":"Tier1"}}'; Result = 'Unread'; Reason = '<unread>' }
    @{ Case = 'the answer in a list'; Json = '[{"pricing":{"priceId":"Tier1"}}]'; Result = 'Unread'; Reason = '<unread>' }
    @{ Case = 'text before it'; Json = 'Answer: {"pricing":{"priceId":"Tier1"}}'; Result = 'Unread'; Reason = '<unread>' }
    @{ Case = 'one JSON object (the control)'; Json = '{"pricing":{"priceId":"Tier1"}}'; Result = 'Pass'; Reason = 'pricing.priceId is set and is kept as is (the price is not printed)' }
  ) {
    $r = Test-SubmissionPricing -SubmissionJson $Json
    $r.Result | Should -Be $Result -Because '[result]'
    $r.Reason | Should -BeExactly $Reason.Replace('<unread>', "the submission GET returned $UnreadAnswer")
  }

  It 'publish, the read before the PUT shows <Case>: could not verify, no PUT, no delete or re-run advice' -ForEach @(
    @{ Case = 'pricing as a list'; Edit = { param($o) $o['pricing'] = [System.Text.Json.Nodes.JsonNode]::Parse('[{"priceId":"Free"}]') }; Fail = 'price check: pricing is not a JSON object; this run does not send a price it cannot read' }
    @{ Case = 'priceId as a list'; Edit = { param($o) $o['pricing']['priceId'] = [System.Text.Json.Nodes.JsonNode]::Parse('["Free"]') }; Fail = 'price check: pricing.priceId is not text; this run does not send a price it cannot read' }
  ) {
    $x = Invoke-R10Run @(@{ Kind = 'SubmissionRead'; At = 1; Map = (New-R10JsonMap $Edit) })
    $x.R.Err | Should -BeExactly (Get-R10Unverified $Fail $R10Read1)
    $x.Sent | Should -BeExactly "POST $Base/submissions" -Because '[sent]'
    Assert-R10Safe $x
  }

  # Point 1: Pepper's repro. The pending check's answer holds an upload URL
  # whose signature the pending id repeats.
  # r12: a sig in another field is not a credential this run was given (only
  # a fileUploadUrl is), so nothing of it is masked and the pending id is
  # usable: the usual stop by id, the id in full (r11 masked it in output).
  It 'the pending check''s answer holds a signature, <Case>, in <Where>, and the pending id is that signature: <Then>' -ForEach @(
    foreach ($w in 'fileUploadUrl', 'a nested fileUploadUrl', 'another field') { foreach ($c in $urlCases) { $c + @{ Where = $w; Then = $(if ($w -ceq 'another field') { 'the id is usable, the usual stop by id, the id in full (r12)' } else { 'no usable id, no delete advice, never printed' }) } } }
  ) {
    # Locals only: a closure does not see this script's variables.
    $url = $R10Url + $Query + $R10Sig + $After; $sig = $R10Sig
    $x = Invoke-R10Run @(@{ Kind = 'AppRead'; At = 1; Map = (New-R10JsonMap {
      param($o)
      switch ($Where) {
        'fileUploadUrl' { $o['fileUploadUrl'] = [System.Text.Json.Nodes.JsonValue]::Create($url) }
        'a nested fileUploadUrl' { $o['r10'] = [System.Text.Json.Nodes.JsonObject]::new(); $o['r10']['fileUploadUrl'] = [System.Text.Json.Nodes.JsonValue]::Create($url) }
        'another field' { $o['r10note'] = [System.Text.Json.Nodes.JsonValue]::Create("upload to $url") }
      }
      $o['pendingApplicationSubmission'] = [System.Text.Json.Nodes.JsonNode]::Parse('{"id":"' + $sig + '","resourceLocation":"y"}')
    }.GetNewClosure()) })
    if ($Where -ceq 'another field') {
      # The usable id: one more GET, of that submission by its id, for its
      # status (the fake has no such submission: HTTP 404, status not read).
      $x.Log | Should -Be @("GET $Base", "GET $Base/submissions/$R10Sig") -Because '[sent]'
      $want = ("Partner Center already has a pending submission $R10Sig for $App (its status was not read). This run did not create it, " +
        "so it stops and touches nothing (it never deletes, changes or commits a submission it did not create). " +
        "A person decides what happens to submission $R10Sig. To look at it without changing anything, run this workflow with " +
        "mode=diagnose and submission_id=$R10Sig (GET calls only). $ApiNote " +
        "If it is in certification, let certification finish. If it is an uncommitted draft: " + (& $Mod { param($a, $b) Get-DeleteByIdText $a $b } $App $R10Sig))
      $x.R.Err | Should -BeExactly $want
      $x.R.Out | Should -Match "the status of pending submission $R10Sig was not read: "
      $x.R.All | Should -Not -Match "\[redacted\]|$Leak|r10-planted" -Because '[printed]'
      $x.R.Out | Should -Not -Match 'verified submission' -Because '[verified]'
    } else {
      $x.Log | Should -Be @("GET $Base") -Because '[sent]'
      $x.R.Err | Should -BeExactly ("Partner Center already has a pending submission (no usable id) for $App. This run did not create it, " +
        "so it stops and touches nothing. Check GET /v1.0/my/applications/$App before doing anything. $ApiNote")
      Assert-R10Safe $x
    }
  }

  # r12: in another field the pending id is usable (it is not a credential
  # this run was given), so the run gives the usual stop for another pending
  # id, the id in full (delete advice for this run's own draft only, then a
  # re-run, as for any other pending id). In an answer with text before it,
  # the fileUploadUrl is still a confirmed credential (read from the text as
  # it came, Register-StoreTextUploadUrl), as in r10.
  It 'the create answer holds a signature, <Case>, in <Where>, and the app read after it shows that signature as pending: <Then>' -ForEach @(
    foreach ($w in 'fileUploadUrl', 'a nested fileUploadUrl', 'another field', 'an answer with text before it') { foreach ($c in $urlCases) { $c + @{ Where = $w; Then = $(if ($w -ceq 'another field') { 'the usual stop, the id in full, delete advice for this run''s own draft only (r12)' } else { 'never printed, no delete advice' }) } } }
  ) {
    # Locals only: a closure does not see this script's variables.
    $url = $R10Url + $Query + $R10Sig + $After; $sig = $R10Sig
    $opt = $R10Out
    $create = {
      param($b)
      $n = [System.Text.Json.Nodes.JsonNode]::Parse($b)
      switch ($Where) {
        'a nested fileUploadUrl' { $n['r10'] = [System.Text.Json.Nodes.JsonObject]::new(); $n['r10']['fileUploadUrl'] = [System.Text.Json.Nodes.JsonValue]::Create($url) }
        'another field' { $n['r10note'] = [System.Text.Json.Nodes.JsonValue]::Create("upload to $url") }
        default { $n['fileUploadUrl'] = [System.Text.Json.Nodes.JsonValue]::Create($url) }
      }
      $t = $n.ToJsonString($opt)
      if ($Where -ceq 'an answer with text before it') { "Answer: $t" } else { $t }
    }.GetNewClosure()
    $pending = New-R10JsonMap { param($o) $o['pendingApplicationSubmission'] = [System.Text.Json.Nodes.JsonNode]::Parse('{"id":"' + $sig + '","resourceLocation":"y"}') }.GetNewClosure()
    $x = Invoke-R10Run @(@{ Kind = 'Create'; At = 1; Map = $create }, @{ Kind = 'AppRead'; At = 2; Map = $pending })
    if ($Where -ceq 'an answer with text before it') {
      $x.R.Err | Should -Match 'Created, id unknown'
      $x.R.Err | Should -Match ([regex]::Escape('Read-back of the app (one GET): a pending submission without a usable id.'))
    } elseif ($Where -ceq 'another field') {
      $apiOnly = & $Mod { $script:ApiOnlyNote }
      $x.R.Err | Should -Match ('^' + [regex]::Escape("after create, the app's pending submission is '$R10Sig', not $NewId. Not committed: draft $NewId stays uncommitted. $apiOnly Delete exactly this submission through the API: DELETE $Base/submissions/$NewId "))
      $x.R.Err | Should -Not -Match 'Could not verify'
      $x.Sent | Should -BeExactly "POST $Base/submissions" -Because '[sent]'
      $x.R.All | Should -Not -Match "\[redacted\]|$Leak|r10-planted" -Because '[printed]'
      $x.R.Out | Should -Not -Match 'verified submission' -Because '[verified]'
      return
    } else {
      $x.R.Err | Should -BeExactly (Get-R10Unverified "after create, the app's pending submission has no usable id" $R10ReadApp)
    }
    $x.Sent | Should -BeExactly "POST $Base/submissions" -Because '[sent]'
    Assert-R10Safe $x
  }

  # r12: only a fileUploadUrl (the field the API hands an upload URL in) is a
  # confirmed credential, wherever it is in the answer and whatever the
  # answer's shape; a sig anywhere else is not one this run was given, so
  # nothing of it is masked (until r11 it was, found by scanning the text).
  It 'an answer holding a signature, <Case>: <Then>' -ForEach @(
    foreach ($c in @(
      @{ Case = 'fileUploadUrl, %73ig'; Body = '{"fileUploadUrl":"<u>&%73ig=<v>"}' }
      @{ Case = 'fileUploadUrl, a fragment after the signature'; Body = '{"fileUploadUrl":"<u>&sig=<v>#r10"}' }
      @{ Case = 'fileUploadUrl, the signature in the fragment'; Body = '{"fileUploadUrl":"<u>#sig=<v>"}' }
      @{ Case = 'fileUploadUrl, a ; before the signature'; Body = '{"fileUploadUrl":"<u>;sig=<v>"}' }
      @{ Case = 'fileUploadUrl twice, the URL with the signature first'; Body = '{"fileUploadUrl":"<u>&sig=<v>","fileUploadUrl":"https://jlfakeupload.blob.core.windows.net/blob/x.zip"}' }
      @{ Case = 'a nested fileUploadUrl'; Body = '{"id":"1","r10":{"fileUploadUrl":"<u>&sig=<v>"}}' }
      @{ Case = 'a fileUploadUrl in a list'; Body = '{"id":"1","r10":[{"fileUploadUrl":"<u>&sig=<v>"}]}' }
      @{ Case = 'an answer in a list'; Body = '[{"fileUploadUrl":"<u>&sig=<v>"}]' }
      @{ Case = 'an answer with text before it'; Body = 'Answer: {"fileUploadUrl":"<u>&%73ig=<v>"}' }
      @{ Case = 'an answer cut off after the fileUploadUrl'; Body = '{"id":"1","fileUploadUrl":"<u>&sig=<v>",' }
      @{ Case = 'an answer that is not read, the key and the URL JSON-escaped'; Body = '{"File\u0055ploadURL":"<u>\u0026sig=<v>"} (r12)' }
      @{ Case = 'fileUploadUrl, sig (the control)'; Body = '{"fileUploadUrl":"<u>&sig=<v>"}' }
    )) { $c + @{ Masked = $true; Then = 'masked before anything of it is read' } }
    foreach ($c in @(
      @{ Case = 'another field'; Body = '{"id":"1","note":"upload to <u>&sig=<v>"}' }
      @{ Case = 'another field, "&" and the name JSON-escaped'; Body = '{"id":"1","note":"upload to <u>\u0026\u0073ig=<v>"}' }
      @{ Case = 'another field holding the text "fileUploadUrl": "..."'; Body = '{"id":"1","description":"See \"fileUploadUrl\": \"<u>&sig=<v>\"."}' }
      @{ Case = 'an answer that is not JSON'; Body = 'upload to <u>&sig=<v> failed' }
    )) { $c + @{ Masked = $false; Then = 'not a credential this run was given: nothing masked (r12)' } }
  ) {
    $b = $Body.Replace('<u>', $R10Url).Replace('<v>', $R10Sig)
    Reset-StoreSecrets
    $t = & $Mod { param($a, $v) Register-StoreAnswerUploadUrl $a; [pscustomobject]@{ Hidden = (Hide-StoreSecret "pending submission $v"); Id = (Test-StoreId $v) } } $b $R10Sig
    Reset-StoreSecrets
    if ($Masked) {
      $t.Hidden | Should -Not -Match $R10Sig -Because '[printed]'
      $t.Id | Should -BeFalse
    } else {
      $t.Hidden | Should -BeExactly "pending submission $R10Sig"
      $t.Id | Should -BeTrue
    }
  }

  # Pepper, PR #74 r12 review, point 1: the create is answered HTTP 201, its
  # JSON cut off inside the fileUploadUrl, after the (synthetic, numeric)
  # signature and before the closing quote; the app read after it shows that
  # signature as the pending id. The answer is still not read (strict JSON),
  # so the id is unknown, but what is left of the fileUploadUrl is registered
  # before any field is read (Register-StoreCutUploadUrl): the pending id
  # holds a confirmed credential, so it is never printed, and the lookup
  # guidance names the app's GET path in full. The 99de31b and a73e156
  # modules registered nothing of a value without its closing quote and
  # printed the signature as the pending id, in the error and in the GET path
  # to check.
  It 'the create answer is cut off inside its fileUploadUrl, <Case>, and the app read after it shows the signature as pending: never printed, the GET path in full (r12 review)' -ForEach @(
    @{ Case = 'right after the signature (Pepper''s repro)' }
    @{ Case = 'on a backslash after the signature'; Cut = '\' }
    @{ Case = 'in a JSON escape after the signature'; Cut = '\u00' }
    @{ Case = 'in a percent escape after the signature'; Cut = '%2' }
    @{ Case = 'the "&" JSON-escaped, right after the signature'; Escaped = $true }
    @{ Case = 'a percent-encoded name (%73ig), right after the signature'; Query = '&%73ig=' }
    @{ Case = 'a nested fileUploadUrl, right after the signature'; Nested = $true }
  ) {
    # Locals only: a closure does not see this script's variables.
    $q = if ($Query) { $Query } else { '&sig=' }
    $url = $R10Url + $q + $R10Sig; $sig = $R10Sig; $opt = $R10Out; $cut = [string]$Cut; $esc = [bool]$Escaped; $nest = [bool]$Nested
    $create = {
      param($b)
      $n = [System.Text.Json.Nodes.JsonNode]::Parse($b)
      if ($nest) { $n['r10'] = [System.Text.Json.Nodes.JsonObject]::new(); $n['r10']['fileUploadUrl'] = [System.Text.Json.Nodes.JsonValue]::Create($url) }
      else { $n['fileUploadUrl'] = [System.Text.Json.Nodes.JsonValue]::Create($url) }
      $t = $n.ToJsonString($opt)
      if ($esc) { $t = $t.Replace($q + $sig, '&' + $q.Substring(1) + $sig) }
      $t.Substring(0, $t.IndexOf($sig) + $sig.Length) + $cut
    }.GetNewClosure()
    $pending = New-R10JsonMap { param($o) $o['pendingApplicationSubmission'] = [System.Text.Json.Nodes.JsonNode]::Parse('{"id":"' + $sig + '","resourceLocation":"y"}') }.GetNewClosure()
    $x = Invoke-R10Run @(@{ Kind = 'Create'; At = 1; Map = $create }, @{ Kind = 'AppRead'; At = 2; Map = $pending })
    $look = "A person needs to check the app's pending submission in Partner Center (look only, change nothing there) or with GET /v1.0/my/applications/$App (pendingApplicationSubmission.id)"
    $x.R.Err | Should -Match ([regex]::Escape('the create response (HTTP 200, 201 or 204) has no usable submission id. Created, id unknown'))
    $x.R.Err | Should -Match ([regex]::Escape("Read-back of the app (one GET): a pending submission without a usable id. $look. $ApiNote"))
    $x.R.Out | Should -Match ([regex]::Escape("If this step ends before a result is printed below: $look;"))
    $x.Sent | Should -BeExactly "POST $Base/submissions" -Because '[sent]'
    $x.R.All | Should -Not -Match '\[redacted\]|\[invalid\]' -Because '[masked]: nothing printed holds it'
    Assert-R10Safe $x
  }

  # The same answers read on their own: what is left of the fileUploadUrl is
  # masked (its signature as far as it goes, at least CutMinLength
  # characters), and the answer is still not read.
  It 'an answer cut off inside its fileUploadUrl, <Case>: what is left of the signature masked, the answer still not read (r12 review)' -ForEach @(
    @{ Case = 'right after the signature'; Body = '{"id":"1","fileUploadUrl":"<u>&sig=<v>' }
    @{ Case = 'on a backslash after the signature'; Body = '{"id":"1","fileUploadUrl":"<u>&sig=<v>\' }
    @{ Case = 'in a JSON escape after the signature (\u)'; Body = '{"id":"1","fileUploadUrl":"<u>&sig=<v>\u' }
    @{ Case = 'in a JSON escape after the signature (\u002)'; Body = '{"id":"1","fileUploadUrl":"<u>&sig=<v>\u002' }
    @{ Case = 'in a percent escape after the signature (%)'; Body = '{"id":"1","fileUploadUrl":"<u>&sig=<v>%' }
    @{ Case = 'in a percent escape after the signature (%2)'; Body = '{"id":"1","fileUploadUrl":"<u>&sig=<v>%2' }
    @{ Case = 'a space after the signature'; Body = '{"id":"1","fileUploadUrl":"<u>&sig=<v> ' }
    @{ Case = 'in the parameter after the signature'; Body = '{"id":"1","fileUploadUrl":"<u>&sig=<v>&se=2026-11' }
    @{ Case = 'in the fragment after the signature'; Body = '{"id":"1","fileUploadUrl":"<u>&sig=<v>#r1' }
    @{ Case = 'the signature in the fragment'; Body = '{"id":"1","fileUploadUrl":"<u>#sig=<v>' }
    @{ Case = 'a ; before the signature'; Body = '{"id":"1","fileUploadUrl":"<u>;sig=<v>' }
    @{ Case = 'a percent-encoded name (%73ig)'; Body = '{"id":"1","fileUploadUrl":"<u>&%73ig=<v>' }
    @{ Case = 'the key and the "&" JSON-escaped'; Body = '{"FileUploadURL":"<u>&sig=<v>' }
    @{ Case = 'a nested fileUploadUrl'; Body = '{"id":"1","r10":{"fileUploadUrl":"<u>&sig=<v>' }
    @{ Case = 'a fileUploadUrl in a list'; Body = '{"id":"1","r10":[{"fileUploadUrl":"<u>&sig=<v>' }
    @{ Case = 'text before the answer'; Body = 'Answer: {"fileUploadUrl":"<u>&sig=<v>' }
    @{ Case = 'a complete fileUploadUrl before it, without a signature'; Body = '{"fileUploadUrl":"https://jlfakeupload.blob.core.windows.net/blob/x.zip","r10":{"fileUploadUrl":"<u>&sig=<v>' }
    @{ Case = 'eight characters into the signature (the shortest piece masked)'; Body = '{"id":"1","fileUploadUrl":"<u>&sig=<v>'; Sig = '11529215' }
  ) {
    $v = if ($Sig) { $Sig } else { $R10Sig }
    $b = $Body.Replace('<u>', $R10Url).Replace('<v>', $v)
    Reset-StoreSecrets
    $t = & $Mod { param($a, $v) $o = ConvertFrom-StoreJson $a; [pscustomobject]@{ Read = ($null -ne $o); Hidden = (Hide-StoreSecret "pending submission $v"); Id = (Test-StoreId $v) } } $b $v
    Reset-StoreSecrets
    $t.Hidden | Should -BeExactly 'pending submission [redacted]' -Because '[printed]'
    $t.Id | Should -BeFalse
    $t.Read | Should -BeFalse -Because 'strict JSON: a cut-off answer is not read'
  }

  # Guards: a cut may fall anywhere, so a piece of a cut-off fileUploadUrl
  # shorter than CutMinLength is not registered (it would cut the draft id
  # and the GET path out of the lines that say what to check), and a cut-off
  # value of another field is not a fileUploadUrl (r12, point 2).
  It 'an answer cut off <Case>: nothing masked, the draft id and the GET path whole (r12 review)' -ForEach @(
    @{ Case = 'one character into the signature of its fileUploadUrl'; Body = '{"id":"1","fileUploadUrl":"<u>&sig=1' }
    @{ Case = 'seven characters into the signature of its fileUploadUrl (one short of a piece masked)'; Body = '{"id":"1","fileUploadUrl":"<u>&sig=1152921' }
    @{ Case = 'one character into its fileUploadUrl'; Body = '{"id":"1","fileUploadUrl":"1' }
    @{ Case = 'in a JSON escape one character into the signature'; Body = '{"id":"1","fileUploadUrl":"<u>&sig=5\u00' }
    @{ Case = 'inside another field, after a signature'; Body = '{"id":"1","note":"upload to <u>&sig=<v>' }
    @{ Case = 'inside another field holding the text "fileUploadUrl": "..."'; Body = '{"id":"1","description":"See \"fileUploadUrl\": \"<u>&sig=<v>' }
  ) {
    $b = $Body.Replace('<u>', $R10Url).Replace('<v>', $R10Sig)
    $get = "GET /v1.0/my/applications/$App/submissions/$NewId"
    Reset-StoreSecrets
    $t = & $Mod { param($a, $g, $i, $v) [void](ConvertFrom-StoreJson $a); [pscustomobject]@{ Get = (Hide-StoreSecret $g); Id = (Test-StoreId $i); Sig = (Hide-StoreSecret "pending submission $v") } } $b $get $NewId $R10Sig
    Reset-StoreSecrets
    $t.Get | Should -BeExactly $get
    $t.Id | Should -BeTrue
    $t.Sig | Should -BeExactly "pending submission $R10Sig"
  }

  # The same end to end: the GET of the draft before the PUT is answered with
  # its JSON cut off a few characters into the fileUploadUrl's signature (a
  # part of the draft id); the stop names the draft id and its GET path in
  # full, nothing masked.
  It 'the draft read before the PUT is cut off <Case>: the stop names the draft id and the GET path in full (r12 review)' -ForEach @(
    @{ Case = 'one character into the signature of its fileUploadUrl'; Frag = '1' }
    @{ Case = 'seven characters into the signature of its fileUploadUrl'; Frag = '1152921' }
  ) {
    $url = $R10Url + '&sig=' + $Frag; $opt = $R10Out
    $map = { param($b) $n = [System.Text.Json.Nodes.JsonNode]::Parse($b); $n['fileUploadUrl'] = [System.Text.Json.Nodes.JsonValue]::Create($url); $t = $n.ToJsonString($opt); $t.Substring(0, $t.IndexOf($url) + $url.Length) }.GetNewClosure()
    $want = Get-R10Unverified "GET submission $NewId returned $UnreadSubmission" $R10Read1
    $x = Invoke-R10Run @(@{ Kind = 'SubmissionRead'; At = 1; Map = $map })
    $x.R.Err | Should -BeExactly $want
    $x.R.Err | Should -Match ([regex]::Escape("GET /v1.0/my/applications/$App/submissions/$NewId."))
    $x.Sent | Should -BeExactly "POST $Base/submissions" -Because '[sent]'
    $x.R.All | Should -Not -Match '\[redacted\]' -Because '[masked]'
    Assert-R10Safe $x
  }

  It 'Register-StoreUploadUrl, a URL with <Case>: its signature masked' -ForEach @($urlCases) {
    $u = $R10Url + $Query + $R10Sig + $After
    Reset-StoreSecrets
    $t = & $Mod { param($a, $v) Register-StoreUploadUrl $a; Hide-StoreSecret "pending submission $v" } $u $R10Sig
    $t | Should -Not -Match $R10Sig -Because '[printed]'
    Reset-StoreSecrets
  }

  It 'Register-StoreUploadUrl, a URL with a fragment: the URL without the fragment masked whole' {
    $u = $R10Url + '&sig=' + $R10Sig + '#r10'
    Reset-StoreSecrets
    $t = & $Mod { param($a) Register-StoreUploadUrl $a; Hide-StoreSecret "<$($a.Substring(0, $a.IndexOf('#')))>" } $u
    Reset-StoreSecrets
    $t | Should -BeExactly '<[redacted]>'
  }

  # Pepper, PR #74 r11: a plain "sig=" in a public listing of the submission
  # (a description, a document link), its value a digit of the draft id or of
  # the version. It is not a confirmed credential (the token, the client
  # secret, the signature read from a fileUploadUrl), so the id and the
  # version stay usable: the run goes as without it. The 954a12f module stops
  # before the PUT, the check after the commit is not verified, a delete by
  # hand deletes nothing. r12: nothing of it is masked either, so every line
  # names the id and the GET path in full (the 7c9a6ff module masked the
  # value in output, cutting digits out of both).
  Context 'a sig in a public listing (PR #74 r11)' {
    BeforeAll {
      # Adds Text to the listing field (a list: one more item) in the fake's
      # submission fields.
      function script:Set-R11Listing($Store, [string]$Lang, [string]$Field, [string]$Text) {
        $n = [System.Text.Json.Nodes.JsonNode]::Parse($Store.Fields)
        $l = $n['listings'][$Lang]['baseListing']
        if ($l[$Field] -is [System.Text.Json.Nodes.JsonArray]) { $l[$Field].Add([System.Text.Json.Nodes.JsonValue]::Create($Text)) }
        else { $l[$Field] = [System.Text.Json.Nodes.JsonValue]::Create($l[$Field].GetValue[string]() + $Text) }
        $Store.Fields = $n.ToJsonString()
      }
      $script:R11Sent = "POST $Base/submissions | PUT $Base/submissions/$NewId | PUT /blob/upload.zip | POST $Base/submissions/$NewId/commit"
    }

    $listingCases = @(
      @{ Case = 'the en-us description holds "sig=5" (a digit of the draft id)'; Lang = 'en-us'; Field = 'description'; Text = ' Help: sig=5' }
      @{ Case = 'the en-us privacy policy link holds "?sig=9" (a document link)'; Lang = 'en-us'; Field = 'privacyPolicy'; Text = 'https://example.com/privacy?sig=9' }
      @{ Case = 'the en-us website link holds "&sig=0" (a digit of the id and of the version)'; Lang = 'en-us'; Field = 'websiteUrl'; Text = 'https://example.com/docs?lang=en&sig=0' }
      @{ Case = 'the zh-hk description holds "sig=4" (a digit of the version only)'; Lang = 'zh-hk'; Field = 'description'; Text = ' sig=4' }
      @{ Case = 'an en-us feature holds "%73ig=1" (an encoded name)'; Lang = 'en-us'; Field = 'features'; Text = 'Docs: https://example.com/help?%73ig=1' }
      # r12: text that reads like a fileUploadUrl member, inside a field.
      @{ Case = 'the en-us description holds the text "fileUploadUrl": "...&sig=5"'; Lang = 'en-us'; Field = 'description'; Text = ' "fileUploadUrl": "https://jlfakeupload.blob.core.windows.net/x?sp=r&sig=5"' }
    )

    It 'publish, <Case>: committed as without it, the listing sent as it is' -ForEach $listingCases {
      $x = Invoke-R10Run @() @{} $null { param($s) Set-R11Listing $s $Lang $Field $Text }
      $x.R.Err | Should -BeNullOrEmpty
      $x.Sent | Should -BeExactly $R11Sent -Because '[sent]'
      $x.Committed | Should -BeTrue -Because '[commit sent]'
      $x.R.Value | Should -Be @($NewId) -Because '[result]'
      $x.R.Out | Should -Match 'draft verified: '
      $x.R.Out | Should -Match 'commit requested through the API: status=CommitStarted'
      # The PUT sends the listing as the Store gave it: a request is not masked.
      $v = [System.Text.Json.Nodes.JsonNode]::Parse($x.Store.LastPut)['listings'][$Lang]['baseListing'][$Field]
      if ($v -is [System.Text.Json.Nodes.JsonArray]) { $v = $v[$v.Count - 1] }
      $v.GetValue[string]().EndsWith($Text, [StringComparison]::Ordinal) | Should -BeTrue -Because '[PUT body]'
      $x.R.All | Should -Not -Match $Leak -Because '[printed]'
      # r12: the id and the GET path in full, nothing masked.
      $x.R.Out | Should -Match ([regex]::Escape("check GET /v1.0/my/applications/$App/submissions/$NewId by hand"))
      $x.R.All | Should -Not -Match '\[redacted\]' -Because '[masked]'
    }

    It 'the check after the commit, <Case>: verified' -ForEach $listingCases {
      $x = Invoke-R10Run @() @{} {
        Assert-SubmissionHasPackage -ProductId $App -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -ExpectedFileName $File -TimeoutMinutes 0 -IntervalSeconds 0 } {
        param($s) $s.Sub = @{ id = $SubId; status = 'Certification'; applicationPackages = @(
          [ordered]@{ id = 'p3'; fileName = $File; fileStatus = 'Uploaded'; version = '0.4.1.0' }) }
        Set-R11Listing $s $Lang $Field $Text }
      $x.R.Err | Should -BeNullOrEmpty
      $x.R.Out | Should -Match 'verified submission \S+: submission holds exactly one Uploaded package, version '
      $x.Sent | Should -BeExactly '' -Because '[sent]'
    }

    It 'a delete by hand, <Case>: deleted' -ForEach $listingCases {
      $x = Invoke-R10Run @() @{} { Remove-StoreDraftSubmission -ProductId $App -SubmissionId $NewId } {
        param($s) $s.Sub = @{ id = $NewId; status = 'PendingCommit'; applicationPackages = @(
          [ordered]@{ id = 'p1'; fileName = $File; fileStatus = 'PendingUpload'; minimumDirectXVersion = 'None'; minimumSystemRam = 'None' }) }; $s.PendingId = $NewId
        Set-R11Listing $s $Lang $Field $Text }
      $x.R.Err | Should -BeNullOrEmpty
      $x.Sent | Should -BeExactly "DELETE $Base/submissions/$NewId" -Because '[sent]'
      $x.R.Out | Should -Match 'deleted draft submission '
    }

    # r12: a "sig=" outside a fileUploadUrl (a listing, a link, the app's
    # name, text inside a field that reads like a fileUploadUrl member, an
    # answer that is not JSON) is not registered at all: nothing is masked,
    # the id, the version and the GET path stay whole and usable (7c9a6ff
    # masked such a value in output, so "sig=5" cut every 5 out of the id).
    It 'a sig outside a fileUploadUrl, <Case>: nothing masked, the id and the version usable (r12)' -ForEach @(
      @{ Case = 'in an answer''s listing, links and the app''s name'; Body = '{"primaryName":"JerisLink sig=5","description":"Help: sig=0","privacyPolicy":"https://example.com/privacy?sig=1","r12":"see ?sig=my"}' }
      @{ Case = 'a field holding the text "fileUploadUrl": "..."'; Body = '{"description":"See \"fileUploadUrl\": \"https://jlfakeupload.blob.core.windows.net/x?sp=w&sig=5\"."}' }
      @{ Case = 'an answer that is not JSON'; Body = 'Help: sig=5 &sig=0 ?sig=1 ?sig=my' }
    ) {
      Reset-StoreSecrets
      $r = & $Mod { param($b, $id, $app)
        Register-StoreAnswerUploadUrl $b
        [pscustomobject]@{ Count = $script:KnownSecrets.Count; Id = (Test-StoreId $id); SafeId = (Get-SafeValue $id $script:SafeId); Version = (Get-SafeValue '0.4.1.0' $script:SafeVersion)
          Hidden = (Hide-StoreSecret "id $id, GET /v1.0/my/applications/$app/submissions/$id") } } $Body $NewId $App
      Reset-StoreSecrets
      $r.Count | Should -Be 0 -Because 'nothing is registered'
      $r.Id | Should -BeTrue
      $r.SafeId | Should -BeExactly $NewId
      $r.Version | Should -BeExactly '0.4.1.0'
      $r.Hidden | Should -BeExactly "id $NewId, GET /v1.0/my/applications/$App/submissions/$NewId"
    }

    # r9 kept: a confirmed credential still makes an id that holds it unusable
    # and is masked wherever it is, also when the same value is in a listing.
    It 'a confirmed credential, <Case>: an id that holds it is not usable' -ForEach @(
      @{ Case = 'the signature of an upload URL'; Code = 'param($v) Register-StoreUploadUrl "https://jlfakeupload.blob.core.windows.net/blob/upload.zip?sv=2020-08-04&sr=b&sp=w&sig=$v"' }
      # Decoded as a server reads it (%35 is 5); in the fragment, so only this
      # value's own forms give it.
      @{ Case = 'the signature of an upload URL, percent-encoded in the fragment'; Code = 'param($v) Register-StoreUploadUrl ("https://jlfakeupload.blob.core.windows.net/blob/upload.zip?sp=w#sig=%3" + $v)' }
      # Its value trimmed too (%20 is a space).
      @{ Case = 'the signature of an upload URL, a space before it'; Code = 'param($v) Register-StoreUploadUrl ("https://jlfakeupload.blob.core.windows.net/blob/upload.zip?sp=w&sig=%20" + $v)' }
      @{ Case = 'the signature of a fileUploadUrl in an answer, the name in another case'; Code = 'param($v) Register-StoreAnswerUploadUrl (''{"id":"1","FileUploadURL":"https://jlfakeupload.blob.core.windows.net/blob/upload.zip?sp=w&sig='' + $v + ''"}'')' }
      @{ Case = 'the signature of a nested fileUploadUrl in an answer'; Code = 'param($v) Register-StoreAnswerUploadUrl (''{"id":"1","r11":{"fileUploadUrl":"https://jlfakeupload.blob.core.windows.net/blob/upload.zip?sp=w&sig='' + $v + ''"}}'')' }
      @{ Case = 'the signature of a fileUploadUrl in an answer that is not read (text before it)'; Code = 'param($v) Register-StoreAnswerUploadUrl (''Answer: {"fileUploadUrl":"https://jlfakeupload.blob.core.windows.net/blob/upload.zip?sp=w&sig='' + $v + ''"}'')' }
      @{ Case = 'the same value in a listing first, then from an upload URL'; Code = 'param($v) Register-StoreAnswerUploadUrl (''{"description":"Help: sig='' + $v + ''"}''); Register-StoreUploadUrl "https://jlfakeupload.blob.core.windows.net/blob/upload.zip?sp=w&sig=$v"' }
      @{ Case = 'from an upload URL first, then the same value in a listing'; Code = 'param($v) Register-StoreUploadUrl "https://jlfakeupload.blob.core.windows.net/blob/upload.zip?sp=w&sig=$v"; Register-StoreAnswerUploadUrl (''{"description":"Help: sig='' + $v + ''"}'')' }
      @{ Case = 'the client secret, signing in'; Code = ''; SignIn = @{ Secret = '5' } }
      @{ Case = 'the access token, signing in'; Code = ''; SignIn = @{ Token = '5' } }
    ) {
      Reset-StoreSecrets
      if ($Code) { & $Mod.NewBoundScriptBlock([scriptblock]::Create($Code)) '5' }
      else {
        $s = New-FakeStore; Use-FakeStore $s
        if ($SignIn.Token) { $s.Token = $SignIn.Token }
        $sec = if ($SignIn.Secret) { $SignIn.Secret } else { $Secret }
        # Signed in or refused: the credential is registered either way.
        $null = Invoke-Captured { Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $sec }
      }
      $r = & $Mod { param($id) [pscustomobject]@{ Id = (Test-StoreId $id); SafeId = (Get-SafeValue $id $script:SafeId); Version = (Get-SafeValue '0.5.1.0' $script:SafeVersion); Hidden = (Hide-StoreSecret "id $id") } } $NewId
      Reset-StoreSecrets
      $r.Id | Should -BeFalse
      $r.SafeId | Should -BeExactly '[invalid]'
      $r.Version | Should -BeExactly '[invalid]'
      $r.Hidden | Should -BeExactly ('id ' + ($NewId -creplace '5', '[redacted]'))
    }

    # Pepper, PR #74 r12, point 2: the app's name (or a listing) holds a plain
    # "sig=" whose value is one digit of the draft id (or "my", a part of the
    # GET path); the commit is answered HTTP 202 and every read-back shows
    # PendingCommit, so the result is unconfirmed and a person has to look.
    # Every line that says what to check names the draft id and its GET path
    # in full, and nothing is masked. The 7c9a6ff module masked the value
    # wherever it was printed: the log had no full id and the GET path was cut.
    It 'commit answered HTTP 202, read back PendingCommit, <Case>: the lookup guidance names the id and the GET path in full' -ForEach @(
      @{ Case = 'the app''s name holds "sig=5" (a digit of the draft id)'; Name = 'JerisLink sig=5' }
      @{ Case = 'the app''s name holds "sig=9" (the last digit of the draft id)'; Name = 'JerisLink sig=9' }
      @{ Case = 'the app''s name holds "(sig=1)" (a digit of the id and of "v1.0")'; Name = 'JerisLink (sig=1)' }
      @{ Case = 'the app''s name holds "?sig=my" (a part of the GET path)'; Name = 'JerisLink ?sig=my' }
      @{ Case = 'the en-us description holds "sig=0" (a digit of the id)'; Lang = 'en-us'; Field = 'description'; Text = ' Help: sig=0' }
    ) {
      $x = Invoke-R10Run @() @{ AcceptOn = 'Commit'; AcceptNotDone = $true } $null {
        param($s) if ($Name) { $s.AppName = $Name } else { Set-R11Listing $s $Lang $Field $Text } }
      $get = "GET /v1.0/my/applications/$App/submissions/$NewId"
      $x.R.Value | Should -BeNullOrEmpty
      $x.Sent | Should -BeExactly $R11Sent -Because '[sent]: one commit, nothing after it'
      $x.R.Err | Should -Match ('^' + [regex]::Escape("Store API POST $Base/submissions/$NewId/commit answered HTTP 202: accepted, completion unconfirmed. Accepted, completion unconfirmed: the commit request for submission $NewId was accepted (HTTP 202) but the Store has not confirmed it is done"))
      $x.R.Err | Should -Match ([regex]::Escape('last: read-back 3 of 3 shows status PendingCommit.'))
      $x.R.Err | Should -Match ([regex]::Escape("A person needs to check $get later: CommitStarted or a later status means it was committed."))
      # Before the commit, and when it is answered.
      $x.R.Out | Should -Match ([regex]::Escape("committing submission $NewId (waiting up to "))
      $x.R.Out | Should -Match ([regex]::Escape("check $get by hand (CommitStarted or a later status means it was committed)"))
      $x.R.Out | Should -Match ([regex]::Escape("::warning title=Store commit::Accepted, completion unconfirmed: the commit request for submission $NewId was accepted (HTTP 202)"))
      $x.R.Out | Should -Match ([regex]::Escape("If this step ends before a result is printed below, check $get by hand:"))
      $x.R.All | Should -Not -Match '\[redacted\]' -Because '[masked]'
      $x.R.All | Should -Not -Match "$DeleteAdvice|$RetryAdvice|$Leak" -Because '[advice, printed]'
    }
  }

  # Each strict-read gate on its own, apart from the reader that runs before
  # it in a publish (r10 mutants ZB4, ZB5, ZB14, ZC2 and ZC6 survived the
  # end-to-end cases, since an earlier read stops the same answers).
  Context 'the strict-read gates on their own (PR #74 r11)' {
    BeforeAll {
      $script:GateSub = '{"id":"1152921505699999999","status":"PendingCommit","pricing":{"trialPeriod":"NoFreeTrial","priceId":"Free"},"applicationPackages":[{"fileName":"a.msixupload","fileStatus":"Uploaded","version":"0.4.1.0"}]}'
    }

    It 'Test-StoreJsonObject refuses <Case>' -ForEach @(
      @{ Case = 'an array root'; Json = '[{"id":"1"}]' }
      @{ Case = 'an empty array root'; Json = '[]' }
      @{ Case = 'a string root'; Json = '"x"' }
      @{ Case = 'a number root'; Json = '1' }
      @{ Case = 'a null root'; Json = 'null' }
      @{ Case = 'a true root'; Json = 'true' }
      @{ Case = 'a key twice in another case'; Json = '{"id":"1","ID":"2"}' }
      @{ Case = 'a nested key twice in another case'; Json = '{"a":{"b":1,"B":2}}' }
      @{ Case = 'a key twice in another case in a list'; Json = '{"a":[{"b":1,"B":2}]}' }
    ) {
      & $Mod { param($j) Test-StoreJsonObject $j } $Json | Should -BeFalse
    }

    It 'Test-StoreJsonObject takes one object, nested objects and lists (the control)' {
      & $Mod { param($j) Test-StoreJsonObject $j } $GateSub | Should -BeTrue
      & $Mod { param($j) Test-StoreJsonObject $j } '{"a":{"b":1,"c":[{"b":1},{"b":2}]},"B":[]}' | Should -BeTrue
    }

    It 'Read-SubmissionSafe: applicationPackages holding <Case> is not read' -ForEach @(
      @{ Case = 'a number'; Pkgs = '[1]' }
      @{ Case = 'text'; Pkgs = '["x"]' }
      @{ Case = 'null'; Pkgs = '[null]' }
      @{ Case = 'true'; Pkgs = '[true]' }
      @{ Case = 'a list'; Pkgs = '[[]]' }
      @{ Case = 'a package and a number'; Pkgs = '[{"fileName":"a.msixupload","fileStatus":"Uploaded","version":"0.4.1.0"},1]' }
    ) {
      $j = $GateSub -replace '"applicationPackages":\[.*\]\}$', ('"applicationPackages":' + $Pkgs + '}')
      $j | Should -Not -BeExactly $GateSub
      & $Mod { param($j) Read-SubmissionSafe -SubmissionJson $j -ExpectedFileName 'a.msixupload' } $j | Should -BeNullOrEmpty
    }

    It 'Read-SubmissionSafe reads one package object in the list (the control)' {
      $r = & $Mod { param($j) Read-SubmissionSafe -SubmissionJson $j -ExpectedFileName 'a.msixupload' } $GateSub
      @($r.Packages).Count | Should -Be 1
      $r.Packages[0].FileStatus | Should -BeExactly 'Uploaded'
    }

    It 'Set-SubmissionPackage: a key twice <Case> in a part it does not change is the fixed stop' -ForEach @(
      @{ Case = 'as it is'; Dup = '"priceId":"Free",' }
      @{ Case = 'in another case'; Dup = '"PriceId":"Free",' }
    ) {
      $j = $GateSub.Replace('"pricing":{', '"pricing":{' + $Dup)
      $j | Should -Not -BeExactly $GateSub
      { Set-SubmissionPackage -SubmissionJson $j -FileName 'b.msixupload' } |
        Should -Throw -ExpectedMessage 'the submission JSON could not be read to set the packages (the parser''s message is not printed)'
    }

    It 'Set-SubmissionPackage sets the packages of a submission it reads (the control)' {
      $n = [System.Text.Json.Nodes.JsonNode]::Parse((Set-SubmissionPackage -SubmissionJson $GateSub -FileName 'b.msixupload'))
      $n['applicationPackages'].Count | Should -Be 2
      [string]$n['applicationPackages'][0]['fileStatus'] | Should -BeExactly 'PendingDelete'
      [string]$n['applicationPackages'][1]['fileName'] | Should -BeExactly 'b.msixupload'
    }
  }
}

# Pepper, PR #74 r12, point 1: a change goes over the wire at most once. The
# fake Store is served over TCP (Start-FakeStoreServer -Tcp) so each request
# that reaches it is counted with the connection it came on; DropOn makes it
# read a request whole, then close the connection without a byte of answer.
# SocketsHttpHandler sends such a request again (up to 3 more times, each on a
# new connection) when it had no content (r4 to r11: create, commit, DELETE).
Describe 'A change is sent at most once: the server read it whole, then closed the connection without an answer (PR #74 r12, fake Store over TCP)' {
  BeforeEach {
    $script:Pkg = New-TestPackage
    $o = if ($Opt) { $Opt } else { @{} }
    $script:Srv = New-FakeStore @o
    $script:Url = Start-FakeStoreServer $Srv -Tcp
  }
  AfterEach {
    Stop-FakeStoreServer $Srv
    Remove-Item -LiteralPath (Split-Path $Pkg) -Recurse -Force
    InModuleScope MsStoreRunner { $script:LoopbackTestServer = $false; $script:Token = '' }
  }

  # Invoke-StoreHttp on its own: the server drops every such request (and
  # carries none out), so the count is how often the handler sent it.
  It 'sends <Name> once, throws, and the request has Content-Length <Length> and no Expect' -ForEach @(
    @{ Name = 'a create (POST without a body)'; Drop = 'Create'; Method = 'POST'; Path = "submissions?isMinimalResponse=true"; Kind = 'Api'; Body = $null; Length = '0' }
    @{ Name = 'a commit (POST without a body)'; Drop = 'Commit'; Method = 'POST'; Path = "submissions/1152921505000000099/commit"; Kind = 'Api'; Body = $null; Length = '0' }
    @{ Name = 'a DELETE'; Drop = 'Delete'; Method = 'DELETE'; Path = "submissions/1152921505000000099"; Kind = 'Api'; Body = $null; Length = '0' }
    @{ Name = 'the PUT of a submission (a body)'; Drop = 'Update'; Method = 'PUT'; Path = "submissions/1152921505000000099"; Kind = 'Api'; Body = '{}'; Length = '2' }
    @{ Name = 'the token request (a form body)'; Drop = 'Token'; Method = 'POST'; Path = '/tenant-1/oauth2/v2.0/token'; Kind = 'Token'; Body = 'grant_type=client_credentials'; Length = '29' }
    @{ Name = 'the package upload (a file)'; Drop = 'Upload'; Method = 'PUT'; Path = '/blob/upload.zip'; Kind = 'Upload'; Body = $null; Length = '512' }
  ) {
    $Srv.DropOn = $Drop; $Srv.DropTimes = 100; $Srv.DropNotDone = $true
    InModuleScope MsStoreRunner { $script:LoopbackTestServer = $true }
    $a = @{ Method = $Method; Uri = $(if ($Kind -eq 'Api') { "$Url$Base/$Path" } else { "$Url$Path" }); Kind = $Kind; TimeoutSec = 30 }
    if ($Kind -eq 'Api') { $a.Headers = @{ Authorization = "Bearer $($Srv.Token)" } }
    if ($Kind -eq 'Upload') { $a.InFile = $Pkg; $a.Headers = @{ 'x-ms-blob-type' = 'BlockBlob' } }
    if ($null -ne $Body) { $a.Body = $Body; $a.ContentType = $(if ($Kind -eq 'Token') { 'application/x-www-form-urlencoded' } else { 'application/json' }) }
    $err = $null
    try { & (Get-Module MsStoreRunner) { param($a) Invoke-StoreHttp @a } $a | Out-Null } catch { $err = $_ }
    $err | Should -Not -BeNullOrEmpty -Because 'a request that got no answer throws'
    $seen = @($Srv.Seen)
    $seen.Count | Should -Be 1 -Because "the server read the request whole each time it came (connections: $(@($seen | ForEach-Object { $_.Connection }) -join ', '))"
    $Srv.Dropped | Should -Be 1
    $seen[0].Headers['Content-Length'] | Should -BeExactly $Length
    $seen[0].Headers.ContainsKey('Expect') | Should -BeFalse
    @($Srv.Log).Count | Should -Be 0 -Because 'the server carried none of them out'
  }

  # The control: the same drop of a GET is one SocketsHttpHandler retries, on
  # this platform too, each time on a new connection (a read changes nothing).
  It 'a GET dropped the same way is sent again by the handler, each time on a new connection (the control)' -ForEach @(@{ Opt = @{ DropOn = 'AppRead'; DropTimes = 100; DropNotDone = $true } }) {
    InModuleScope MsStoreRunner { $script:LoopbackTestServer = $true }
    $a = @{ Method = 'GET'; Uri = "$Url$Base"; Kind = 'Api'; Headers = @{ Authorization = "Bearer $($Srv.Token)" }; TimeoutSec = 30 }
    { & (Get-Module MsStoreRunner) { param($a) Invoke-StoreHttp @a } $a } | Should -Throw
    $c = @($Srv.Seen | ForEach-Object { $_.Connection })
    $c.Count | Should -BeGreaterThan 1
    @($c | Sort-Object -Unique).Count | Should -Be $c.Count
  }

  It 'a whole publish sends every request once, each on a connection of its own (no connection is reused from an earlier call)' {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $r = Invoke-Publish $Pkg
    $r.Err | Should -BeNullOrEmpty
    $r.Value | Should -Be @($NewId)
    $seen = @($Srv.Seen)
    @($seen | ForEach-Object { $_.Line }) | Should -Be @(@($Srv.Log) | ForEach-Object { $_ })
    $c = @($seen | ForEach-Object { $_.Connection })
    @($c | Sort-Object -Unique).Count | Should -Be $seen.Count
    foreach ($s in $seen) {
      if ($s.Line -notlike 'GET *') { $s.Headers['Content-Length'] | Should -Not -BeNullOrEmpty -Because "$($s.Line) is a change" }
      $s.Headers.ContainsKey('Expect') | Should -BeFalse
    }
  }

  # End to end: the request is carried out, then its connection is closed
  # without an answer (the realistic case: the Store did it, the answer was
  # lost). r4 to r11 sent it again: a second create got 409 (reported as not
  # created), a second commit got 409 (reported as not accepted), a second
  # DELETE got 404 (reported as a failed delete).
  It 'a create carried out, then no answer: sent once, read back, the pending draft reported with its origin unconfirmed, no advice' -ForEach @(@{ Opt = @{ DropOn = 'Create' } }) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $r = Invoke-Publish $Pkg
    @($Srv.Seen | Where-Object { $_.Line -ceq "POST $Base/submissions" }).Count | Should -Be 1
    @($Srv.Log) | Should -Be @('POST /tenant-1/oauth2/v2.0/token', "GET $Base", "POST $Base/submissions", "GET $Base")
    $r.Value | Should -BeNullOrEmpty
    $r.Err | Should -Match "^Store API POST $([regex]::Escape("$Base/submissions?isMinimalResponse=true")) failed: "
    $r.Err | Should -Match "pending submission $NewId"
    $r.Err | Should -Not -Match 'No submission was created|HTTP 409'
    $r.All | Should -Not -Match "$DeleteAdvice|$RetryAdvice|$Leak|$([regex]::Escape($Srv.Token))"
  }

  It 'a commit carried out, then no answer: sent once, read back by id, committed, the run goes on' -ForEach @(@{ Opt = @{ DropOn = 'Commit' } }) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    $r = Invoke-Publish $Pkg
    @($Srv.Seen | Where-Object { $_.Line -ceq "POST $Base/submissions/$NewId/commit" }).Count | Should -Be 1
    $r.Err | Should -BeNullOrEmpty
    $r.Value | Should -Be @($NewId)
    $r.Out | Should -Match "read-back 1 by id shows status Certification: it was committed"
    $r.All | Should -Not -Match "$DeleteAdvice|$RetryAdvice|$Leak|$([regex]::Escape($Srv.Token))|not accepted|HTTP 409"
  }

  It 'a manual DELETE carried out, then no answer: sent once, result unconfirmed, read back by id (gone), not sent again' -ForEach @(@{ Opt = @{ DropOn = 'Delete' } }) {
    Connect-StoreApi -TenantId 'tenant-1' -ClientId 'client-1' -ClientSecret $Secret -AuthorityHost $Url -ApiBase $Url -LoopbackTestServer 6>$null
    # The draft to delete, made in the fake directly (nothing over the wire).
    $made = Invoke-FakeStoreRequest -Store $Srv -Method POST -Uri "$Url$Base/submissions" -Headers @{ Authorization = "Bearer $($Srv.Token)" }
    $made.StatusCode | Should -Be 201
    $Srv.Log.Clear(); $Srv.Seen.Clear()
    $r = Invoke-Captured { Remove-StoreDraftSubmission -ProductId $App -SubmissionId $NewId }
    @($Srv.Seen | Where-Object { $_.Line -ceq "DELETE $Base/submissions/$NewId" }).Count | Should -Be 1
    @($Srv.Log) | Should -Be @("GET $Base/submissions/$NewId", "DELETE $Base/submissions/$NewId", "GET $Base/submissions/$NewId")
    $Srv.Sub | Should -BeNullOrEmpty
    $r.Out | Should -Not -Match 'deleted draft'
    $r.Err | Should -Match ('^' + [regex]::Escape("Store API DELETE $Base/submissions/$NewId failed: "))
    $r.Err | Should -Match ([regex]::Escape("Result unconfirmed: the delete request for submission $NewId got no answer that says what happened, so it may or may not have been deleted; it is not sent again. Read-back of submission $NewId by id (one GET; nothing changed): failed ("))
    $r.Err | Should -Match ([regex]::Escape("A person needs to check GET /v1.0/my/applications/$App/submissions/$NewId later: HTTP 404 there means it is gone.") + '$')
    $r.All | Should -Not -Match "$RetryAdvice|$Leak|$([regex]::Escape($Srv.Token))"
  }
}

# Pepper, PR #74 r9, point 2: the "src" steps of msstore-publish.yml and
# msstore-publish-check.yml (the msix run lookups) run here as GitHub's pwsh
# shell runs them, with `gh api` answered by a stand-in. Each field of each
# GitHub API answer the step gets is made missing, empty, null, not valid,
# another valid value, a number, an array, an object, true, a credential of
# the shape GitHub's own token has, and a key given twice in another case;
# each whole answer is made a gh failure (the credential in gh's error
# output), not JSON, an array, empty, null and a JSON string. Only fixed text
# and checked values (run id: digits; sha: 40 hex; ref: main, the release tag
# or [not shown]; compare status: listed) may come out, and the step goes on
# only where the table below says so (success-condition matrix).
Describe 'Workflow lookups print only fixed text and checked values of each GitHub API answer (PR #74 r9)' {
  BeforeAll {
    $script:WfDir = Join-Path $PSScriptRoot '..' '..' 'workflows'
    # The `run: |` script of the step with this id in a workflow, dedented.
    function script:Get-StepScript([string]$Workflow, [string]$Id) {
      $lines = @(Get-Content -LiteralPath $Workflow)
      $at = -1
      for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -ceq "        id: $Id") { $at = $i; break } }
      if ($at -lt 0) { throw "no step with id $Id in $Workflow" }
      while ($lines[$at] -cne '        run: |') { $at++ }
      $body = [System.Collections.Generic.List[string]]::new()
      for ($i = $at + 1; $i -lt $lines.Count; $i++) {
        $l = $lines[$i]
        if ($l.Trim() -and -not $l.StartsWith('          ')) { break }
        $body.Add($(if ($l.Length -ge 10) { $l.Substring(10) } else { '' }))
      }
      $body -join "`n"
    }
    # Runs a step script as GitHub's pwsh shell does ($ErrorActionPreference
    # Stop), with `gh api <path>` answered from Answers (path -> @{ Exit; Out;
    # Err }; a path not listed exits 1) and these environment variables.
    # Returns what it printed, the error it stopped with, its outputs and the
    # gh calls.
    function script:Invoke-WorkflowStep([scriptblock]$Script, [hashtable]$Answers, [hashtable]$Vars) {
      $global:GhAnswers = $Answers
      $global:GhCalls = [System.Collections.Generic.List[string]]::new()
      $out = New-TemporaryFile
      $names = @('GITHUB_REPOSITORY', 'GITHUB_SHA', 'GITHUB_OUTPUT', 'EVENT', 'TAG', 'RUN_ID')
      $saved = @{}; foreach ($n in $names) { $saved[$n] = [Environment]::GetEnvironmentVariable($n) }
      try {
        foreach ($n in $names) { [Environment]::SetEnvironmentVariable($n, $null) }
        [Environment]::SetEnvironmentVariable('GITHUB_OUTPUT', $out.FullName)
        foreach ($k in $Vars.Keys) { [Environment]::SetEnvironmentVariable($k, $Vars[$k]) }
        $printed = [System.Collections.Generic.List[string]]::new(); $err = ''
        try {
          & {
            $ErrorActionPreference = 'Stop'
            function gh {
              if ($args.Count -ne 2 -or $args[0] -cne 'api') { throw "unexpected gh call: $($args -join ' ')" }
              $global:GhCalls.Add([string]$args[1])
              $a = $global:GhAnswers[[string]$args[1]]
              if (-not $a) { $a = @{ Exit = 1; Err = 'gh: Not Found (HTTP 404)' } }
              if ($a.Throw) { throw $a.Throw }
              if ($a.Err) { Write-Error -Message $a.Err -ErrorAction Continue }
              if ($null -ne $a.Out) { ([string]$a.Out).Split("`n") }
              $global:LASTEXITCODE = [int]$a.Exit
            }
            . $Script
          } *>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.InformationRecord]) { $printed.Add([string]$_.MessageData) } else { $printed.Add([string]$_) }
          }
        } catch { $err = "$_" }
        [pscustomobject]@{
          Out = @($printed); Err = $err; All = (($printed -join "`n") + "`n" + $err)
          Outputs = @(Get-Content -LiteralPath $out.FullName); Calls = @($global:GhCalls)
        }
      } finally {
        foreach ($n in $names) { [Environment]::SetEnvironmentVariable($n, $saved[$n]) }
        Remove-Item -LiteralPath $out.FullName -Force
        $global:LASTEXITCODE = 0
      }
    }

    $script:Repo = 'JerisHQ/jerislink'
    # The shape of the token GitHub gives a job (GH_TOKEN): the one GitHub
    # credential these steps hold.
    $script:GhCred = 'ghs_R9plantedGitHubTokenAbCdEf0123456789Z'
    $script:Sha1 = '0123456789abcdef0123456789abcdef01234567'
    $script:Sha2 = 'fedcba9876543210fedcba9876543210fedcba98'
    # Planted text that must never come out: the credential, and the
    # made-up values below (r9-...).
    $script:WfNever = 'ghs_|R9planted|r9-'
    function script:New-RunJson([string]$Branch) {
      '{"id":123456789,"name":"msix","event":"push","conclusion":"success","head_sha":"' + $Sha1 + '","head_branch":"' + $Branch +
        '","head_repository":{"full_name":"JerisHQ/jerislink"},"created_at":"2026-11-20T10:00:00Z"}'
    }
    $b64 = { param($t) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($t)) }
    # GitHub sends base64 content in lines of 60 characters.
    $content = '{"encoding":"base64","content":"' + (& $b64 "0.4.1`n").Insert(4, '\n') + '"}'
    $pub = [scriptblock]::Create((Get-StepScript (Join-Path $WfDir 'msstore-publish.yml') 'src'))
    $chk = [scriptblock]::Create((Get-StepScript (Join-Path $WfDir 'msstore-publish-check.yml') 'src'))
    $runs = "repos/$Repo/actions/workflows/msix.yml/runs?head_sha=$Sha1&event=push&status=success&per_page=20"
    $newest = "repos/$Repo/actions/workflows/msix.yml/runs?branch=main&event=push&status=success&per_page=1"
    $byId = "repos/$Repo/actions/runs/123456789"
    $cmp1 = "repos/$Repo/compare/$Sha1...main"; $cmp2 = "repos/$Repo/compare/$Sha2...main"
    $ver1 = "repos/$Repo/contents/VERSION?ref=$Sha1"; $ver2 = "repos/$Repo/contents/VERSION?ref=$Sha2"
    $ahead = '{"status":"ahead"}'
    # Each step as the workflow runs it. Answers: path -> JSON. Out and
    # Outputs: what a run that goes on prints and outputs, from its run id,
    # sha and ref.
    $script:WfScenarios = @{
      'publish, release' = @{ Script = $pub; Env = @{ GITHUB_REPOSITORY = $Repo; GITHUB_SHA = $Sha1; EVENT = 'release'; TAG = 'v0.4.1' }
        Answers = [ordered]@{ "repos/$Repo/commits/v0.4.1" = '{"sha":"' + $Sha1 + '"}'; $runs = '{"total_count":1,"workflow_runs":[' + (New-RunJson 'v0.4.1') + ']}'; $cmp1 = $ahead }
        Ref = 'v0.4.1'
        Out = { param($Id, $Sha, $Ref) "msix run ${Id}: event=push ref=$Ref sha=$Sha conclusion=success", "main vs $Sha : ahead" }
        Outputs = { param($Id, $Sha) "run_id=$Id", "sha=$Sha", 'version=0.4.1.0' } }
      'publish, dispatch' = @{ Script = $pub; Env = @{ GITHUB_REPOSITORY = $Repo; GITHUB_SHA = $Sha2; EVENT = 'workflow_dispatch'; RUN_ID = '123456789' }
        Answers = [ordered]@{ $byId = (New-RunJson 'main'); $cmp1 = $ahead; $cmp2 = $ahead }
        Ref = 'main'
        Out = { param($Id, $Sha, $Ref) "msix run ${Id}: event=push ref=$Ref sha=$Sha conclusion=success", "main vs $Sha : ahead" }
        Outputs = { param($Id, $Sha) "run_id=$Id", "sha=$Sha", 'version=' } }
      'check, by run id' = @{ Script = $chk; Env = @{ GITHUB_REPOSITORY = $Repo; RUN_ID = '123456789' }
        Answers = [ordered]@{ $byId = (New-RunJson 'main'); $ver1 = $content; $ver2 = $content }
        Ref = 'main'
        Out = { param($Id, $Sha, $Ref) "msix run ${Id}: event=push ref=$Ref sha=$Sha -> expected package version 0.4.1.0" }
        Outputs = { param($Id, $Sha) "run_id=$Id", 'version=0.4.1.0' } }
      'check, newest on main' = @{ Script = $chk; Env = @{ GITHUB_REPOSITORY = $Repo }
        Answers = [ordered]@{ $newest = '{"total_count":1,"workflow_runs":[' + (New-RunJson 'main') + ']}'; $ver1 = $content; $ver2 = $content }
        Ref = 'main'
        Out = { param($Id, $Sha, $Ref) "msix run ${Id}: event=push ref=$Ref sha=$Sha -> expected package version 0.4.1.0" }
        Outputs = { param($Id, $Sha) "run_id=$Id", 'version=0.4.1.0' } }
    }
    # Every text a lookup may stop with (fixed text and checked values only).
    $p = 'repos/JerisHQ/jerislink/[A-Za-z0-9/._?&=-]+'
    $script:WfStops = '^(' + (@(
      "GitHub API GET $p failed \(gh exit code 1; its answer is not printed\)"
      "the GitHub API answer to GET $p is not one JSON object that parses \(not printed\)"
      'the GitHub API answered no commit sha for tag v0\.4\.1 \(its answer is not printed\)'
      'tag v0\.4\.1 points at [0-9a-f]{40}, but the event is for [0-9a-f]{40}'
      'the GitHub API answer has no list of workflow runs \(not printed\)'
      'a run in the GitHub API answer has no created_at date \(not printed\)'
      'no successful msix push run for [0-9a-f]{40} yet; re-run this job once it has finished'
      'the GitHub API did not answer with run 123456789'
      'run is not the msix workflow', 'run was not triggered by a push', 'run did not succeed', 'run is from another repository'
      'the GitHub API answered a run id or commit sha of an unexpected shape \(not printed\)'
      'commit [0-9a-f]{40} is not in main''s history \((behind|diverged|\[unlisted\])\)'
      'no successful msix push run on main', 'the newest run the GitHub API answered is not on main'
      'not a successful msix push run of this repository'
      'the GitHub API answered VERSION at [0-9a-f]{40} without base64 content \(not printed\)'
      'VERSION at [0-9a-f]{40} is not MAJOR\.MINOR\.PATCH \(its text is not printed\)'
      'the msix run lookup failed; its error message is not printed \(it can quote the GitHub API answer\)'
    ) -join '|') + ')\z'
    # The value each variant puts at a field (JSON), or $null for missing.
    $script:WfValues = [ordered]@{
      'missing' = $null; 'empty' = '""'; 'null' = 'null'; 'not valid' = '"r9-not valid"'; 'other' = ''
      'a number' = '7'; 'an array' = '["r9-in-an-array"]'; 'an object' = '{"r9key":"r9-in-an-object"}'; 'true' = 'true'
      'a credential' = '"' + $GhCred + '"'; 'a key given twice in another case' = ''; 'the key only in another case' = ''; 'the value sent, in an array' = ''
    }
    # The answer at Path with the field Key of the object at At made Variant.
    function script:Set-WfField([string]$Json, [object[]]$At, [string]$Key, [string]$Variant, [string]$Other) {
      $root = [System.Text.Json.Nodes.JsonNode]::Parse($Json)
      $o = $root; foreach ($k in $At) { $o = $o[$k] }
      $o = $o.AsObject()
      switch ($Variant) {
        'missing' { [void]$o.Remove($Key) }
        'other' { $o[$Key] = [System.Text.Json.Nodes.JsonNode]::Parse($Other) }
        'a key given twice in another case' { $o[$Key.ToUpperInvariant()] = [System.Text.Json.Nodes.JsonValue]::Create($GhCred) }
        # The field is missing; the same key in capitals holds the value sent.
        'the key only in another case' { $v = $o[$Key]; [void]$o.Remove($Key); $o[$Key.ToUpperInvariant()] = $v }
        # The value sent, as the one item of a JSON array.
        'the value sent, in an array' { $v = $o[$Key]; [void]$o.Remove($Key); $l = [System.Text.Json.Nodes.JsonArray]::new(); $l.Add($v); $o[$Key] = $l }
        'extra' { $o[$Key] = [System.Text.Json.Nodes.JsonNode]::Parse($Other) }
        # Assigned directly: a JSON array or object written to the pipeline
        # would be enumerated.
        default { if ($WfValues[$Variant] -ceq 'null') { $o[$Key] = $null } else { $o[$Key] = [System.Text.Json.Nodes.JsonNode]::Parse($WfValues[$Variant]) } }
      }
      $root.ToJsonString()
    }
    # Runs scenario Name with Answers; returns '' when it did what Ok (and,
    # when it goes on, Id, Sha, Ref) says, else what went wrong.
    function script:Test-WfRun([string]$Name, [string]$Case, $Answers, [bool]$Ok, [string]$Id = '123456789', [string]$Sha = $Sha1, [string]$Ref = '', [string]$Stop = '') {
      $sc = $WfScenarios[$Name]
      if (-not $Ref) { $Ref = $sc.Ref }
      $r = Invoke-WorkflowStep $sc.Script $Answers $sc.Env
      $bad = [System.Collections.Generic.List[string]]::new()
      if ($r.All -match $WfNever -or ($r.Outputs -join "`n") -match $WfNever) { $bad.Add('planted text came out') }
      if (($r.Calls -join "`n") -match $WfNever) { $bad.Add('planted text in a GitHub API path') }
      if ($Ok) {
        if ($r.Err) { $bad.Add("stopped: $($r.Err)") }
        if (($r.Out -join "`n") -cne ((& $sc.Out $Id $Sha $Ref) -join "`n")) { $bad.Add("printed: $($r.Out -join ' / ')") }
        if (($r.Outputs -join "`n") -cne ((& $sc.Outputs $Id $Sha) -join "`n")) { $bad.Add("outputs: $($r.Outputs -join ' / ')") }
      } else {
        if ($r.Err -cnotmatch $WfStops) { $bad.Add("stop text not fixed: $($r.Err)") }
        if ($Stop -and $r.Err -cne $Stop) { $bad.Add("stopped with: $($r.Err)") }
        if ($r.Outputs.Count) { $bad.Add("outputs: $($r.Outputs -join ' / ')") }
        foreach ($l in $r.Out) {
          if ($l -cnotmatch '^(msix run 123456789: event=push ref=(main|v0\.4\.1|\[not shown\]) sha=[0-9a-f]{40} conclusion=success|main vs [0-9a-f]{40} : (ahead|identical|behind|diverged|\[unlisted\]))\z') { $bad.Add("printed: $l") }
        }
      }
      if ($bad.Count) { "${Name}, ${Case}: $($bad -join '; ')" } else { '' }
    }
  }
  AfterAll { $global:GhAnswers = $null; $global:GhCalls = $null }

  It '<Name>: the answers as GitHub sends them go on' -ForEach @(
    @{ Name = 'publish, release' }, @{ Name = 'publish, dispatch' }, @{ Name = 'check, by run id' }, @{ Name = 'check, newest on main' }
  ) {
    $a = @{}; foreach ($kv in $WfScenarios[$Name].Answers.GetEnumerator()) { $a[$kv.Key] = @{ Exit = 0; Out = $kv.Value } }
    Test-WfRun $Name 'as sent' $a $true | Should -BeNullOrEmpty
  }

  # Name, the answer (Path: 'runs', 'run', 'commit', 'compare', 'content'),
  # the object in it (At), the field (Key), its other valid value (Other) and
  # the variants with which the step goes on (Ok; with Id, Sha or Ref when
  # those change).
  It '<Name>: field <Field> missing, empty, null, not valid, other, of another JSON type, a credential, or given twice' -ForEach @(
    $runAt = @{ 'publish, release' = @('runs', @('workflow_runs', 0)); 'check, newest on main' = @('runs', @('workflow_runs', 0)); 'publish, dispatch' = @('run', @()); 'check, by run id' = @('run', @()) }
    $notCaseDup = @('missing', 'the key only in another case', 'empty', 'null', 'not valid', 'other', 'a number', 'an array', 'the value sent, in an array', 'an object', 'true', 'a credential')
    foreach ($n in 'publish, release', 'publish, dispatch', 'check, by run id', 'check, newest on main') {
      $pa = $runAt[$n][0]; $at = $runAt[$n][1]
      $release = $n -eq 'publish, release'; $newestRun = $n -eq 'check, newest on main'
      if ($release) { @{ Name = $n; Field = 'sha (commit of the tag)'; Path = 'commit'; At = @(); Key = 'sha'; Other = '"' + 'fedcba9876543210fedcba9876543210fedcba98' + '"'; Ok = @() } }
      if ($release -or $newestRun) { @{ Name = $n; Field = 'workflow_runs'; Path = 'runs'; At = @(); Key = 'workflow_runs'; Other = '[]'; Ok = @() } }
      # A run id is any JSON whole number above 0: the release and newest-run
      # lookups go on with it; a lookup by id needs the id it asked for.
      @{ Name = $n; Field = 'id'; Path = $pa; At = $at; Key = 'id'; Other = '987654321'; Ok = $(if ($release -or $newestRun) { @('other', 'a number') } else { @() }); IdOf = @{ 'other' = '987654321'; 'a number' = '7' }
         Extra = @{ 'the run id as JSON text' = '"123456789"' } }
      # The release lookup lists the runs of msix.yml only, so it does not read name.
      @{ Name = $n; Field = 'name'; Path = $pa; At = $at; Key = 'name'; Other = '"windows"'; Ok = $(if ($release) { $notCaseDup } else { @() }) }
      @{ Name = $n; Field = 'event'; Path = $pa; At = $at; Key = 'event'; Other = '"workflow_dispatch"'; Ok = @() }
      @{ Name = $n; Field = 'conclusion'; Path = $pa; At = $at; Key = 'conclusion'; Other = '"failure"'; Ok = @() }
      @{ Name = $n; Field = 'head_sha'; Path = $pa; At = $at; Key = 'head_sha'; Other = '"fedcba9876543210fedcba9876543210fedcba98"'; Ok = $(if ($release) { @() } else { @('other') }); Sha = 'fedcba9876543210fedcba9876543210fedcba98' }
      # The branch is never printed: main or the release tag shows as such,
      # anything else as [not shown]; the newest run must be on main.
      @{ Name = $n; Field = 'head_branch'; Path = $pa; At = $at; Key = 'head_branch'; Other = '"r9-other-branch"'; Ok = $(if ($newestRun) { @() } else { $notCaseDup }); Ref = '[not shown]' }
      # Only the release lookup reads created_at (to pick the newest run).
      @{ Name = $n; Field = 'created_at'; Path = $pa; At = $at; Key = 'created_at'; Other = '"2026-11-21T09:00:00Z"'; Ok = $(if ($release) { @('other') } else { $notCaseDup }) }
      @{ Name = $n; Field = 'head_repository'; Path = $pa; At = $at; Key = 'head_repository'; Other = '{"full_name":"someone/else"}'; Ok = @() }
      @{ Name = $n; Field = 'head_repository.full_name'; Path = $pa; At = @($at + 'head_repository'); Key = 'full_name'; Other = '"someone/else"'; Ok = @() }
      if ($n -like 'publish*') { @{ Name = $n; Field = 'status (compare with main)'; Path = 'compare'; At = @(); Key = 'status'; Other = '"behind"'; Ok = @() } }
      else {
        @{ Name = $n; Field = 'encoding (VERSION)'; Path = 'content'; At = @(); Key = 'encoding'; Other = '"utf-8"'; Ok = @() }
        @{ Name = $n; Field = 'content (VERSION)'; Path = 'content'; At = @(); Key = 'content'; Other = '"MS4yCg=="'; Ok = @() }
      }
    }
  ) {
    $sc = $WfScenarios[$Name]
    $like = switch ($Path) { 'commit' { '*/commits/*' } 'runs' { '*/workflows/msix.yml/runs?*' } 'run' { '*/actions/runs/*' }
                             'compare' { "*/compare/$Sha1...main" } 'content' { "*VERSION?ref=$Sha1" } }
    $path = @($sc.Answers.Keys | Where-Object { $_ -like $like })
    $path.Count | Should -Be 1
    $variants = @($WfValues.Keys)
    # VERSION content: also the credential, base64 encoded.
    if ($Key -ceq 'content') { $variants += 'the credential, base64 encoded' }
    if ($Extra) { $variants += @($Extra.Keys) }
    $fails = @(foreach ($v in $variants) {
      $a = @{}; foreach ($kv in $sc.Answers.GetEnumerator()) { $a[$kv.Key] = @{ Exit = 0; Out = $kv.Value } }
      foreach ($q in $(if ($Path -eq 'content') { @($sc.Answers.Keys | Where-Object { $_ -like '*VERSION?ref=*' }) } elseif ($Path -eq 'compare') { @($sc.Answers.Keys | Where-Object { $_ -like '*/compare/*' }) } else { $path })) {
        $json = if ($v -ceq 'the credential, base64 encoded') { Set-WfField $sc.Answers[$q] $At $Key 'extra' ('"' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($GhCred)) + '"') }
          elseif ($Extra -and $Extra.Contains($v)) { Set-WfField $sc.Answers[$q] $At $Key 'extra' $Extra[$v] }
          else { Set-WfField $sc.Answers[$q] $At $Key $v $Other }
        $a[$q] = @{ Exit = 0; Out = $json }
      }
      # (Not $ok: PowerShell names are not case-sensitive, so it would be $Ok.)
      $goesOn = $v -cin $Ok
      $ar = @{ Ok = $goesOn }
      if ($goesOn -and $IdOf) { $ar.Id = $IdOf[$v] }
      if ($goesOn -and $v -ceq 'other' -and $Sha) { $ar.Sha = $Sha }
      if ($goesOn -and $Ref) { $ar.Ref = $Ref }
      Test-WfRun $Name "$Field $v" $a @ar
    }) | Where-Object { $_ }
    $fails | Should -BeNullOrEmpty
  }

  # Pepper, PR #74 r10: an answer is read only as exactly one complete JSON
  # object with each key once. ConvertFrom-Json takes a comment, single
  # quotes, a trailing comma and NaN, and keeps the last of two equal keys
  # (here the value sent comes last, so a reader that took it would go on).
  It '<Name>: each whole answer a gh failure, not JSON, an array, empty, null or a JSON string, or not one strict JSON object; an unexpected error' -ForEach @(
    @{ Name = 'publish, release' }, @{ Name = 'publish, dispatch' }, @{ Name = 'check, by run id' }, @{ Name = 'check, newest on main' }
  ) {
    $sc = $WfScenarios[$Name]
    $n = 0
    $fails = @(foreach ($q in @($sc.Answers.Keys)) {
      $failed = "GitHub API GET $q failed (gh exit code 1; its answer is not printed)"
      $notJson = "the GitHub API answer to GET $q is not one JSON object that parses (not printed)"
      foreach ($w in @(
          @{ Case = 'gh failed'; Answer = @{ Exit = 1; Out = $null; Err = "HTTP 401: Bad credentials $GhCred" }; Stop = $failed }
          @{ Case = 'gh failed with output'; Answer = @{ Exit = 1; Out = $sc.Answers[$q]; Err = "gh: $GhCred" }; Stop = $failed }
          @{ Case = 'not JSON'; Answer = @{ Exit = 0; Out = "r9-not json $GhCred" }; Stop = $notJson }
          @{ Case = 'an array'; Answer = @{ Exit = 0; Out = '[' + $sc.Answers[$q] + ']' }; Stop = $notJson }
          @{ Case = 'empty'; Answer = @{ Exit = 0; Out = '' }; Stop = $notJson }
          @{ Case = 'null'; Answer = @{ Exit = 0; Out = 'null' }; Stop = $notJson }
          @{ Case = 'a JSON string'; Answer = @{ Exit = 0; Out = '"' + $GhCred + '"' }; Stop = $notJson }
          @{ Case = 'two JSON objects'; Answer = @{ Exit = 0; Out = $sc.Answers[$q] + "`n" + '{"r9":"' + $GhCred + '"}' }; Stop = $notJson }
          @{ Case = 'text before it'; Answer = @{ Exit = 0; Out = "r9-before $GhCred " + $sc.Answers[$q] }; Stop = $notJson }
          @{ Case = 'text after it'; Answer = @{ Exit = 0; Out = $sc.Answers[$q] + " r9-after $GhCred" }; Stop = $notJson }
          @{ Case = 'a comment in it'; Answer = @{ Exit = 0; Out = '{/* r9-comment */' + $sc.Answers[$q].Substring(1) }; Stop = $notJson }
          @{ Case = 'a key in single quotes'; Answer = @{ Exit = 0; Out = ($sc.Answers[$q] -creplace '^\{"([^"]+)"', "{''`$1''") }; Stop = $notJson }
          @{ Case = 'a trailing comma'; Answer = @{ Exit = 0; Out = $sc.Answers[$q].Substring(0, $sc.Answers[$q].Length - 1) + ',}' }; Stop = $notJson }
          @{ Case = 'NaN'; Answer = @{ Exit = 0; Out = '{"r9nan":NaN,' + $sc.Answers[$q].Substring(1) }; Stop = $notJson }
          @{ Case = 'its first key twice'; Answer = @{ Exit = 0; Out = ($sc.Answers[$q] -creplace '^\{"([^"]+)":', '{"$1":"r9-planted","$1":') }; Stop = $notJson }
          @{ Case = 'its first key twice, in another case'; Answer = @{ Exit = 0; Out = ('{"' + ([regex]::Match($sc.Answers[$q], '^\{"([^"]+)"').Groups[1].Value.ToUpperInvariant()) + '":"r9-planted",' + $sc.Answers[$q].Substring(1)) }; Stop = $notJson }
          @{ Case = 'a nested key twice'; Answer = @{ Exit = 0; Out = $(if ($sc.Answers[$q] -cmatch '":\{"') { $sc.Answers[$q] -creplace '":\{"([^"]+)":', '":{"$1":"r9-planted","$1":' } else { '{"r9n":{"k":"r9-planted","k":1},' + $sc.Answers[$q].Substring(1) }) }; Stop = $notJson }
          # An error the step does not expect (here gh itself throws, its
          # message holding the credential) is replaced by fixed text.
          @{ Case = 'gh threw'; Answer = @{ Throw = "r9-gh threw $GhCred" }; Stop = 'the msix run lookup failed; its error message is not printed (it can quote the GitHub API answer)' })) {
        $a = @{}; foreach ($kv in $sc.Answers.GetEnumerator()) { $a[$kv.Key] = @{ Exit = 0; Out = $kv.Value } }
        $a[$q] = $w.Answer
        # The answer for the other sha is never asked for.
        $asked = -not ($q -like "*$Sha2*")
        $n++
        Test-WfRun $Name "$q $($w.Case)" $a (-not $asked) -Stop $(if ($asked) { $w.Stop } else { '' })
      }
    }) | Where-Object { $_ }
    $fails | Should -BeNullOrEmpty
    $n | Should -BeGreaterThan 40
  }
}
