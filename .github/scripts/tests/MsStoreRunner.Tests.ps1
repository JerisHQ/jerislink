# Pester 5 tests for the draft check before commit, the commit guard and the
# submission read-back in MsStoreRunner.psm1.
# Run: Invoke-Pester -Path .github/scripts/tests -Output Detailed
# The fixtures are shaped like `msstore submission get <productId>` output from
# Microsoft Store Developer CLI v0.4.4 (DevCenterSubmission, PascalCase names).
# They are made up, not captured from Partner Center; the FileUploadUrl in them
# carries a fake SAS signature so the tests can check it is never printed.

BeforeAll {
  # The module builds paths from LOCALAPPDATA at import; it is unset off Windows.
  if (-not $env:LOCALAPPDATA) { $env:LOCALAPPDATA = [IO.Path]::GetTempPath() }
  Import-Module (Join-Path $PSScriptRoot '..' 'MsStoreRunner.psm1') -Force
  $script:Fixtures = Join-Path $PSScriptRoot 'fixtures'
  function script:Fixture([string]$Name) { Get-Content -Raw -LiteralPath (Join-Path $script:Fixtures "submission-$Name.json") }
  $script:SubId = '1152921505000000004'
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

  It 'passes when CLI status text comes before the JSON' {
    $json = "Retrieving Submission`nFound Pending Submission.`n" + (Fixture 'new-package-only')
    (Test-SubmissionHasPackage -SubmissionJson $json -ExpectedVersion '0.4.1.0').Result | Should -Be 'Pass'
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

  It 'fails when submission get returned another submission than the one this run created' {
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

Describe 'Assert-SubmissionHasPackage' {
  BeforeAll {
    # Stand-in for the CLI so Pester can mock it inside the module.
    function global:msstore { }
    $script:AppJson = '{"Id":"9NM3VWQ9MD7N","PendingApplicationSubmission":{"Id":"1152921505000000004","ResourceLocation":"x"}}'
  }
  AfterAll { Remove-Item function:global:msstore -ErrorAction SilentlyContinue }

  It 'passes, prints only safe fields, and warns when targetPublishMode is not Manual' {
    $sub = Fixture 'new-package-only'
    Mock -ModuleName MsStoreRunner msstore {
      $global:LASTEXITCODE = 0
      if ($args[0] -eq 'apps') { $AppJson } else { $sub }
    }
    $out = Assert-SubmissionHasPackage -ProductId '9NM3VWQ9MD7N' -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -IntervalSeconds 0 6>&1 | Out-String
    $out | Should -Match 'submission id=1152921505000000004 status=PreProcessing targetPublishMode=Immediate'
    $out | Should -Match 'fileName=Jerislink-0\.4\.1\.0-x64\.msix version=0\.4\.1\.0 fileStatus=Uploaded'
    $out | Should -Match '::warning title=Store publish mode::'
    $out | Should -Match 'verified \(Pending submission 1152921505000000004\):'
    $out | Should -Not -Match 'sig=|blob\.core|FileUploadUrl'
  }

  It 'does not warn when targetPublishMode is Manual' {
    $sub = (Fixture 'new-package-only') -replace '"TargetPublishMode": "Immediate"', '"TargetPublishMode": "Manual"'
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 0; if ($args[0] -eq 'apps') { $AppJson } else { $sub } }
    $out = Assert-SubmissionHasPackage -ProductId '9NM3VWQ9MD7N' -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -IntervalSeconds 0 6>&1 | Out-String
    $out | Should -Not -Match '::warning'
  }

  It 'throws on a failing submission without printing the upload URL' {
    $sub = Fixture 'old-package-still-present'
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 0; if ($args[0] -eq 'apps') { $AppJson } else { $sub } }
    $err = $null
    $out = try { Assert-SubmissionHasPackage -ProductId '9NM3VWQ9MD7N' -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -IntervalSeconds 0 6>&1 | Out-String } catch { $err = "$_" }
    $err | Should -Match 'submission check failed: .*0\.3\.0\.0'
    "$out $err" | Should -Not -Match 'sig=|blob\.core'
  }

  It 'throws "not verified" when the version never gets filled in' {
    $sub = Fixture 'version-unset'
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 0; if ($args[0] -eq 'apps') { $AppJson } else { $sub } }
    { Assert-SubmissionHasPackage -ProductId '9NM3VWQ9MD7N' -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -TimeoutMinutes 0 -IntervalSeconds 0 6>$null } |
      Should -Throw '*not verified*version not filled in*'
  }

  # Item 2: the read-back follows the submission id this run created.
  It 'passes once that submission is Published (no longer pending, now the last published one)' {
    $app = '{"Id":"9NM3VWQ9MD7N","PendingApplicationSubmission":null,"LastPublishedApplicationSubmission":{"Id":"1152921505000000004","ResourceLocation":"x"}}'
    $sub = (Fixture 'new-package-only') -replace '"Status": "PreProcessing"', '"Status": "Published"'
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 0; if ($args[0] -eq 'apps') { $app } else { $sub } }
    $out = Assert-SubmissionHasPackage -ProductId '9NM3VWQ9MD7N' -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -IntervalSeconds 0 6>&1 | Out-String
    $out | Should -Match 'status=Published'
    $out | Should -Match 'verified \(LastPublished submission 1152921505000000004\):'
  }

  It 'throws when nothing is pending and the last published submission is another one' {
    $app = '{"Id":"9NM3VWQ9MD7N","PendingApplicationSubmission":null,"LastPublishedApplicationSubmission":{"Id":"1152921505000000001","ResourceLocation":"x"}}'
    $sub = (Fixture 'new-package-only') -replace '1152921505000000004', '1152921505000000001' -replace '"Status": "PreProcessing"', '"Status": "Published"'
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 0; if ($args[0] -eq 'apps') { $app } else { $sub } }
    { Assert-SubmissionHasPackage -ProductId '9NM3VWQ9MD7N' -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -IntervalSeconds 0 6>$null } |
      Should -Throw '*neither pending nor the last published*last published: 1152921505000000001*'
  }

  It 'throws when nothing is pending or published' {
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 0; '{"Id":"9NM3VWQ9MD7N","PendingApplicationSubmission":null}' }
    { Assert-SubmissionHasPackage -ProductId '9NM3VWQ9MD7N' -SubmissionId $SubId -ExpectedVersion '0.4.1.0' 6>$null } |
      Should -Throw '*neither pending nor the last published*last published: none*'
  }

  It 'throws when another submission is pending' {
    $app = '{"Id":"9NM3VWQ9MD7N","PendingApplicationSubmission":{"Id":"1152921505000000005","ResourceLocation":"x"}}'
    $sub = (Fixture 'new-package-only') -replace '1152921505000000004', '1152921505000000005'
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 0; if ($args[0] -eq 'apps') { $app } else { $sub } }
    { Assert-SubmissionHasPackage -ProductId '9NM3VWQ9MD7N' -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -IntervalSeconds 0 6>$null } |
      Should -Throw "*pending submission is 1152921505000000005, not submission $SubId that this run created*"
  }

  It 'throws when submission get returns another submission than the one this run created' {
    $sub = (Fixture 'new-package-only') -replace '1152921505000000004', '1152921505000000001'
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 0; if ($args[0] -eq 'apps') { $AppJson } else { $sub } }
    { Assert-SubmissionHasPackage -ProductId '9NM3VWQ9MD7N' -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -IntervalSeconds 0 6>$null } |
      Should -Throw '*returned submission 1152921505000000001, not submission*that this run created*'
  }

  It 'throws on a submission that was never committed (PendingCommit)' {
    $sub = (Fixture 'new-package-only') -replace '"Status": "PreProcessing"', '"Status": "PendingCommit"'
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 0; if ($args[0] -eq 'apps') { $AppJson } else { $sub } }
    { Assert-SubmissionHasPackage -ProductId '9NM3VWQ9MD7N' -SubmissionId $SubId -ExpectedVersion '0.4.1.0' -IntervalSeconds 0 6>$null } |
      Should -Throw "*status is 'PendingCommit', not a committed status*"
  }

  It 'throws when msstore apps get fails' {
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 1; 'Error' }
    { Assert-SubmissionHasPackage -ProductId '9NM3VWQ9MD7N' -SubmissionId $SubId -ExpectedVersion '0.4.1.0' 6>$null } | Should -Throw '*apps get failed (exit 1)*'
  }
}

# Item 3: before commit, only the new package may remain in the draft.
Describe 'Test-DraftReadyToCommit' {
  BeforeAll { $script:NewFile = 'Jerislink-0.4.1.0-x64.msixupload' }

  It 'passes when the old package is PendingDelete and only the new one remains' {
    $r = Test-DraftReadyToCommit -SubmissionJson (Fixture 'draft-ready') -SubmissionId $SubId -ExpectedFileName $NewFile -ExpectedVersion '0.4.1.0'
    $r.Result | Should -Be 'Pass'
    $r.Reason | Should -Match 'only Jerislink-0\.4\.1\.0-x64\.msixupload would remain'
  }

  It 'fails when an old package with another extension stays Uploaded (CLI marks only the same extension)' {
    $r = Test-DraftReadyToCommit -SubmissionJson (Fixture 'draft-old-other-extension') -SubmissionId $SubId -ExpectedFileName $NewFile -ExpectedVersion '0.4.1.0'
    $r.Result | Should -Be 'Fail'
    $r.Reason | Should -Match '2 package\(s\) would remain after commit .*Jerislink-0\.3\.0\.0-x64\.msix version=0\.3\.0\.0'
  }

  It 'fails when a second old package with the same extension stays (CLI marks only the first)' {
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

  It 'fails when submission get returned another submission than the draft' {
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

Describe 'Assert-DraftReadyToCommit and Invoke-SubmissionCommit' {
  BeforeAll {
    function global:msstore { }
    $script:NewFile = 'Jerislink-0.4.1.0-x64.msixupload'
    $script:DraftApp = '{"Id":"9NM3VWQ9MD7N","PendingApplicationSubmission":{"Id":"1152921505000000004","ResourceLocation":"x"},"LastPublishedApplicationSubmission":{"Id":"1152921505000000001","ResourceLocation":"y"}}'
  }
  AfterAll { Remove-Item function:global:msstore -ErrorAction SilentlyContinue }

  It 'returns the draft id when only the new package would remain, and never commits' {
    $sub = Fixture 'draft-ready'
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 0; if ($args[0] -eq 'apps') { $DraftApp } else { $sub } }
    $id = Assert-DraftReadyToCommit -ProductId '9NM3VWQ9MD7N' -ExpectedFileName $NewFile -ExpectedVersion '0.4.1.0' 6>$null
    $id | Should -Be $SubId
    Should -Invoke -ModuleName MsStoreRunner msstore -Times 0 -ParameterFilter { $args[0] -eq 'submission' -and $args[1] -eq 'publish' }
  }

  It 'throws "not committing" and points to the API when an old package would remain' {
    $sub = Fixture 'draft-old-other-extension'
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 0; if ($args[0] -eq 'apps') { $DraftApp } else { $sub } }
    $err = $null
    $out = try { Assert-DraftReadyToCommit -ProductId '9NM3VWQ9MD7N' -ExpectedFileName $NewFile -ExpectedVersion '0.4.1.0' 6>&1 | Out-String } catch { $err = "$_" }
    $err | Should -Match 'draft check failed, not committing: 2 package\(s\) would remain'
    $err | Should -Match 'msstore submission delete 9NM3VWQ9MD7N --no-confirm'
    $err | Should -Not -Match 'press Submit'
    "$out $err" | Should -Not -Match 'sig=|blob\.core'
    Should -Invoke -ModuleName MsStoreRunner msstore -Times 0 -ParameterFilter { $args[0] -eq 'submission' -and $args[1] -eq 'publish' }
  }

  It 'throws when nothing is pending after the upload' {
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 0; '{"Id":"9NM3VWQ9MD7N","PendingApplicationSubmission":null}' }
    { Assert-DraftReadyToCommit -ProductId '9NM3VWQ9MD7N' -ExpectedFileName $NewFile -ExpectedVersion '0.4.1.0' 6>$null } | Should -Throw '*no pending submission*not committing*'
  }

  It 'commits with submission publish when the checked draft is still pending' {
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 0; if ($args[0] -eq 'apps') { $DraftApp } else { 'Submission Committed with status CommitStarted' } }
    $out = Invoke-SubmissionCommit -ProductId '9NM3VWQ9MD7N' -SubmissionId $SubId 6>&1 | Out-String
    $out | Should -Match "submission $SubId committed through the API"
    Should -Invoke -ModuleName MsStoreRunner msstore -Times 1 -Exactly -ParameterFilter { $args[0] -eq 'submission' -and $args[1] -eq 'publish' -and $args[2] -eq '9NM3VWQ9MD7N' }
  }

  It 'does not commit when another submission is pending' {
    $app = $DraftApp -replace '1152921505000000004', '1152921505000000005'
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 0; $app }
    { Invoke-SubmissionCommit -ProductId '9NM3VWQ9MD7N' -SubmissionId $SubId 6>$null } | Should -Throw '*not checked draft*not committing*'
    Should -Invoke -ModuleName MsStoreRunner msstore -Times 0 -ParameterFilter { $args[0] -eq 'submission' }
  }

  It 'throws when submission publish fails, without printing URLs' {
    Mock -ModuleName MsStoreRunner msstore { if ($args[0] -eq 'apps') { $global:LASTEXITCODE = 0; $DraftApp } else { $global:LASTEXITCODE = 1; 'failed https://x.blob.core.windows.net/a?sig=FAKE' } }
    $err = $null
    $out = try { Invoke-SubmissionCommit -ProductId '9NM3VWQ9MD7N' -SubmissionId $SubId 6>&1 | Out-String } catch { $err = "$_" }
    $err | Should -Match 'submission publish failed \(exit 1\); submission 1152921505000000004 not committed'
    "$out $err" | Should -Not -Match 'sig=|blob\.core'
  }
}
