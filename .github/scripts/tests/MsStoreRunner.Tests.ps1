# Pester 5 tests for the submission read-back in MsStoreRunner.psm1.
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

  It 'fails when submission get returned another submission than the pending one' {
    $r = Test-SubmissionHasPackage -SubmissionJson (Fixture 'new-package-only') -ExpectedVersion '0.4.1.0' -ExpectedSubmissionId '1152921505000000003'
    $r.Result | Should -Be 'Fail'
    $r.Reason | Should -Match 'not the pending submission'
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
    $out = Assert-SubmissionHasPackage -ProductId '9NM3VWQ9MD7N' -ExpectedVersion '0.4.1.0' -IntervalSeconds 0 6>&1 | Out-String
    $out | Should -Match 'submission id=1152921505000000004 status=PreProcessing targetPublishMode=Immediate'
    $out | Should -Match 'fileName=Jerislink-0\.4\.1\.0-x64\.msix version=0\.4\.1\.0 fileStatus=Uploaded'
    $out | Should -Match '::warning title=Store publish mode::'
    $out | Should -Match 'verified:'
    $out | Should -Not -Match 'sig=|blob\.core|FileUploadUrl'
  }

  It 'does not warn when targetPublishMode is Manual' {
    $sub = (Fixture 'new-package-only') -replace '"TargetPublishMode": "Immediate"', '"TargetPublishMode": "Manual"'
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 0; if ($args[0] -eq 'apps') { $AppJson } else { $sub } }
    $out = Assert-SubmissionHasPackage -ProductId '9NM3VWQ9MD7N' -ExpectedVersion '0.4.1.0' -IntervalSeconds 0 6>&1 | Out-String
    $out | Should -Not -Match '::warning'
  }

  It 'throws on a failing submission without printing the upload URL' {
    $sub = Fixture 'old-package-still-present'
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 0; if ($args[0] -eq 'apps') { $AppJson } else { $sub } }
    $err = $null
    $out = try { Assert-SubmissionHasPackage -ProductId '9NM3VWQ9MD7N' -ExpectedVersion '0.4.1.0' -IntervalSeconds 0 6>&1 | Out-String } catch { $err = "$_" }
    $err | Should -Match 'submission check failed: .*0\.3\.0\.0'
    "$out $err" | Should -Not -Match 'sig=|blob\.core'
  }

  It 'throws "not verified" when the version never gets filled in' {
    $sub = Fixture 'version-unset'
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 0; if ($args[0] -eq 'apps') { $AppJson } else { $sub } }
    { Assert-SubmissionHasPackage -ProductId '9NM3VWQ9MD7N' -ExpectedVersion '0.4.1.0' -TimeoutMinutes 0 -IntervalSeconds 0 6>$null } |
      Should -Throw '*not verified*version not filled in*'
  }

  It 'throws when no pending submission exists after publish' {
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 0; '{"Id":"9NM3VWQ9MD7N","PendingApplicationSubmission":null}' }
    { Assert-SubmissionHasPackage -ProductId '9NM3VWQ9MD7N' -ExpectedVersion '0.4.1.0' 6>$null } | Should -Throw '*no pending submission*not verified*'
  }

  It 'throws when msstore apps get fails' {
    Mock -ModuleName MsStoreRunner msstore { $global:LASTEXITCODE = 1; 'Error' }
    { Assert-SubmissionHasPackage -ProductId '9NM3VWQ9MD7N' -ExpectedVersion '0.4.1.0' 6>$null } | Should -Throw '*apps get failed (exit 1)*'
  }
}
