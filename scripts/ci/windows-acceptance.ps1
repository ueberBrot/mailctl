param (
    [Parameter(Mandatory)]
    [ValidateSet('repeat-drafts', 'credentials', 'mime-depth')]
    [string]$Suite
)

$ErrorActionPreference = 'Stop'
Set-Location "$PSScriptRoot/../.."

switch ($Suite) {
    'mime-depth' {
        # Compile both probes with one workspace dependency feature graph. The
        # package-only builds otherwise relink mailctl and shared dependencies.
        $artifacts = cargo test --release --locked --workspace --no-default-features `
            --features "$env:MAILCTL_FEATURES" --test mime_depth --test imap_allocations `
            --no-run --message-format=json | ForEach-Object { $_ | ConvertFrom-Json }
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        $mimeTests = switch ($env:MAILCTL_FEATURES) {
            'cli' { 'cli_decodes_deep_mime_from_a_one_mib_lifecycle_caller' }
            'mcp' { 'mcp_decodes_deep_mime_from_a_one_mib_lifecycle_caller' }
            'cli,mcp' {
                'cli_decodes_deep_mime_from_a_one_mib_lifecycle_caller'
                'mcp_decodes_deep_mime_from_a_one_mib_lifecycle_caller'
            }
            default { throw 'Expected cli, mcp, or cli,mcp component selection' }
        }
        $codecTest = 'deep_bodystructure_codec_has_finite_work_and_stack'
        $targets = @(
            @{
                Name = 'mime_depth'
                Source = 'tests/process-driver/tests/mime_depth.rs'
                Tests = @($mimeTests)
                # Shared fixture unit tests are covered by the workspace run.
                Filter = @('_decodes_deep_mime_from_a_one_mib_lifecycle_caller')
            },
            @{
                Name = 'imap_allocations'
                Source = 'tests/imap_allocations.rs'
                Tests = @($codecTest)
                Filter = @($codecTest, '--exact')
            }
        )
        foreach ($target in $targets) {
            $source = [System.IO.Path]::GetFullPath("$PSScriptRoot/../../$($target.Source)")
            $harness = @($artifacts | Where-Object {
                $_.reason -eq 'compiler-artifact' -and $_.executable -and
                $_.target.name -eq $target.Name -and $_.target.src_path -eq $source
            })
            if ($harness.Count -ne 1) { throw "Expected one workspace-built $($target.Name) harness" }
            $binary = $harness[0].executable
            $filter = $target.Filter
            $listing = @(& $binary @filter --list)
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
            $listedTests = @($listing | Where-Object { $_ -match ': test$' } | Sort-Object)
            $expectedTests = @($target.Tests | ForEach-Object { "${_}: test" } | Sort-Object)
            if ($listedTests.Count -ne $expectedTests.Count -or
                @(Compare-Object $listedTests $expectedTests).Count -ne 0) {
                throw "Required $($target.Name) tests are missing or differ from the selected components"
            }
            & $binary @filter
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        }
    }
    'repeat-drafts' {
        # Match the preceding workspace/component build instead of relinking
        # the drivers with a different package-only dependency feature graph.
        $artifacts = cargo test --locked --workspace --no-default-features --features 'cli,mcp' `
            --test drafts --no-run --message-format=json | ForEach-Object { $_ | ConvertFrom-Json }
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        $source = [System.IO.Path]::GetFullPath("$PSScriptRoot/../../tests/process-driver/tests/drafts.rs")
        $harness = @($artifacts | Where-Object {
            $_.reason -eq 'compiler-artifact' -and $_.executable -and
            $_.target.name -eq 'drafts' -and $_.target.src_path -eq $source
        })
        if ($harness.Count -ne 1) { throw 'Expected one workspace-built process-driver draft harness' }
        $binary = $harness[0].executable
        $test = 'independent_cli_and_mcp_create_once_and_inspect_without_provider_work'
        $listing = & $binary $test --exact --list
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        if ($listing -notcontains "${test}: test") { throw 'Required concurrent draft test is missing' }
        for ($attempt = 1; $attempt -le 20; $attempt++) {
            & $binary $test --exact
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        }
    }
    'credentials' {
        cargo test --locked --workspace --no-default-features --features "$env:MAILCTL_FEATURES" `
            --test windows_credentials native_windows_credentials_cross_processes_and_rotate `
            -- --ignored --nocapture --test-threads=1
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture
        Get-ChildItem target/debug/mailctl*.exe | Get-FileHash -Algorithm SHA256
    }
}
