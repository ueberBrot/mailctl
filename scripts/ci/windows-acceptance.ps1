param (
    [Parameter(Mandatory)]
    [ValidateSet('repeat-drafts', 'credentials', 'mime-depth')]
    [string]$Suite
)

$ErrorActionPreference = 'Stop'
Set-Location "$PSScriptRoot/../.."

switch ($Suite) {
    'mime-depth' {
        cargo test --release --locked -p mailctl-process-tests `
            --no-default-features --features "$env:MAILCTL_FEATURES" --test mime_depth
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        cargo test --release --locked -p mailctl --no-default-features `
            --features "$env:MAILCTL_FEATURES" --test imap_allocations `
            deep_bodystructure_codec_has_finite_work_and_stack
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
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
        cargo test --locked --no-default-features --features "$env:MAILCTL_FEATURES" `
            --test windows_credentials native_windows_credentials_cross_processes_and_rotate `
            -- --ignored --nocapture --test-threads=1
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture
        Get-ChildItem target/debug/mailctl*.exe | Get-FileHash -Algorithm SHA256
    }
}
