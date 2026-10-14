param (
    [Parameter(Mandatory)]
    [ValidateSet('repeat-drafts', 'credentials')]
    [string]$Suite
)

$ErrorActionPreference = 'Stop'
Set-Location "$PSScriptRoot/../.."

switch ($Suite) {
    'repeat-drafts' {
        for ($attempt = 1; $attempt -le 20; $attempt++) {
            cargo test --locked -p mailctl-process-tests --test drafts `
                independent_cli_and_mcp_create_once_and_inspect_without_provider_work -- --exact
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
