param (
    [Parameter(Mandatory)]
    [ValidateSet('build', 'prepare', 'installer', 'record', 'inspect', 'host')]
    [string]$Phase,
    [string]$Binary
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Set-Location "$PSScriptRoot/../.."
$target = 'x86_64-pc-windows-msvc'
$utf8 = [Text.UTF8Encoding]::new($false)
if ($Phase -eq 'host') {
    $PSVersionTable.PSVersion.ToString()
    exit
}
if (-not $IsWindows -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') {
    throw 'The native candidate requires Windows x86_64'
}

if ($Phase -eq 'inspect') {
    if (-not $Binary -or -not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
        throw 'An executable is required for Authenticode inspection'
    }
    @{
        authenticode_status = (Get-AuthenticodeSignature -LiteralPath $Binary).Status.ToString()
        powershell_version = $PSVersionTable.PSVersion.ToString()
        windows_caption = (Get-CimInstance Win32_OperatingSystem).Caption
    } | ConvertTo-Json -Compress
    exit
}

if ($Phase -eq 'build') {
    New-Item -ItemType Directory -Path target -Force | Out-Null
    & dist build --artifacts=local --target $target --output-format=json |
        Out-File -LiteralPath target/dist-build.json -Encoding utf8NoBOM
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    exit
}

foreach ($name in 'MAILCTL_CANDIDATE_DIR', 'MAILCTL_PACKAGED_BIN_DIR') {
    if (-not [Environment]::GetEnvironmentVariable($name)) { throw "$name is required" }
}
$candidate = $env:MAILCTL_CANDIDATE_DIR
$installed = $env:MAILCTL_PACKAGED_BIN_DIR

if ($Phase -eq 'prepare') {
    if (-not $env:GITHUB_ENV) { throw 'GITHUB_ENV is required' }
    & python scripts/prepare-installer.py --target $target --output $candidate
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    [IO.File]::AppendAllLines($env:GITHUB_ENV, @(
        "MAILCTL_CANDIDATE_DIR=$candidate",
        "MAILCTL_PACKAGED_BIN_DIR=$installed"
    ), $utf8)
    exit
}

function Assert-PassingLog {
    param ([string]$Path, [switch]$Installer)
    $text = [IO.File]::ReadAllText($Path)
    if ($Installer) {
        if ($text -notmatch '(?m)^OK\s*$') { throw "Missing passing installer result: $Path" }
    } else {
        $results = [regex]::Matches($text, '(?m)^test result: (.+)$')
        if ($results.Count -eq 0) { throw "Missing test results: $Path" }
        foreach ($result in $results) {
            if ($result.Groups[1].Value -notmatch '^ok\. [1-9][0-9]* passed; 0 failed; 0 ignored;') {
                throw "Packaged acceptance must pass tests without failures or ignored tests: $Path"
            }
        }
    }
}

function Get-InstallerArguments {
    param ([string]$HostName)
    $directory = if ($HostName -eq 'pwsh') { $installed } else { $installed + '-powershell' }
    @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'tests/installer.ps1',
        '-Artifacts', $candidate, '-InstallTo', $directory)
}

if ($Phase -eq 'installer') {
    foreach ($hostName in 'powershell.exe', 'pwsh') {
        $label = if ($hostName -eq 'pwsh') { 'pwsh' } else { 'powershell' }
        $log = Join-Path $candidate "installer-acceptance-$label.log"
        $arguments = @(Get-InstallerArguments -HostName $hostName)
        & $hostName @arguments 2>&1 | Tee-Object -FilePath $log
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        Assert-PassingLog -Path $log -Installer
    }
    exit
}

# Check the prepared bytes before adding any passing acceptance evidence.
$hashes = @{}
foreach ($line in [IO.File]::ReadAllLines((Join-Path $candidate 'SHA256SUMS'))) {
    if ($line -notmatch '^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$') { throw 'Malformed candidate checksum line' }
    $hash, $name = $Matches[1], $Matches[2]
    if ($hashes.ContainsKey($name)) { throw "Duplicate candidate checksum: $name" }
    $path = Join-Path $candidate $name
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash) {
        throw "Prepared candidate changed: $name"
    }
    $hashes[$name] = $hash
}
foreach ($hostName in 'powershell', 'pwsh') {
    Assert-PassingLog -Path (Join-Path $candidate "installer-acceptance-$hostName.log") -Installer
}
foreach ($suite in 'state', 'process', 'native', 'reading', 'drafts') {
    foreach ($selection in 'cli', 'mcp', 'cli-mcp') {
        Assert-PassingLog -Path (Join-Path $candidate "installed-$suite-$selection-acceptance.log")
    }
}
$sourceEvidence = Join-Path $candidate 'windows-source-evidence.txt'
if (-not (Test-Path -LiteralPath $sourceEvidence -PathType Leaf) -or
    (Get-Item -LiteralPath $sourceEvidence).Length -eq 0) {
    throw 'Missing Windows native source evidence'
}
$legacyVersion = & powershell.exe -NoProfile -File scripts/ci/windows-candidate.ps1 -Phase host
if ($LASTEXITCODE -ne 0 -or $legacyVersion -notmatch '^5\.1\.') {
    throw 'Windows PowerShell 5.1 host evidence is missing'
}
$evidence = @(
    'status=passed',
    'topology=cooperative-embedded',
    'credential_source=disposable-windows-credential-manager',
    'reading_credential_source=disposable-windows-credential-manager',
    'reading_tls_source=fixture-ca-via-SSL_CERT_FILE',
    'drafts_credential_source=disposable-windows-credential-manager',
    'drafts_tls_source=fixture-ca-via-SSL_CERT_FILE',
    "target=$target",
    "powershell_version=$($PSVersionTable.PSVersion)",
    "windows_powershell_version=$legacyVersion",
    "packaged_bin_directory=$installed",
    'real_provider=not-qualified',
    'isolation=not-qualified',
    'publication=not-performed'
) + [IO.File]::ReadAllLines($sourceEvidence)
foreach ($hostName in 'powershell.exe', 'pwsh') {
    $label = if ($hostName -eq 'pwsh') { 'pwsh' } else { 'powershell' }
    $command = @($hostName) + @(Get-InstallerArguments -HostName $hostName)
    $evidence += "installer_command_$label=" + (ConvertTo-Json -InputObject $command -Compress)
}
[IO.File]::WriteAllLines((Join-Path $candidate 'acceptance-evidence.txt'), $evidence, $utf8)
$checksums = @(Get-ChildItem -LiteralPath $candidate -File | Where-Object Name -ne 'SHA256SUMS' |
    Sort-Object Name | ForEach-Object {
        (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $_.Name
    })
[IO.File]::WriteAllLines((Join-Path $candidate 'SHA256SUMS'), $checksums, $utf8)
