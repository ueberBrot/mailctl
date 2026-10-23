[CmdletBinding(DefaultParameterSetName = 'Phase')]
param (
    [Parameter(Mandatory, ParameterSetName = 'Phase')]
    [ValidateSet('prepare', 'state', 'process', 'native', 'reading', 'drafts', 'wsl')]
    [string]$Phase,
    [Parameter(Mandatory, ParameterSetName = 'Session')]
    [string]$SessionFile
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = [System.IO.Path]::GetFullPath("$PSScriptRoot/../..")
Set-Location $repository

function Invoke-Checked {
    param ([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Executable failed with exit code $LASTEXITCODE" }
}

function Invoke-Harness {
    param ($Harness, [string]$Log)
    $arguments = @('--skip', 'native_support::tests::cancel_export_console')
    switch ($Harness.Name) {
        'windows_credentials' {
            $arguments += @('native_windows_credentials_cross_processes_and_rotate', '--exact', '--ignored')
        }
        'windows_wsl' {
            $arguments += @('windows_hosted_wsl2_reading_drafts_and_restart', '--exact', '--ignored')
        }
        { $_ -in 'packaged_reading', 'packaged_drafts' } { $arguments += '--ignored' }
    }
    $listing = @(& $Harness.Executable @arguments --list)
    if ($LASTEXITCODE -ne 0) { throw "Cannot list $($Harness.Name) acceptance tests" }
    $tests = @($listing | Where-Object { $_ -match ': test$' })
    if ($tests.Count -eq 0) { throw "$($Harness.Name) selected no acceptance tests" }
    if ($Harness.Name -eq 'windows_credentials' -and
        ($tests.Count -ne 1 -or $tests[0] -ne 'native_windows_credentials_cross_processes_and_rotate: test')) {
        throw 'The required native Credential Manager test is missing'
    }
    if ($Harness.Name -eq 'windows_wsl' -and
        ($tests.Count -ne 1 -or $tests[0] -ne 'windows_hosted_wsl2_reading_drafts_and_restart: test')) {
        throw 'The required Windows-hosted WSL 2 qualification test is missing'
    }
    "harness=$($Harness.Name) executable=$($Harness.Executable) arguments=$($arguments -join ' ')" |
        Tee-Object -FilePath $Log -Append
    $output = @(& $Harness.Executable @arguments --nocapture --test-threads=1 2>&1 |
        Tee-Object -FilePath $Log -Append)
    if ($LASTEXITCODE -ne 0) { throw "$($Harness.Name) acceptance failed" }
    $summary = @($output | Where-Object {
        "$_" -match '^test result: ok\. ([1-9][0-9]*) passed; 0 failed; 0 ignored;'
    })
    if ($summary.Count -ne 1 -or
        "$($summary[0])" -notmatch "^test result: ok\. $($tests.Count) passed; 0 failed; 0 ignored;") {
        throw "$($Harness.Name) did not pass every listed acceptance test"
    }
}

if ($PSCmdlet.ParameterSetName -eq 'Session') {
    $session = Get-Content -LiteralPath $SessionFile -Raw | ConvertFrom-Json
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -ne $session.Sid) {
        throw 'Packaged acceptance must run under its disposable local identity'
    }
    $profileRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    if (!$profileRoot -or !(Test-Path -LiteralPath $profileRoot -PathType Container)) {
        throw 'The disposable Windows profile was not loaded'
    }
    $env:USERNAME = $session.User
    $env:USERDOMAIN = $env:COMPUTERNAME
    $env:USERPROFILE = $profileRoot
    $env:HOME = $profileRoot
    $env:APPDATA = Join-Path $profileRoot 'AppData/Roaming'
    $env:LOCALAPPDATA = Join-Path $profileRoot 'AppData/Local'
    $env:CARGO_HOME = Join-Path $session.Root 'cargo'
    $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot"
    $env:MAILCTL_DISPOSABLE_WINDOWS = '1'
    $env:MAILCTL_PACKAGED_CREDENTIAL_SOURCE = 'native'
    $env:TEMP = Join-Path $session.Root 'temp'
    $env:TMP = $env:TEMP
    New-Item -ItemType Directory -Path $env:TEMP -Force | Out-Null
    "phase=$($session.Phase) identity=$($identity.Name) sid=$($identity.User.Value) credential_source=windows-credential-manager" |
        Set-Content -LiteralPath (Join-Path $session.Root 'windows-source-evidence.txt') -Encoding utf8
    if ($session.Phase -eq 'wsl') { . "$PSScriptRoot/windows-wsl.ps1" }
    try {
        if ($session.Phase -eq 'wsl') { Start-MailctlWsl $session.Root $session.Sid }
        foreach ($selection in $session.Selections) {
            $label = $selection.Features.Replace(',', '-')
            $installed = Join-Path $session.Root "installed-$label"
            $log = Join-Path $session.Root "installed-$($session.Phase)-$label-acceptance.log"
            $installer = Join-Path $repository 'tests/installer.ps1'
            $engine = (Get-Process -Id $PID).Path
            $installerArguments = @('-NoLogo', '-NoProfile', '-File', $installer,
                '-Artifacts', $session.Artifacts, '-InstallTo', $installed,
                '-Components', $selection.Features, '-InstallOnly', '-Reuse')
            "installer=$engine arguments=$($installerArguments -join ' ')" | Set-Content -LiteralPath $log -Encoding utf8
            & $engine @installerArguments 2>&1 | Tee-Object -FilePath $log -Append
            if ($LASTEXITCODE -ne 0) { throw "Installing $label components failed" }
            $env:MAILCTL_PACKAGED_BIN_DIR = $installed
            foreach ($harness in $selection.Harnesses) { Invoke-Harness $harness $log }
            "phase=$($session.Phase) components=$($selection.Features) installed=$installed log=$([System.IO.Path]::GetFileName($log))" |
                Add-Content -LiteralPath (Join-Path $session.Root 'windows-source-evidence.txt') -Encoding utf8
        }
        if ($session.Phase -eq 'wsl') {
            $path = Join-Path $session.Root 'windows-wsl-evidence.txt'
            $evidence = [IO.File]::ReadAllText($path).Replace('status=prepared', 'status=passed')
            [IO.File]::WriteAllText($path, $evidence, [Text.UTF8Encoding]::new($false))
        }
    } finally {
        if ($session.Phase -eq 'wsl') { Stop-MailctlWsl $session.Root $session.Sid }
    }
    exit 0
}

if ($env:OS -ne 'Windows_NT' -or [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') {
    throw 'Native packaged acceptance requires x86_64 Windows'
}
if (!$env:MAILCTL_CANDIDATE_DIR -or !$env:MAILCTL_PACKAGED_BIN_DIR) {
    throw 'MAILCTL_CANDIDATE_DIR and MAILCTL_PACKAGED_BIN_DIR are required'
}
$candidate = [System.IO.Path]::GetFullPath($env:MAILCTL_CANDIDATE_DIR)
$manifestPath = Join-Path $candidate 'windows-harnesses.json'
$harnessDirectory = $null
if ($env:MAILCTL_HARNESS_DIR) {
    if (![System.IO.Path]::IsPathFullyQualified($env:MAILCTL_HARNESS_DIR)) {
        throw 'MAILCTL_HARNESS_DIR must be an absolute directory'
    }
    $harnessDirectory = [System.IO.Path]::GetFullPath($env:MAILCTL_HARNESS_DIR)
    $cache = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $repository 'target' }
    foreach ($other in @($candidate, (Join-Path $repository 'target'), $cache)) {
        $other = [System.IO.Path]::GetFullPath($other)
        $separator = [System.IO.Path]::DirectorySeparatorChar
        $left = $harnessDirectory.TrimEnd($separator) + $separator
        $right = $other.TrimEnd($separator) + $separator
        if ($left.StartsWith($right, [StringComparison]::OrdinalIgnoreCase) -or
            $right.StartsWith($left, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'MAILCTL_HARNESS_DIR must be separate from candidate files and Cargo target caches'
        }
    }
}
$phaseTargets = @{
    state = @('administration_process', 'state_maintenance', 'windows_private_state')
    process = @('message_process', 'attachment_process', 'search_process')
    native = @('windows_credentials')
    reading = @('packaged_reading')
    drafts = @('packaged_drafts')
    wsl = @('windows_wsl')
}

if ($Phase -eq 'prepare') {
    if ($harnessDirectory) { New-Item -ItemType Directory -Path $harnessDirectory -Force | Out-Null }
    # Do not retain a previous successful manifest when a rebuild fails.
    if (Test-Path -LiteralPath $manifestPath) { Remove-Item -LiteralPath $manifestPath }
    $selections = @()
    foreach ($features in 'cli', 'mcp', 'cli,mcp') {
        $targets = @($phaseTargets.Values | ForEach-Object { $_ })
        if ($features -match 'cli') { $targets += @('discovery_process', 'draft_process', 'windows_export') }
        if ($features -match 'mcp') { $targets += @('mcp_process', 'read_contention_process') }
        $targets = @($targets | Sort-Object -Unique)
        $arguments = @('test', '--locked', '--workspace', '--no-default-features', '--features', $features,
            '--no-run', '--message-format=json')
        foreach ($target in $targets) { $arguments += @('--test', $target) }
        $artifacts = @(& cargo @arguments | ForEach-Object { $_ | ConvertFrom-Json })
        if ($LASTEXITCODE -ne 0) { throw "Building $features acceptance harnesses failed" }
        $harnesses = @()
        foreach ($target in $targets) {
            $source = [System.IO.Path]::GetFullPath((Join-Path $repository "tests/$target.rs"))
            $artifact = @($artifacts | Where-Object {
                $_.reason -eq 'compiler-artifact' -and $_.executable -and
                $_.target.name -eq $target -and $_.target.src_path -eq $source
            })
            if ($artifact.Count -ne 1) { throw "Expected one workspace-built $features/$target harness" }
            $executable = $artifact[0].executable
            if ($harnessDirectory) {
                $filename = "$($features.Replace(',', '-'))-$target.exe"
                Copy-Item -LiteralPath $executable -Destination (Join-Path $harnessDirectory $filename) -Force
                $executable = $filename
            }
            $harnesses += @{ Name = $target; Executable = $executable }
        }
        $selections += @{ Features = $features; Harnesses = $harnesses }
    }
    $selections | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding utf8
    exit 0
}

$selections = @(Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json)
if ($selections.Count -ne 3) { throw 'All three component selections must have compiled acceptance harnesses' }
$root = Join-Path $env:RUNNER_TEMP "mailctl-windows-$([Guid]::NewGuid().ToString('N'))"
$userName = "mailctl_$([Guid]::NewGuid().ToString('N').Substring(0, 10))"
$passwordBytes = [byte[]]::new(48)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($passwordBytes)
$password = ConvertTo-SecureString ([Convert]::ToBase64String($passwordBytes) + 'Aa1!') -AsPlainText -Force
$user = $null
$child = $null
try {
    $user = New-LocalUser -Name $userName -Password $password -AccountNeverExpires -PasswordNeverExpires
    $sid = $user.SID.Value
    $users = Get-LocalGroup -SID ([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'))
    if (@(Get-LocalGroupMember -Group $users | Where-Object { $_.SID.Value -eq $sid }).Count -eq 0) {
        Add-LocalGroupMember -Group $users -Member $user
    }
    New-Item -ItemType Directory -Path $root | Out-Null
    Invoke-Checked icacls.exe @($root, '/inheritance:r', '/grant:r',
        "*${sid}:(OI)(CI)(F)", '*S-1-5-18:(OI)(CI)(F)', '*S-1-5-32-544:(OI)(CI)(F)')
    $stagedRepository = Join-Path $root 'repository'
    New-Item -ItemType Directory -Path (Join-Path $stagedRepository 'scripts/ci'),
        (Join-Path $stagedRepository 'tests'), (Join-Path $root 'artifacts'), (Join-Path $root 'harnesses') | Out-Null
    Copy-Item -LiteralPath (Join-Path $repository 'install.ps1') -Destination $stagedRepository
    Copy-Item -LiteralPath (Join-Path $repository 'tests/installer.ps1') -Destination (Join-Path $stagedRepository 'tests')
    Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $stagedRepository 'scripts/ci')
    if ($Phase -eq 'wsl') {
        Copy-Item -LiteralPath (Join-Path $repository 'scripts/ci/windows-wsl.ps1') -Destination (Join-Path $stagedRepository 'scripts/ci')
        $rootfs = Join-Path $root 'wsl-rootfs.tar.gz'
        $rootfsUrl = 'https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/alpine-minirootfs-3.22.6-x86_64.tar.gz'
        "rootfs_url=$rootfsUrl" | Set-Content -LiteralPath (Join-Path $root 'windows-wsl.log') -Encoding utf8
        Invoke-WebRequest -Uri $rootfsUrl -OutFile $rootfs -TimeoutSec 180
        if ((Get-FileHash -LiteralPath $rootfs -Algorithm SHA256).Hash.ToLowerInvariant() -ne
            '27694aaa55fd7a9e3ef596e0ad4eb66802308bb20172b17030cd5f4d8ae9bac2') {
            throw 'The Alpine WSL qualification root filesystem checksum differs from the pinned release'
        }
    }
    Get-ChildItem -LiteralPath $candidate -File | Where-Object {
        $_.Name -eq 'install.ps1' -or $_.Name -match '^manifest-.*\.txt$' -or $_.Name -match '^mailctl.*\.exe$'
    } | Copy-Item -Destination (Join-Path $root 'artifacts')
    foreach ($selection in $selections) {
        $targets = @($phaseTargets[$Phase])
        if ($Phase -eq 'process') {
            if ($selection.Features -match 'cli') { $targets += @('discovery_process', 'draft_process', 'windows_export') }
            if ($selection.Features -match 'mcp') { $targets += @('mcp_process', 'read_contention_process') }
        }
        $selected = @($selection.Harnesses | Where-Object { $_.Name -in $targets })
        if ($selected.Count -ne $targets.Count) { throw "Missing $Phase harnesses for $($selection.Features)" }
        foreach ($harness in $selected) {
            $executable = $harness.Executable
            if ($harnessDirectory) {
                if ($executable -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*\.exe$') {
                    throw "Expected a portable harness filename: $executable"
                }
                $executable = Join-Path $harnessDirectory $executable
            }
            $destination = Join-Path $root "harnesses/$([System.IO.Path]::GetFileName($harness.Executable))"
            Copy-Item -LiteralPath $executable -Destination $destination -Force
            $harness.Executable = $destination
        }
        $selection.Harnesses = $selected
    }
    $session = @{ Root = $root; Sid = $sid; User = $userName; Phase = $Phase;
        Artifacts = (Join-Path $root 'artifacts'); Selections = $selections }
    $sessionFile = Join-Path $root 'session.json'
    $session | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $sessionFile -Encoding utf8
    $script = Join-Path $stagedRepository 'scripts/ci/windows-packaged-acceptance.ps1'
    $arguments = @('-NoLogo', '-NoProfile', '-File', "`"$script`"", '-SessionFile', "`"$sessionFile`"")
    $credential = [PSCredential]::new("$env:COMPUTERNAME\$userName", $password)
    $child = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $arguments `
        -Credential $credential -LoadUserProfile -WorkingDirectory $stagedRepository -PassThru `
        -RedirectStandardOutput (Join-Path $root 'session.stdout.log') `
        -RedirectStandardError (Join-Path $root 'session.stderr.log')
    if (!$child.WaitForExit(1200000)) { throw "$Phase acceptance exceeded twenty minutes" }
    $child.Refresh()
    if ($child.ExitCode -ne 0) { throw "$Phase acceptance failed with exit code $($child.ExitCode)" }
} finally {
    if ($child -and !$child.HasExited) {
        & taskkill.exe /PID $child.Id /T /F | Out-Null
    }
    $wslCleanupError = $null
    try {
        if ($Phase -eq 'wsl' -and $user -and (Test-Path -LiteralPath (Join-Path $root 'windows-wsl-owned.json'))) {
            $cleanup = Join-Path $root 'repository/scripts/ci/windows-wsl.ps1'
            $arguments = @('-NoLogo', '-NoProfile', '-File', "`"$cleanup`"", '-Action', 'cleanup',
                '-Root', "`"$root`"", '-Sid', $sid)
            $recovery = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $arguments `
                -Credential ([PSCredential]::new("$env:COMPUTERNAME\$userName", $password)) -LoadUserProfile `
                -WorkingDirectory $stagedRepository -PassThru `
                -RedirectStandardOutput (Join-Path $root 'wsl-cleanup.stdout.log') `
                -RedirectStandardError (Join-Path $root 'wsl-cleanup.stderr.log')
            try {
                if (!$recovery.WaitForExit(240000)) {
                    & taskkill.exe /PID $recovery.Id /T /F | Out-Null
                    throw 'WSL qualification cleanup exceeded four minutes'
                }
                $recovery.Refresh()
                if ($recovery.ExitCode -ne 0) { throw 'Owned WSL qualification cleanup failed' }
            } finally { $recovery.Dispose() }
        }
    } catch { $wslCleanupError = $_ }
    if (Test-Path -LiteralPath $root) {
        Get-ChildItem -LiteralPath $root -Filter '*.log' -File | ForEach-Object {
            $name = if ($_.Name -like 'session.*') { "$Phase-$($_.Name)" } else { $_.Name }
            Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $candidate $name)
            if ($_.Name -like 'session.*') { Get-Content -LiteralPath $_.FullName }
        }
        $evidence = Join-Path $root 'windows-source-evidence.txt'
        if (Test-Path -LiteralPath $evidence) {
            Get-Content -LiteralPath $evidence | Add-Content -LiteralPath (Join-Path $candidate 'windows-source-evidence.txt') -Encoding utf8
        }
        $wslEvidence = Join-Path $root 'windows-wsl-evidence.txt'
        if (Test-Path -LiteralPath $wslEvidence) {
            Copy-Item -LiteralPath $wslEvidence -Destination $candidate
        }
    }
    try {
        if ($user) {
            try {
                Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $user.SID.Value } | Remove-CimInstance
            } finally { Remove-LocalUser -SID $user.SID }
        }
    } finally {
        try {
            if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
        } finally { [Array]::Clear($passwordBytes, 0, $passwordBytes.Length) }
    }
    if ($wslCleanupError) { throw $wslCleanupError }
}
