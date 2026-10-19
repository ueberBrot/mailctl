param (
    [ValidateSet('cleanup')]
    [string]$Action,
    [string]$Root,
    [string]$Sid
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-MailctlWslContext {
    param ([string]$Root, [string]$Sid)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($env:OS -ne 'Windows_NT' -or $identity.User.Value -ne $Sid -or
        $identity.Name.Split('\')[-1] -notmatch '^mailctl_[0-9a-f]{10}$') {
        throw 'WSL qualification requires its disposable Windows identity'
    }
    if (![IO.Path]::IsPathFullyQualified($Root) -or
        [IO.Path]::GetFileName($Root) -notmatch '^mailctl-windows-[0-9a-f]{32}$' -or
        !(Test-Path -LiteralPath $Root -PathType Container) -or
        ((Get-Item -LiteralPath $Root).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'WSL qualification requires its owned private staging directory'
    }
}

function Invoke-MailctlWsl {
    param ([string]$Root, [string[]]$Arguments)
    $log = Join-Path $Root 'windows-wsl.log'
    $encoding = [Text.UTF8Encoding]::new($false)
    [IO.File]::AppendAllText($log, 'wsl_arguments=' + (ConvertTo-Json -InputObject $Arguments -Compress) + "`n", $encoding)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $env:SystemRoot 'System32/wsl.exe'
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (!$process.WaitForExit(180000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw 'WSL qualification command exceeded three minutes'
        }
        # Management commands sometimes emit UTF-16 without a BOM, while Linux
        # command output is UTF-8. The asserted fields and arguments are ASCII.
        $output = $stdout.GetAwaiter().GetResult().Replace([string][char]0, '').Trim()
        $errors = $stderr.GetAwaiter().GetResult().Replace([string][char]0, '').Trim()
        [IO.File]::AppendAllText($log, "exit=$($process.ExitCode)`n$output`n$errors`n", $encoding)
        if ($process.ExitCode -ne 0) { throw "WSL qualification command failed with exit code $($process.ExitCode); see windows-wsl.log" }
        return $output
    } finally { $process.Dispose() }
}

function Start-MailctlWsl {
    param ([string]$Root, [string]$Sid)
    Assert-MailctlWslContext $Root $Sid
    $registry = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
    if (Test-Path -LiteralPath $registry) {
        $existing = @(Get-ChildItem -LiteralPath $registry | Where-Object { $_.GetValue('DistributionName') })
        if ($existing.Count -ne 0) { throw 'WSL qualification requires an empty disposable distribution inventory' }
    }
    $rootfs = Join-Path $Root 'wsl-rootfs.tar.gz'
    $expected = '27694aaa55fd7a9e3ef596e0ad4eb66802308bb20172b17030cd5f4d8ae9bac2'
    if ((Get-FileHash -LiteralPath $rootfs -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
        throw 'The staged Alpine root filesystem checksum differs from its pinned release'
    }
    $version = Invoke-MailctlWsl $Root @('--version')
    if ($version -notmatch '(?m)^WSL version:\s*([0-9]+(?:\.[0-9]+){2,3})\s*$') {
        throw 'Missing observed WSL application version'
    }
    $wslVersion = $Matches[1]
    $null = Invoke-MailctlWsl $Root @('--status')
    $name = 'mailctl-wsl-' + [Guid]::NewGuid().ToString('N')
    $marker = Join-Path $Root 'windows-wsl-owned.json'
    if (Test-Path -LiteralPath $marker) { throw 'Refusing to replace a WSL qualification ownership marker' }
    @{ Root = $Root; Sid = $Sid; Distro = $name } | ConvertTo-Json |
        Set-Content -LiteralPath $marker -Encoding utf8
    $null = Invoke-MailctlWsl $Root @('--import', $name, (Join-Path $Root 'wsl-distro'), $rootfs, '--version', '2')
    $registration = @(Get-ChildItem -LiteralPath $registry | Where-Object { $_.GetValue('DistributionName') -eq $name })
    if ($registration.Count -ne 1 -or $registration[0].GetValue('Version') -ne 2) {
        throw 'The disposable distribution must be registered as WSL 2'
    }
    $listing = Invoke-MailctlWsl $Root @('--list', '--verbose')
    if ($listing -notmatch ('(?m)^[ \t]*\*?[ \t]*' + [regex]::Escape($name) + '[ \t]+\S+[ \t]+2[ \t\r]*$')) {
        throw 'WSL did not list the owned distribution as version 2'
    }
    $kernel = Invoke-MailctlWsl $Root @('--distribution', $name, '--exec', '/bin/uname', '-r')
    if ($kernel -notmatch '(?i)WSL2' -or $kernel -match '[\r\n]') {
        throw 'The disposable distribution did not boot a WSL 2 Linux kernel'
    }
    $release = Invoke-MailctlWsl $Root @('--distribution', $name, '--exec', '/bin/cat', '/etc/alpine-release')
    if ($release -ne '3.22.6') { throw 'The running Alpine version differs from the pinned root filesystem' }
    $whoami = '/mnt/' + $env:SystemRoot.Substring(0, 1).ToLowerInvariant() +
        $env:SystemRoot.Substring(2).Replace('\', '/') + '/System32/whoami.exe'
    $windowsUser = @(Invoke-MailctlWsl $Root @('--distribution', $name, '--exec', $whoami, '/user', '/fo', 'csv', '/nh') |
        ConvertFrom-Csv -Header Name, Sid)
    if ($windowsUser.Count -ne 1 -or $windowsUser[0].Sid -ne $Sid) {
        throw 'Windows interoperability did not preserve the disposable Windows SID'
    }
    $values = @('status=prepared', "distro=$name", "rootfs_sha256=$expected", "kernel=$kernel",
        "wsl_version=$wslVersion", "linux_release=$release", "windows_identity_sid=$Sid")
    [IO.File]::WriteAllText((Join-Path $Root 'windows-wsl-evidence.txt'), ($values -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
    $env:MAILCTL_WSL_DISTRO = $name
}

function Stop-MailctlWsl {
    param ([string]$Root, [string]$Sid)
    Assert-MailctlWslContext $Root $Sid
    $marker = Join-Path $Root 'windows-wsl-owned.json'
    if (!(Test-Path -LiteralPath $marker)) { return }
    if ((Get-Item -LiteralPath $marker).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Refusing a reparse-point WSL qualification marker'
    }
    $owned = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
    if ($owned.Root -ne $Root -or $owned.Sid -ne $Sid -or $owned.Distro -notmatch '^mailctl-wsl-[0-9a-f]{32}$') {
        throw 'The WSL qualification ownership marker is invalid'
    }
    $registry = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
    if (Test-Path -LiteralPath $registry) {
        $registration = @(Get-ChildItem -LiteralPath $registry | Where-Object { $_.GetValue('DistributionName') -eq $owned.Distro })
        if ($registration.Count -gt 1) { throw 'The owned WSL registration is ambiguous' }
        if ($registration.Count -ne 0) {
            $null = Invoke-MailctlWsl $Root @('--unregister', $owned.Distro)
            $remaining = @(Get-ChildItem -LiteralPath $registry | Where-Object { $_.GetValue('DistributionName') -eq $owned.Distro })
            if ($remaining.Count -ne 0) { throw 'The owned WSL registration was not removed' }
        }
    }
    Remove-Item -LiteralPath $marker
    Remove-Item Env:MAILCTL_WSL_DISTRO -ErrorAction SilentlyContinue
}

if ($Action -eq 'cleanup') { Stop-MailctlWsl $Root $Sid }
