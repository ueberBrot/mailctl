# Standalone installation owns only product binaries and .mailctl-components.
[CmdletBinding()]
param(
    [string] $Version = '',
    [ValidateSet('cli', 'mcp', 'cli,mcp', 'mcp,cli')]
    [string] $Components = '',
    [string] $InstallDir = '',
    [string] $BaseUrl = '',
    [string] $Config = '',
    [switch] $Uninstall,
    [switch] $Recover,
    [Alias('h')][switch] $Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$target = 'x86_64-pc-windows-msvc'
$encoding = [Text.UTF8Encoding]::new($false, $true)
$names = @{ cli = 'mailctl.exe'; mcp = 'mailctl-mcp.exe' }

function Fail([string] $Message) { throw "mailctl installer: $Message" }
function Write-Text([string] $Path, [string] $Text) {
    [IO.File]::WriteAllText($Path, $Text, $encoding)
}
function Test-StableVersion([string] $Value) {
    return $Value -cmatch '\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z'
}
function Assert-Path([string] $Path) {
    if ($Path -notmatch '\A[A-Za-z]:[\\/]' -or $Path.IndexOfAny([IO.Path]::GetInvalidPathChars()) -ge 0) {
        Fail 'Use an absolute local Windows path.'
    }
    $full = [IO.Path]::GetFullPath($Path)
    for ($current = $full; $current; $current = [IO.Path]::GetDirectoryName($current)) {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
        if ($null -ne $item) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Fail 'Installation paths must not contain reparse points.'
            }
        }
    }
    foreach ($part in $full.Substring([IO.Path]::GetPathRoot($full).Length) -split '[\\/]') {
        if ($part -and ($part.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0 -or $part -match '[. ]$')) {
            Fail 'Installation paths contain an unsupported Windows file name.'
        }
    }
    if ($full -eq [IO.Path]::GetPathRoot($full)) { return $full }
    return $full.TrimEnd('\')
}
function Assert-Regular([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail 'Expected a regular installer-owned file.'
    }
}
function Get-Hash([string] $Path) {
    Assert-Regular $Path
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Read-Fields([string] $Path, [int] $Limit) {
    Assert-Regular $Path
    if ((Get-Item -LiteralPath $Path).Length -gt $Limit) { Fail 'Manifest is too large.' }
    $fields = @{}
    $lines = [IO.File]::ReadAllText($Path, $encoding) -split '\r?\n'
    if ($lines[-1] -eq '') { $lines = $lines[0..($lines.Length - 2)] }
    foreach ($line in $lines) {
        if ($line -cnotmatch '\A([a-z_0-9]+)=([^=\r\n]+)\z' -or $fields.ContainsKey($Matches[1])) {
            Fail 'Unsupported or malformed manifest.'
        }
        $fields.Add($Matches[1], $Matches[2])
    }
    return $fields
}
function Assert-Common($Fields) {
    if (!$Fields.ContainsKey('format') -or !$Fields.ContainsKey('compatibility') -or !$Fields.ContainsKey('target') -or
        $Fields.format -cne '1' -or $Fields.compatibility -cne '1' -or $Fields.target -cne $target) {
        Fail 'Unsupported manifest format, compatibility, or target.'
    }
}
function Read-Receipt([string] $Path) {
    $fields = Read-Fields $Path 4096
    Assert-Common $fields
    $known = @('format', 'target', 'compatibility')
    foreach ($component in @('cli', 'mcp')) {
        $keys = @('version', 'commit', 'sha256', 'origin') | ForEach-Object { "${component}_$_" }
        $count = @($keys | Where-Object { $fields.ContainsKey($_) }).Count
        if ($count -ne 0 -and $count -ne 4) { Fail 'Incomplete component manifest.' }
        if ($count -eq 4) {
            if (!(Test-StableVersion $fields["${component}_version"]) -or
                $fields["${component}_commit"] -cnotmatch '\A[0-9a-f]{40}\z' -or
                $fields["${component}_sha256"] -cnotmatch '\A[0-9a-f]{64}\z') {
                Fail 'Unsupported or malformed component manifest.'
            }
            $null = Get-DownloadUri $fields["${component}_origin"]
            $known += $keys
        }
    }
    if ($fields.Count -ne $known.Count) { Fail 'Unknown component manifest fields.' }
    return $fields
}
function Write-Receipt([string] $Path, $Fields) {
    $text = "format=1`ntarget=$target`ncompatibility=1`n"
    foreach ($component in @('cli', 'mcp')) {
        foreach ($field in @('version', 'commit', 'sha256', 'origin')) {
            $key = "${component}_$field"
            if ($Fields.ContainsKey($key)) { $text += "$key=$($Fields[$key])`n" }
        }
    }
    Write-Text $Path $text
}
function Get-DownloadUri([string] $Value, [switch] $Redirect) {
    $uri = $null
    if ($Value -cmatch '[\s@]' -or ![Uri]::TryCreate($Value, [UriKind]::Absolute, [ref] $uri) -or
        $uri.UserInfo -or (!$Redirect -and $uri.Query) -or $uri.Fragment) { Fail 'Invalid download URL.' }
    if ($uri.Scheme -eq 'https') { return $uri }
    if (!$Redirect -and $uri.Scheme -eq 'http' -and $uri.Host -eq '127.0.0.1' -and
        $Value -match '\Ahttp://127\.0\.0\.1:[0-9]+(?:/|$)') { return $uri }
    Fail 'Downloads require HTTPS (or HTTP on 127.0.0.1 for local tests); redirects require HTTPS.'
}
function Get-Download([string] $Url, [string] $Destination, [long] $Limit) {
    $uri = Get-DownloadUri $Url
    $timer = [Diagnostics.Stopwatch]::StartNew()
    for ($redirects = 0; $redirects -le 5; $redirects++) {
        $request = [Net.HttpWebRequest]::Create($uri)
        $request.AllowAutoRedirect = $false
        $request.Timeout = 10000
        $request.ReadWriteTimeout = 180000
        $request.Proxy = $null
        $response = $request.GetResponse()
        try {
            $status = [int] $response.StatusCode
            if ($status -ge 300 -and $status -le 399) {
                if ($redirects -eq 5 -or !$response.Headers['Location']) { Fail 'Download redirect limit exceeded.' }
                $uri = Get-DownloadUri ([Uri]::new($uri, $response.Headers['Location']).AbsoluteUri) -Redirect
                continue
            }
            if ($status -ne 200 -or $response.ContentLength -gt $Limit) { Fail 'Download failed or exceeded its size limit.' }
            $inputStream = $response.GetResponseStream()
            $outputStream = [IO.File]::Create($Destination)
            try {
                $buffer = New-Object byte[] 65536
                $total = 0L
                while (($count = $inputStream.Read($buffer, 0, $buffer.Length)) -ne 0) {
                    $total += $count
                    if ($total -gt $Limit -or $timer.Elapsed.TotalSeconds -gt 180) { Fail 'Download exceeded its size or time limit.' }
                    $outputStream.Write($buffer, 0, $count)
                }
            } finally {
                $outputStream.Dispose()
                $inputStream.Dispose()
            }
            return
        } finally { $response.Dispose() }
    }
}
function Read-FieldsAfterDownload {
    $path = "$lock/download/manifest"
    Get-Download "$BaseUrl/manifest-$target.txt" $path 16384
    $fields = Read-Fields $path 16384
    Assert-Common $fields
    if ($fields.Count -ne 13 -or !$fields.ContainsKey('version') -or !(Test-StableVersion $fields.version) -or
        !$fields.ContainsKey('commit') -or $fields.commit -cnotmatch '\A[0-9a-f]{40}\z') {
        Fail 'Unsupported or malformed candidate manifest.'
    }
    foreach ($component in @('cli', 'mcp')) {
        foreach ($field in @('file', 'sha256', 'size', 'signing')) {
            if (!$fields.ContainsKey("${component}_$field")) { Fail 'Incomplete candidate manifest.' }
        }
        if ($fields["${component}_file"] -cnotmatch '\A[a-z0-9._-]+\z' -or
            $fields["${component}_sha256"] -cnotmatch '\A[0-9a-f]{64}\z' -or
            $fields["${component}_size"] -cnotmatch '\A[1-9][0-9]{0,8}\z' -or
            [long] $fields["${component}_size"] -gt 104857600 -or
            $fields["${component}_signing"] -cne 'unsigned') {
            Fail 'Unsupported or malformed candidate manifest.'
        }
    }
    return $fields
}
function Invoke-Component([string] $Path, [string[]] $Arguments) {
    $quoted = foreach ($argument in $Arguments) {
        '"' + [regex]::Replace($argument, '(\\*)("|$)', {
            param($match)
            $slashes = '\' * (2 * $match.Groups[1].Length)
            if ($match.Groups[2].Value -eq '"') { return $slashes + '\"' }
            return $slashes
        }) + '"'
    }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Path
    $start.Arguments = $quoted -join ' '
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
        if (!$process.WaitForExit(30000)) {
            $process.Kill()
            $process.WaitForExit()
            Fail 'Component verification timed out; stop running mailctl/MCP processes.'
        }
        $result = @{ Code = $process.ExitCode; Output = $stdout.GetAwaiter().GetResult().TrimEnd("`r", "`n") }
        $null = $stderr.GetAwaiter().GetResult()
        return $result
    } finally { $process.Dispose() }
}
function Move-Replacement([string] $Source, [string] $Destination) {
    if (Test-Path -LiteralPath $Destination) { [IO.File]::Replace($Source, $Destination, $null) }
    else { [IO.File]::Move($Source, $Destination) }
}
function Assert-LockTree {
    $null = Assert-Path $lock
    $files = @('pid', 'started', 'before', 'after', 'had-receipt', 'ready', 'committed',
        'new-receipt', 'restore-receipt', 'restore-mailctl.exe', 'restore-mailctl-mcp.exe')
    foreach ($entry in Get-ChildItem -LiteralPath $lock -Force) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail 'Installer lock contains a reparse point; preserve it for inspection.'
        }
        if ($entry.PSIsContainer) {
            if ($entry.Name -notin @('backup', 'download')) { Fail 'Unrecognized installer lock directory.' }
            $allowed = @('mailctl.exe', 'mailctl-mcp.exe')
            if ($entry.Name -eq 'download') { $allowed += 'manifest' }
            foreach ($child in Get-ChildItem -LiteralPath $entry.FullName -Force) {
                if ($child.PSIsContainer -or $child.Name -notin $allowed -or
                    ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    Fail 'Unrecognized installer transaction contents; preserve them for inspection.'
                }
            }
        } elseif ($entry.Name -notin $files) { Fail 'Unrecognized installer lock file.' }
    }
}
function Undo-Transaction {
    if (!(Test-Path -LiteralPath "$lock/ready")) { return }
    $before = Read-Receipt "$lock/before"
    $after = Read-Receipt "$lock/after"
    if (Test-Path -LiteralPath $receipt) {
        $receiptHash = Get-Hash $receipt
        if ($receiptHash -cne (Get-Hash "$lock/after") -and
            (!(Test-Path -LiteralPath "$lock/had-receipt") -or $receiptHash -cne (Get-Hash "$lock/before"))) {
            Fail 'Component manifest ownership changed during rollback; preserve the installer lock.'
        }
    }
    foreach ($component in @('cli', 'mcp')) {
        $binary = Join-Path $InstallDir $names[$component]
        $old = $before["${component}_sha256"]
        $new = $after["${component}_sha256"]
        if (Test-Path -LiteralPath $binary) {
            $current = Get-Hash $binary
            if ($current -cne $old -and $current -cne $new) { Fail 'Ownership changed during rollback; preserve the installer lock.' }
        }
        if ($old -and (Get-Hash "$lock/backup/$($names[$component])") -cne $old) { Fail 'Installer backup is damaged; preserve it for inspection.' }
    }
    foreach ($component in @('cli', 'mcp')) {
        $binary = Join-Path $InstallDir $names[$component]
        if ($before["${component}_sha256"]) {
            if ((Test-Path -LiteralPath $binary) -and (Get-Hash $binary) -ceq $before["${component}_sha256"]) { continue }
            $restore = "$lock/restore-$($names[$component])"
            [IO.File]::Copy("$lock/backup/$($names[$component])", $restore, $true)
            Move-Replacement $restore $binary
        } elseif (Test-Path -LiteralPath $binary) { [IO.File]::Delete($binary) }
    }
    if (Test-Path -LiteralPath "$lock/had-receipt") {
        if (!(Test-Path -LiteralPath $receipt) -or (Get-Hash $receipt) -cne (Get-Hash "$lock/before")) {
            [IO.File]::Copy("$lock/before", "$lock/restore-receipt", $true)
            Move-Replacement "$lock/restore-receipt" $receipt
        }
    } elseif (Test-Path -LiteralPath $receipt) { [IO.File]::Delete($receipt) }
}

try {
    if ($Help) {
        @'
Usage: powershell -File install.ps1 [options]
  -Version VERSION       Stable release (default: latest stable).
  -Components SELECTION  cli, mcp, or cli,mcp (default: installed selection,
                         or cli,mcp for a new installation).
  -InstallDir DIRECTORY  Override USERPROFILE\.local\bin.
  -BaseUrl URL           Candidate directory; HTTPS or loopback HTTP.
  -Config FILE           Verify an existing installation before replacement.
  -Uninstall             Remove selected installer-owned components.
  -Recover               Roll back an interrupted installer after it exits.
  -Help                  Show this help.

Rust is not required. Configuration, credentials, and draft history are preserved.
Stop mailctl/MCP runtimes before updating a configured installation.
'@ | Write-Output
        exit 0
    }
    if ($env:OS -ne 'Windows_NT' -or ![Environment]::Is64BitProcess -or
        $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { Fail 'This installer requires native Windows x86_64 PowerShell.' }
    if ($Uninstall -and $Recover) { Fail 'Choose one installer action.' }
    if ($Version) {
        $Version = $Version -creplace '\Av', ''
        if (!(Test-StableVersion $Version)) { Fail 'Specify -Version with a stable release version.' }
    }
    $githubRelease = !$BaseUrl
    if (!$Uninstall -and !$Recover) {
        if (!$BaseUrl) {
            $BaseUrl = 'https://github.com/ueberBrot/mailctl/releases/latest/download'
            if ($Version) { $BaseUrl = "https://github.com/ueberBrot/mailctl/releases/download/v$Version" }
        }
        $BaseUrl = $BaseUrl.TrimEnd('/')
        $null = Get-DownloadUri $BaseUrl
    }
    if (!$InstallDir) {
        if ($env:USERPROFILE) { $InstallDir = Join-Path $env:USERPROFILE '.local/bin' }
        else { Fail 'Set USERPROFILE or -InstallDir.' }
    }
    $InstallDir = Assert-Path $InstallDir
    if (!(Test-Path -LiteralPath $InstallDir)) {
        if ($Uninstall -or $Recover) { Fail 'Installation directory does not exist.' }
        $null = New-Item -ItemType Directory -Path $InstallDir -Force
    }
    if (!(Get-Item -LiteralPath $InstallDir).PSIsContainer) { Fail 'Installation directory is not a directory.' }
    $receipt = Join-Path $InstallDir '.mailctl-components'
    $lock = Join-Path $InstallDir '.mailctl-installer.lock'
    if ($Recover) {
        if (!(Test-Path -LiteralPath $lock -PathType Container)) { Fail 'No recognized interrupted installer to recover.' }
        $null = Assert-Path $lock
        Assert-LockTree
        $owner = [IO.File]::ReadAllText("$lock/pid", $encoding).Trim()
        $started = [IO.File]::ReadAllText("$lock/started", $encoding).Trim()
        if ($owner -cnotmatch '\A[1-9][0-9]*\z' -or $started -cnotmatch '\A[0-9]+\z') { Fail 'Invalid installer owner; preserve the lock for inspection.' }
        $running = Get-Process -Id ([int] $owner) -ErrorAction SilentlyContinue
        if ($running -and $running.StartTime.ToUniversalTime().Ticks -eq [long] $started) { Fail 'The installer owner is still running; do not remove its lock.' }
        $recoveryLock = Join-Path $InstallDir '.mailctl-installer.recovery'
        $null = New-Item -ItemType Directory -Path $recoveryLock
        try {
            if (!(Test-Path -LiteralPath "$lock/committed")) { Undo-Transaction }
            Remove-Item -LiteralPath $lock -Recurse -Force
        } finally { Remove-Item -LiteralPath $recoveryLock -Force }
        Write-Output "Recovered interrupted installation in $InstallDir. Application state is preserved."
        exit 0
    }
    $acquired = $false
    $preserveLock = $false
    try {
        $null = Assert-Path $lock
        $null = New-Item -ItemType Directory -Path $lock
        $acquired = $true
        Write-Text "$lock/pid" "$PID`n"
        Write-Text "$lock/started" "$((Get-Process -Id $PID).StartTime.ToUniversalTime().Ticks)`n"
        $null = New-Item -ItemType Directory -Path "$lock/backup", "$lock/download"
        if (Test-Path -LiteralPath $receipt) {
            $before = Read-Receipt $receipt
            [IO.File]::Copy($receipt, "$lock/before")
            Write-Text "$lock/had-receipt" ''
        } else {
            $before = @{ format = '1'; target = $target; compatibility = '1' }
            Write-Receipt "$lock/before" $before
        }
        foreach ($component in @('cli', 'mcp')) {
            $binary = Join-Path $InstallDir $names[$component]
            $owned = $before["${component}_sha256"]
            if (Test-Path -LiteralPath $binary) {
                if (!$owned -or (Get-Hash $binary) -cne $owned) { Fail "Foreign or modified $($names[$component]); use its owning installation channel or move it aside explicitly." }
                [IO.File]::Copy($binary, "$lock/backup/$($names[$component])")
            } elseif ($owned) { Fail 'Owned component is missing; preserve the component manifest for inspection.' }
        }
        $selected = @()
        if ($Components) { $selected = $Components -split ',' }
        else {
            $selected = @('cli', 'mcp') | Where-Object { $before.ContainsKey("${_}_version") }
            if (!$selected -and !$Uninstall) { $selected = @('cli', 'mcp') }
        }
        $after = @{ format = '1'; target = $target; compatibility = '1' }
        if (!$Uninstall) {
            $explicitConfig = !!$Config
            if (!$Config -and $env:APPDATA) { $Config = Join-Path $env:APPDATA 'ueberBrot/mailctl/config/config.toml' }
            if ($explicitConfig -or ($Config -and (Test-Path -LiteralPath $Config))) {
                $Config = Assert-Path $Config
                Assert-Regular $Config
            }
            $manifest = Read-FieldsAfterDownload
            $resolvedVersion = $manifest.version
            if ($Version -and $Version -cne $resolvedVersion) { Fail 'Candidate version does not match the request.' }
            $Version = $resolvedVersion
            if ($githubRelease) { $BaseUrl = "https://github.com/ueberBrot/mailctl/releases/download/v$Version" }
            foreach ($component in @('cli', 'mcp')) {
                $stem = [IO.Path]::GetFileNameWithoutExtension($names[$component])
                if ($manifest["${component}_file"] -cne "$stem-v$Version-$target.exe") { Fail 'Unexpected candidate filename.' }
                if ($selected -notcontains $component -and $before["${component}_version"] -and
                    ($before["${component}_version"] -cne $Version -or $before["${component}_commit"] -cne $manifest.commit)) {
                    Fail 'Component versions or source commits differ; update both components together.'
                }
                if ($selected -contains $component) {
                    $staged = "$lock/download/$($names[$component])"
                    Get-Download "$BaseUrl/$($manifest["${component}_file"])" $staged ([long] $manifest["${component}_size"])
                    if ((Get-Item -LiteralPath $staged).Length -ne [long] $manifest["${component}_size"] -or
                        (Get-Hash $staged) -cne $manifest["${component}_sha256"]) { Fail 'Candidate checksum or size verification failed.' }
                    $reported = Invoke-Component $staged @('--version')
                    if ($reported.Code -ne 0 -or $reported.Output -cne "$stem $Version") { Fail 'Candidate reports a different version.' }
                    $after["${component}_version"] = $Version
                    $after["${component}_commit"] = $manifest.commit
                    $after["${component}_sha256"] = $manifest["${component}_sha256"]
                    $after["${component}_origin"] = $BaseUrl
                } elseif ($before["${component}_version"]) {
                    foreach ($field in @('version', 'commit', 'sha256', 'origin')) { $after["${component}_$field"] = $before["${component}_$field"] }
                }
            }
            if ($explicitConfig -or ($Config -and (Test-Path -LiteralPath $Config))) {
                $Config = Assert-Path $Config
                Assert-Regular $Config
                foreach ($component in $selected) {
                    $verified = Invoke-Component "$lock/download/$($names[$component])" @('--config', $Config, '--json', 'state', 'verify')
                    if ($verified.Code -ne 0) { Fail 'Installation history is incompatible, unavailable, or busy. Stop runtimes and run state verify with a compatible component; installed files are preserved.' }
                }
            }
        } else {
            if (!(Test-Path -LiteralPath "$lock/had-receipt")) { Fail 'No installer-owned components to remove.' }
            foreach ($component in @('cli', 'mcp')) {
                if ($selected -notcontains $component -and $before["${component}_version"]) {
                    foreach ($field in @('version', 'commit', 'sha256', 'origin')) { $after["${component}_$field"] = $before["${component}_$field"] }
                }
            }
        }
        Write-Receipt "$lock/after" $after
        $null = Read-Receipt "$lock/after"
        Write-Text "$lock/ready" ''
        foreach ($component in $selected) {
            $binary = Join-Path $InstallDir $names[$component]
            $previous = $before["${component}_sha256"]
            if (Test-Path -LiteralPath $binary) {
                if (!$previous -or (Get-Hash $binary) -cne $previous) { Fail 'Component ownership changed during installation.' }
            } elseif ($previous) { Fail 'Owned component disappeared during installation.' }
            if (!$Uninstall) { Move-Replacement "$lock/download/$($names[$component])" $binary }
            elseif ($previous) { [IO.File]::Delete($binary) }
        }
        [IO.File]::Copy("$lock/after", "$lock/new-receipt")
        Move-Replacement "$lock/new-receipt" $receipt
        Write-Text "$lock/committed" ''
        $action = if ($Uninstall) { 'Uninstall' } else { 'Install' }
        Write-Output "$action completed in $InstallDir. Configuration, credentials, and draft history are preserved."
        if (!$Uninstall) {
            Write-Output "  Version: $Version"
            foreach ($component in $selected) { Write-Output "  $(Join-Path $InstallDir $names[$component])" }
            if (($env:PATH -split ';') -notcontains $InstallDir) { Write-Output "Add this directory to PATH: $InstallDir" }
        }
    } catch {
        if ($acquired -and !(Test-Path -LiteralPath "$lock/committed")) {
            try { Assert-LockTree; Undo-Transaction }
            catch { $preserveLock = $true; Write-Error "Rollback failed; preserve $lock and use -Recover after the installer exits." -ErrorAction Continue }
        }
        throw
    } finally {
        if ($acquired -and !$preserveLock) { $null = Assert-Path $lock; Assert-LockTree; Remove-Item -LiteralPath $lock -Recurse -Force }
    }
} catch {
    Write-Error $_ -ErrorAction Continue
    exit 1
}
