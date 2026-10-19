[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Artifacts,
    [string] $InstallTo = '',
    [ValidateSet('cli', 'mcp', 'cli,mcp', 'mcp,cli')][string] $Components = 'cli,mcp',
    [switch] $InstallOnly,
    [switch] $Reuse
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$target = 'x86_64-pc-windows-msvc'
$names = @{ cli = 'mailctl.exe'; mcp = 'mailctl-mcp.exe' }
$utf8 = [Text.UTF8Encoding]::new($false)
$engine = (Get-Process -Id $PID).Path
$originalEnvironment = @{}
foreach ($key in @('USERPROFILE', 'HOME', 'APPDATA', 'LOCALAPPDATA', 'CARGO_HOME')) {
    $originalEnvironment[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
}
$root = Join-Path ([IO.Path]::GetTempPath()) ("mailctl-installer-" + [guid]::NewGuid().ToString('N'))
$server = $null

function Assert([bool] $Condition, [string] $Message) {
    if (!$Condition) { throw "installer acceptance: $Message" }
}
function Write-Text([string] $Path, [string] $Text) { [IO.File]::WriteAllText($Path, $Text, $utf8) }
function Hash([string] $Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Fields([string] $Path) {
    $result = @{}
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        $pair = $line -split '=', 2
        Assert ($pair.Length -eq 2 -and !$result.ContainsKey($pair[0])) 'Malformed fixture manifest.'
        $result[$pair[0]] = $pair[1]
    }
    return $result
}
function Write-Manifest($Values) {
    $text = ($Values.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "`n"
    Write-Text $manifestPath ($text + "`n")
}
function Snapshot([string] $Path) {
    if (!(Test-Path -LiteralPath $Path)) { return '' }
    return (@(Get-ChildItem -LiteralPath $Path -File -Recurse -Force | Sort-Object FullName | ForEach-Object {
        "$($_.FullName.Substring($Path.Length))=$(Hash $_.FullName)"
    }) -join "`n")
}
function Quote([string] $Argument) {
    return '"' + [regex]::Replace($Argument, '(\\*)("|$)', {
        param($match)
        $slashes = '\' * (2 * $match.Groups[1].Length)
        if ($match.Groups[2].Value -eq '"') { return $slashes + '\"' }
        return $slashes
    }) + '"'
}
function Start-Installer([string[]] $Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $engine
    $start.Arguments = (@('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $installer) + $Arguments | ForEach-Object { Quote $_ }) -join ' '
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $null = $process.Start()
    return @{ Process = $process; Out = $process.StandardOutput.ReadToEndAsync(); Err = $process.StandardError.ReadToEndAsync() }
}
function Invoke-Installer([string[]] $Arguments, [switch] $Fails) {
    $running = Start-Installer $Arguments
    $process = $running.Process
    try {
        if (!$process.WaitForExit(120000)) { $process.Kill(); $process.WaitForExit(); throw 'Installer timed out.' }
        $stdout = $running.Out.GetAwaiter().GetResult()
        $stderr = $running.Err.GetAwaiter().GetResult()
        if ($Fails) { Assert ($process.ExitCode -ne 0) "Installer unexpectedly succeeded: $stdout" }
        else { Assert ($process.ExitCode -eq 0) "Installer failed ($($Arguments -join ' ')): $stdout $stderr" }
    } finally { $process.Dispose() }
}
function Install([string] $Directory, [string[]] $Extra = @(), [switch] $Fails) {
    $arguments = @('-InstallDir', $Directory)
    if ($Extra -notcontains '-BaseUrl') { $arguments += @('-BaseUrl', $url) }
    Invoke-Installer ($arguments + $Extra) -Fails:$Fails
}
function Verify([string] $Directory, [string] $Selection, $Expected) {
    Assert (!(Test-Path -LiteralPath "$Directory/.mailctl-installer.lock")) 'Installer left a transaction lock.'
    $receipt = Fields "$Directory/.mailctl-components"
    Assert ($receipt.format -eq '1' -and $receipt.target -eq $target -and $receipt.compatibility -eq '1') 'Wrong installed receipt contract.'
    $selected = $Selection -split ',' | Where-Object { $_ }
    $expectedCount = 3
    foreach ($component in @('cli', 'mcp')) {
        $binary = Join-Path $Directory $names[$component]
        if ($selected -contains $component) {
            $expectedCount += 4
            Assert (Test-Path -LiteralPath $binary -PathType Leaf) 'Selected component is missing.'
            Assert ((Hash $binary) -ceq $Expected["${component}_sha256"]) 'Installed bytes differ from candidate.'
            Assert ((Get-Item -LiteralPath $binary).Length -eq [long] $Expected["${component}_size"]) 'Installed size differs from candidate.'
            Assert ($receipt["${component}_version"] -ceq $Expected.version -and $receipt["${component}_commit"] -ceq $Expected.commit -and
                $receipt["${component}_sha256"] -ceq $Expected["${component}_sha256"]) 'Installed receipt differs from candidate.'
        } else {
            Assert (!(Test-Path -LiteralPath $binary) -and !$receipt.ContainsKey("${component}_version")) 'Unexpected component exists.'
        }
    }
    Assert ($receipt.Count -eq $expectedCount) 'Unexpected installed receipt fields.'
}
function Invoke-Json([string] $Binary, [string[]] $Arguments) {
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $Binary @Arguments
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    Assert ($code -eq 0) 'Installed component invocation failed.'
    $reply = ($output -join "`n") | ConvertFrom-Json
    Assert $reply.ok 'Installed component returned an error.'
    return $reply.result
}

try {
    Assert ($env:OS -eq 'Windows_NT') 'Run this suite on native Windows.'
    $Artifacts = [IO.Path]::GetFullPath($Artifacts)
    $installer = Join-Path $Artifacts 'install.ps1'
    Assert (Test-Path -LiteralPath $installer -PathType Leaf) 'Candidate installer is missing.'
    $null = New-Item -ItemType Directory -Path $root
    $downloads = Join-Path $root 'downloads'
    $null = New-Item -ItemType Directory -Path $downloads
    $manifestPath = Join-Path $downloads "manifest-$target.txt"
    Copy-Item -LiteralPath (Join-Path $Artifacts "manifest-$target.txt") -Destination $manifestPath
    $manifest = Fields $manifestPath
    foreach ($component in @('cli', 'mcp')) {
        $file = $manifest["${component}_file"]
        Assert ($file -cmatch '\A[a-z0-9._-]+\z') 'Unsafe candidate file name.'
        Copy-Item -LiteralPath (Join-Path $Artifacts $file) -Destination (Join-Path $downloads $file)
        Assert ((Hash (Join-Path $downloads $file)) -ceq $manifest["${component}_sha256"]) 'Artifact checksum mismatch before installer acceptance.'
    }
    foreach ($key in @('USERPROFILE', 'HOME', 'APPDATA', 'LOCALAPPDATA', 'CARGO_HOME')) {
        $path = Join-Path $root "private $key"
        $null = New-Item -ItemType Directory -Path $path
        [Environment]::SetEnvironmentVariable($key, $path, 'Process')
    }
    $ready = Join-Path $root 'server-url'
    $requests = Join-Path $root 'requests'
    $paused = Join-Path $root 'paused'
    $release = Join-Path $root 'release'
    $server = Start-Job -ArgumentList $downloads, $ready, $requests, $paused, $release -ScriptBlock {
        param($Directory, $Ready, $Requests, $Paused, $Release)
        $ErrorActionPreference = 'Stop'
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $listener.Start()
        [IO.File]::WriteAllText($Ready, "http://127.0.0.1:$($listener.LocalEndpoint.Port)")
        try {
            while ($true) {
                $client = $listener.AcceptTcpClient()
                try {
                    $client.ReceiveTimeout = 10000
                    $stream = $client.GetStream()
                    $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::ASCII, $false, 1024, $true)
                    $request = $reader.ReadLine()
                    do { $header = $reader.ReadLine() } while ($null -ne $header -and $header -ne '')
                    $path = ($request -split ' ')[1]
                    [IO.File]::AppendAllText($Requests, "$path`n")
                    if ($path.StartsWith('/pause/')) {
                        [IO.File]::WriteAllText($Paused, 'ready')
                        $timer = [Diagnostics.Stopwatch]::StartNew()
                        while (!(Test-Path -LiteralPath $Release) -and $timer.Elapsed.TotalSeconds -lt 30) { Start-Sleep -Milliseconds 20 }
                        $path = $path.Substring(6)
                    }
                    if ($path.StartsWith('/redirect/')) {
                        $header = "HTTP/1.1 302 Found`r`nLocation: http://example.invalid/forbidden`r`nContent-Length: 0`r`nConnection: close`r`n`r`n"
                        $body = New-Object byte[] 0
                    } elseif ($path -cmatch '\A/([a-zA-Z0-9._-]+)\z' -and [IO.File]::Exists((Join-Path $Directory $Matches[1]))) {
                        $body = [IO.File]::ReadAllBytes((Join-Path $Directory $Matches[1]))
                        $header = "HTTP/1.1 200 OK`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n"
                    } else {
                        $body = New-Object byte[] 0
                        $header = "HTTP/1.1 404 Not Found`r`nContent-Length: 0`r`nConnection: close`r`n`r`n"
                    }
                    $bytes = [Text.Encoding]::ASCII.GetBytes($header)
                    $stream.Write($bytes, 0, $bytes.Length)
                    $stream.Write($body, 0, $body.Length)
                    $reader.Dispose()
                } catch [IO.IOException] {
                    # An intentionally terminated installer closes its pending download.
                } finally { $client.Dispose() }
            }
        } finally { $listener.Stop() }
    }
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (!(Test-Path -LiteralPath $ready) -and $timer.Elapsed.TotalSeconds -lt 30) {
        Assert ($server.State -ne 'Failed') 'Loopback fixture server failed to start.'
        Start-Sleep -Milliseconds 50
    }
    Assert (Test-Path -LiteralPath $ready) 'Loopback fixture server did not become ready.'
    $url = [IO.File]::ReadAllText($ready)

    if (!$InstallOnly) {
        foreach ($selection in @('cli', 'mcp', 'cli,mcp')) {
            $directory = Join-Path $root "installed $selection"
            Install $directory @('-Components', $selection, '-Version', $manifest.version)
            Verify $directory $selection $manifest
            $first = if ($selection -eq 'mcp') { $names.mcp } else { $names.cli }
            $config = Join-Path $root "configuration $selection/config.toml"
            $setup = Invoke-Json (Join-Path $directory $first) @('--config', $config, '--json', 'setup', '--alias', 'work', '--server', 'imap.example.test', '--username', 'work@example.test')
            $state = Snapshot ([IO.Path]::GetDirectoryName($config))
            $identity = $setup.installation_id
            $installed = Snapshot $directory
            Install $directory @('-Config', $config)
            Verify $directory $selection $manifest
            Assert ((Snapshot $directory) -ceq $installed) 'Repeated installation changed installed bytes or left replacement files.'
            Assert ((Snapshot ([IO.Path]::GetDirectoryName($config))) -ceq $state) 'Update changed application state.'
            $again = Invoke-Json (Join-Path $directory $first) @('--config', $config, '--json', 'setup')
            Assert ($again.installation_id -eq $identity) 'Update changed installation identity.'
            Install $directory @('-Components', 'cli,mcp', '-Config', $config)
            Verify $directory 'cli,mcp' $manifest
            Install $directory @('-Uninstall', '-Components', 'cli')
            Verify $directory 'mcp' $manifest
            Install $directory @('-Uninstall')
            Verify $directory '' $manifest
            Assert ((Snapshot ([IO.Path]::GetDirectoryName($config))) -ceq $state) 'Uninstall changed application state.'
        }
        $default = Join-Path $env:USERPROFILE '.local/bin'
        $cargoBefore = Snapshot $env:CARGO_HOME
        Invoke-Installer @('-BaseUrl', $url)
        Verify $default 'cli,mcp' $manifest
        Assert ((Snapshot $env:CARGO_HOME) -ceq $cargoBefore) 'Installer used CARGO_HOME instead of the standalone destination.'
        Invoke-Installer @('-Uninstall')
        Verify $default '' $manifest
        $cargoHome = $env:CARGO_HOME
        try {
            Remove-Item Env:CARGO_HOME
            $fallback = Join-Path $env:USERPROFILE '.local/bin'
            Invoke-Installer @('-BaseUrl', $url, '-Components', 'cli')
            Verify $fallback 'cli' $manifest
            Invoke-Installer @('-Uninstall')
            Verify $fallback '' $manifest
        } finally { $env:CARGO_HOME = $cargoHome }

        $directory = Join-Path $root 'defect installation'
        Install $directory
        Write-Text (Join-Path $directory 'unrelated-tool.exe') 'unrelated product'
        $before = Snapshot $directory
        foreach ($defect in @('checksum', 'size', 'target', 'format', 'filename', 'signing', 'duplicate')) {
            $bad = $manifest.Clone()
            switch ($defect) {
                checksum { $bad.cli_sha256 = '0' * 64 }
                size { $bad.cli_size = ([long] $bad.cli_size + 1).ToString() }
                target { $bad.target = 'x86_64-unknown-linux-gnu' }
                format { $bad.format = '2' }
                filename { $bad.cli_file = '../foreign.exe' }
                signing { $bad.cli_signing = 'ad-hoc' }
            }
            Write-Manifest $bad
            if ($defect -eq 'duplicate') { [IO.File]::AppendAllText($manifestPath, "format=1`n") }
            Install $directory @() -Fails
            Assert ((Snapshot $directory) -ceq $before) "Rejected $defect changed installed files."
        }
        Write-Manifest $manifest
        $changed = $manifest.Clone()
        $changed.commit = if ($manifest.commit -eq ('b' * 40)) { 'c' * 40 } else { 'b' * 40 }
        Write-Manifest $changed
        Install $directory @('-Components', 'cli') -Fails
        Assert ((Snapshot $directory) -ceq $before) 'A mixed source-commit update changed installed files.'
        Install $directory
        Verify $directory 'cli,mcp' $changed
        Write-Manifest $manifest
        Install $directory
        Assert ((Snapshot $directory) -ceq $before) 'Coherent update did not restore the original receipt.'

        $binary = Join-Path $directory $names.cli
        [IO.File]::AppendAllText($binary, 'modified')
        $tampered = Snapshot $directory
        Install $directory @('-Uninstall') -Fails
        Assert ((Snapshot $directory) -ceq $tampered) 'Uninstall removed a modified binary.'
        Copy-Item -LiteralPath (Join-Path $downloads $manifest.cli_file) -Destination $binary -Force
        $foreign = Join-Path $root 'foreign installation'
        $null = New-Item -ItemType Directory -Path $foreign
        Write-Text (Join-Path $foreign $names.cli) 'owned by another channel'
        $foreignBefore = Snapshot $foreign
        Install $foreign @() -Fails
        Assert ((Snapshot $foreign) -ceq $foreignBefore) 'Installer changed a foreign binary.'

        $receipt = Join-Path $directory '.mailctl-components'
        $receiptText = [IO.File]::ReadAllText($receipt)
        Write-Text $receipt ($receiptText.Replace('format=1', 'format=2'))
        $unknownReceipt = Snapshot $directory
        Install $directory @('-Uninstall') -Fails
        Assert ((Snapshot $directory) -ceq $unknownReceipt) 'Installer changed an unknown receipt schema.'
        Write-Text $receipt $receiptText
        $unknown = Join-Path $root 'unknown interrupted installation'
        $null = New-Item -ItemType Directory -Path (Join-Path $unknown '.mailctl-installer.lock')
        Write-Text (Join-Path $unknown '.mailctl-installer.lock/unrelated') 'unknown owner'
        $unknownBefore = Snapshot $unknown
        Install $unknown @('-Recover') -Fails
        Assert ((Snapshot $unknown) -ceq $unknownBefore) 'Recovery deleted an unknown lock.'

        $junctionTarget = Join-Path $root 'junction target'
        $junction = Join-Path $root 'junction installation'
        $null = New-Item -ItemType Directory -Path $junctionTarget
        $null = New-Item -ItemType Junction -Path $junction -Target $junctionTarget
        try {
            Install $junction @() -Fails
            Assert (@(Get-ChildItem -LiteralPath $junctionTarget -Force).Count -eq 0) 'Installer wrote through a junction.'
        } finally { [IO.Directory]::Delete($junction) }
        foreach ($extra in @(@('-BaseUrl', 'http://example.invalid/releases'), @('-BaseUrl', "$url/redirect"),
            @('-Version', '0.1.0-preview'), @('-Config', (Join-Path $root 'missing-config.toml')))) {
            Install $directory $extra -Fails
            Assert ((Snapshot $directory) -ceq $before) 'Invalid input changed installed files.'
        }

        $null = Invoke-Json (Join-Path $directory $names.cli) @('--json', 'setup', '--alias', 'default', '--server', 'imap.example.test', '--username', 'default@example.test')
        $defaultConfig = Join-Path $env:APPDATA 'ueberBrot/mailctl/config/config.toml'
        Assert (Test-Path -LiteralPath $defaultConfig) 'Installer and application default configuration paths differ.'
        Install $directory
        $originalConfig = [IO.File]::ReadAllText($defaultConfig)
        Write-Text $defaultConfig ("unknown_setting = true`n" + $originalConfig)
        Install $directory @() -Fails
        Assert ((Snapshot $directory) -ceq $before) 'Invalid default configuration did not prevent replacement.'
        Write-Text $defaultConfig $originalConfig

        $config = Join-Path $root 'invalid configuration/config.toml'
        $null = New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($config))
        Write-Text $config 'unknown_setting = true'
        Install $directory @('-Config', $config) -Fails
        Assert ((Snapshot $directory) -ceq $before) 'Invalid state preflight changed installed files.'
        Assert ([IO.File]::ReadAllText($config) -ceq 'unknown_setting = true') 'State preflight rewrote the configuration.'

        $locked = [IO.File]::Open((Join-Path $directory $names.mcp), [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            Install $directory @('-Uninstall') -Fails
            Assert ((Snapshot $directory) -ceq $before) 'Failed partial removal did not roll back.'
        } finally { $locked.Dispose() }

        $running = Start-Installer @('-InstallDir', $directory, '-BaseUrl', "$url/pause")
        try {
            $timer.Restart()
            while (!(Test-Path -LiteralPath $paused) -and $timer.Elapsed.TotalSeconds -lt 15) {
                Assert (!$running.Process.HasExited) 'Installer exited before its paused download.'
                Start-Sleep -Milliseconds 20
            }
            Assert (Test-Path -LiteralPath $paused) 'Installer did not reach a paused download.'
            Install $directory @('-Recover') -Fails
            Install $directory @() -Fails
            $running.Process.Kill()
            $running.Process.WaitForExit()
        } finally {
            if (!$running.Process.HasExited) { $running.Process.Kill(); $running.Process.WaitForExit() }
            $running.Process.Dispose()
            Write-Text $release 'continue'
        }
        Install $directory @() -Fails
        Install $directory @('-Recover')
        Assert ((Snapshot $directory) -ceq $before) 'Interrupted-download recovery changed installed files.'
        Install $directory
        Verify $directory 'cli,mcp' $manifest
        Write-Output 'Windows installer lifecycle, refusals, rollback, and recovery passed.'
    }

    if ($InstallTo) {
        $InstallTo = [IO.Path]::GetFullPath($InstallTo)
        if ($Reuse -and (Test-Path -LiteralPath $InstallTo)) { Verify $InstallTo $Components $manifest }
        else {
            if (Test-Path -LiteralPath $InstallTo) {
                Assert (@(Get-ChildItem -LiteralPath $InstallTo -Force).Count -eq 0) '-InstallTo must be missing or empty.'
            }
            Install $InstallTo @('-Components', $Components)
            Verify $InstallTo $Components $manifest
        }
        Write-Output "Verified installed candidate components $Components in $InstallTo"
    }
    Write-Output 'OK'
} finally {
    if ($null -ne $server) { Stop-Job $server; Remove-Job $server -Force }
    foreach ($key in $originalEnvironment.Keys) { [Environment]::SetEnvironmentVariable($key, $originalEnvironment[$key], 'Process') }
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
