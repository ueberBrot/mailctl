$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

foreach ($name in 'RUNNER_TEMP', 'DIST_BIN_DIR', 'GITHUB_PATH') {
    if (-not [Environment]::GetEnvironmentVariable($name)) { throw "$name is required" }
}
if (-not $IsWindows -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') {
    throw 'The native dist candidate requires Windows x86_64'
}

$temporary = Join-Path $env:RUNNER_TEMP ('mailctl-dist-' + [Guid]::NewGuid().ToString('N'))
$archive = Join-Path $temporary 'dist.zip'
$expected = '9a36d70795e14326a5ec4bf17aee085df00ab85a322739291ea5d4b1b5f693cd'
New-Item -ItemType Directory -Path $temporary | Out-Null
try {
    Invoke-WebRequest -Uri 'https://github.com/axodotdev/cargo-dist/releases/download/v0.33.0/cargo-dist-x86_64-pc-windows-msvc.zip' -OutFile $archive
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
        throw 'The cargo-dist Windows release checksum differs from the pinned release'
    }
    Expand-Archive -LiteralPath $archive -DestinationPath (Join-Path $temporary 'unpacked')
    $executables = @(Get-ChildItem -LiteralPath (Join-Path $temporary 'unpacked') -Recurse -File -Filter dist.exe)
    if ($executables.Count -ne 1) { throw 'Expected exactly one dist.exe in the release archive' }
    New-Item -ItemType Directory -Path $env:DIST_BIN_DIR -Force | Out-Null
    $destination = Join-Path $env:DIST_BIN_DIR 'dist.exe'
    if (Test-Path -LiteralPath $destination) { throw 'Refusing to replace an existing dist executable' }
    Copy-Item -LiteralPath $executables[0].FullName -Destination $destination
    $version = & $destination --version
    if ($LASTEXITCODE -ne 0 -or $version -ne 'cargo-dist 0.33.0') {
        throw 'The downloaded dist executable has an unexpected version'
    }
    [IO.File]::AppendAllText($env:GITHUB_PATH, $env:DIST_BIN_DIR + "`n", [Text.UTF8Encoding]::new($false))
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
