param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('x86_64', 'arm64')]
    [string]$Architecture,
    [string]$OutputDirectory = 'dist'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$target = if ($Architecture -eq 'arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
$versionLine = Select-String -Path (Join-Path $root 'Cargo.toml') -Pattern '^version = "([^"]+)"' | Select-Object -First 1
if (-not $versionLine) { throw 'Cargo package version is missing.' }
$version = $versionLine.Matches[0].Groups[1].Value
$binary = Join-Path $root "target/$target/release/ipatool.exe"
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw "Missing release binary: $binary" }

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$output = (Resolve-Path -LiteralPath $OutputDirectory).Path
$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("ipatool-rs-package-" + [guid]::NewGuid())
try {
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    Copy-Item -LiteralPath $binary -Destination (Join-Path $stage 'ipatool-rs.exe')
    foreach ($name in @('LICENSE', 'NOTICE', 'README.md')) {
        Copy-Item -LiteralPath (Join-Path $root $name) -Destination $stage
    }
    New-Item -ItemType Directory -Force -Path (Join-Path $stage 'licenses'), (Join-Path $stage 'assets') | Out-Null
    Copy-Item -LiteralPath (Join-Path $root 'licenses/LICENSE-DARKPHOENIX.txt') -Destination (Join-Path $stage 'licenses')
    Copy-Item -LiteralPath (Join-Path $root 'assets/fairplay-startup') -Destination (Join-Path $stage 'assets') -Recurse
    $base = "ipatool-rs-$version-windows-$Architecture"
    $archive = Join-Path $output "$base.zip"
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -CompressionLevel Optimal
    $digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText((Join-Path $output "$base.zip.sha256"), "$digest  $base.zip`n")
    Write-Output "Built $archive"
}
finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
