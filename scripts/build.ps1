Param(
    [switch]$Release
)

$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot\..

if ($Release) {
    cargo build --workspace --release
} else {
    cargo build --workspace
}

Push-Location web-ui
if (-not (Test-Path node_modules)) { npm install }
npm run build
Pop-Location

Pop-Location
Write-Host "Build complete."
