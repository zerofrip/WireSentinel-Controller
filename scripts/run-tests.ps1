$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot\..

cargo test --workspace

Push-Location web-ui
if (-not (Test-Path node_modules)) { npm install }
npm run build
Pop-Location

Pop-Location
Write-Host "Tests complete."
