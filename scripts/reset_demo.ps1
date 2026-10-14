<#
.SYNOPSIS
  Start the demo from a clean slate (module 10, docs/DEMO_SCRIPT.md).

.DESCRIPTION
  1. Creates .env from .env.example if it doesn't exist, generating every
     secret; adds any module 10 setting an older .env is missing. Existing
     values are never changed.
  2. Deletes the stack's containers AND its database volume (all teams,
     keys, audit entries), after asking.
  3. Rebuilds and starts everything; the stack seeds itself with demo data.

  Run from the repository root:  powershell -ExecutionPolicy Bypass -File scripts\reset_demo.ps1
  Add -Yes to skip the question.
#>
param([switch]$Yes)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

function New-Secret([int]$Bytes = 18) {
    $buffer = New-Object byte[] $Bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buffer)
    # URL-safe base64: also the format a Fernet key (32 bytes) needs.
    return [Convert]::ToBase64String($buffer).Replace('+', '-').Replace('/', '_')
}

$created = $false
if (-not (Test-Path .env)) {
    Copy-Item .env.example .env
    $created = $true
    Write-Host "Created .env from .env.example"
}
$envText = Get-Content .env -Raw

# Setting -> value to use when it's missing or empty in .env.
$wanted = [ordered]@{
    "REDACTION_VAULT_KEY"                 = (New-Secret 32)
    "POSTGRES_APP_PASSWORD"               = (New-Secret)
    "DEMO_SEED"                           = "true"
    "DEMO_SECRET"                         = (New-Secret 24)
    "DEMO_ADMIN_USERNAME"                 = "admin"
    "DEMO_ADMIN_PASSWORD"                 = (New-Secret 15)
    "DEMO_MODEL"                          = "local-llama3:latest"
    "OLLAMA_BASE_URL"                     = "http://host.docker.internal:11434/v1"
    "LOCAL_MODEL_DEMO_PRICE_PER_MILLION"  = "60"
}
$newAdminPassword = $null
foreach ($name in $wanted.Keys) {
    $line = [regex]::Match($envText, "(?m)^$name=(.*)$")
    if ($line.Success -and $line.Groups[1].Value.Trim() -ne "" -and -not ($created -and $name -eq "LOCAL_MODEL_DEMO_PRICE_PER_MILLION")) {
        continue
    }
    $value = $wanted[$name]
    if ($line.Success) {
        $envText = [regex]::Replace($envText, "(?m)^$name=.*$", "$name=$value")
    } else {
        $envText = $envText.TrimEnd() + "`n$name=$value`n"
    }
    if ($name -eq "DEMO_ADMIN_PASSWORD") { $newAdminPassword = $value }
    if ($name -notlike "*SECRET*" -and $name -notlike "*PASSWORD*" -and $name -ne "REDACTION_VAULT_KEY") {
        Write-Host "  .env: $name=$value"
    } else {
        Write-Host "  .env: $name generated"
    }
}
# UTF-8 without a BOM: Docker Compose would read a BOM as part of the first name.
[System.IO.File]::WriteAllText((Join-Path (Get-Location) ".env"), $envText, (New-Object System.Text.UTF8Encoding $false))

if (-not $Yes) {
    Write-Host ""
    Write-Host "This DELETES the stack's database (all teams, keys and audit entries) and starts fresh."
    $answer = Read-Host "Type yes to continue"
    if ($answer -ne "yes") { Write-Host "Nothing changed."; exit 1 }
}

docker compose down --volumes --remove-orphans
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
docker compose up -d --build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Waiting for the demo traffic to finish (the classifier loads first, ~30 s)..."
docker compose wait seed-traffic | Out-Null
docker compose logs --no-log-prefix seed-traffic

$admin = [regex]::Match((Get-Content .env -Raw), "(?m)^DEMO_ADMIN_USERNAME=(.*)$").Groups[1].Value.Trim()
Write-Host ""
Write-Host "Ready."
Write-Host "  Dashboard: http://localhost:3000   (user: $admin)"
if ($newAdminPassword) {
    Write-Host "  Password:  $newAdminPassword   (new - it's also in .env as DEMO_ADMIN_PASSWORD)"
} else {
    Write-Host "  Password:  DEMO_ADMIN_PASSWORD in .env"
}
Write-Host "  Gateway:   http://localhost:8000"
Write-Host "  Demo steps: docs/DEMO_SCRIPT.md"
