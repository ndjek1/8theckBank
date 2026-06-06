# Task 4 demo script — run from src/secure after setup
# Usage: .\run_task4_demo.ps1

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "Creating virtual environment..."
    python -m venv .venv
    .\.venv\Scripts\python.exe -m pip install --upgrade pip -q
    # Pinned requirements target Python 3.12 (Docker). On 3.14 use latest compatible:
    .\.venv\Scripts\python.exe -m pip install Flask Werkzeug Jinja2 itsdangerous click bcrypt PyJWT Flask-Limiter pydantic email-validator
}

if (-not (Test-Path "bank.db")) {
    Write-Host "Seeding database..."
    .\.venv\Scripts\python.exe seed.py
}

Write-Host "`n=== Running Task 4 automated tests ==="
.\.venv\Scripts\python.exe test_task4.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n=== Live API demo (http://127.0.0.1:5001) ==="
$base = "http://127.0.0.1:5001"

# Check if server is already running
try {
    Invoke-WebRequest -Uri "$base/login" -UseBasicParsing -TimeoutSec 2 | Out-Null
    $running = $true
} catch { $running = $false }

if (-not $running) {
    Write-Host "Starting Flask app in background..."
    Start-Process -FilePath ".\.venv\Scripts\python.exe" -ArgumentList "app.py" -WorkingDirectory $PSScriptRoot -WindowStyle Hidden
    Start-Sleep -Seconds 2
}

Write-Host "`n1. Get JWT token (alice):"
$tok = Invoke-RestMethod -Uri "$base/api/auth/token" -Method POST -ContentType "application/json" `
    -Body '{"username":"alice","password":"alice123"}'
$tok | ConvertTo-Json

Write-Host "`n2. Profile (/api/me):"
Invoke-RestMethod -Uri "$base/api/me" -Headers @{ Authorization = "Bearer $($tok.access_token)" } | Format-List

Write-Host "`n3. Rate limit test (6 bad logins, expect 429 on last):"
for ($i = 1; $i -le 6; $i++) {
    try {
        $r = Invoke-WebRequest -Uri "$base/api/auth/token" -Method POST -ContentType "application/json" `
            -Body '{"username":"x","password":"y"}' -UseBasicParsing
        Write-Host "  Attempt $i : $($r.StatusCode)"
    } catch {
        Write-Host "  Attempt $i : $($_.Exception.Response.StatusCode.value__)"
    }
}

Write-Host "`nDone. Open $base/login in your browser."
Write-Host "For Docker sandbox (Task 4.3): install Docker Desktop, then run: docker compose up --build"
