# ============================================================
# NetShield AI -- One-Command Environment Setup (Windows PowerShell)
# ============================================================
# Creates a Python venv, installs all Python dependencies,
# installs Node.js dependencies for both server and dashboard,
# and copies .env.example to .env if it doesn't exist.
#
# Usage:
#   .\scripts\setup_env.ps1
# ============================================================

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  NetShield AI -- Environment Setup" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# -- 1. Create Python virtual environment --------------------
$VenvPath = Join-Path $ProjectRoot "python-engine\.venv"

if (Test-Path $VenvPath) {
    Write-Host "[1/5] Python venv already exists at $VenvPath" -ForegroundColor Yellow
} else {
    Write-Host "[1/5] Creating Python virtual environment..." -ForegroundColor White
    $PythonEngine = Join-Path $ProjectRoot "python-engine"
    & py -m venv $VenvPath
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to create Python venv. Make sure Python 3.11+ is installed." -ForegroundColor Red
        exit 1
    }
    Write-Host "  Created at: $VenvPath" -ForegroundColor Green
}

# -- 2. Activate and install Python dependencies ------------
Write-Host "[2/5] Installing Python dependencies..." -ForegroundColor White

$ActivateScript = Join-Path $VenvPath "Scripts\Activate.ps1"
if (Test-Path $ActivateScript) {
    & $ActivateScript
}

$ReqPath = Join-Path $ProjectRoot "python-engine\requirements.txt"
& py -m pip install --upgrade pip -q
& py -m pip install -r $ReqPath

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to install Python dependencies." -ForegroundColor Red
    exit 1
}
Write-Host "  Python dependencies installed." -ForegroundColor Green

# -- 3. Install Node.js server dependencies -----------------
Write-Host "[3/5] Installing Node.js server dependencies..." -ForegroundColor White

$ServerPath = Join-Path $ProjectRoot "server"
Push-Location $ServerPath
& npm install
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to install server dependencies." -ForegroundColor Red
    Pop-Location
    exit 1
}
Pop-Location
Write-Host "  Server dependencies installed." -ForegroundColor Green

# -- 4. Install dashboard dependencies -----------------------
Write-Host "[4/5] Installing dashboard dependencies..." -ForegroundColor White

$DashboardPath = Join-Path $ProjectRoot "dashboard"
Push-Location $DashboardPath
& npm install
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to install dashboard dependencies." -ForegroundColor Red
    Pop-Location
    exit 1
}
Pop-Location
Write-Host "  Dashboard dependencies installed." -ForegroundColor Green

# -- 5. Copy .env.example to .env if it doesn't exist -------
Write-Host "[5/5] Checking .env file..." -ForegroundColor White

$EnvPath = Join-Path $ProjectRoot ".env"
$EnvExamplePath = Join-Path $ProjectRoot ".env.example"

if (-not (Test-Path $EnvPath)) {
    if (Test-Path $EnvExamplePath) {
        Copy-Item $EnvExamplePath $EnvPath
        Write-Host "  Copied .env.example to .env" -ForegroundColor Green
        Write-Host "  Edit .env to add your API keys (Gemini, Telegram, Email)." -ForegroundColor Yellow
    } else {
        Write-Host "  WARNING: No .env.example found - create .env manually." -ForegroundColor Yellow
    }
} else {
    Write-Host "  .env already exists." -ForegroundColor Green
}

# -- Done ----------------------------------------------------
Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Start all servers:  .\scripts\start_all.ps1"
Write-Host "  2. Open dashboard:     http://localhost:5173"
Write-Host "  3. Simulate an attack: py scripts\simulate_attack.py --ddos"
Write-Host ""
