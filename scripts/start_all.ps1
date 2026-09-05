# ============================================================
# NetShield AI -- Start All Servers (Windows PowerShell)
# ============================================================
# Starts the three backend servers in separate windows:
#   1. Python FastAPI engine  (port 8000)
#   2. Node.js backend        (port 3001)
#   3. Vite React dashboard   (port 5173)
#
# Usage:
#   .\scripts\start_all.ps1
# ============================================================

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

$PythonEngine = Join-Path $ProjectRoot "python-engine"
$ServerPath   = Join-Path $ProjectRoot "server"
$DashboardPath = Join-Path $ProjectRoot "dashboard"

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  NetShield AI -- Starting All Servers" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# -- 0a. Stop any running servers first ----------------------
Write-Host "  Stopping any running NetShield processes..." -ForegroundColor DarkGray
& (Join-Path $MyInvocation.MyCommand.Path "..\stop_all.ps1") | Out-Null

# -- 0. Clean previous session database (restart values to 0) -
Write-Host "[0/3] Preparing fresh monitoring session..." -ForegroundColor White
$DbFile = Join-Path $PythonEngine "netshield.db"
$DbWal  = Join-Path $PythonEngine "netshield.db-wal"
$DbShm  = Join-Path $PythonEngine "netshield.db-shm"

if (Test-Path $DbFile) { Remove-Item -Path $DbFile -Force -ErrorAction SilentlyContinue }
if (Test-Path $DbWal)  { Remove-Item -Path $DbWal  -Force -ErrorAction SilentlyContinue }
if (Test-Path $DbShm)  { Remove-Item -Path $DbShm  -Force -ErrorAction SilentlyContinue }
Write-Host "  Session data reset -- all counters starting from 0!" -ForegroundColor Green
Write-Host ""

# -- 1. Start Python FastAPI Engine (port 8000) -------------
Write-Host "[1/3] Starting Python FastAPI engine on port 8000..." -ForegroundColor White

$PythonCmd = "`$host.UI.RawUI.WindowTitle = 'NetShield -- Python Engine'; cd '$PythonEngine'; .\.venv\Scripts\python.exe -m uvicorn app:app --host 0.0.0.0 --port 8000"
Start-Process -FilePath "powershell" -ArgumentList "-NoExit", "-Command", $PythonCmd
Write-Host "  Python engine starting..." -ForegroundColor Green

# Wait for Python to load model and start
Write-Host "  Waiting for model to load (8 seconds)..." -ForegroundColor DarkGray
Start-Sleep -Seconds 8

# -- 2. Start Node.js Backend (port 3001) -------------------
Write-Host "[2/3] Starting Node.js backend on port 3001..." -ForegroundColor White

$NodeCmd = "`$host.UI.RawUI.WindowTitle = 'NetShield -- Node.js Backend'; cd '$ServerPath'; node src/index.js"
Start-Process -FilePath "powershell" -ArgumentList "-NoExit", "-Command", $NodeCmd
Write-Host "  Node.js backend starting..." -ForegroundColor Green

Start-Sleep -Seconds 3

# -- 3. Start Vite React Dashboard (port 5173) -------------
Write-Host "[3/3] Starting Vite React dashboard on port 5173..." -ForegroundColor White

$ViteCmd = "`$host.UI.RawUI.WindowTitle = 'NetShield -- Dashboard'; cd '$DashboardPath'; npx vite --host"
Start-Process -FilePath "powershell" -ArgumentList "-NoExit", "-Command", $ViteCmd
Write-Host "  Vite dashboard starting..." -ForegroundColor Green

Start-Sleep -Seconds 4

# -- Done ----------------------------------------------------
Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "  All Servers Started!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Dashboard:  http://localhost:5173" -ForegroundColor Cyan
Write-Host "  Node API:   http://localhost:3001" -ForegroundColor Cyan
Write-Host "  Python API: http://localhost:8000" -ForegroundColor Cyan
Write-Host ""
Write-Host "To simulate an attack:" -ForegroundColor Yellow
Write-Host "  py scripts\simulate_attack.py --ddos"
Write-Host ""
Write-Host "To stop all servers:" -ForegroundColor Yellow
Write-Host "  .\scripts\stop_all.ps1"
Write-Host ""
