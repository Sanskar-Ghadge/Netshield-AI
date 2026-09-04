# ============================================================
# NetShield AI -- Stop All Servers (Windows PowerShell)
# ============================================================
# Kills all processes related to NetShield AI:
#   - Python uvicorn (port 8000)
#   - Node.js backend (port 3001)
#   - Vite dev server (port 5173)
#
# Usage:
#   .\scripts\stop_all.ps1
# ============================================================

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  NetShield AI -- Stopping All Servers" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# -- Kill processes by port ----------------------------------
$Ports = @(8000, 3001, 5173)
$Killed = 0

foreach ($port in $Ports) {
    $connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($connections) {
        foreach ($conn in $connections) {
            $pid = $conn.OwningProcess
            if ($pid -and $pid -ne 0) {
                $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                $procName = if ($proc) { $proc.ProcessName } else { "unknown" }
                Write-Host "  Killing PID $pid ($procName) on port $port..." -ForegroundColor Yellow
                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                $Killed++
            }
        }
    } else {
        Write-Host "  Port $port -- nothing running" -ForegroundColor DarkGray
    }
}

# -- Also kill any stray uvicorn processes --------------------
$uvicorn = Get-Process -Name python -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like "*uvicorn*" -or $_.MainWindowTitle -like "*NetShield*"
}
foreach ($proc in $uvicorn) {
    Write-Host "  Killing stray Python process PID $($proc.Id)..." -ForegroundColor Yellow
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    $Killed++
}

# -- Also kill windows titled "NetShield" -------------------
$netshieldWindows = Get-Process | Where-Object { $_.MainWindowTitle -like "*NetShield*" }
foreach ($proc in $netshieldWindows) {
    Write-Host "  Killing $($proc.ProcessName) PID $($proc.Id) ($($proc.MainWindowTitle))..." -ForegroundColor Yellow
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    $Killed++
}

# -- Summary -------------------------------------------------
Write-Host ""
if ($Killed -gt 0) {
    Write-Host "  Stopped $Killed process(es)." -ForegroundColor Green
} else {
    Write-Host "  No NetShield processes found." -ForegroundColor DarkGray
}
Write-Host ""
