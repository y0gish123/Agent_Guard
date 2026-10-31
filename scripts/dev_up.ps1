# Start AgentGuard mock tool and backend services
param(
    [ValidateSet("guarded", "naive")]
    [string]$Mode = "guarded"
)

$env:DEMO_MODE = $Mode
$env:SIMULATION = "true"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Starting AgentGuard AI SOC in [$Mode] mode" -ForegroundColor Cyan
Write-Host " Mock Tool: http://localhost:8001" -ForegroundColor Yellow
Write-Host " Backend:   http://localhost:8000" -ForegroundColor Green
Write-Host " Press Ctrl+C in either window to stop services" -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Cyan

# Start Mock Tool in a separate PowerShell process
$toolJob = Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:DEMO_MODE='$Mode'; `$env:SIMULATION='true'; python -m uvicorn mock_tool.app:app --port 8001 --reload" -PassThru

# Start Backend in current process or separate process
$backendJob = Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:DEMO_MODE='$Mode'; `$env:SIMULATION='true'; python -m uvicorn backend.main:app --port 8000 --reload" -PassThru

Write-Host "Services launched successfully (Mock Tool PID: $($toolJob.Id), Backend PID: $($backendJob.Id))." -ForegroundColor Green

