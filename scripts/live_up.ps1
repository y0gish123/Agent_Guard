# Start AgentGuard in LIVE mode (Mock Tool, Stub Site, Backend, and Collector)
param(
    [ValidateSet("guarded", "naive")]
    [string]$Mode = "guarded"
)

$env:DEMO_MODE = $Mode
$env:LIVE_MODE = "true"
$env:SIMULATION = "true"
$env:TOOL_BACKEND = "portal"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Starting AgentGuard AI SOC in LIVE [$Mode] mode" -ForegroundColor Cyan
Write-Host " Mock Tool (Portal mode): http://localhost:8001" -ForegroundColor Yellow
Write-Host " Stub Victim Clinic Site: http://localhost:8002" -ForegroundColor Magenta
Write-Host " SOC Backend:             http://localhost:8000" -ForegroundColor Green
Write-Host " Collector:               Tailing site logs -> Backend" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Start Stub Site on port 8002
$siteJob = Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:SITE_DEMO='true'; python -m uvicorn testbed.stub_site.main:app --port 8002 --reload" -PassThru

# 2. Start Mock Tool on port 8001 (configured for portal backend)
$toolJob = Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:DEMO_MODE='$Mode'; `$env:SIMULATION='true'; `$env:TOOL_BACKEND='portal'; python -m uvicorn mock_tool.app:app --port 8001 --reload" -PassThru

# 3. Start Backend on port 8000
$backendJob = Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:DEMO_MODE='$Mode'; `$env:LIVE_MODE='true'; `$env:SIMULATION='true'; python -m uvicorn backend.main:app --port 8000 --reload" -PassThru

# 4. Start Collector
Start-Sleep -Seconds 2
$collectorJob = Start-Process powershell -ArgumentList "-NoExit", "-Command", "python collector/collector.py" -PassThru

Write-Host "All Live services launched successfully." -ForegroundColor Green
Write-Host "Stub Site PID: $($siteJob.Id), Tool PID: $($toolJob.Id), Backend PID: $($backendJob.Id), Collector PID: $($collectorJob.Id)" -ForegroundColor Gray

