# Reset backend and mock tool, then seed all demonstration scenarios
param(
    [string]$BaseUrl = "http://localhost:8000"
)

Write-Host "Resetting backend and mock tool via $BaseUrl/api/demo/reset..." -ForegroundColor Yellow
try {
    $resetResp = Invoke-RestMethod -Uri "$BaseUrl/api/demo/reset" -Method Post -TimeoutSec 5
    Write-Host "Reset complete:" ($resetResp | ConvertTo-Json -Compress) -ForegroundColor Green
} catch {
    Write-Host "Reset failed (is backend running?): $_" -ForegroundColor Red
}

Write-Host "Seeding scenario 'all' via $BaseUrl/api/demo/seed?scenario=all..." -ForegroundColor Yellow
try {
    $seedResp = Invoke-RestMethod -Uri "$BaseUrl/api/demo/seed?scenario=all" -Method Post -TimeoutSec 10
    Write-Host "Seeding complete:" ($seedResp | ConvertTo-Json -Compress) -ForegroundColor Green
} catch {
    Write-Host "Seeding failed: $_" -ForegroundColor Red
}

try {
    $funnelResp = Invoke-RestMethod -Uri "$BaseUrl/api/funnel" -Method Get
    Write-Host "Current Funnel counts:" ($funnelResp | ConvertTo-Json -Compress) -ForegroundColor Cyan
} catch {
    # ignore
}

