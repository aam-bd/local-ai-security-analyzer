Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Starting Local AI Security Log Analyzer" -ForegroundColor Green
Write-Host "Server running at http://localhost:8000" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Cyan
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

