Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Starting Local AI Security Log Analyzer" -ForegroundColor Green

if (Test-Path ".venv\Scripts\python.exe") {
    Write-Host "Using isolated virtual environment: .venv" -ForegroundColor Gray
    $PYTHON_EXEC = ".venv\Scripts\python.exe"
} else {
    $PYTHON_EXEC = "python"
}

Write-Host "Server running at http://localhost:8000" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Cyan
& $PYTHON_EXEC -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
