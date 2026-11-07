Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Starting in Resource-Constrained Mode (2 vCPU, 4GB RAM)" -ForegroundColor Green

if (Test-Path ".venv\Scripts\python.exe") {
    Write-Host "Using isolated virtual environment: .venv" -ForegroundColor Gray
    $PYTHON_EXEC = ".venv\Scripts\python.exe"
} else {
    $PYTHON_EXEC = "python"
}

Write-Host "========================================================" -ForegroundColor Cyan
& $PYTHON_EXEC run_constrained.py
