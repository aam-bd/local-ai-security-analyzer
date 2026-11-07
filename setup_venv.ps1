Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Creating Python Virtual Environment (.venv)" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Cyan
python -m venv .venv
& .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Virtual Environment Setup Complete!" -ForegroundColor Green
Write-Host "Run '.\run_constrained.ps1' to start the app." -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Cyan
