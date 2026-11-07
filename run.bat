@echo off
echo ========================================================
echo Starting Local AI Security Log Analyzer
echo ========================================================

if exist .venv\Scripts\python.exe (
    echo Using isolated virtual environment: .venv
    set "PYTHON_EXEC=.venv\Scripts\python.exe"
) else (
    set "PYTHON_EXEC=python"
)

echo Server running at http://localhost:8000
echo ========================================================
%PYTHON_EXEC% -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
