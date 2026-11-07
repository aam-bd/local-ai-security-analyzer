@echo off
echo ========================================================
echo Starting in Resource-Constrained Mode (2 vCPU, 4GB RAM)
echo ========================================================

if exist .venv\Scripts\python.exe (
    echo Using isolated virtual environment: .venv
    set "PYTHON_EXEC=.venv\Scripts\python.exe"
) else (
    set "PYTHON_EXEC=python"
)

%PYTHON_EXEC% run_constrained.py
