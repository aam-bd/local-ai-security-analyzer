@echo off
echo ========================================================
echo Starting Local AI Security Log Analyzer
echo Server will run at http://localhost:8000
echo ========================================================
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

