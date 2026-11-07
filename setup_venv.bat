@echo off
echo ========================================================
echo Creating Python Virtual Environment (.venv)
echo ========================================================
python -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
echo ========================================================
echo Virtual Environment Setup Complete!
echo Run 'run_constrained.bat' to start the app.
echo ========================================================
