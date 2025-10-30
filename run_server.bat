@echo off
REM One-click batch script to activate the venv and run the Flask app
cd /d %~dp0
IF NOT EXIST .venv\Scripts\activate.bat (
  echo Virtualenv activate script not found. Create a virtualenv and install requirements.
  echo python -m venv .venv
  echo .venv\Scripts\activate.bat
  echo pip install -r requirements.txt
  pause
  exit /b 1
)
.venv\Scripts\activate.bat
python app.py
pause
