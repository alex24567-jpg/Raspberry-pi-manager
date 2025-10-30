# One-click PowerShell script to activate the virtualenv and run the Flask app
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $here
if (-Not (Test-Path .\.venv\Scripts\Activate.ps1)) {
  Write-Host "Virtualenv activate script not found at .\.venv\Scripts\Activate.ps1" -ForegroundColor Yellow
  Write-Host "Run: python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt"
  exit 1
}
. .\.venv\Scripts\Activate.ps1
python app.py
