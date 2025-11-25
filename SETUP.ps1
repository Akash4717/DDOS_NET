# AI-Powered DDoS Detection System - Setup Script
# Run this script to set up the entire project automatically

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  AI-POWERED DDoS DETECTION SYSTEM - SETUP" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Check Python installation
Write-Host "[1/5] Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "  ✓ Found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Python not found! Please install Python 3.8+ first." -ForegroundColor Red
    Write-Host "  Download from: https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# Create virtual environment
Write-Host ""
Write-Host "[2/5] Creating virtual environment..." -ForegroundColor Yellow
if (Test-Path "venv") {
    Write-Host "  ! Virtual environment already exists, skipping..." -ForegroundColor Yellow
} else {
    python -m venv venv
    Write-Host "  ✓ Virtual environment created" -ForegroundColor Green
}

# Activate virtual environment
Write-Host ""
Write-Host "[3/5] Activating virtual environment..." -ForegroundColor Yellow
& .\venv\Scripts\Activate.ps1
Write-Host "  ✓ Virtual environment activated" -ForegroundColor Green

# Install dependencies
Write-Host ""
Write-Host "[4/5] Installing dependencies (this may take 3-5 minutes)..." -ForegroundColor Yellow
pip install --upgrade pip -q
pip install -r requirements.txt -q
Write-Host "  ✓ Dependencies installed" -ForegroundColor Green

# Train models
Write-Host ""
Write-Host "[5/5] Training ML models (this may take 1-2 minutes)..." -ForegroundColor Yellow
Set-Location models
python train_model.py
Set-Location ..

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  SETUP COMPLETE! 🎉" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Start the web dashboard:" -ForegroundColor White
Write-Host "     cd web" -ForegroundColor Yellow
Write-Host "     python app.py" -ForegroundColor Yellow
Write-Host ""
Write-Host "  2. Open browser: http://localhost:5000" -ForegroundColor White
Write-Host ""
Write-Host "  3. In a new terminal, generate traffic:" -ForegroundColor White
Write-Host "     cd src" -ForegroundColor Yellow
Write-Host "     python traffic_generator.py --scenario 2" -ForegroundColor Yellow
Write-Host ""
Write-Host "For detailed documentation, see:" -ForegroundColor Cyan
Write-Host "  - README.md (Quick start guide)" -ForegroundColor White
Write-Host "  - PROJECT_GUIDE.md (Complete documentation)" -ForegroundColor White
Write-Host ""
Write-Host "Good luck at your hackathon! 🚀" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
