@echo off
title Threat Intelligence Pipeline — Setup
color 0A

echo.
echo  ============================================
echo   Threat Intelligence Pipeline — Windows Setup
echo  ============================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Download from https://python.org
    pause
    exit /b 1
)
echo [OK] Python found

:: Check Docker
docker --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker not found. Download Docker Desktop from https://docker.com
    pause
    exit /b 1
)
echo [OK] Docker found

:: Create .env if not exists
if not exist .env (
    copy .env.example .env
    echo [OK] Created .env from template
) else (
    echo [OK] .env already exists
)

:: Create virtual environment
if not exist venv (
    echo.
    echo [*] Creating Python virtual environment...
    python -m venv venv
)
echo [OK] Virtual environment ready

:: Activate and install deps
echo.
echo [*] Installing Python dependencies...
call venv\Scripts\activate.bat
pip install -r requirements.txt --quiet
echo [OK] Dependencies installed

:: Create required folders
if not exist logs mkdir logs
if not exist data mkdir data
if not exist reports\output mkdir reports\output
echo [OK] Folders created

:: Start Elastic stack
echo.
echo [*] Starting Elasticsearch + Kibana via Docker...
echo     (This may take 2-3 minutes on first run)
docker compose up -d
echo [OK] Docker containers started

echo.
echo  ============================================
echo   Setup Complete!
echo  ============================================
echo.
echo   Next steps:
echo   1. Wait ~60s for Elasticsearch to be ready
echo   2. Run the pipeline:
echo      venv\Scripts\activate.bat
echo      python main.py
echo.
echo   Kibana Dashboard:  http://localhost:5601
echo   Elasticsearch:     http://localhost:9200
echo.
pause
