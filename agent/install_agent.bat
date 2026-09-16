@echo off
title NetShield AI -- 1-Click Laptop Protection Agent Setup
color 0A
cls

echo ========================================================
echo   NetShield AI -- 1-Click Laptop Agent Setup
echo ========================================================
echo.

:: 1. Check Python installation
where py >nul 2>&1
if %errorlevel% neq 0 (
    where python >nul 2>&1
    if %errorlevel% neq 0 (
        color 0C
        echo [ERROR] Python is not installed or not added to PATH!
        echo Please install Python 3.9+ from https://www.python.org/downloads/
        echo.
        pause
        exit /b 1
    )
)

echo [1/3] Python installation detected!
echo.

:: 2. Install dependencies
echo [2/3] Installing NetShield AI agent dependencies...
py -m pip install --quiet --upgrade pip
py -m pip install "python-socketio[client]" websocket-client requests scapy python-dotenv
echo.

:: 3. Configure API Key
set /p API_KEY="Enter your NetShield Agent API Key (from web profile): "

if "%API_KEY%"=="" (
    color 0C
    echo [ERROR] API Key cannot be empty!
    pause
    exit /b 1
)

echo NETSHIELD_API_KEY=%API_KEY%> .env
echo NETSHIELD_SERVER_URL=http://localhost:3001>> .env

echo.
echo ========================================================
echo   Setup Complete! Starting NetShield Agent...
echo ========================================================
echo.

py agent.py --key %API_KEY%

pause
