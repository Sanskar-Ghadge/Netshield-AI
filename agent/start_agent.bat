@echo off
title NetShield AI Agent Launcher
color 0B
cls

echo ========================================================
echo   NetShield AI -- Starting Laptop Protection Agent
echo ========================================================
echo.

if exist .env (
    for /f "tokens=1,2 delims==" %%a in (.env) do (
        if "%%a"=="NETSHIELD_API_KEY" set API_KEY=%%b
    )
)

if "%API_KEY%"=="" (
    echo [NOTICE] No saved API Key found in .env
    set /p API_KEY="Enter your NetShield Agent API Key: "
)

py agent.py --key %API_KEY%

pause
