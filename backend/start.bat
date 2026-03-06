@echo off
REM AEGIS Backend Server Starter
REM This batch file starts the AEGIS backend server using the Playwright Node.js binary

SET NODE_EXE=%LOCALAPPDATA%\ms-playwright-go\1.50.1\node.exe
SET BACKEND_DIR=%~dp0

echo.
echo ================================================
echo  AEGIS Autonomous Cyber Defense OS - Backend
echo ================================================
echo.

IF EXIST "%NODE_EXE%" (
    echo Starting server with embedded Node.js...
    echo Node: %NODE_EXE%
    echo.
    "%NODE_EXE%" "%BACKEND_DIR%server.js"
) ELSE (
    REM Try standard Node.js from PATH
    where node >nul 2>&1
    IF %ERRORLEVEL% EQU 0 (
        echo Starting server with system Node.js...
        node "%BACKEND_DIR%server.js"
    ) ELSE (
        echo ERROR: Node.js not found!
        echo Please install Node.js from https://nodejs.org/
        echo Or ensure Node.js is in your PATH.
        pause
        exit /b 1
    )
)
