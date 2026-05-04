@echo off
title LouisMod Setup
cd /d "%~dp0.."

:: ==========================================
:: LouisMod One-Click Setup
::   - Enables test signing mode
::   - Installs/starts kernel driver
::   - Skips to driver install if testsigning is already on
:: ==========================================

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Run this script as Administrator!
    pause
    exit /b 1
)

:: -------------------------------------------------------
:: Phase 1 — Check / Enable Test Signing
:: -------------------------------------------------------
bcdedit /enum 2>&1 | findstr /i "testsigning.*Yes" >nul
if %errorlevel% neq 0 (
    echo.
    echo ==========================================
    echo  [1/2] Enabling Test Signing Mode
    echo ==========================================
    echo.
    bcdedit /set testsigning on
    if %errorlevel% neq 0 (
        echo Failed to enable test signing! Disable Secure Boot in BIOS and try again.
        pause
        exit /b 1
    )
    echo.
    echo Test signing enabled. A reboot is required.
    echo After reboot, run this script again to install the driver.
    echo.
    shutdown /r /t 10 /c "LouisMod: Reboot to enable test signing"
    echo System will reboot in 10 seconds. Press any key to reboot now...
    pause >nul
    shutdown /r /t 0
    exit /b 0
)

echo.
echo Test signing: Enabled

:: -------------------------------------------------------
:: Phase 2 — Install Driver
:: -------------------------------------------------------
echo.
echo ==========================================
echo  [2/2] Installing LouisMod Kernel Driver
echo ==========================================

set "SYS_SRC=louismod-kdriver\driver\build\bin\louismod.sys"
if not exist "%SYS_SRC%" (
    echo [ERROR] Driver file not found: %SYS_SRC%
    echo Build the driver with build.bat first.
    pause
    exit /b 1
)

:: Copy driver to tools directory
copy /Y "%SYS_SRC%" "tools\louismod.sys" >nul
set "SYS_PATH=%~dp0louismod.sys"

:: Install test certificate (if available)
set "CERT_PATH=louismod-kdriver\driver\build\louismod_test.cer"
if exist "%CERT_PATH%" (
    echo Installing test certificate...
    certutil -addstore Root "%CERT_PATH%" >nul 2>&1
    certutil -addstore TrustedPublisher "%CERT_PATH%" >nul 2>&1
)

:: Remove old service
echo Removing old driver service...
sc.exe stop LouisModDriver >nul 2>&1
sc.exe delete LouisModDriver >nul 2>&1
ping -n 2 127.0.0.1 >nul

:: Create service
echo Registering driver service...
sc.exe create LouisModDriver type= kernel binPath= "%SYS_PATH%"
if %errorlevel% neq 0 (
    echo [ERROR] Service registration failed
    pause
    exit /b 1
)

:: Start service
echo Starting driver...
sc.exe start LouisModDriver
if %errorlevel% neq 0 (
    echo.
    echo ==========================================
    echo  Driver start failed!
    echo ==========================================
    echo.
    echo Check the following:
    echo   1. Memory Integrity is OFF (Windows Security -^> Core Isolation)
    echo   2. Hyper-V / VBS is disabled
    echo   3. Reboot then run this script again
    echo.
    sc.exe delete LouisModDriver >nul 2>&1
    pause
    exit /b 1
)

echo.
echo ==========================================
echo  LouisMod driver installed successfully!
echo  Service: LouisModDriver - RUNNING
echo ==========================================
echo.
echo Run controller.exe directly to start LouisMod.
echo.
pause
