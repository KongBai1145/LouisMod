@echo off
title LouisMod Driver Uninstall

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Run this script as Administrator!
    pause
    exit /b 1
)

echo Stopping driver...
sc.exe stop LouisModDriver >nul 2>&1
ping -n 2 127.0.0.1 >nul

echo Removing driver service...
sc.exe delete LouisModDriver
echo.
echo Driver uninstalled.
echo Note: If test signing was enabled, disable manually: bcdedit /set testsigning off
pause
