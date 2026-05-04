@echo off
chcp 65001 >nul
title LouisMod Kernel Driver Build

:: ============================================================
:: LouisMod Kernel Driver Build Script
:: Requires: Visual Studio 2022 + WDK (Windows Driver Kit)
:: ============================================================

setlocal enabledelayedexpansion

set "BUILD_DIR=%~dp0build"
set "SRC_DIR=%~dp0"

:: -----------------------------------------------------------------
:: Find Visual Studio installation
:: -----------------------------------------------------------------
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [ERROR] Visual Studio not detected. Install VS2022 with WDK.
    echo [ERROR] vswhere.exe not found at: %VSWHERE%
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property installationPath`) do (
    set "VS_DIR=%%i"
)

if not defined VS_DIR (
    echo [ERROR] Could not locate Visual Studio installation.
    exit /b 1
)

echo [INFO] Visual Studio : %VS_DIR%

:: -----------------------------------------------------------------
:: Find WDK installation (look for the latest version)
:: -----------------------------------------------------------------
set "WDK_FOUND=0"
set "WDK_DIR="

:: Check typical WDK paths
set "WDK_PATHS[0]=%ProgramFiles(x86)%\Windows Kits\10"
set "WDK_PATHS[1]=%ProgramFiles%\Windows Kits\10"
set "WDK_PATHS[2]=C:\Program Files (x86)\Windows Kits\10"
set "WDK_PATHS[3]=C:\Program Files\Windows Kits\10"

for %%p in ("%WDK_PATHS[0]%", "%WDK_PATHS[1]%", "%WDK_PATHS[2]%", "%WDK_PATHS[3]%") do (
    if exist "%%~p" (
        set "WDK_DIR=%%~p"
        set "WDK_FOUND=1"
    )
)

if "%WDK_FOUND%"=="0" (
    echo [ERROR] Windows Kits 10 (WDK) not found.
    exit /b 1
)

:: Find latest SDK version
set "LATEST_SDK=0"
for /d %%d in ("%WDK_DIR%\Include\*") do (
    set "VER=%%~nxd"
    if !VER! GTR !LATEST_SDK! set "LATEST_SDK=!VER!"
)

if "%LATEST_SDK%"=="0" (
    echo [ERROR] No SDK versions found in %WDK_DIR%\Include
    exit /b 1
)

echo [INFO] WDK path     : %WDK_DIR%
echo [INFO] SDK version  : %LATEST_SDK%

:: -----------------------------------------------------------------
:: Detect target architecture (x64 is default for kernel drivers)
:: -----------------------------------------------------------------
set "ARCH=x64"
set "ARCH_DIR=x64"
if /i "%1"=="x86" set "ARCH=x86" & set "ARCH_DIR=x86"
if /i "%1"=="arm64" set "ARCH=arm64" & set "ARCH_DIR=arm64"

echo [INFO] Architecture : %ARCH%

:: -----------------------------------------------------------------
:: Set up MSVC environment
:: -----------------------------------------------------------------
call "%VS_DIR%\VC\Auxiliary\Build\vcvarsall.bat" %ARCH% 2>nul

if errorlevel 1 (
    echo [ERROR] Failed to initialize MSVC environment for %ARCH%.
    exit /b 1
)

:: -----------------------------------------------------------------
:: Build directories
:: -----------------------------------------------------------------
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%BUILD_DIR%\obj" mkdir "%BUILD_DIR%\obj"
if not exist "%BUILD_DIR%\bin" mkdir "%BUILD_DIR%\bin"

:: -----------------------------------------------------------------
:: Compiler and linker flags for kernel-mode driver
:: -----------------------------------------------------------------
set "INCLUDES=/I"%WDK_DIR%\Include\%LATEST_SDK%\kmdf" /I"%WDK_DIR%\Include\%LATEST_SDK%\kmdf\kmdf" /I"%WDK_DIR%\Include\%LATEST_SDK%\shared" /I"%WDK_DIR%\Include\%LATEST_SDK%\um" /I"%WDK_DIR%\Include\%LATEST_SDK%\ucrt""

set "LIBS=/LIBPATH:"%WDK_DIR%\Lib\%LATEST_SDK%\kmdf\%ARCH_DIR%" /LIBPATH:"%WDK_DIR%\Lib\%LATEST_SDK%\um\%ARCH_DIR%""

set "CFLAGS=/nologo /c /kernel /W4 /WX- /O2 /GS /GF /Gy /Zp8 /I. %INCLUDES% /DKERNEL_MODE /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00"

set "LDFLAGS=/nologo /kernel /subsystem:native /driver /entry:DriverEntry /MACHINE:%ARCH_DIR% /align:64 /OPT:REF /OPT:ICF /NXCOMPAT /DEBUG:FULL %LIBS% ntoskrnl.lib hal.lib"

:: -----------------------------------------------------------------
:: Compile source files
:: -----------------------------------------------------------------
set "OBJS="
for %%f in ("%SRC_DIR%\*.c") do (
    set "BASENAME=%%~nf"
    set "OBJ_FILE=%BUILD_DIR%\obj\!BASENAME!_%ARCH%.obj"
    echo [COMPILE] %%~nf.c
    cl %CFLAGS% /Fo"!OBJ_FILE!" "%%f" 2>&1
    if errorlevel 1 (
        echo [ERROR] Compilation failed: %%~nf.c
        exit /b 1
    )
    set "OBJS=!OBJS! !OBJ_FILE!"
)

:: -----------------------------------------------------------------
:: Link into .sys
:: -----------------------------------------------------------------
set "SYS_FILE=%BUILD_DIR%\bin\louismod.sys"
echo [LINK] louismod.sys
link %LDFLAGS% /OUT:"%SYS_FILE%" %OBJS% 2>&1
if errorlevel 1 (
    echo [ERROR] Linking failed.
    exit /b 1
)

:: -----------------------------------------------------------------
:: Sign test certificate (if available) and copy to deploy
:: -----------------------------------------------------------------
:: Check if a test certificate exists; if not, create one
set "CERT_FILE=%BUILD_DIR%\louismod_test.pfx"
if not exist "%CERT_FILE%" (
    echo [INFO] Creating test signing certificate...
    "C:\Program Files (x86)\Windows Kits\10\bin\%LATEST_SDK%\%ARCH_DIR%\certmgr" /add "%WDK_DIR%\..\..\..\..\..\..\..\Program Files (x86)\Windows Kits\10\Include\%LATEST_SDK%\kmdf\cert\WDKTestCert.cer" /s /r localMachine root 2>nul
)

:: Sign the driver if signtool is available
set "SIGNTOOL=%WDK_DIR%\bin\%LATEST_SDK%\%ARCH_DIR%\signtool.exe"
if exist "%SIGNTOOL%" (
    echo [SIGN] Signing driver with test certificate...
    "%SIGNTOOL%" sign /fd SHA256 /a /v /ph "%SYS_FILE%" 2>nul
    if errorlevel 1 (
        echo [WARN] Signing failed (non-fatal, use testsigning mode).
    ) else (
        echo [SIGN] Driver signed successfully.
    )
) else (
    echo [WARN] signtool not found. Driver will need testsigning mode.
)

:: -----------------------------------------------------------------
:: Copy to deploy directory
:: -----------------------------------------------------------------
set "DEPLOY_DIR=%SRC_DIR%..\..\target\release\deploy"
if not exist "%DEPLOY_DIR%" mkdir "%DEPLOY_DIR%"

copy /Y "%SYS_FILE%" "%DEPLOY_DIR%\louismod.sys" >nul
copy /Y "%SYS_FILE%" "%SRC_DIR%..\..\target\release\louismod.sys" >nul
echo [DONE] Driver deployed to:
echo        %DEPLOY_DIR%\louismod.sys

echo.
echo ============================================
echo  Build successful!
echo ============================================
echo.
echo  Output: %SYS_FILE%
echo.
echo  Next steps:
echo    1. Enable testsigning: bcdedit /set testsigning on  ^&^& restart
echo    2. Install driver as service:
echo       sc create LouisMod type= kernel binPath= "C:\full\path\to\louismod.sys"
echo       sc start LouisMod
echo.

endlocal
