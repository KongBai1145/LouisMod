$ErrorActionPreference = "Stop"
$buildDir = "D:\work\KongBaiware\LouisMod\louismod-kdriver\driver"
Set-Location $buildDir

# Find VS
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsDir = & $vswhere -latest -property installationPath
Write-Host "VS: $vsDir"

# Find WDK
$w接送 = "${env:ProgramFiles(x86)}\Windows Kits\10"
if (-not (Test-Path $w接送)) { $w接送 = "C:\Program Files (x86)\Windows Kits\10" }
Write-Host "WDK: $w接送"

# Find latest SDK version
$sdkVer = Get-ChildItem "$w接送\Include" | Select-Object -Last 1 | Select-Object -ExpandProperty Name
Write-Host "SDK: $sdkVer"

# Setup MSVC env
$vcvars = "$vsDir\VC\Auxiliary\Build\vcvarsall.bat"
cmd /c "`"$vcvars`" x64 && set" | ForEach-Object {
    if ($_ -match '^(\w+)=(.*)$') {
        Set-Item -Path "env:$($matches[1])" -Value $matches[2]
    }
}

$includes = "/I`"$w接送\Include\$sdkVer\kmdf`" /I`"$w接送\Include\$sdkVer\shared`" /I`"$w接送\Include\$sdkVer\um`" /I`"$w接送\Include\$sdkVer\ucrt`""
$libpath = "/LIBPATH:`"$w接送\Lib\$sdkVer\kmdf\x64`" /LIBPATH:`"$w接送\Lib\$sdkVer\um\x64`""
$cflags = "/nologo /c /kernel /W4 /WX- /O2 /GS /GF /Gy /Zp8 /I. $includes /DKERNEL_MODE /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00"
$ldflags = "/nologo /kernel /subsystem:native /driver /entry:DriverEntry /MACHINE:x64 /align:64 /OPT:REF /OPT:ICF /NXCOMPAT $libpath ntoskrnl.lib hal.lib"

$buildDir = "$buildDir\build"
New-Item -ItemType Directory -Path "$buildDir\obj" -Force | Out-Null
New-Item -ItemType Directory -Path "$buildDir\bin" -Force | Out-Null

$srcDir = "D:\work\KongBaiware\LouisMod\louismod-kdriver\driver"
$objs = @()
Get-ChildItem "$srcDir\*.c" | ForEach-Object {
    $basename = $_.BaseName
    $objFile = "$buildDir\obj\${basename}_x64.obj"
    Write-Host "[COMPILE] $basename.c"
    cl $cflags "/Fo$objFile" $_.FullName 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Compilation failed: $basename.c"
        exit 1
    }
    $objs += $objFile
}

$sysFile = "$buildDir\bin\louismod.sys"
Write-Host "[LINK] louismod.sys"
link $ldflags "/OUT:$sysFile" $objs 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Linking failed."
    exit 1
}

Write-Host "[DONE] $sysFile"
