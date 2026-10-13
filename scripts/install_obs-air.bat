@echo off
setlocal EnableExtensions
set "install_result=1"
title OBS-Air Install

set "source=%~dp0obs-studio\plugins\obs-air"
set "target=%PROGRAMDATA%\obs-studio\plugins\obs-air"
set "obs_program=%ProgramFiles%\obs-studio\bin\64bit\obs64.exe"

for %%F in (obs-air.dll avcodec-61.dll avutil-59.dll swscale-8.dll swresample-5.dll libx264-164.dll zlib.dll) do (
    if not exist "%source%\bin\64bit\%%F" (
        echo Incomplete package: missing %%F
        echo Extract the entire OBS-Air ZIP before running this script.
        goto failed
    )
)
if not exist "%obs_program%" (
    echo OBS was not found: %obs_program%
    echo This installer requires OBS Studio in its default location.
    goto failed
)

"%SystemRoot%\System32\fltmc.exe" >nul 2>&1
if errorlevel 1 (
    echo Right-click this script and select Run as administrator.
    goto failed
)

"%SystemRoot%\System32\tasklist.exe" /FI "IMAGENAME eq obs64.exe" /NH | "%SystemRoot%\System32\findstr.exe" /I /C:"obs64.exe" >nul
if not errorlevel 1 (
    echo Exit OBS before installing.
    goto failed
)

echo Installing OBS-Air...
"%SystemRoot%\System32\robocopy.exe" "%source%" "%target%" /E /COPY:DAT /DCOPY:DAT /R:1 /W:1 /NFL /NDL /NP
if errorlevel 8 (
    echo File copy failed. Check administrator permissions and the destination.
    goto failed
)

echo Configuring OBS firewall rules...
call :firewall OBS-Air-TCP TCP
if errorlevel 1 goto firewall_failed
call :firewall OBS-Air-UDP UDP
if errorlevel 1 goto firewall_failed

echo.
echo Installed: %target%
echo OBS TCP/UDP allowed on private networks from the local subnet.
echo Restart OBS 32 or later and add AirPlay (OBS-Air).
echo Connect your device to the same LAN and select your receiver in Screen Mirroring.
echo Set the current Windows network to Private.
set "install_result=0"
goto finish

:firewall
"%SystemRoot%\System32\netsh.exe" advfirewall firewall show rule name="%~1" >nul 2>&1
if errorlevel 1 (
    "%SystemRoot%\System32\netsh.exe" advfirewall firewall add rule name="%~1" dir=in action=allow program="%obs_program%" enable=yes profile=private protocol=%~2 localport=any remoteip=LocalSubnet >nul
) else (
    "%SystemRoot%\System32\netsh.exe" advfirewall firewall set rule name="%~1" new dir=in action=allow program="%obs_program%" enable=yes profile=private protocol=%~2 localport=any remoteip=LocalSubnet >nul
)
exit /b %errorlevel%

:firewall_failed
echo Files copied, but firewall setup failed. Check admin rights and the firewall service.
:failed
echo.
echo Installation failed.
:finish
echo.
if "%install_result%"=="0" (
    "%SystemRoot%\System32\timeout.exe" /t 5 /nobreak
) else (
    echo Press any key to close.
    pause >nul
)
exit /b %install_result%
