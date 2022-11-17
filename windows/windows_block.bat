@echo off
echo 'Starting mpssvc service'
net stop mpssvc && net start mpssvc
echo 'Turning on the Windows firewall'
netsh advfirewall set allprofiles set on

rem - Examples -
rem CALL :BlockRange 192.168.1.
rem CALL :BlockIp 10.0.0.1
rem CALL :BlockPortOut 505001
rem Call :BlockPortIn 445

echo 'Blocking stuff'

CALL :BlockPortOut 8080
CALL :BlockIp 192.168.133.7

EXIT /b %ERRORLEVEL%
:BlockRange
for /l %%n in (1, 1, 254) do (
    echo 'blocking %~1%%n in and out"
    netsh advfirewall firewall add rule name="IP block %~1%%n" dir=in action=block protocol=ANY remoteip=%~1%%n-255.255.255.255
    netsh advfirewall firewall add rule name="IP block %~1%%n" dir=out action=block protocol=ANY remoteip=%~1%%n-255.255.255.255
)
EXIT /b
:BlockIp
echo 'Blocking %~1 in and out"
netsh advfirewall firewall add rule name="IP block %~1" dir=in action=block protocol=ANY remoteip=%~1-255.255.255.255
netsh advfirewall firewall add rule name="IP block %~1" dir=out action=block protocol=ANY remoteip=%~1-255.255.255.255
EXIT /b
:BlockPortTCPIn
echo 'Blocking port %~1 in"
netsh advfirewall firewall add rule name="Port block in: %~1" dir=in action=block protocol=tcp localport=%~1
EXIT /b
:BlockPortTCPOut
echo 'Blocking port %~1 out"
netsh advfirewall firewall add rule name="Port block out: %~1" dir=out action=block protocol=tcp localport=%~1
EXIT /b
:BlockPortUDPIn
echo 'Blocking port %~1 in"
netsh advfirewall firewall add rule name="Port block in: %~1" dir=in action=block protocol=udp localport=%~1
EXIT /b
:BlockPortUDPOut
echo 'Blocking port %~1 out"
netsh advfirewall firewall add rule name="Port block out: %~1" dir=out action=block protocol=udp localport=%~1
EXIT /b
