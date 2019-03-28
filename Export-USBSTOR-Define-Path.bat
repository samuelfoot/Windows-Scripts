@echo off
set /p location="Enter Location To Export To: "
SET full=%location%\USBSTOR.reg 
echo %full%
reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR %full%
Echo "Finished"
pause