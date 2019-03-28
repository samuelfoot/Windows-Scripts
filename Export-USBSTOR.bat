@echo off
reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR .\USBSTOR.reg
Echo "Finished"
Pause