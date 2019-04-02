@echo off
setlocal EnableDelayedExpansion

ver | find "10." > nul
if errorlevel 1 (
	echo Your Windows version is not Windows 10... yet. Brace yourself, Windows 10 is coming^^!
	pause
	exit
)

echo Make Windows 10 Great Again^^! Ultimate batch spyware and trash remover, v. 2.2.4.
echo Optimized for Anniversary Update.

echo.
echo | set /p=Checking permissions... 
net session >nul 2>&1
if errorlevel 1 (
	echo Permission denied. Run this script as administrator.
	pause
	exit
) else (
	echo OK.
	timeout /t 1 > nul
)

reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v "ProductName" | find "LTSB" > nul
if not errorlevel 1 (
	set LTSB=1
)

echo | set /p=Running Custom Reg edits 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 1 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d 2 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "HidePeopleBar" /t REG_DWORD /d 1 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f > nul
echo [OK]

taskkill /im explorer.exe /f
start explorer.exe


cls
echo Deleting spyware firewall rules... 
powershell -Command "& {Get-NetFirewallRule | Where { $_.Group -like '*@{*' } | Remove-NetFirewallRule;}"
powershell -Command "& {Get-NetFirewallRule | Where { $_.Group -eq 'DiagTrack' } | Remove-NetFirewallRule;}"
powershell -Command "& {Get-NetFirewallRule | Where { $_.DisplayGroup -eq 'Delivery Optimization' } | Remove-NetFirewallRule;}"
powershell -Command "& {Get-NetFirewallRule | Where { $_.DisplayGroup -like 'Windows Media Player Network Sharing Service*' } | Remove-NetFirewallRule;}"

cls
echo | set /p=Deleting OneDrive... 
taskkill /f /im OneDrive.exe > nul 2>&1
if exist %SystemRoot%\System32\OneDriveSetup.exe (
	start /wait %SystemRoot%\System32\OneDriveSetup.exe /uninstall
) else (
	start /wait %SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall
)
rd "%UserProfile%\OneDrive" /q /s > nul 2>&1
rd "%SystemDrive%\OneDriveTemp" /q /s > nul 2>&1
rd "%LocalAppData%\Microsoft\OneDrive" /q /s > nul 2>&1
rd "%ProgramData%\Microsoft OneDrive" /q /s > nul 2>&1
reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul 2>&1
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableMeteredNetworkFileSync" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d 1 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\OneDrive" /v "DisablePersonalSync" /t REG_DWORD /d 1 /f > nul
echo OK.

echo.
echo Deleting spyware/bloatware services...
set spy_services=^
	DiagTrack,dmwappushservice,diagnosticshub.standardcollector.service,DcpSvc,^
	WerSvc,PcaSvc,DoSvc,WMPNetworkSvc,XblAuthManager,XblGameSave,XboxNetApiSvc,^
	xboxgip,wlidsvc,lfsvc,NcbService,WbioSrvc,LicenseManager,OneSyncSvc,CDPSvc,^
	CDPUserSvc,MapsBroker,PhoneSvc,RetailDemo,WalletService
for %%i in (%spy_services%) do (
	sc query %%i > nul
	if not errorlevel 1060 (
		echo Current service: %%i
		sc stop %%i > nul
		sc delete %%i
		set spy_svc_found=1
	)
)
if not defined spy_svc_found (
	echo No spyware services found.
)

echo.
echo Disabling unsafe services...
set unsafe_services=^
	RemoteRegistry,TermService,TrkWks,DPS,^
	SensorDataService,SensorService,SensrSvc
for %%i in (%unsafe_services%) do (
	echo Current service: %%i
	sc stop %%i > nul
	sc config %%i start= disabled
)


echo.
echo Adding registry tweaks...

echo | set /p=Disable telemetry 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushsvc" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d 4 /f > nul
echo [OK]

echo | set /p=Disable Windows Customer Experience Improvement Program 
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d "0.0.0.0" /f > nul
echo [OK]

echo | set /p=Disable Application Telemetry 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f > nul
echo [OK]

echo | set /p=Disable Inventory Collector 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Disable Steps Recorder 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Disable Advertising ID 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Disable keylogger 
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Disable browser access to local language 
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Disable SmartScreen 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f > nul
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f > nul
echo [OK]

echo | set /p=Disable Cortana and web search 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d 3 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD /d 0 /f > nul
echo [OK]

echo | set /p=Disable Wi-Fi Sense 
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d 0 /f > nul
echo [OK]

echo | set /p=Disable biometrics 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d 4 /f > nul
echo [OK]

echo | set /p=Disable location access and sensors 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d 0 /f > nul
echo [OK]

echo | set /p=Disable sync 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v "Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /v "Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v "Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSync" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSync" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSyncUserOverride" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSync" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSyncUserOverride" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSync" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSyncUserOverride" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSync" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Disable device access for Universal Apps 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" /v "Value" /t REG_SZ /d "Deny" /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v "Value" /t REG_SZ /d "Deny" /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /v "Value" /t REG_SZ /d "Deny" /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /v "Value" /t REG_SZ /d "Deny" /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /v "Value" /t REG_SZ /d "Deny" /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v "Value" /t REG_SZ /d "Deny" /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9D9E0118-1807-4F2E-96E4-2CE57142E196}" /v "Value" /t REG_SZ /d "Deny" /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v "Value" /t REG_SZ /d "Deny" /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{B19F89AF-E3EB-444B-8DEA-202575A71599}" /v "Value" /t REG_SZ /d "Deny" /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v "Value" /t REG_SZ /d "Deny" /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v "Value" /t REG_SZ /d "Deny" /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v "Value" /t REG_SZ /d "Deny" /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E6AD100E-5F4E-44CD-BE0F-2265D88D14F5}" /v "Value" /t REG_SZ /d "Deny" /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E83AF229-8640-4D18-A213-E22675EBB2C3}" /v "Value" /t REG_SZ /d "Deny" /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Deny" /f > nul
if not defined LTSB (
	set edge_path=HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\S-1-15-2-3624051433-2125758914-1423191267-1740899205-1073925389-3782572162-737981194
	reg add !edge_path!\{2EEF81BE-33FA-4800-9670-1CD474972C3F} /v "Value" /t REG_SZ /d "Deny" /f > nul
	reg add !edge_path!\{E5323777-F976-4f5b-9B55-B94699C46E44} /v "Value" /t REG_SZ /d "Deny" /f > nul
)
set shell_exp_path=HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\S-1-15-2-155514346-2573954481-755741238-1654018636-1233331829-3075935687-2861478708
reg add %shell_exp_path%\{7D7E8402-7C54-4821-A34E-AEEFD62DED93} /v "Value" /t REG_SZ /d "Deny" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" /v "UserAuthPolicy" /t REG_DWORD /d 0 /f > nul
echo [OK]

if not defined LTSB (
	echo | set /p=Disable background access for Universal Apps 
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.PPIProjection_cw5n1h2txyewy" /v "Disabled" /t REG_DWORD /d 1 /f > nul
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.PPIProjection_cw5n1h2txyewy" /v "DisabledByUser" /t REG_DWORD /d 1 /f > nul
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Windows.ContactSupport_cw5n1h2txyewy" /v "Disabled" /t REG_DWORD /d 1 /f > nul
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Windows.ContactSupport_cw5n1h2txyewy" /v "DisabledByUser" /t REG_DWORD /d 1 /f > nul
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" /v "Disabled" /t REG_DWORD /d 1 /f > nul
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" /v "DisabledByUser" /t REG_DWORD /d 1 /f > nul
	echo [OK]
)

echo | set /p=Disable protected trash services 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvc" /v "Start" /t REG_DWORD /d 4 /f > nul
echo [OK]

echo | set /p=Disable Windows Defender 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d 4 /f > nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d 4 /f > nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d 4 /f > nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d 4 /f > nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d 4 /f > nul 2>&1
regsvr32 /s /u "%ProgramFiles%\Windows Defender\shellext.dll"
taskkill /f /im MSASCuiL.exe > nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefender" /f > nul 2>&1
echo [OK]

if not defined LTSB (
	echo | set /p=Disable Windows Store 
	reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d 2 /f > nul
	reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "DisableStoreApps" /t REG_DWORD /d 1 /f > nul
	reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "RemoveWindowsStore" /t REG_DWORD /d 1 /f > nul
	echo [OK]
)

echo | set /p=Disable Delivery Optimization 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d 4 /f > nul
echo [OK]

echo | set /p=Disable Program Compatibility Assistant 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d 4 /f > nul
echo [OK]

echo | set /p=Disable Windows Error Reporting 
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Disable Windows Tips 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Disable Windows Consumer Features (App Suggestions on Start) 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f > nul
echo [OK]

if not defined LTSB (
	echo | set /p=Disable ads on lock screen 
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f > nul
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" /v "LockImageFlags" /t REG_DWORD /d 0 /f > nul
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" /v "CreativeId" /t REG_SZ /d "" /f > nul
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" /v "PortraitAssetPath" /t REG_SZ /d "" /f > nul
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" /v "LandscapeAssetPath" /t REG_SZ /d "" /f > nul
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" /v "DescriptionText" /t REG_SZ /d "" /f > nul
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" /v "ActionText" /t REG_SZ /d "" /f > nul
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" /v "ActionUri" /t REG_SZ /d "" /f > nul
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" /v "PlacementId" /t REG_SZ /d "" /f > nul
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" /v "ClickthroughToken" /t REG_SZ /d "" /f > nul
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" /v "ImpressionToken" /t REG_SZ /d "" /f > nul
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" /v "HotspotImageFolderPath" /t REG_SZ /d "" /f > nul
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" /v "CreativeJson" /t REG_SZ /d "" /f > nul
	echo [OK]
)

echo | set /p=Disable File History 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Disable Active Help 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoActiveHelp" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Disable loggers 
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f > nul
echo [OK]

echo | set /p=Disable Windows Feedback 
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Disable Microsoft Help feedback 
reg add "HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Disable feedback on write 
reg add "HKLM\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f > nul
echo [OK]

echo | set /p=Disable lock screen camera 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Disable password reveal button 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Disable Windows Insider Program 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d 0 /f > nul
echo [OK]

echo | set /p=Disable DRM features 
reg add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Disable Office 2016 telemetry 
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" /v "Enablelogging" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" /v "EnableUpload" /t REG_DWORD /d 0 /f > nul
echo [OK]

if not defined LTSB (
	echo | set /p=Disable Adobe Flash Player in Microsoft Edge 
	reg add "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Addons" /v "FlashPlayerEnabled" /t REG_DWORD /d 0 /f > nul
	echo [OK]
)

echo | set /p=Disable Game DVR 
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f > nul
echo [OK]

echo | set /p=Disable Live Tiles 
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Disable AutoPlay and AutoRun 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Disable Remote Assistance 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d 0 /f > nul
echo [OK]

echo | set /p=Disable administrative shares 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d 0 /f > nul
echo [OK]

echo | set /p=Do not send Windows Media Player statistics 
reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f > nul
echo [OK]

echo | set /p=Remove 3D Builder from context menu 
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\.bmp\Shell\T3D Print" /f > nul 2>&1
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\.jpg\Shell\T3D Print" /f > nul 2>&1
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\.png\Shell\T3D Print" /f > nul 2>&1
echo [OK]

echo | set /p=Set default PhotoViewer 
reg add "HKCU\SOFTWARE\Classes\.ico" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f > nul
reg add "HKCU\SOFTWARE\Classes\.tiff" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f > nul
reg add "HKCU\SOFTWARE\Classes\.bmp" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f > nul
reg add "HKCU\SOFTWARE\Classes\.png" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f > nul
reg add "HKCU\SOFTWARE\Classes\.gif" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f > nul
reg add "HKCU\SOFTWARE\Classes\.jpeg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f > nul
reg add "HKCU\SOFTWARE\Classes\.jpg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f > nul
echo [OK]

echo | set /p=Turn off "You have new apps that can open this type of file" alert 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoNewAppAlert" /t REG_DWORD /d 1 /f > nul
echo [OK]

if not defined LTSB (
	echo | set /p=Turn off "Look For An App In The Store" option 
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d 1 /f > nul
	echo [OK]
)

echo | set /p=Open File Explorer to This PC instead of Quick Access 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Do not show recently used files in Quick Access 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d 0 /f > nul
echo [OK]

echo | set /p=Do not show frequently used folders in Quick Access 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d 0 /f > nul
echo [OK]

echo | set /p=Show hidden files, folders and drives in File Explorer 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Show file extensions in File Explorer 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f > nul
echo [OK]

echo | set /p=Launch folder windows in a separate process 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Auto-end non responsive tasks 
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f > nul
echo [OK]

echo | set /p=Maximize wallpaper quality 
reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d 100 /f > nul
echo [OK]

echo | set /p=Set icon cache size to 4096 KB 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /t REG_SZ /d "4096" /f > nul
echo [OK]

echo | set /p=Add Recycle Bin to Navigation Pane 
reg add "HKCU\SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Restore Classic Context Menu in Explorer 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\FlightedFeatures" /v "ImmersiveContextMenu" /t REG_DWORD /d 0 /f > nul
echo [OK]

echo | set /p=Set "Do this for all current items" checkbox by default in the file operation conflict dialog 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "ConfirmationCheckBoxDoForAll" /t REG_DWORD /d 1 /f > nul
echo [OK]

echo | set /p=Enable NTFS long paths 
reg add "HKLM\SYSTEM\CurrentControlSet\Policies" /v "LongPathsEnabled" /t REG_DWORD /d 1 /f > nul
echo [OK]



echo.
echo Deleting spyware tasks...
set spy_tasks=^
	"Microsoft\Office\Office 15 Subscription Heartbeat"^
	"Microsoft\Office\OfficeTelemetryAgentFallBack2016"^
	"Microsoft\Office\OfficeTelemetryAgentLogOn2016"^
	"Microsoft\Windows\AppID\SmartScreenSpecific"^
	"Microsoft\Windows\Application Experience\AitAgent"^
	"Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"^
	"Microsoft\Windows\Application Experience\ProgramDataUpdater"^
	"Microsoft\Windows\Application Experience\StartupAppTask"^
	"Microsoft\Windows\Autochk\Proxy"^
	"Microsoft\Windows\Clip\License Validation"^
	"Microsoft\Windows\CloudExperienceHost\CreateObjectTask"^
	"Microsoft\Windows\Customer Experience Improvement Program\BthSQM"^
	"Microsoft\Windows\Customer Experience Improvement Program\Consolidator"^
	"Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"^
	"Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"^
	"Microsoft\Windows\Device Information\Device"^
	"Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"^
	"Microsoft\Windows\Feedback\Siuf\DmClient"^
	"Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"^
	"Microsoft\Windows\License Manager\TempSignedLicenseExchange"^
	"Microsoft\Windows\Location\Notifications"^
	"Microsoft\Windows\Location\WindowsActionDialog"^
	"Microsoft\Windows\Maps\MapsToastTask"^
	"Microsoft\Windows\Maps\MapsUpdateTask"^
	"Microsoft\Windows\Media Center\ActivateWindowsSearch"^
	"Microsoft\Windows\Media Center\ConfigureInternetTimeService"^
	"Microsoft\Windows\Media Center\DispatchRecoveryTasks"^
	"Microsoft\Windows\Media Center\ehDRMInit"^
	"Microsoft\Windows\Media Center\InstallPlayReady"^
	"Microsoft\Windows\Media Center\mcupdate"^
	"Microsoft\Windows\Media Center\MediaCenterRecoveryTask"^
	"Microsoft\Windows\Media Center\ObjectStoreRecoveryTask"^
	"Microsoft\Windows\Media Center\OCURActivate"^
	"Microsoft\Windows\Media Center\OCURDiscovery"^
	"Microsoft\Windows\Media Center\PBDADiscovery"^
	"Microsoft\Windows\Media Center\PBDADiscoveryW1"^
	"Microsoft\Windows\Media Center\PBDADiscoveryW2"^
	"Microsoft\Windows\Media Center\PvrRecoveryTask"^
	"Microsoft\Windows\Media Center\PvrScheduleTask"^
	"Microsoft\Windows\Media Center\RegisterSearch"^
	"Microsoft\Windows\Media Center\ReindexSearchRoot"^
	"Microsoft\Windows\Media Center\SqlLiteRecoveryTask"^
	"Microsoft\Windows\Media Center\UpdateRecordPath"^
	"Microsoft\Windows\Maintenance\WinSAT"^
	"Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"^
	"Microsoft\Windows\RetailDemo\CleanupOfflineContent"^
	"Microsoft\Windows\SettingSync\BackgroundUploadTask"^
	"Microsoft\Windows\SettingSync\BackupTask"^
	"Microsoft\Windows\SettingSync\NetworkStateChangeTask"^
	"Microsoft\Windows\Shell\FamilySafetyMonitor"^
	"Microsoft\Windows\Shell\FamilySafetyMonitorToastTask"^
	"Microsoft\Windows\Shell\FamilySafetyRefresh"^
	"Microsoft\Windows\Shell\FamilySafetyRefreshTask"^
	"Microsoft\Windows\Speech\SpeechModelDownloadTask"^
	"Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"^
	"Microsoft\Windows\Windows Defender\Windows Defender Cleanup"^
	"Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"^
	"Microsoft\Windows\Windows Defender\Windows Defender Verification"^
	"Microsoft\Windows\Windows Error Reporting\QueueReporting"^
	"Microsoft\Windows\WindowsUpdate\Automatic App Update"^
	"Microsoft\Windows\WindowsUpdate\sih"^
	"Microsoft\Windows\WindowsUpdate\sihboot"^
	"Microsoft\Windows\WS\License Validation"^
	"Microsoft\Windows\WS\WSTask"^
	"Microsoft\XblGameSave\XblGameSaveTask"^
	"Microsoft\XblGameSave\XblGameSaveTaskLogon"
set tasks_dir=%SystemRoot%\System32\Tasks
for %%i in (%spy_tasks%) do (
	schtasks /query /tn %%i > nul 2>&1
	if not errorlevel 1 (
		echo | set /p=%%i
		schtasks /delete /tn %%i /f > nul
		set item=%%i
		set dir_path="%tasks_dir%\!item:~1!
		mkdir !dir_path!
		icacls !dir_path! /deny "Everyone:(OI)(CI)W" > nul
		set spy_task_deleted=1
		echo  [OK]
	)
)
if not defined spy_task_deleted (
	echo Spyware tasks already deleted.
)

set update_orchestrator_dir=%tasks_dir%\Microsoft\Windows\UpdateOrchestrator
if not exist %update_orchestrator_dir%\Reboot\ (
	echo.
	echo | set /p=Prevent Windows 10 reboots after installing updates... 
	schtasks /delete /tn "Microsoft\Windows\UpdateOrchestrator\Reboot" /f > nul 2>&1
	mkdir %update_orchestrator_dir%\Reboot
	icacls %update_orchestrator_dir%\Reboot /deny "Everyone:(OI)(CI)W" > nul
	echo OK.
)

taskkill /im explorer.exe /f
start explorer.exe

echo.
echo Finished.
pause