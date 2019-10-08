:: SCHEDULED TASKS

:: Privacy - Disable telemetry scheduled tasks.
:: Disable Customer Experience Improvement Program (CEIP) tasks.
schtasks /change /tn "\Microsoft\Windows\Autochk\Proxy" /disable
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /change /tn "\Microsoft\Windows\PI\Sqm-Tasks" /disable

:: Disable setting sync tasks.
schtasks /change /tn "\Microsoft\Windows\SettingSync\BackgroundUploadTask" /disable
schtasks /change /tn "\Microsoft\Windows\SettingSync\BackupTask" /disable
schtasks /change /tn "\Microsoft\Windows\SettingSync\NetworkStateChangeTask" /disable

:: Disable Windows Error Reporting task.
schtasks /change /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable

:: Disable Office subscription heartbeat task.
schtasks /change /tn "\Microsoft\Office\Office 15 Subscription Heartbeat" /disable

:: Optional - Disable SmartScreen data collection task.
:: schtasks /change /tn "\Microsoft\Windows\AppID\SmartScreenSpecific" /disable
