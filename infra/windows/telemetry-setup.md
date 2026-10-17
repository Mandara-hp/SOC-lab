# WS01 telemetry setup (Windows 11 ARM)

Reproducible record of the endpoint logging configured in Phase 1.
Run all of this in an elevated PowerShell on WS01.

## 1. Audit policy (Security log)
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable
    auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
    auditpol /set /subcategory:"Special Logon" /success:enable
    auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
    auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

## 2. Command line in 4688 (critical)
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

## 3. PowerShell logging (4104 + module)
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" EnableScriptBlockLogging 1
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" EnableModuleLogging 1

## 4. Sysmon (ARM build)
- Binary: Sysmon64a.exe  (the x64 driver is BLOCKED on Win11 ARM)
- Config: SwiftOnSecurity baseline (github.com/SwiftOnSecurity/sysmon-config)
- Install: .\Sysmon64a.exe -accepteula -i sysmonconfig.xml
- TODO (learning task): read + tune the config, document 3 changes, commit the tuned sysmonconfig.xml here.

## Events now flowing
4688 (process+cmdline), 4624/4634/4672 (logon), 4720/4728 (accounts),
4104 (PowerShell), Sysmon 1/3/11/13/22 (process/network/file/registry/dns)
