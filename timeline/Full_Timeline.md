# Full Investigation Timeline — CorpHealth: Traceback Threat Hunt

| Time (UTC) | Event | Details |
| --- | --- | --- |
| 2025-11-23T03:08:31Z | Earliest Suspicious Remote Logon | Account: chadmin, Remote Device: 对手 |
| 2025-11-23T03:08:52Z | First Process Launched Post-Logon | explorer.exe executed under chadmin session |
| 2025-11-23T03:11:00Z | First File Accessed | NOTEPAD.EXE opened `C:\Users\chadmin\Documents\CH-OPS-WKS02 user-pass.txt` |
| 2025-11-23T03:11:45Z | Next Action | ipconfig.exe executed to enumerate network configuration |
| 2025-11-23T03:43:03Z | Next Account Accessed | Successful logon as ops.maintenance |
| 2025-11-23T03:45:33Z | Maintenance Script Execution | Distributed.ps1 ran on CH-OPS-WKS02 |
| 2025-11-23T03:46:25Z | First PowerShell Encoded Command | Suspicious encoded PowerShell executed |
| 2025-11-23T03:46:37Z | Defender Exclusion Attempt | Attacker attempted to bypass endpoint protections |
| 2025-11-23T03:47:21Z | Privilege Escalation | Token and event manipulation command executed |
| 2025-11-25T04:14:07Z | Privilege Token Modification | Elevated privileges confirmed on CH-OPS-WKS02 |
| 2025-11-25T04:14:40Z | Registry Key Created | `HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent` |
| 2025-11-25T04:15:02Z | File Created | `C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv` |
| 2025-11-25T04:15:26Z | Scheduled Task Created | First scheduled task for persistence created |
| 2025-11-30T01:03:17Z | Outbound Connection | CH-OPS-WKS02 connected to beacon IP on nonstandard port (ConnectionSuccess) |
| 2025-12-02T12:17:07Z | Staged Binary Written | `revshell.exe` dropped to disk |
| 2025-12-02T12:17:07Z | External Source Identified | Downloaded from `https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe` |
| 2025-12-02T12:30:25Z | Execution of Staged Binary | revshell.exe launched by explorer.exe |
| 2025-12-02T12:57:50Z | Failed Outbound Attempt | revshell.exe attempted connection to 13.228.171.119 on port 11746 |
