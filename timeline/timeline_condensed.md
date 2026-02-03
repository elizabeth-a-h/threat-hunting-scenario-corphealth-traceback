# Condensed Investigation Timeline — CorpHealth: Traceback Threat Hunt

This high-level timeline highlights the most significant events during the attack:

| Time (UTC) | Event |
| --- | --- |
| 2025-11-23T03:08:31Z | First suspicious remote logon detected (chadmin) |
| 2025-11-23T03:08:52Z | Initial process launched (explorer.exe) |
| 2025-11-23T03:11:00Z | First file accessed: `user-pass.txt` |
| 2025-11-23T03:11:45Z | Reconnaissance executed: ipconfig.exe |
| 2025-11-23T03:43:03Z | Lateral account access: ops.maintenance |
| 2025-11-23T03:45:33Z | Suspicious maintenance script executed (Distributed.ps1) |
| 2025-11-23T03:46:25Z | PowerShell encoded command executed |
| 2025-11-23T03:46:37Z | Attempted Defender exclusion |
| 2025-11-23T03:47:21Z | Privilege escalation activities |
| 2025-11-25T04:14:07Z | Privilege token modification confirmed |
| 2025-11-25T04:15:02Z | File created for staging/exfiltration |
| 2025-12-02T12:17:07Z | External binary staged and downloaded |
| 2025-12-02T12:30:25Z | Staged binary executed (revshell.exe) |
| 2025-12-02T12:57:50Z | Failed outbound C2 connection attempt |
