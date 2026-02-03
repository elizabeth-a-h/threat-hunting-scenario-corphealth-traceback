# Indicators of Compromise (IOCs) — CorpHealth: Traceback

## Overview

This document consolidates Indicators of Compromise (IOCs) identified during the CorpHealth: Traceback threat-hunting investigation. These indicators were derived through manual analysis of host, process, authentication, file, registry, and network telemetry.

The listed IOCs represent confirmed malicious artifacts, infrastructure, and accounts associated with unauthorized access, post-exploitation activity, and persistence mechanisms observed during the hunt.

---

## IOC Handling Notes

- All indicators originate from a controlled training scenario
- Timestamps reflect first observed or most relevant activity
- Indicators are organized by category to support detection engineering and incident response
- Some values may appear benign in isolation but are malicious in this context

---

## Host-Based Indicators

### Affected Systems

| Hostname | Role | Notes |
| --- | --- | --- |
| CH-OPS-WKS02 | Operations workstation | Primary compromised endpoint |

---

## Account Indicators

| Account Name | Type | Description |
| --- | --- | --- |
| chadmin | User account | Initial interactive access and reconnaissance |
| ops.maintenance | Privileged service account | Used for escalation, persistence, and tooling execution |

---

## File-Based Indicators

### Malicious / Suspicious Files

| File Name | File Path | Description |
| --- | --- | --- |
| revshell.exe | C:\Users\chadmin\revshell.exe | Unsigned executable staged via external tunnel |
| user-pass.txt | C:\Users\chadmin\Documents\ | Credential-containing file accessed post-logon |

### Persistence Locations

| Location | Purpose |
| --- | --- |
| C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\ | Startup persistence |

---

## Process Indicators

| Process Name | Context |
| --- | --- |
| explorer.exe | Used to launch attacker tooling |
| powershell.exe | Encoded command execution |
| curl.exe | External payload retrieval |
| ipconfig.exe | Post-compromise reconnaissance |
| revshell.exe | External C2 communication |

---

## Network Indicators

### External IP Addresses

| IP Address | Role | Notes |
| --- | --- | --- |
| 104.164.168.17 | Initial remote access IP | Used during early logon activity |
| 13.228.171.119 | C2 endpoint | Failed outbound connection attempts |

### Domains / URLs

| Indicator | Description |
| --- | --- |
| unresuscitating-donnette-smothery.ngrok-free.dev | External tunneling service used to stage payload |
| https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe | Payload download source |

### Network Characteristics

| Attribute | Value |
| --- | --- |
| Protocol | TCP / HTTPS |
| Nonstandard Port | 11746 |
| Tunnel Service | Ngrok |

---

## Registry Indicators

| Registry Path | Description |
| --- | --- |
| HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent | Suspicious key creation linked to persistence |

---

## Detection Opportunities

The following detection opportunities were identified based on IOC analysis:

- Unsigned executables written to user profile directories
- curl.exe usage on endpoints where it is not part of baseline operations
- Startup folder modifications by non-administrative processes
- Privileged account logons outside defined maintenance windows
- External tunnel services (e.g., ngrok) in corporate environments

---

## Related Artifacts

- Full investigation timeline: `/appendix/Timeline.md`
- MITRE ATT&CK mapping: `/appendix/MITRE_Mapping.md`
- Incident report: `/report/Incident_Report.md`

---

## Disclaimer

All indicators listed in this document are part of a simulated training environment and do not represent real-world production indicators.

