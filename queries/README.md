# Threat Hunt Queries — CorpHealth: Traceback

## Overview

This directory documents the investigative queries developed and executed during the **CorpHealth: Traceback** threat hunt. The Query Index below serves as a reference for the full set of Kusto Query Language (KQL) used during the investigation.

Associated screenshot images provide visual evidence captured during the hunt, including query execution, results, and verification steps. These screenshots serve as supporting documentation and preserve investigative context.

Rather than relying on a single alert or predefined detection, the investigation progressed through a series of iterative, hypothesis-driven queries. Each query was used to validate findings, pivot to related telemetry, or eliminate benign explanations as the hunt evolved.

---

## Contents

- [Overview](#overview)
- [Query Philosophy](#query-philosophy)
- [Query Organization](#query-organization)
- [Using These Queries](#using-these-queries)
- [Notes](#notes)
- [Query Index](#query-index)

---

## Query Philosophy

In real-world threat hunting, analysts rarely know the full scope of activity at the outset. Queries are written to:

- Confirm or refute hypotheses  
- Narrow suspicious time windows  
- Pivot between hosts, accounts, processes, and network activity  
- Add context to previously identified indicators  
- Reconstruct attacker intent and sequencing  

Many queries are intentionally narrow, designed to answer a single investigative question before progressing to the next step.

---

## Query Organization

Queries are numbered sequentially to reflect the investigative flow of the hunt rather than strict MITRE ATT&CK phase boundaries.

General progression:

1. **Initial Access & Environment Validation**  
   - Identify suspicious logons and validate host identity  
   - Establish the earliest abnormal activity  

2. **Execution & Process Analysis**  
   - Inspect script execution and manual process launches  
   - Compare behavior against expected automation baselines  

3. **Network Activity & External Connectivity**  
   - Identify outbound connections to non-corporate infrastructure  
   - Validate tunneling and command-and-control behavior  

4. **Credential Access & Privilege Exploration**  
   - Detect access to credential-related files and registry keys  
   - Identify privilege escalation attempts  

5. **Payload Staging & Persistence**  
   - Track file creation, modification, and execution  
   - Identify startup folder placement and registry-based persistence  

6. **Correlation & Timeline Reconstruction**  
   - Align logon events, processes, files, and network activity  
   - Reconstruct the full attack chain  

---

## Using These Queries

Queries are preserved as written and documented inline to reflect authentic analyst workflow, including pivots, refinements, and contextual validation. Screenshots capture execution results and investigative decision points.

Readers are encouraged to:

- Review queries in numerical order to follow the hunt progression  
- Reference the investigation timeline and incident report for context  
- Adapt queries for their own threat-hunting labs or environments  

---

## Notes

- Queries were executed against a **Log Analytics Workspace** using Kusto Query Language (KQL).
- Screenshots are provided to preserve investigative context and observable telemetry at the time of analysis.
- Queries were written and executed manually to support hypothesis-driven investigation rather than automated alerting.

This directory is intended to showcase **how analysts think**, not just what they detect.

---

## Query Index

---

## 01 – Identify Unique Maintenance Script Executed on CH-OPS-WKS02

**Purpose:**  
Identify non-standard script execution activity on CH-OPS-WKS02 associated with an administrative account during the investigation window.

**Query ID:**  
01-CorpHealth-Query1

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-26))
| where DeviceName == "ch-ops-wks02"
| where ProcessCommandLine has_any (".ps1", ".bat", ".cmd", ".vbs")
| where InitiatingProcessAccountName contains "chadmin"
| where InitiatingProcessAccountName !startswith "NT AUTHORITY"
| where InitiatingProcessAccountName !startswith "SYSTEM"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated asc
```
**Result:**  
This query identified a script uniquely executed on CH-OPS-WKS02 during the investigation window by an administrative account. The activity differed from routine maintenance behavior observed across other endpoints, warranting further investigation.


---

## 02 & 03 First Outbound Network Activity Following Maintenance Script Execution

**Purpose:**  
First Outbound Network Activity Following Maintenance Script Execution
Query 2 and Query 3 were used to identify the earliest outbound network communication from PowerShell on CH-OPS-WKS02 occurring immediately after execution of the maintenance script to determine when the script first initiated external connectivity.

**Query ID:**  
02-CorpHealth-Query2
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-01))
| where DeviceName == "ch-ops-wks02"
| where ProcessCommandLine has "Distributed.ps1"
| order by TimeGenerated asc
| project TimeGenerated

```
**Result:**  The earliest execution of the Distributed.ps1 maintenance script during the investigation window occurred at:2025-11-23T03:45:33.7232323Z
This timestamp was used as the anchor point for subsequent outbound network analysis.

---

**Query Executed 03-CorpHealth Query3: Outbound Network Activity Following Script Execution**
```kql
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessFileName == "powershell.exe"
| where TimeGenerated > datetime(2025-11-23T03:45:33.7232323Z)
| order by TimeGenerated asc
| project TimeGenerated, ActionType, RemoteIP

```
**Result:**  The first outbound network communication initiated by PowerShell after script execution occurred at:2025-11-23T03:46:08.400686Z
This confirmed that the maintenance script initiated external connectivity immediately following execution.


---
## 04 - Outbound Beacon Remote Endpoint

**Purpose:**  
 Identify Outbound Beacon Remote IP Endpoint

**Query ID:**  
04-CorpHealth-Query4
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-12-01))
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine has "Distributed.ps1"
| project TimeGenerated, InitiatingProcessCommandLine, RemoteIP, RemotePort, ActionType
| order by TimeGenerated asc 

```
**Result:**  The script attempted outbound connections to the following endpoint:
127.0.0.1:8080 This non-standard destination is inconsistent with approved CorpHealth infrastructure.


---
## 05 – Determine the Most Recent Successful Connection to Beacon Endpoint

**Purpose:**  
 Identify Time of most recent successful connection to outbound beacon Remote IP Endpoint

**Query ID:**  
05-CorpHealth-Query5

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-12-01))
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine has "Distributed.ps1"
| where ActionType == "ConnectionSuccess"
| where RemoteIP == "127.0.0.1"
| where RemotePort == "8080"
| project TimeGenerated, InitiatingProcessCommandLine, RemoteIP, RemotePort, ActionType
| sort by TimeGenerated desc 

```
**Result:**  The most recent successful connection to the beacon endpoint occurred at:
2025-11-30T01:03:17.6985973Z

---
## 06 – First Staged Artifact Created by Attacker

**Purpose:**  
Identifies the first file created under CorpHealth by the Distributed.ps1 script on CH-OPS-WKS02, representing the primary artifact the attacker staged for collection or manipulation.

**Query ID:**  
06-CorpHealth Query6
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-12-10))
| where ActionType == "FileCreated"
| where DeviceName == "ch-ops-wks02"
| where FolderPath has "CorpHealth"
| where InitiatingProcessCommandLine has "Distributed.ps1" 
| project TimeGenerated, FullPath = strcat(FolderPath, "\\", FileName), InitiatingProcessCommandLine
| order by TimeGenerated asc
| take 10

```
**Result:**  The first staged artifact created was C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv\inventory_6ECFD4DF.csv

---
## 07 – SHA256 of First Staged Artifact

**Purpose:**  
Retrieves the SHA256 hash of the first file created by the Distributed.ps1 script under CorpHealth on CH-OPS-WKS02 to uniquely identify the primary staged artifact.

**Query ID:** 
07-CorpHealth Query7
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-12-10))
| where ActionType == "FileCreated"
| where DeviceName == "ch-ops-wks02"
| where FolderPath has "CorpHealth"
| where InitiatingProcessCommandLine has "Distributed.ps1" 
| project TimeGenerated, FullPath = strcat(FolderPath, "\\", FileName), InitiatingProcessCommandLine, SHA256
| order by TimeGenerated asc
| take 10


```
**Result:**  SHA256 hash of the primary staged artifact: 7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8

---
## 08 – Secondary Inventory Staging File Identification

**Purpose:**  
Identifies an additional inventory file created by the Distributed.ps1 script on CH‑OPS‑WKS02 with a similar name and timeframe but a different SHA‑256 hash, indicating an alternate attacker staging location.

**Query ID:** 
08-CorpHealth Query8
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-12-10))
| where ActionType == "FileCreated"
| where DeviceName == "ch-ops-wks02"
| where FolderPath has "CorpHealth"
| where FolderPath has "inventory"
| where InitiatingProcessCommandLine has "Distributed.ps1" 
| project TimeGenerated, FullPath = strcat(FolderPath, "\\", FileName), InitiatingProcessCommandLine, SHA256
| order by TimeGenerated asc
| take 10

```
**Result:**  A secondary staging artifact was identified at: C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv\inventory_tmp_6ECFD4DF.csv39f12d8


---
## 09 – Suspicious PowerShell Registry Modification (Credential Harvesting Simulation)

**Purpose:**  
Identifies registry keys created or modified on ch-ops-wks02 by a specific PowerShell execution associated with the attacker’s staging activity, highlighting anomalous registry interaction consistent with credential-harvesting behavior.

**Query ID:** 
09-CorpHealth Query9
```kql
DeviceRegistryEvents
| where ActionType == "RegistryKeyCreated"
 or ActionType == "RegistryValueSet"
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-26)) 
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine contains "Distributed.ps1"
| project TimeGenerated, ActionType, RegistryKey, InitiatingProcessCommandLine

```
**Result:**  The following registry key was created during script execution: HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent

---
## 10 – Unauthorized Scheduled Task Creation via Registry Persistence 

**Purpose:**  
Identifies newly created scheduled task registry keys on ch-ops-wks02 during the attack window and highlights the first non-baseline (non-Microsoft) task consistent with attacker persistence activity.

**Query ID:** 
010-CorpHealth Query10
```kql
DeviceRegistryEvents
| where ActionType == "RegistryKeyCreated"
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26)) 
| where DeviceName == "ch-ops-wks02"
| where RegistryKey contains @"TaskCache\Tree"
| extend TaskName = tostring(split(RegistryKey, @"TaskCache\Tree\")[1])
| project TimeGenerated, TaskName, ActionType, RegistryKey, InitiatingProcessCommandLine
| order by TimeGenerated asc 

```
**Result:**  The first non-baseline scheduled task created during the attack was: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64

---
## 11 – Ephemeral Run-Key Persistence Detection

**Purpose:**  
Identifies the registry value in a Run key created or modified by PowerShell on ch-ops-wks02, revealing the attacker’s short-lived startup persistence attempt.

**Query ID:** 
11-CorpHealth Query11
```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-23T04:15:26.9010509Z) .. datetime(2025-11-30)) 
| where DeviceName == "ch-ops-wks02"
| where ActionType == "RegistryValueSet"
 or ActionType == "RegistryValueCreated"
| where RegistryValueData contains "powershell.exe"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
| order by TimeGenerated asc

```
**Result:**  A new Run key value was created for transient persistence:
Registry Value Name: MaintenanceRunner


---
## 12 – Privilege Escalation 

**Purpose:**  
Identifies the time of the first privilege escalation event. 

**Query ID:** 
12-CorpHealth Query12
```kql
DeviceEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-05T01:00:00Z) .. datetime(2025-12-05T01:10:00Z))
| where AdditionalFields contains "ConfigAdjust"
| project TimeGenerated, ActionType, AdditionalFields
| order by TimeGenerated asc

```
**Result:**  The first privilege escalation event occurred at: 2025-11-23T03:47:21.8529749Z

---
## 13 – AV Exclusion Attempt

**Purpose:**  
This query identifies processes on CH-OPS-WKS02 that attempted to add exclusions in Windows Defender by filtering for command lines containing “Exclusion” and showing the relevant timestamps and command details.

**Query ID:** 
13-CorpHealth Query13
```kql
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-05) .. datetime(2025-11-26))
| where InitiatingProcessCommandLine contains "Exclusion"
| project TimeGenerated, AdditionalFields, InitiatingProcessCommandLine
| order by TimeGenerated asc 

```
**Result:**  The attacker attempted to add the following folder as a Defender exclusion: C:\ProgramData\Corp\Ops\staging -Force

---
## 14 - Decode First PowerShell EncodedCommand Execution

**Purpose:**  
This query identifies the first PowerShell process executed with -EncodedCommand by the ops.maintenance account on CH-OPS-WKS02, extracts the Base64 string from the command line, and decodes it to reveal the plaintext PowerShell command.

**Query ID:** 
14-CorpHealth Query14
```kql
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-05) .. datetime(2025-12-05))
| where AccountName == "ops.maintenance"
| where InitiatingProcessCommandLine contains "-EncodedCommand"
| project TimeGenerated, InitiatingProcessCommandLine, ProcessCommandLine
| extend Enc = extract(@"-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, InitiatingProcessCommandLine)
| extend Decoded = base64_decode_tostring(Enc)
| order by TimeGenerated asc 

```
**Result:**  The first decoded PowerShell command was: Write-Output 'token-6D5E4EE08227'

---
## 15 – Identify Process Responsible for Privilege Token Modification

**Purpose:**  
This query filters DeviceEvents on CH-OPS-WKS02 to locate PowerShell-driven events where token privileges were modified, allowing identification of the InitiatingProcessId responsible for the ProcessPrimaryTokenModified activity.

**Query ID:** 
15-CorpHealth Query15
```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-05) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessAccountName == "ops.maintenance"
| where AdditionalFields contains "tokenChangeDescription"
 or AdditionalFields contains "Privileges were added"
| where InitiatingProcessCommandLine contains "powershell.exe"
| order by TimeGenerated asc 


```
**Result:**  The process responsible for token privilege modification had: InitiatingProcessID: 4888.

---

## 16 – Extract Modified Token User SID from Token Privilege Change Event

**Purpose:**  
Locate the security identifier (SID) that the modified token belongs to.

**Query ID:** 
16-CorpHealth Query16
```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-05) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessAccountName == "ops.maintenance"
| where AdditionalFields contains "tokenChangeDescription"
| where InitiatingProcessCommandLine contains "powershell.exe"
| extend AF = parse_json(AdditionalFields)
| extend OriginalTokenUserSid = tostring(AF.OriginalTokenUserSid)
| project TimeGenerated, InitiatingProcessId, OriginalTokenUserSid
| order by TimeGenerated asc

```
**Result:**  The modified token belonged to the following SID: S-1-5-21-1605642021-30596605-784192815-1000

---

## 17 – Ingress Executable Written to Disk via curl.exe

**Purpose:**  
This query identifies executable files written to disk by curl.exe on CH-OPS-WKS02, filtering specifically for .exe payloads created in a user profile directory immediately following outbound transfer activity. It isolates ingress tooling delivered directly from an external source rather than legitimate installer behavior.

**Query ID:** 
17-CorpHealth Query17
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-02) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| where ActionType == "FileCreated"
| where InitiatingProcessFileName == "curl.exe"
| where FileName endswith ".exe"
| where FolderPath startswith @"C:\Users\"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc


```
**Result:**  The executable that was written to disk after the outbound request was: revshell.exe


---

## 18 – External Dynamic Tunnel Used to Download Post-Escalation Tooling
**Purpose:**  
This query identifies executable files written to a user directory by curl.exe, allowing the external download URL to be extracted directly from the initiating command line.
The command line reveals the exact remote source used to stage attacker tooling.


**Query ID:** 
18-CorpHealth Query18
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-02) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| where ActionType == "FileCreated"
| where InitiatingProcessFileName == "curl.exe"
| where FileName endswith ".exe"
| where FolderPath startswith @"C:\Users\"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc


```
**Result:**  The file was retrieved from the following external URL: https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe

---

## 19 – Execution of Unsigned Binary from User Profile Directory
**Purpose:**  
This query identifies the first execution of the downloaded unsigned binary and reveals the parent process responsible for launching it.


**Query ID:** 
19-CorpHealth Query19
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-02T12:17:07.718921Z) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessFileName == "revshell.exe"
| project TimeGenerated, InitiatingProcessParentFileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc


```
**Result:**  The binary was executed by the following parent process: explorer.exe

---

## 20 – Identify the External IP Contacted by the Executable
**Purpose:**  
This query identifies failed outbound TCP connection attempts initiated by the malicious executable after execution, revealing the external IP it attempted to contact on a high, non-standard port.


**Query ID:** 
20-CorpHealth Query20
```kql

DeviceNetworkEvents 
| where TimeGenerated between (datetime(2025-12-02T12:17:07.718921Z) .. datetime(2025-12-05)) 
| where DeviceName == "ch-ops-wks02" 
| where InitiatingProcessFileName == "revshell.exe" 
| where ActionType in ("ConnectionFailed", "ConnectionAttempted")
| where RemotePort == 11746
| project TimeGenerated, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, LocalIP, RemotePort 
| sort by TimeGenerated asc

```
**Result:**  The executable attempted outbound connections to the following external IP: 13.228.171.119


---

## 21 – Persistence via Startup Folder Executable Placement
**Purpose:**  
This query identifies malicious persistence by detecting an executable written into a Windows Startup directory under ProgramData, a location that ensures automatic execution at user logon.

**Query ID:** 
21-CorpHealth Query21
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-02) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| where FileName endswith ".exe"
| where FolderPath startswith @"c:\programdata\"
| where FolderPath contains "Start"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc

```
**Result:**  The attacker established persistence by placing the executable in: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe

---

## 22 part 1: Recognition Query- Identify the remote session associated with confirmed malicious persistence activity.
**Purpose:**  
Correlate attacker activity to a specific remote session identifier and validate that the same remote session label is consistently present across file, process, and network telemetry during the attack window.

**Query ID:** 
22-CorpHealth Query22
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-02) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| where FileName endswith ".exe"
| where FolderPath startswith @"c:\programdata\"
| where FolderPath contains "Start"
| project TimeGenerated, InitiatingProcessRemoteSessionDeviceName, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc

```
**Result:**  Remote session label associated with the attacker’s activity: 对手

---

## 22 part 2 – File Event Validation- File Event Validation for Remote Session Consistency

**Purpose:**  
This query summarizes file system events by InitiatingProcessRemoteSessionDeviceName to determine whether the same remote session appears consistently across file operations on the host during the attack window.


**Query ID:** 
22-CorpHealth Query22 part 2
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-02) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| summarize Count = count() by InitiatingProcessRemoteSessionDeviceName
| order by Count desc


```
**Result:** Remote session label prevalence in file telemetry: 对手 observed 216 times

---

## 22 part 3 – Process Event Validation- Validate that the same remote session initiated process executions

**Purpose:**  
This query aggregates process execution events by remote session identifier, confirming that process launches (including attacker tooling) were driven by the same interactive session.


**Query ID:** 
22-CorpHealth Query22 part 3
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-02) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| summarize Count = count() by InitiatingProcessRemoteSessionDeviceName
| order by Count desc

```
**Result:** Validate that the same remote session initiated process executions: 对手 observed 56 times

---

## 22 part 4 – Network Event Validation- Network Event Validation for Remote Session Consistency

**Purpose:**  
This query summarizes network telemetry by InitiatingProcessRemoteSessionDeviceName, demonstrating that external communication attempts were initiated from the same session observed in file and process activity.

**Query ID:** 
22-CorpHealth Query22 part 4
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-02) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| project InitiatingProcessRemoteSessionDeviceName
| summarize Count = count() by InitiatingProcessRemoteSessionDeviceName
| order by Count desc

```
**Result:**  Remote session label prevalence in network telemetry: 对手 obsesrved 99 times

---

## 23 – Identify the Remote Session IP Address

**Purpose:**  
Identifies the source IP addres for the remote session tied to the attacker's activity. 

**Query ID:** 
23-CorpHealth Query23
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-02) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| where FileName endswith ".exe"
| where FolderPath startswith @"c:\programdata\"
| where FolderPath contains "Start"
| project TimeGenerated, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc

```
**Result:** Remote session source IP observed during attacker activity: 100.64.100.6

---


## 24 – Identification of Internal Pivot Host via Remote Session Metadata

**Purpose:**  
This query extracts unique remote session IP addresses associated with attacker activity on CH-OPS-WKS02, excluding CGNAT relay addresses and isolating internal Azure-range IPs indicative of an internal pivot host. 

**Query ID:** 
24-CorpHealth Query24
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-02) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| where isnotempty(InitiatingProcessRemoteSessionIP)
| where InitiatingProcessRemoteSessionIP startswith "10."
| where not(InitiatingProcessRemoteSessionIP startswith "100.64.")
| distinct InitiatingProcessRemoteSessionIP

```
**Result:** Internal pivot IP identified: 10.168.0.6

---

## 25 – Earliest Suspicious Remote Logon Event

**Purpose:**  
This query filters CH-OPS-WKS02 logon events to exclude system and background accounts, focusing on successful remote logons from a specific remote session device to determine the earliest suspicious access by the attacker.

**Query ID:** 
25-CorpHealth Query25
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| where RemoteDeviceName contains "对手"
| where ActionType == "LogonSuccess"
| where AccountName !startswith "DWM-"
| where AccountName !startswith "UMFD-"
| where AccountName !in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| order by TimeGenerated asc
| project TimeGenerated, AccountName, LogonType, RemoteIP, RemoteDeviceName


```
**Result:** Internal pivot IP identified: 2025-11-23T03:08:31.1849379Z

---

## 26 – IP address associated with the earliest suspicious logon

**Purpose:**  
This query filters for 104.164.168.17 logons to verify the earliest instance from this IP address

**Query ID:** 
26-CorpHealth Query26
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| where RemoteDeviceName contains "对手"
| where ActionType == "LogonSuccess"
| where AccountName !startswith "DWM-"
| where AccountName !startswith "UMFD-"
| where AccountName !in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| where RemoteIP == "104.164.168.17"
| order by TimeGenerated asc
| project TimeGenerated, AccountName, LogonType, RemoteIP, RemoteDeviceName


```
**Result:** Public source IP associated with attacker logons: 104.164.168.17

---

## 27 – Attacker Geolocation Analysis 

**Purpose:**  
This query enriches the suspicious remote logon IP (104.164.168.17) using geo_info_from_ip_address() to identify the country, region, and city from which the attacker accessed CH-OPS-WKS02. 

**Query ID:** 
27-CorpHealth Query27
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| where RemoteDeviceName contains "对手"
| where ActionType == "LogonSuccess"
| where AccountName !startswith "DWM-"
| where AccountName !startswith "UMFD-"
| where AccountName !in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| where RemoteIP == "104.164.168.17"
| extend Geo = geo_info_from_ip_address(RemoteIP)
| order by TimeGenerated asc
| project TimeGenerated, Geo, AccountName, LogonType, RemoteIP, RemoteDeviceName

```
**Result:** Geolocation enrichment indicated attacker origin: Vietnam


---

## 28 – First Process Launched Post-Attacker Logon

**Purpose:**  
This query identifies the first process executed by the attacker on CH-OPS-WKS02 immediately after their initial login by filtering DeviceProcessEvents for the attacker’s account and remote session, then sorting by timestamp ascending.

**Query ID:** 
28-CorpHealth Query28
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23T03:08:31.1849379Z) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| where AccountName == "chadmin"
| where InitiatingProcessRemoteSessionDeviceName contains "对手"
| project TimeGenerated, AccountName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, ProcessCommandLine, ProcessRemoteSessionDeviceName
| order by TimeGenerated asc


```
**Result:** The first process launched by the attacker immediately after logging in was explorer.exe

---


## 29 – First File Accessed by Attacker After Initial Logon

**Purpose:**  
This query identifies the first file accessed by the attacker after logging in by pivoting from the initial attacker process ID and examining subsequent GUI-based process executions for file paths referenced in their command lines.

**Query ID:** 
29-CorpHealth Query29
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23T03:08:31.1849379Z) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| where AccountName == "chadmin"
| where InitiatingProcessId == 5732
| where InitiatingProcessRemoteSessionDeviceName contains "对手"
| project TimeGenerated, ProcessCommandLine, AccountName, FileName, FolderPath, ProcessId, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, ProcessRemoteSessionDeviceName
| order by TimeGenerated asc
| take 10


```
**Result:** First file opened after attacker logon:
C:\Users\chadmin\Documents\CH-OPS-WKS02 user-pass.txt (opened via NOTEPAD.EXE)

---

## 30 – Attacker’s First Post-File-Access Action

**Purpose:**  
This query identifies the attacker’s next action after reading a file by examining the earliest process executions tied to the same remote session and account immediately following the file-access timestamp.

**Query ID:** 
30-CorpHealth Query30**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23T03:11:00.6981995Z) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| where AccountName == "chadmin"
| where InitiatingProcessRemoteSessionDeviceName contains "对手"
| project TimeGenerated, ProcessCommandLine, AccountName, FileName, FolderPath, ProcessId, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, ProcessRemoteSessionDeviceName
| order by TimeGenerated asc
| take 10


```
**Result:** Next attacker action observed: "ipconfig.exe"


---

## 31 – Next User Account Accessed After Initial Reconnaissance

**Purpose:**  
This query identifies the first successful logon event occurring immediately after the attacker’s enumeration activity, revealing the next user account the attacker accessed as they shifted from recon to credentialed interaction.

**Query ID:** 
31-CorpHealth Query31
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-23T03:11:45.1631084Z) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| where RemoteDeviceName == "对手"
| where ActionType == "LogonSuccess"
| where AccountName !in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| project TimeGenerated, AccountName, RemoteDeviceName, RemoteIP
| order by TimeGenerated asc
| take 10


```
**Result:** Next attacker action observed: ops.maintenance




