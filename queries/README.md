# Threat Hunt Queries — CorpHealth: Traceback

## Overview

This directory contains the complete set of Kusto Query Language (KQL) queries developed and executed during the CorpHealth: Traceback threat hunt.

Rather than relying on a single alert or predefined detection, the investigation progressed through a series of iterative, hypothesis-driven queries. Each query was used to validate findings, pivot to related telemetry, or eliminate benign explanations as the hunt evolved.

---

## Query Philosophy

In real-world threat hunting, analysts rarely know the full scope of activity at the outset. Queries are written to:

- Confirm or refute hypotheses  
- Narrow suspicious time windows  
- Pivot between hosts, accounts, processes, and network activity  
- Add context to previously identified indicators  
- Reconstruct attacker intent and sequencing  

Many queries are intentionally narrow, designed to answer a single investigative question before moving to the next step.

---

## Query Organization

Queries are numbered sequentially to reflect the investigative flow of the hunt rather than MITRE phase boundaries.

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

Each `.kql` file represents a point-in-time investigative step. Queries are intentionally preserved as-written to reflect authentic analyst workflow, including pivots, refinements, and contextual validation.

Readers are encouraged to:

- Review queries in numerical order to follow the hunt progression  
- Reference the investigation timeline and report for context  
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
## 01-CorpHealth Query1 – Identify Unique Maintenance Script Executed on CH-OPS-WKS02

**Purpose:**  
 Identify Unique Maintenance Script Executed on CH-OPS-WKS02

**Query Executed:01-CorpHealth Query1**
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
**Result:**  This query identified a script uniquely executed on CH-OPS-WKS02 during the maintenance window by an administrative account, distinguishing it from routine maintenance activity observed across other endpoints.


---

## 02-CorpHealth Query2 & 03-CorpHealth Query3- First Outbound Network Activity Following Maintenance Script Execution

**Purpose:**  
First Outbound Network Activity Following Maintenance Script Execution
Query 2 and Query 3 were used to identify the earliest outbound network communication from PowerShell on CH-OPS-WKS02 occurring immediately after execution of the maintenance script to determine when the script first initiated external connectivity.

**Query Executed 02-CorpHealth Query2: Maintenance Script Execution Timeline**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-01))
| where DeviceName == "ch-ops-wks02"
| where ProcessCommandLine has "Distributed.ps1"
| order by TimeGenerated asc
| project TimeGenerated

```
**Result:**  Retrieves all execution events of the Distributed.ps1 maintenance script on CH-OPS-WKS02 during the observation window to determine when the script ran. Results timestamp = 2025-11-23T03:45:33.7232323Z

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
**Result:**  Final Results indicate that the earliest outbound network communication from PowerShell on CH-OPS-WKS02 occurred immediately after the execution of the maintenance script. The script first initiated external connectivity= 2025-11-23T03:46:08.400686Z


---
## 04-CorpHealth Query4 – Outbound Beacon Remote Endpoint

**Purpose:**  
 Identify Outbound Beacon Remote IP Endpoint

**Query Executed:04-CorpHealth Query4**
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-12-01))
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine has "Distributed.ps1"
| project TimeGenerated, InitiatingProcessCommandLine, RemoteIP, RemotePort, ActionType
| order by TimeGenerated asc 

```
**Result:**  The remote IP and port that CH-OPS-WKS02 attempted to connect to during the beacon event was: 127.0.0.1:8080



---
## 05-CorpHealth Query5 – Determine the Most Recent Successful Connection to Beacon Endpoint

**Purpose:**  
 Identify Time of most recent successful connection to outbound beacon Remote IP Endpoint

**Query Executed:05-CorpHealth Query5**
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
**Result:**  2025-11-30T01:03:17.6985973Z

---
## 06-CorpHealth Query6 – First Staged Artifact Created by Attacker

**Purpose:**  
Identifies the first file created under CorpHealth by the Distributed.ps1 script on CH-OPS-WKS02, representing the primary artifact the attacker staged for collection or manipulation.

**Query Executed:06-CorpHealth Query6**
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
**Result:**  C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv\inventory_6ECFD4DF.csv

---
## 07-CorpHealth Query7 – SHA256 of First Staged Artifact

**Purpose:**  
Retrieves the SHA256 hash of the first file created by the Distributed.ps1 script under CorpHealth on CH-OPS-WKS02 to uniquely identify the primary staged artifact.

**Query Executed:07-CorpHealth Query7**
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
**Result:**  7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8

---
## 08-CorpHealth Query8 – Secondary Inventory Staging File Identification

**Purpose:**  
Identifies an additional inventory file created by the Distributed.ps1 script on CH‑OPS‑WKS02 with a similar name and timeframe but a different SHA‑256 hash, indicating an alternate attacker staging location.

**Query Executed:08-CorpHealth Query8**
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
**Result:**  The file path of the second file created by the Distributed.ps1 script is: C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv\inventory_tmp_6ECFD4DF.csv39f12d8




---
## 09-CorpHealth Query9 – Suspicious PowerShell Registry Modification (Credential Harvesting Simulation)

**Purpose:**  
Identifies registry keys created or modified on ch-ops-wks02 by a specific PowerShell execution associated with the attacker’s staging activity, highlighting anomalous registry interaction consistent with credential-harvesting behavior.

**Query Executed:09-CorpHealth Query9**
```kql
DeviceRegistryEvents
| where ActionType == "RegistryKeyCreated"
 or ActionType == "RegistryValueSet"
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-26)) 
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine contains "Distributed.ps1"
| project TimeGenerated, ActionType, RegistryKey, InitiatingProcessCommandLine


```
**Result:**  HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent

---
## 10-CorpHealth Query10 – Unauthorized Scheduled Task Creation via Registry Persistence 

**Purpose:**  
Identifies newly created scheduled task registry keys on ch-ops-wks02 during the attack window and highlights the first non-baseline (non-Microsoft) task consistent with attacker persistence activity.

**Query Executed:010-CorpHealth Query10**
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
**Result:**  HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64

---
## 11-CorpHealth Query11 – Ephemeral Run-Key Persistence Detection

**Purpose:**  
Identifies the registry value in a Run key created or modified by PowerShell on ch-ops-wks02, revealing the attacker’s short-lived startup persistence attempt.

**Query Executed:11-CorpHealth Query11**
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
**Result:**  Newly created registry value name that was added to the Run Key: MaintenanceRunner


---
## 12-CorpHealth Query12 – Privilege Escalation 

**Purpose:**  
Identifies the time of the first privilege escalation event. 

**Query Executed:12-CorpHealth Query12**
```kql
DeviceEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-05T01:00:00Z) .. datetime(2025-12-05T01:10:00Z))
| where AdditionalFields contains "ConfigAdjust"
| project TimeGenerated, ActionType, AdditionalFields
| order by TimeGenerated asc


```
**Result:**  Time of the first privilege escalation event is: 2025-11-23T03:47:21.8529749Z

---
## 13-CorpHealth Query13 – AV Exclusion Attempt

**Purpose:**  
This query identifies processes on CH-OPS-WKS02 that attempted to add exclusions in Windows Defender by filtering for command lines containing “Exclusion” and showing the relevant timestamps and command details.

**Query Executed:13-CorpHealth Query13**
```kql
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-05) .. datetime(2025-11-26))
| where InitiatingProcessCommandLine contains "Exclusion"
| project TimeGenerated, AdditionalFields, InitiatingProcessCommandLine
| order by TimeGenerated asc 

```
**Result:**  The folder path the attacker attempted to add as an exclusion in Windows Defender is C:\ProgramData\Corp\Ops\staging -Force

---
## 14-CorpHealth Query14 – Decode First PowerShell EncodedCommand Execution

**Purpose:**  
This query identifies the first PowerShell process executed with -EncodedCommand by the ops.maintenance account on CH-OPS-WKS02, extracts the Base64 string from the command line, and decodes it to reveal the plaintext PowerShell command.

**Query Executed:14-CorpHealth Query14**
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
**Result:**  The first decoded PowerShell command was Write-Output 'token-6D5E4EE08227'

---
## 15-CorpHealth Query15 – Identify Process Responsible for Privilege Token Modification

**Purpose:**  
This query filters DeviceEvents on CH-OPS-WKS02 to locate PowerShell-driven events where token privileges were modified, allowing identification of the InitiatingProcessId responsible for the ProcessPrimaryTokenModified activity.

**Query Executed:15-CorpHealth Query15**
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
**Result:**  The InitiatingProcessID of the process whose token privileges were modified is 4888.

---

## 16-CorpHealth Query16 – Extract Modified Token User SID from Token Privilege Change Event

**Purpose:**  
Locate the security identifier (SID) that the modified token belongs to.

**Query Executed:16-CorpHealth Query16**
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
**Result:**  TSID is S-1-5-21-1605642021-30596605-784192815-1000

---

## 17-CorpHealth Query17 – Ingress Executable Written to Disk via curl.exe

**Purpose:**  
This query identifies executable files written to disk by curl.exe on CH-OPS-WKS02, filtering specifically for .exe payloads created in a user profile directory immediately following outbound transfer activity. It isolates ingress tooling delivered directly from an external source rather than legitimate installer behavior.

**Query Executed:17-CorpHealth Query17**
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
**Result:**  The executable that was written to disk after the outbound request is: revshell.exe


---

## 18-CorpHealth Query18 – External Dynamic Tunnel Used to Download Post-Escalation Tooling
**Purpose:**  
This query identifies executable files written to a user directory by curl.exe, allowing the external download URL to be extracted directly from the initiating command line.
The command line reveals the exact remote source used to stage attacker tooling.


**Query Executed:18-CorpHealth Query18**
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
**Result:**  The workstation connected to this URL when retrieving the file: https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe

---

## 19-CorpHealth Query19 – Execution of Unsigned Binary from User Profile Directory
**Purpose:**  
This query identifies the first execution of the downloaded unsigned binary and reveals the parent process responsible for launching it.


**Query Executed:19-CorpHealth Query19**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-02T12:17:07.718921Z) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessFileName == "revshell.exe"
| project TimeGenerated, InitiatingProcessParentFileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc


```
**Result:**  The explorer.exe is the process that executed the downloaded binary on CH-OPS-WKS02

---

## 20-CorpHealth Query20 – Identify the External IP Contacted by the Executable
**Purpose:**  
This query identifies failed outbound TCP connection attempts initiated by the malicious executable after execution, revealing the external IP it attempted to contact on a high, non-standard port.


**Query Executed:20-CorpHealth Query20**
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
**Result:**  The external IP address the executable attempted to contact after execution was: 13.228.171.119



---

## 21-CorpHealth Query21 – Persistence via Startup Folder Executable Placement
**Purpose:**  
This query identifies malicious persistence by detecting an executable written into a Windows Startup directory under ProgramData, a location that ensures automatic execution at user logon.


**Query Executed:21-CorpHealth Query21**
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
**Result:**  The folder path that the attacker used to establish persistence for the executable is C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe

---

## 22-CorpHealth Query22 part 1: Recognition Query- Identify the remote session associated with confirmed malicious persistence activity.
**Purpose:**  
This query isolates the executable placement in a Startup directory and captures the associated InitiatingProcessRemoteSessionDeviceName, establishing the initial linkage between attacker activity and a remote interactive session.


**Query Executed:22-CorpHealth Query22**
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
**Result:**  Identified remote IP label 对手

---

## 22-CorpHealth Query22 part 2 – File Event Validation- Confirm the prevalence of the remote session across file system activity.

**Purpose:**  
This query summarizes file system events by InitiatingProcessRemoteSessionDeviceName to determine whether the same remote session appears consistently across file operations on the host during the attack window.


**Query Executed:22-CorpHealth Query22 part 2**
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-02) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| summarize Count = count() by InitiatingProcessRemoteSessionDeviceName
| order by Count desc


```
**Result:**  对手 appears 216 times

---

## 22-CorpHealth Query22 part 3 – Process Event Validation- Validate that the same remote session initiated process executions

**Purpose:**  
This query aggregates process execution events by remote session identifier, confirming that process launches (including attacker tooling) were driven by the same interactive session.


**Query Executed:22-CorpHealth Query22 part 3**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-02) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| summarize Count = count() by InitiatingProcessRemoteSessionDeviceName
| order by Count desc

```
**Result:**  对手 appears 56 times

---

## 22-CorpHealth Query22 part 4 – Network Event Validation- Confirm outbound network activity originated from the same remote session.

**Purpose:**  
This query summarizes network telemetry by InitiatingProcessRemoteSessionDeviceName, demonstrating that external communication attempts were initiated from the same session observed in file and process activity.

**Query Executed:22-CorpHealth Query22 part 4**
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-02) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| project InitiatingProcessRemoteSessionDeviceName
| summarize Count = count() by InitiatingProcessRemoteSessionDeviceName
| order by Count desc

```
**Result:**  对手 appears 99 times

---

## 23-CorpHealth Query23 – Identify the Remote Session IP Address

**Purpose:**  
Identifies the source IP addres for the remote session tied to the attacker's activity. 

**Query Executed:23-CorpHealth Query23**
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
**Result:** The IP address that appears as the source of the remote session tied to the attacker’s activity is 100.64.100.6

---


## 24-CorpHealth Query24 – Identification of Internal Pivot Host via Remote Session Metadata

**Purpose:**  
This query extracts unique remote session IP addresses associated with attacker activity on CH-OPS-WKS02, excluding CGNAT relay addresses and isolating internal Azure-range IPs indicative of an internal pivot host. 

**Query Executed:24-CorpHealth Query24**
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-02) .. datetime(2025-12-05))
| where DeviceName == "ch-ops-wks02"
| where isnotempty(InitiatingProcessRemoteSessionIP)
| where InitiatingProcessRemoteSessionIP startswith "10."
| where not(InitiatingProcessRemoteSessionIP startswith "100.64.")
| distinct InitiatingProcessRemoteSessionIP

```
**Result:** 10.168.0.6

---

## 25-CorpHealth Query25 – Earliest Suspicious Remote Logon Event

**Purpose:**  
This query filters CH-OPS-WKS02 logon events to exclude system and background accounts, focusing on successful remote logons from a specific remote session device to determine the earliest suspicious access by the attacker.

**Query Executed:25-CorpHealth Query25**
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
**Result:** 2025-11-23T03:08:31.1849379Z

---

## 26-CorpHealth Query26 – IP address associated with the earliest suspicious logon

**Purpose:**  
This query filters for 104.164.168.17 logons to verify the earliest instance from this IP address

**Query Executed:26-CorpHealth Query26**
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
**Result:** 104.164.168.17

---

## 27-CorpHealth Query27 – Attacker Geolocation Analysis via Defender Advanced Hunting

**Purpose:**  
This query enriches the suspicious remote logon IP (104.164.168.17) using geo_info_from_ip_address() to identify the country, region, and city from which the attacker accessed CH-OPS-WKS02. 

**Query Executed:27-CorpHealth Query27**
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
**Result:** According to Defender geolocation enrichment, the attacker’s IPs originate from Vietnam


---

## 28-CorpHealth Query28 – First Process Launched Post-Attacker Logon

**Purpose:**  
This query identifies the first process executed by the attacker on CH-OPS-WKS02 immediately after their initial login by filtering DeviceProcessEvents for the attacker’s account and remote session, then sorting by timestamp ascending.

**Query Executed:28-CorpHealth Query28**
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


## 29-CorpHealth Query29 – First File Accessed by Attacker After Initial Logon

**Purpose:**  
This query identifies the first file accessed by the attacker after logging in by pivoting from the initial attacker process ID and examining subsequent GUI-based process executions for file paths referenced in their command lines.

**Query Executed:29-CorpHealth Query29**
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
**Result:** "NOTEPAD.EXE" C:\Users\chadmin\Documents\CH-OPS-WKS02 user-pass.txt

---

## 30-CorpHealth Query30 – Attacker’s First Post-File-Access Action

**Purpose:**  
This query identifies the attacker’s next action after reading a file by examining the earliest process executions tied to the same remote session and account immediately following the file-access timestamp.

**Query Executed:30-CorpHealth Query30**
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
**Result:** The attacker’s next action was "ipconfig.exe"


---

## 31-CorpHealth Query31 – Next User Account Accessed After Initial Reconnaissance

**Purpose:**  
This query identifies the first successful logon event occurring immediately after the attacker’s enumeration activity, revealing the next user account the attacker accessed as they shifted from recon to credentialed interaction.

**Query Executed:31-CorpHealth Query31**
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
**Result:** Next successful logon account name: ops.maintenance




