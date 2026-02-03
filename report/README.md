# Incident Report — CorpHealth: Traceback Threat Hunt


This folder contains the formal incident report documenting the complete findings from the CorpHealth: Traceback Threat Hunt. The report is written to reflect standard SOC investigation procedures and includes the reconstructed attack chain, analysis of indicators, and recommended remediation steps.

## Contents

- [1. Executive Summary](#1-executive-summary)
- [2. Platforms and Languages Leveraged](#2-platforms-and-languages-leveraged)
- [3. Scenario](#3-scenario)
- [4. Summary of Key Findings](#4-summary-of-key-findings)
- [5. Indicators of Compromise (IoCs) & Supporting Evidence](#5-indicators-of-compromise-iocs--supporting-evidence)
- [6. Chronological Event Timeline (Overview)](#6-chronological-event-timeline-overview)
- [7. Root Cause Analysis](#7-root-cause-analysis)
- [8. Impact Assessment and Severity Evaluation](#8-impact-assessment-and-severity-evaluation)
- [9. Recommended Response Actions & Next Steps](#9-recommended-response-actions--next-steps)
- [10. Conclusion](#10-conclusion)



[4. Summary of Key Findings](#4-summary-of-key-findings)


- **Incident_Report.md** — Complete, structured report including:
  - Executive summary
  - Scope and affected assets
  - Detection and response summary
  - Root cause analysis
  - Step-by-step attack chain
  - Impact assessment
  - Recommendations
  - Appendix with IOC tables, MITRE ATT&CK mapping, and investigation timeline

## Notes

- The report is based entirely on **controlled lab telemetry** and simulated events; no live production data is included.
- Findings are supported by query results, logs, and screenshots located in `/queries` and `/screenshots`.
- The report is suitable for **SOC escalation, training, or internal documentation** purposes.

## Usage

- Analysts can review the report to understand the full attack lifecycle observed during the threat hunt.
- Can be used as a **template for documenting future threat hunts**.
- Provides a reference for correlating telemetry, IOC identification, and incident response workflows.

---

## 1. Executive Summary

This investigation documents a simulated threat hunt conducted against the workstation **CH-OPS-WKS02** after routine monitoring surfaced anomalous activity associated with a privileged maintenance account. While the behavior initially resembled legitimate system maintenance, further analysis revealed multiple indicators inconsistent with approved administrative workflows.

The investigation confirmed **unauthorized remote access**, **credential exposure**, **privilege escalation attempts**, **external command-and-control activity**, and **persistence mechanisms** established on the host. The attacker leveraged an interactive remote session to enumerate the environment, access sensitive files, escalate privileges, stage tooling from an external tunneling service, and maintain access through startup folder persistence.

Correlated host, network, and authentication telemetry conclusively demonstrated deliberate malicious activity rather than benign administrative error. This report documents the investigative methodology, key findings, and conclusions derived from the threat hunt.

---

## 2. Platforms and Languages Leveraged

The following platforms and technologies were used during the CorpHealth: Traceback threat hunt:

- **Microsoft Log Analytics Workspace**  
  Primary investigation platform used to query and correlate host, process, network, registry, and authentication telemetry.

- **Kusto Query Language (KQL)**  
  Utilized to perform hypothesis-driven analysis, pivot between data sources, and reconstruct attacker behavior across the environment.

- **Microsoft Defender Telemetry Schema**  
  Data sources included DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceRegistryEvents, and DeviceLogonEvents ingested into Log Analytics.

All queries were written and executed manually to support an investigative threat-hunting workflow rather than automated alert triage.

---

## 3. Scenario

This threat hunt was conducted as a controlled investigative exercise using a live Log Analytics Workspace that contained both routine operational telemetry and deliberately authored adversary activity. The workspace was active and included unrelated background events, requiring the analyst to distinguish malicious behavior from benign noise.

The adversary activity was injected into historical telemetry by the hunt creator to simulate a realistic intrusion scenario while preserving the complexity and variability of real enterprise data. No alerts or predefined indicators were provided.

Due to the ambiguity between authorized administrative activity and misuse of trusted access, a hypothesis-driven threat hunt was initiated to reconstruct the activity timeline, validate attacker intent, and determine whether the observed behavior represented benign operations or deliberate unauthorized access.

---
## 4. Summary of Key Findings

- An external actor gained unauthorized remote access to the workstation **CH-OPS-WKS02** using valid credentials associated with a privileged administrative account.

- Shortly after initial access, the attacker conducted interactive reconnaissance, including system enumeration and the opening of a locally stored file containing credential information.

- The attacker leveraged a trusted maintenance script to blend malicious activity into routine operational workflows, using PowerShell to stage artifacts and initiate outbound communication.

- Multiple privilege escalation and token manipulation events were observed, indicating deliberate attempts to elevate or adjust execution context beyond normal operational behavior.

- The attacker attempted to weaken host defenses by modifying Windows Defender settings and probing antivirus exclusion mechanisms.

- Post-escalation, the attacker downloaded an unsigned executable from an external dynamic tunneling service and executed it from a user profile directory.

- The staged executable attempted outbound command-and-control communication to an external IP on a high, non-standard port.

- Persistence was established by copying the executable into a Windows Startup directory, ensuring execution upon user logon.

- Remote session metadata consistently linked file, process, and network activity to a single interactive session, confirming hands-on-keyboard attacker behavior rather than automated task execution.

Collectively, these findings confirm deliberate malicious activity involving credential misuse, interactive reconnaissance, privilege escalation, external command-and-control, and persistence — not benign administrative error or misconfiguration.

---
## 5. Indicators of Compromise (IoCs) & Supporting Evidence

The following indicators of compromise were identified during the threat hunt and collectively confirm unauthorized access, post-exploitation activity, and persistence on `CH-OPS-WKS02`. These IoCs were used to pivot across telemetry sources and reconstruct the attacker’s behavior.

Full supporting queries and screenshots are documented in the `/queries` and `/screenshots` directories.

---

### Account & Access Indicators

- **Initial Compromised Account:** `chadmin`
- **Secondary Account Used:** `ops.maintenance`
- **Remote Session Identifier:** `对手`
- **External Source IP:** `104.164.168.17`
- **Internal Pivot IP:** `10.168.0.6`
- **Source Geolocation:** Vietnam

---

### Host & File Artifacts

- **Affected Host:** `CH-OPS-WKS02`

- **Malicious Executable:** `revshell.exe`
  - Initial location:  
    `C:\Users\chadmin\revshell.exe`
  - Persistence location:  
    `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe`

- **Credential File Accessed:**  
  `C:\Users\chadmin\Documents\CH-OPS-WKS02 user-pass.txt`

---

### Registry & Persistence Indicators

- **Run Key Value:** `MaintenanceRunner`
- **Scheduled Task:** `CorpHealth_A65E64`
- **Registry Key Created:**  
  `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent`
- **Privilege Manipulation:** Token modification events via PowerShell

---

### Network & Command-and-Control Indicators

- **External Download URL:**  
  `https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe`
- **Post-Execution C2 IP:** `13.228.171.119`
- **Outbound Port:** `11746`
- **Simulated Beacon Endpoint:** `127.0.0.1:8080`

---

### Techniques Observed

- PowerShell execution with `-EncodedCommand`
- Living-off-the-land tooling (`powershell.exe`, `curl.exe`, `explorer.exe`)
- Credential access via local file exposure
- Privilege escalation and token manipulation
- Defense evasion via Defender exclusion attempts
- Startup folder persistence
- External tunneling infrastructure (ngrok)

---

## 6. Chronological Event Timeline (Overview)

The following timeline summarizes the key phases of attacker activity identified during the CorpHealth: Traceback threat hunt. Detailed event-by-event timelines, including precise timestamps and supporting evidence, are documented separately in the `/timeline` directory.

### High-Level Timeline Summary

- **Initial Access**
  - The attacker established an interactive remote session to `CH-OPS-WKS02` using compromised credentials.
  - Early logon activity originated from an external IP and was associated with a distinct remote session identifier.

- **Post-Login Reconnaissance**
  - Immediately following access, the attacker launched standard desktop processes and opened a locally stored file containing credential information.
  - Local system reconnaissance commands were executed to validate environment details.

- **Privilege Escalation & Credential Abuse**
  - Activity shifted to a secondary service account (`ops.maintenance`).
  - PowerShell was used to perform encoded command execution and simulate privilege escalation behavior.
  - Token modification events confirmed manipulation of process privileges.

- **Defense Evasion Attempts**
  - The attacker attempted to modify Windows Defender settings by adding exclusion paths.
  - Persistence attempts included ephemeral Run key modifications.

- **Tool Staging & Command-and-Control Preparation**
  - A maintenance-related PowerShell script initiated outbound connectivity.
  - External tunneling infrastructure was used to stage additional tooling.

- **Payload Deployment & Execution**
  - An unsigned executable (`revshell.exe`) was downloaded via `curl.exe`.
  - The binary was executed interactively and attempted outbound TCP connections to an external endpoint.

- **Persistence Establishment**
  - The attacker copied the executable into a Windows Startup directory to ensure execution on future logons.

- **Remote Session Correlation**
  - File, process, network, and authentication activity consistently mapped back to the same remote session identifier.
  - Internal pivot activity was identified through private network IP correlation.

This sequence confirms a deliberate intrusion lifecycle progressing from initial access through reconnaissance, privilege escalation, tooling deployment, and persistence establishment.

---

## 7. Root Cause Analysis

The root cause of this incident was the compromise and misuse of legitimate credentials combined with insufficient safeguards around privileged account usage and remote access monitoring.

Specifically:

- A valid user account was used to establish an interactive remote session on `CH-OPS-WKS02`.
- The attacker leveraged access to locally stored credential information to pivot into a secondary maintenance account (`ops.maintenance`) with elevated privileges.
- Existing controls did not prevent interactive use of service or maintenance accounts outside approved automation workflows.
- Remote session activity originating from non-corporate infrastructure was not blocked prior to post-exploitation actions.

No evidence was found indicating exploitation of a software vulnerability. Instead, the intrusion relied on **credential access, living-off-the-land techniques, and trusted tooling** (PowerShell, curl.exe, explorer.exe), allowing the attacker to blend into normal system activity.

This combination of credential exposure, permissive account usage, and delayed detection enabled the attacker to progress through multiple stages of the intrusion lifecycle before discovery.

---

## 8. Impact Assessment and Severity Evaluation

### Impact Summary

The investigation confirmed **unauthorized interactive access** to `CH-OPS-WKS02`, followed by a series of post-exploitation activities consistent with a hands-on-keyboard intrusion.

Observed impact included:

- Unauthorized remote access using valid credentials  
- Exposure and use of credentials stored in a user-accessible file  
- Account pivoting to a privileged maintenance account  
- Privilege escalation testing, including token modification and registry manipulation  
- Attempts to weaken endpoint defenses via Defender exclusion activity  
- External command-and-control communication using a tunneling service  
- Staging, execution, and persistence of an unsigned executable via the Windows Startup folder  

No evidence was observed indicating successful data exfiltration, destructive activity, or lateral movement beyond the affected host during the investigation window. However, the attacker demonstrated the capability and intent to maintain access and execute follow-on operations.

### Severity Assessment

**Severity Level: HIGH**

Although the activity occurred within a controlled threat-hunting scenario, the behaviors observed closely mirror real-world intrusion techniques. The combination of credential misuse, interactive access, privilege escalation attempts, external command-and-control communication, and persistence mechanisms represents a **high-risk security incident**.

In a production environment, this level of activity would warrant **immediate investigation, containment, and remediation**, as the attacker established a foothold capable of supporting further compromise if left unaddressed.

---

## 9. Recommended Response Actions & Next Steps

No containment or remediation actions were executed as part of this threat hunt, as the activity occurred within a controlled investigation scenario. However, based on the confirmed findings, the following response actions would be recommended in a production environment.

### Immediate Actions

- Isolate host `CH-OPS-WKS02` from the network to prevent further command-and-control activity
- Disable or reset credentials for compromised accounts:
  - `chadmin`
  - `ops.maintenance`
- Remove malicious artifacts, including:
  - `revshell.exe` from user and Startup directories
- Terminate any active malicious processes and scheduled tasks associated with the intrusion
- Block identified external IPs and domains at network and endpoint controls

### Short-Term Remediation

- Review authentication logs for lateral movement or additional compromised accounts
- Audit scheduled tasks, Run keys, and Startup folders across similar hosts
- Validate Defender configuration to ensure tamper protection and exclusion safeguards are enforced
- Rotate credentials for privileged and service accounts with interactive access

### Long-Term Improvements

- Restrict interactive logon rights for maintenance and service accounts
- Implement stricter monitoring on scripting engines (PowerShell, curl, cmd)
- Enhance alerting for:
  - Encoded PowerShell execution
  - Unsigned binaries in user directories
  - Startup folder persistence
- Conduct tabletop exercises to rehearse response to similar intrusion patterns

These actions would help contain the threat, eradicate attacker footholds, and reduce the likelihood of recurrence.

---

## 10. Conclusion

This threat hunt successfully reconstructed a complete intrusion narrative on CH-OPS-WKS02 by correlating host, identity, process, registry, and network telemetry across a controlled investigative window.

Although the activity occurred within a manufactured training dataset, the observed behaviors closely mirrored real-world adversary tradecraft, including credential harvesting, privilege escalation, defense evasion, external command-and-control, and persistence establishment. The attacker’s actions demonstrated deliberate intent rather than administrative error or automation drift.

The investigation confirmed that:

- Initial access was achieved through a remote interactive session using compromised credentials.
- The attacker performed reconnaissance, accessed credential material, and escalated privileges.
- External tooling was staged and executed using a tunneling service for command-and-control.
- Persistence mechanisms were deployed to maintain future access.
- Activity was consistently linked to a single remote session origin, enabling reliable attribution within the environment.

This hunt validates the effectiveness of hypothesis-driven threat hunting and highlights the importance of contextual telemetry correlation over reliance on individual alerts. The methodology and documentation produced through this investigation provide a repeatable framework for future hunts and serve as a defensible example of professional SOC-level analysis.

No live containment actions were required for this exercise; however, the findings reinforce the necessity of proactive hunting, service account monitoring, and continuous validation of operational baselines in production environments.
