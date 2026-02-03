# CorpHealth-Traceback Threat Hunt – End-to-End Investigation

## Overview

This repository documents a full end-to-end threat-hunting investigation conducted in a simulated enterprise environment. The hunt focused on identifying anomalous operational behavior associated with a privileged maintenance account and determining whether the observed activity represented legitimate administrative actions or deliberate malicious access.

Through structured analysis of host, process, authentication, and network telemetry, the investigation confirmed unauthorized access, credential exposure, external command-and-control activity, and persistence mechanisms consistent with an active intrusion.

This project emphasizes analyst reasoning, hypothesis-driven investigation, and clear documentation rather than reliance on automated, alert-driven detection alone.

---

## Hunt Objectives

- Validate whether unusual activity in the operations environment was benign or malicious  
- Identify the initial access vector and compromised credentials  
- Reconstruct attacker actions across host, account, and network layers  
- Determine attacker intent and stage of the intrusion lifecycle  
- Produce a defensible incident report suitable for escalation and remediation  

---

## Investigation Summary

Key findings from the threat hunt include:

- Abnormal script execution and diagnostic activity occurring outside approved maintenance windows  
- Manual process execution inconsistent with established automation baselines  
- Unauthorized outbound connectivity to non-corporate infrastructure  
- Use of external tunneling services to facilitate remote command-and-control  
- Credential exposure and exploration of privilege escalation pathways  
- Persistence mechanisms established to maintain continued access  

Collectively, these indicators confirmed deliberate malicious activity rather than administrative error or environmental misconfiguration.

---

## Data Sources & Tooling

The investigation leveraged the following telemetry sources and tools:

- Microsoft Defender for Endpoint (Advanced Hunting)  
- Log Analytics using Kusto Query Language (KQL)  
- Host-based process, file, registry, and logon telemetry  
- Network connection and remote session metadata  

All queries were developed and executed manually to validate hypotheses and pivot between investigative leads.

---


## Repository Structure
.
├── README.md
├── report/
│   └── Incident_Report.md
├── hunt-notes/
│   ├── Hunt_Overview.md
│   └── Flag_Summary.md
├── queries/
│   ├── 01_initial_access.kql
│   ├── 02_execution.kql
│   └── ...
└── appendix/
    ├── MITRE_Mapping.md
    ├── Timeline.md
    └── Screenshots.md


---

## Methodology

The hunt followed a hypothesis-driven investigative approach:

1. Identify abnormal activity and define a suspicious time window  
2. Validate affected hosts and establish baseline behavior  
3. Pivot through execution, network, and authentication events  
4. Correlate telemetry across multiple data sources  
5. Reconstruct attacker intent and the full attack chain  
6. Document findings in a structured, escalation-ready format  

This methodology mirrors real-world threat-hunting and incident-response workflows used in SOC environments.

---

## MITRE ATT&CK Coverage

Observed activity mapped to multiple MITRE ATT&CK tactics, including:

- Initial Access  
- Execution  
- Persistence  
- Credential Access  
- Privilege Escalation  
- Command and Control  

Detailed technique mappings and supporting evidence are documented in the appendix.

---

## Purpose of This Repository

This project is intended to demonstrate:

- Threat-hunting methodology and analytical reasoning  
- Clear, structured incident documentation  
- Practical use of KQL for investigative workflows  
- The ability to translate raw telemetry into defensible conclusions  

---

## Notes & Disclaimer

All data, hostnames, account names, IP addresses, and indicators contained in this repository are part of a controlled training scenario and do not represent a live production environment.

