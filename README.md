# CorpHealth: Traceback — Threat Hunt Investigation

## Overview

This repository documents a full end-to-end threat-hunting investigation conducted against an operations workstation (`CH-OPS-WKS02`) within a controlled enterprise telemetry environment.

The hunt focused on identifying anomalous activity associated with a privileged maintenance account and determining whether the observed behavior represented legitimate administrative activity or deliberate malicious access.

Through structured, hypothesis-driven analysis of host, process, authentication, registry, and network telemetry, the investigation confirmed unauthorized access, credential exposure, external command-and-control activity, and persistence mechanisms consistent with an active intrusion.

This project emphasizes **analyst reasoning, investigative workflow, and defensible documentation**, rather than reliance on automated or alert-driven detection alone.

---
## Contents

- [Overview](#overview)
- [Hunt Objectives](#hunt-objectives)
- [Investigation Summary](#investigation-summary)
- [Data Sources & Tooling](#data-sources--tooling)
- [Repository Structure](#repository-structure)
- [Methodology](#methodology)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Purpose of This Repository](#purpose-of-this-repository)
- [Notes & Disclaimer](#notes--disclaimer)

---

## Hunt Objectives

- Validate whether unusual activity in the operations environment was benign or malicious  
- Identify the initial access vector and compromised credentials  
- Reconstruct attacker actions across host, account, and network layers  
- Determine attacker intent and progression through the intrusion lifecycle  
- Produce a professional incident report suitable for SOC escalation or training  

---

## Investigation Summary

Key findings from the threat hunt include:

- Abnormal script execution and diagnostic activity occurring outside approved maintenance windows  
- Manual process execution inconsistent with established automation baselines  
- Unauthorized outbound connectivity to non-corporate infrastructure  
- Use of external tunneling services to facilitate command-and-control activity  
- Credential exposure and exploration of privilege escalation pathways  
- Persistence mechanisms established to maintain continued access  

Collectively, these indicators confirmed **deliberate malicious activity** rather than administrative error or environmental misconfiguration.

---

## Data Sources & Tooling

The investigation leveraged the following telemetry sources and technologies:

- **Microsoft Log Analytics Workspace**  
  Primary platform used to query and correlate host, process, network, registry, and authentication telemetry.

- **Kusto Query Language (KQL)**  
  Used to perform hypothesis-driven analysis and pivot across investigative leads.

- **Microsoft Defender Telemetry Schema**  
  Including `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`,  
  `DeviceRegistryEvents`, and `DeviceLogonEvents`.

All queries were written and executed manually to reflect a real-world threat-hunting workflow.

---

## Repository Structure
```text
├── README.md
├── report/
│ └── README.md # Formal incident report
├── queries/
│ └── README.md # Investigative queries with screenshots and analysis
├── timeline/
│ ├── README.md # Timeline overview
│ ├── full_timeline.md # Detailed event-by-event timeline
│ └── timeline_condensed.md # High-level condensed timeline
```
---

Each directory is self-documented and can be reviewed independently.

---

## Methodology

The hunt followed a structured, hypothesis-driven investigative approach:

1. Identify abnormal activity and define a suspicious time window  
2. Validate affected hosts and establish baseline behavior  
3. Pivot through execution, network, registry, and authentication events  
4. Correlate telemetry across multiple data sources  
5. Reconstruct attacker intent and the full attack chain  
6. Document findings in a clear, escalation-ready format  

This methodology mirrors real-world SOC threat-hunting and incident response workflows.

---

## MITRE ATT&CK Coverage

Observed activity mapped to multiple MITRE ATT&CK tactics, including:

- Initial Access  
- Execution  
- Persistence  
- Credential Access  
- Privilege Escalation  
- Defense Evasion  
- Command and Control  

Detailed mappings and supporting evidence are documented within the investigation report and query documentation.

---

## Purpose of This Repository

This repository is intended to demonstrate:

- Professional threat-hunting methodology and analytical reasoning  
- Clear, structured incident documentation  
- Practical use of KQL for investigative workflows  
- The ability to translate raw telemetry into defensible conclusions  

It may be used for learning, reference, or as a template for documenting future threat hunts.

---

## Notes & Disclaimer

All data, hostnames, account names, IP addresses, and indicators contained in this repository are part of a **controlled training scenario** and do not represent a live production environment.

