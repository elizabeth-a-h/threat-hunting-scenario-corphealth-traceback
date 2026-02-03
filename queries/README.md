# Threat Hunt Queries — CorpHealth: Traceback

## Overview

This directory contains the complete set of Kusto Query Language (KQL) queries developed and executed during the CorpHealth: Traceback threat hunt.

Rather than relying on a single alert or predefined detection, the investigation progressed through a series of iterative, hypothesis-driven queries. Each query was used to validate findings, pivot to related telemetry, or eliminate benign explanations as the hunt evolved.

A total of **31 queries** were executed during the investigation.

---

## Query Philosophy

The volume of queries reflects **analyst-driven exploration**, not inefficiency.

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

---

## Query Index

### 01 – Initial Access Validation
- **Query:** `01_initial_access.kql`
- **Evidence:** `01_initial_access.png`
- Purpose: Identify abnormal authentication activity and confirm potential initial access.

### 02 – Suspicious Process Execution
- **Query:** `02_execution.kql`
- **Evidence:**  
  - `02_execution.png`  
  - `02_execution_2.png`
- Purpose: Validate manual execution of scripts and diagnostic tools outside approved automation.

### 03 – Network & Command-and-Control Activity
- **Query:** `03_network_activity.kql`
- **Evidence:** `03_network_activity.png`
- Purpose: Identify unauthorized outbound connectivity and tunneling behavior.



---

## Notes

- Queries were executed against a **Log Analytics Workspace** using Kusto Query Language (KQL).
- Screenshots are provided to preserve investigative context and observable telemetry at the time of analysis.
- Queries were written and executed manually to support hypothesis-driven investigation rather than automated alerting.

---


This directory is intended to showcase **how analysts think**, not just what they detect.



