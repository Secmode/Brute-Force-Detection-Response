# Brute-Force-Detection-Response
Elastic SIEM SOC Lab – Brute Force Attack Detection &amp; Response using Windows Server,Pfsense, Kali, and Ubuntu
## Overview
This Project contains a **hands-on SOC lab** built using Elastic SIEM, Windows Server 2022, Kali Linux, Pfsense, and Ubuntu servers. It demonstrates **realistic attack scenarios**, detection rules, dashboards, and incident workflow documentation.

The lab covers:
- Networking Architecture (VM design, pfSense, segmentation)
- Brute-force attacks (SSH & RDP) (simulated adversary TTPs)
- Failed login analysis (Event ID 4625, Linux auth logs)
- Successful login analysis (Event ID 4624, Linux auth logs)
- Privilege escalation (simulated local admin / sudo abuse)
- Lateral movement (moving from one machine to another)
- Dashboards & detection rules (Elastic SIEM use cases)
- KQL Queries & Scripting (custom queries, automation scripts)
- PfSense Configuration (Incident Response & Containment)
  - Blocking malicious IPs
  - Isolating compromised hosts
- Patching (remediation on Windows/Linux clients)
  

This lab is designed to **showcase My SOC skills** Which including detection engineering, log correlation, incident analysis, and workflow documentation.

---

## Lab Archtitecture

| Component | Role | IP |
|-----------|------|----|
|Pfsen |LAN,(Eth1) DHCP Managment, Isolated Lab network |10.0.0.1/24 |
| Kali Linux | Simulated adversary behavior brute force Attempts | 10.0.0.7 |
| Windows Server 2022 | Domain Controller and RDP Target Machine| 10.0.0.6 |
| Ubuntu Server 1 | Fleet Server (Elastic Agent management) | 10.0.0.4 |
| Ubuntu Server 2 | ELK Stack (ElasticSearch, Logstash, Kibana) Centralized log collection and SIEM analytic| 10.0.0.5 |
|SocAnalyst |Kibana Visualization, Alert, Case, Monitor | 10.0.0.2 |

**Tools Used:** Hydra, xfreerdp, Elastic Agent, Pfsense, Winlogbeat, Kibana Dashboards, Elastic Defender, Sysmon.

<img width="992" height="702" alt="image" src="https://github.com/user-attachments/assets/7d73cc16-f8f7-407a-a090-dd9c37a5555a" />


---

## Attack Simulations

### 1. SSH Brute Force
- **Command:** `hydra -l Administrator -P ./passlist.txt ssh://10.0.0.6`
- **Outcome:** Multiple failed SSH login attempts generated authentication logs and were detected in Elastic SIEM.
  <img width="1076" height="493" alt="image" src="https://github.com/user-attachments/assets/0aa0ff96-e44e-4f9c-b84f-a2a42717e730" />




### 2. RDP Brute Force
- **Command:** `hydra -l Administrator -P ./passlist.txt rdp://10.0.0.6`
- **Observed Event IDs:** `4625 – Failed logon (multiple failed RDP attempts)`
- **Outcome:** Elastic correlation rule flagged brute-force behavior. (Event ID 4625).
<img width="1073" height="508" alt="image" src="https://github.com/user-attachments/assets/622653c3-fb74-4338-8373-40191759ae0c" />

### 3. Successful RDP Login
- **Command:** `xfreerdp /u:Administrator /p:"MONKEY@290cyber!" /v:10.0.0.6`
- **Outcome:** Successful login confirmed in Kibana.
📸 *Insert screenshot*

### 4. Elastic Integrations Setup
- **Steps:** Installed and configured Elastic integrations to collect logs and telemetry from endpoints and servers..
- **Integrations Used:** Elastic Agent, Elastic Defend, Fleet Server, Prebuilt Security Detection Rules, Elastic Synthetics
-
- Alerts in Endpoint → Malware dashboard.
📸 *Insert Malware dashboard screenshot*

### 5. Privilege Escalation
- **Steps:** Add testuser to Administrators group.
- **Elastic Detection:** Event IDs 4732, 4672, .
<img width="1075" height="500" alt="image" src="https://github.com/user-attachments/assets/a45eba50-0722-4592-a702-0be1306b204b" />


### 6. Lateral Movement
- **Steps:** Simulate remote PowerShell login to Windows target.
- **Elastic Detection:** Event IDs 4624 (logon), 4688 (process creation).
📸 *Insert screenshot*

---

## Elastic Detection Rules

- **Brute Force Rule:** Threshold ≥5 failed logins in 5 minutes from the same IP.  
- **Malware Rule:** Detect `process.name: "*eicar*"` or hash-based rules.  
- **Privilege Escalation Rule:** Event IDs 4732, 4672, 4728.  

📂 *YAML files included in `Elastic-Rules/` folder*

---

## Dashboards

**Prebuilt & Custom Dashboards:**
- Authentication Overview → failed/successful logins
- Windows Security → RDP & SSH events
- Malware Dashboard → EICAR & other alerts
- Privilege Escalation → group/user changes

📸 *Include screenshots in `Kibana-Dashboards/`*

---

## Skills Demonstrated
- SIEM detection engineering (KQL)
- Log correlation across Windows/Linux hosts
- Incident workflow documentation
- SOC workflow: Detect → Investigate → Respond → Document
- Understanding of brute-force attacks, malware detection, privilege escalation, and lateral movement

---

## Next Steps
- Expand malware simulations (EICAR + custom scripts)
- Add lateral movement detection across multiple hosts
- Build enriched dashboards combining multiple alerts
- Prepare portfolio showcase for SOC roles

---

## Portfolio Highlights
This lab shows end-to-end SOC capabilities:
1. Simulate attacks in a safe lab
2. Detect & investigate using Elastic SIEM
3. Document workflows and alerts
4. Build dashboards and detection rules
5. Demonstrate advanced SOC knowledge for hiring managers
6. <img width="955" height="562" alt="image" src="https://github.com/user-attachments/assets/08d068e6-ce20-44d5-b4f5-791d87487a8a" />

