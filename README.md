# Brute-Force-Detection-Response
Elastic SIEM SOC Lab – Brute Force Attack Detection &amp; Response using Windows Server, Kali, and Ubuntu
## Overview
This repository contains a **hands-on SOC lab** built using Elastic SIEM, Windows Server 2022, Kali Linux, and Ubuntu servers. It demonstrates **realistic attack scenarios**, detection rules, dashboards, and incident workflow documentation.

The lab covers:
- Brute-force attacks (SSH & RDP)
- Successful login analysis
- Malware simulation (EICAR test file)
- Privilege escalation
- Lateral movement
- Dashboards & detection rules

This lab is designed to **showcase SOC skills** for hiring managers, including detection engineering, log correlation, incident analysis, and workflow documentation.

---

## Lab Setup

| Component | Role | IP |
|-----------|------|----|
| Kali Linux | Attack Machine | 10.0.0.7 |
| Windows Server 2022 | Target Machine | 10.0.0.6 |
| Ubuntu Server 1 | Fleet Server (Elastic Agent management) | 10.0.0.4 |
| Ubuntu Server 2 | ELK Stack (ElasticSearch, Logstash, Kibana) | 10.0.0.5 |

**Tools Used:** Hydra, xfreerdp, Elastic Agent, Auditd, Winlogbeat, Kibana Dashboards, Elastic Defender, Sysmon.

📸 *Insert Lab Topology Screenshot*

---

## Attack Simulations

### 1. SSH Brute Force
- **Command:** `hydra -l Administrator -P ./passlist.txt ssh://10.0.0.6`
- **Outcome:** Multiple failed SSH login attempts detected in Elastic SIEM.
📸 *Insert SSH screenshot*

### 2. RDP Brute Force
- **Command:** `hydra -l Administrator -P ./passlist.txt rdp://10.0.0.6`
- **Outcome:** Multiple failed RDP login attempts detected (Event ID 4625).
📸 *Insert RDP screenshot*

### 3. Successful RDP Login
- **Command:** `xfreerdp /u:Administrator /p:"MONKEY@290cyber!" /v:10.0.0.6`
- **Outcome:** Successful login confirmed in Kibana.
📸 *Insert screenshot*

### 4. Malware Detection (EICAR)
- **Steps:** Place EICAR file on Windows Server, detected by Elastic Defender.
- **Elastic Detection:** Alerts in Endpoint → Malware dashboard.
📸 *Insert Malware dashboard screenshot*

### 5. Privilege Escalation
- **Steps:** Add testuser to Administrators group.
- **Elastic Detection:** Event IDs 4732, 4672.
📸 *Insert screenshot*

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
