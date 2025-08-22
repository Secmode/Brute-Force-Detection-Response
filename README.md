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

<p float="left">
  <img src="https://github.com/user-attachments/assets/05b176ea-d624-4a8c-b078-7054c76a878a" width="400" />
  <img src="https://github.com/user-attachments/assets/c53231a9-ea33-45ba-ac94-776c77d4cc6e" width="400" />
</p>






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

### 3. Successful SSH Login via Brute-Force
- **Command:** `hydra -l Administrator -P ./passlist.txt ssh://10.0.0.6`
- **Outcome:** Outcome: Password cyber!2025- found; login successful. Confirmed in Kibana.
<img width="1077" height="679" alt="image" src="https://github.com/user-attachments/assets/c4c4b7b4-8277-4224-96f1-24c606c0a34c" />


### 4. Elastic Integrations Setup
- **Steps:** Installed and configured Elastic integrations to collect logs and telemetry from endpoints and servers..
- **Integrations Used:** Elastic Agent, Elastic Defend, Fleet Server, Prebuilt Security Detection Rules, Elastic Synthetics
*<img width="1079" height="532" alt="image" src="https://github.com/user-attachments/assets/a18c6d05-f881-4778-be45-eef47eb048f6" />*

### 5. Privilege Escalation
- **Steps:** A standard user account (testuser) was added to the Administrators group on the Windows Server, simulating privilege escalation by an attacker.
- Observed Event IDs:
  - 4624 – Successful logon (tracking the session used for escalation)
  - 4672 – Special privileges assigned to new logon (indicates elevated rights)
  - 4634 – Logoff event (previous session closed before escalation attempt)
  - 4648 – Logon with explicit credentials (often seen during escalation attempts)
  - 4728 – A member was added to a security-enabled global group (if you added to “Administrators” group)
  - 4720 – New user account created (if you tested creating an account first)
- **Elastic Detection:** Correlation rules and dashboards in Elastic SIEM captured the privilege escalation by mapping the sequence of logon events, assignment of special privileges, and group membership changes, .
<img width="1075" height="500" alt="image" src="https://github.com/user-attachments/assets/a45eba50-0722-4592-a702-0be1306b204b" />


### 6. Lateral Movement
- **Steps:** Simulate remote PowerShell login to Windows target.
- **Elastic Detection:** Event IDs 4624 (logon), 4688 (process creation).
📸 *Insert screenshot*

### 3. Threat Hunting –  Elastic Detection 
- **Detection Logic:** Multiple failed SSH login attempts from the same source IP ('source.ip') within a short time frame.
   - **KQL Query:** `event.action: "logon-failed" AND winlog.event_id: 4625`
   - **Detection Rule:** Threshold ≥ 5 failed SSH login attempts in 5 minutes from the same source IP.
   - **Outcome:** Identified suspicious brute force attempts against account root from attacker IP `10.0.0.7 (Kali Linux).`
   - Logs confirm repeated logon-failed actions on host WIN-DHNT661G6BP.
     - **SOC Use Case:** Helps analysts hunt brute force attempts that bypass normal authentication rules and confirm malicious login activity
<p float="left">
  <img src="https://github.com/user-attachments/assets/f77d8cad-3563-4ef5-aecc-0c7a3c80f998" width="300" />
  <img src="https://github.com/user-attachments/assets/1b06fdcb-be9f-40a7-8c44-1b2895eb4d8b" width="300" />
  <img src="https://github.com/user-attachments/assets/413c89f3-1a8a-4780-98b0-8a4e5aa6a736" width="300" />
</p>



<img width="970" height="435" alt="image" src="https://github.com/user-attachments/assets/efe479e3-a4f7-43e5-a1b3-ecb6812dd72c" />

---
### MITRE ATT&CK Mapping  
- **Technique:** [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)  
- **Sub-technique:** [T1110.001 – Password Guessing](https://attack.mitre.org/techniques/T1110/001/)  
- **Tactic:** Credential Access
  - **Defense / Mitigation:**
  - [Account Use Policies M1036](https://attack.mitre.org/mitigations/M1036/)
 – Limit login attempts, implement account lockouts
   - [Password Policies (M1027)](https://attack.mitre.org/mitigations/M1027/)
 – Enforce strong password complexity
   - [Operating System Configuration (M1028)](https://attack.mitre.org/mitigations/M1028/)
 – Restrict RDP, SSH, and VNC to authorized IPs using firewall rules.

 
<img width="1910" height="981" alt="image" src="https://github.com/user-attachments/assets/1913f855-61d4-4f04-a747-35dd7ef61a51" />

<p float="left">
  <img src="https://github.com/user-attachments/assets/a9960171-31f5-441d-955e-7ccd705d5d64" width="32%" />
  <img src="https://github.com/user-attachments/assets/01801194-33fc-47d1-87e9-eaabf714d9df" width="32%" />
  <img src="https://github.com/user-attachments/assets/15faedf1-c66f-4367-a311-3dfe6b0397fa" width="32%" />
</p>





---
## Elastic Detection Rules

- **Brute Force Rule:** Threshold ≥5 failed logins in 5 minutes from the same IP.  
- **Malware Rule:** Detect `process.name: "*eicar*"` or hash-based rules.  
- **Privilege Escalation Rule:** Event IDs 4732, 4672, 4728.  

---
## MITRE ATT&CK Defense Recommendations for T1110.001 – Password Guessing

- **Brute Force Rule:** Threshold ≥5 failed logins in 5 minutes from the same IP.  
- **Malware Rule:** Detect `process.name: "*eicar*"` or hash-based rules.  
- **Privilege Escalation Rule:** Event IDs 4732, 4672, 4728.  

---

## Dashboards
**Prebuilt & Custom Dashboards:**
- User Logon Info → administrator & user logons, failed logins
- Windows Security → RDP & SSH events
- Logon Sources → network vs interactive logins, source IPs
- Logon Timeline → logon events per 10 minutes
<img width="1600" height="801" alt="image" src="https://github.com/user-attachments/assets/bb76e720-c87d-4ff1-8bab-d519e811b214" />


---

## Skills Demonstrated
- SIEM detection engineering (KQL)
- Log correlation across Windows/Linux hosts
- Build dashboards and detection rules
- Incident workflow documentation
- SOC workflow: Detect → Investigate → Respond → Document
- Understanding of brute-force attacks, malware detection, privilege escalation, and lateral movement

  

---

## Next Steps
-Currently working on the PFsense Firewall

---

## Portfolio Highlights
This lab shows end-to-end SOC capabilities:
1. Simulate attacks in a safe lab
2. Detect & investigate using Elastic SIEM
3. Document workflows and alerts
4. Build dashboards and detection rules
5. Demonstrate advanced SOC knowledge for hiring managers
6. <img width="955" height="562" alt="image" src="https://github.com/user-attachments/assets/08d068e6-ce20-44d5-b4f5-791d87487a8a" />
<img width="711" height="448" alt="image" src="https://github.com/user-attachments/assets/27f10842-f4a4-4d9c-9ffd-8b51313bac8c" />


