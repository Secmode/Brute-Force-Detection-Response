# Elastic SIEM SOC Lab
Brute Force Attack Detection &amp; Response using Elasticsearch, KQL, Windows Server,Pfsense, Kali, and Ubuntu
<img width="1881" height="1051" alt="Screenshot 2025-08-17 205825" src="https://github.com/user-attachments/assets/38e63191-0937-480f-8023-a431de1af526" />

## Overview
This project is a **hands-on SOC lab** demonstrating **Brute Force Attack Detection & Response** using **Windows Server 2022, Kali Linux, pfSense, and Ubuntu servers** with **Elastic SIEM.** It simulates realistic attack scenarios, detection rules, dashboards, and incident response workflows to showcase **practical SOC skills**.


The lab covers a wide range of security operations tasks, including:
<p float="left"> <code>Networking Architecture</code> &nbsp;&nbsp; | &nbsp;&nbsp; <code>Brute-force attacks</code> &nbsp;&nbsp; | &nbsp;&nbsp; <code>Active Directory</code> &nbsp;&nbsp; | &nbsp;&nbsp; <code>Failed login analysis</code> <br> <code>Privilege escalation</code> &nbsp;&nbsp; | &nbsp;&nbsp; <code>Dashboards & detection rules</code> &nbsp;&nbsp; | &nbsp;&nbsp; <code>SIEM use cases</code> &nbsp;&nbsp; | &nbsp;&nbsp; <code>KQL Queries & Scripting</code> <br> <code>Incident Response & Containment</code> &nbsp;&nbsp; | &nbsp;&nbsp; <code>pfSense Configuration</code> &nbsp;&nbsp; | &nbsp;&nbsp; <code>Patching</code> </p>


---

## Lab Network Architecture

| Component | Role | IP |
|-----------|------|----|
|Pfsense |LAN,(Eth1) DHCP Managment, Isolated Lab network |10.0.0.1/24 |
| Kali Linux | Simulated adversary behavior brute force Attempts | 10.0.0.7/24 |
| Windows Server 2022 | Domain Controller and Target Machine| 10.0.0.6/24 |
| Ubuntu Server 1 | Fleet Server | 10.0.0.5/24 |
| Ubuntu Server 2 | ELK Stack (ElasticSearch, Logstash, Kibana) Centralized log collection | 10.0.0.4/24 |
|SocAnalyst |SIEM analytic, Kibana Visualization, Alert, Case, Monitor | 10.0.0.2/24 |

**Tools Used:** Hydra, xfreerdp,Evil-winrm, Elastic Agent, Elastic Defend, Sysmon, Fleet Server, Kibana..

<img width="986" height="737" alt="image" src="https://github.com/user-attachments/assets/529967e4-9ce9-44b1-9c22-1c0852a418b8" />



<p float="left">
  <img src="https://github.com/user-attachments/assets/05b176ea-d624-4a8c-b078-7054c76a878a" width="400" />
  <img src="https://github.com/user-attachments/assets/c53231a9-ea33-45ba-ac94-776c77d4cc6e" width="400" />
</p>






---

## Attack Simulations


###  RDP Brute Force
- **Command:** `hydra -l Administrator -P ./passlist.txt rdp://10.0.0.6`
- **Observed Event IDs:** `4625 – Failed logon (multiple failed RDP attempts)`
- **Outcome:**  Multiple failed SSH login attempts generated authentication logs and were detected in Elastic SIEM.. (Event ID 4625).
<img width="1073" height="508" alt="image" src="https://github.com/user-attachments/assets/622653c3-fb74-4338-8373-40191759ae0c" />

###  Successful SSH Login via Brute-Force
- **Command:** `hydra -l Administrator -P ./passlist.txt ssh://10.0.0.6`
- **Outcome:** Correlation rules flagged brute force activity. Confirmed in Kibana.
- **Detection**: Confirmed in Kibana (4624, system.auth.ssh.event: Accepted).
<img width="1077" height="679" alt="image" src="https://github.com/user-attachments/assets/c4c4b7b4-8277-4224-96f1-24c606c0a34c" />
 <img width="1076" height="493" alt="image" src="https://github.com/user-attachments/assets/0aa0ff96-e44e-4f9c-b84f-a2a42717e730" />


###  Elastic Integrations Setup
- **Steps:** Installed and configured Elastic integrations to collect logs and telemetry from endpoints and servers..
- **Integrations Used:** Elastic Agent, Elastic Defend, Fleet Server, Prebuilt Security Detection Rules, Elastic Synthetics
*<img width="1079" height="532" alt="image" src="https://github.com/user-attachments/assets/a18c6d05-f881-4778-be45-eef47eb048f6" />*


###  Privilege Escalation – AD User Creation

**Action Taken:**  
- Logged in via Evil-WinRM as `SECMODE\Administrator`
- Verified domain membership: `sec.mode.IT`.  
- Executed `Creatuser.ps1` → Created `JDOE` with administrative privileges.


<img width="1059" height="643" alt="image" src="https://github.com/user-attachments/assets/6da647c0-62a8-47ac-8dea-242130014e08" />
<img width="1321" height="1021" alt="image" src="https://github.com/user-attachments/assets/36fa81f1-5193-447d-a6db-29f55ad76d06" />

- **Elastic Detection:** Correlation rules and dashboards in Elastic SIEM captured the privilege escalation by mapping the sequence of logon events, assignment of special privileges, and group membership changes, .
<img width="1902" height="575" alt="image" src="https://github.com/user-attachments/assets/00c18ce8-f6d7-4081-b840-acd839e3d43f" />


###  Observed Event IDs:
  - 4624 – Successful logon 
  - 4672 – Special privileges assigned to new logon 
  - 4634 – Logoff event 
  - 4648 – Logon with explicit credentials 
  - 4728 – A member was added to a security-enabled global group 
  - 4720 – New user account created 
<img width="1075" height="500" alt="image" src="https://github.com/user-attachments/assets/a45eba50-0722-4592-a702-0be1306b204b" />


---
###  Threat Hunting –  Elastic Detection And Event Viewer
- **Detection Logic:** Multiple failed SSH login attempts from the same source IP ('source.ip') within a short time frame.
   - **KQL Query:** `event.module: "windows" and winlog.event_id: 4625 and winlog.logon.type: 10
| stats count() by source.ip, user.name, host.name, bin(@timestamp, 5m)
| where count >= 5
`
   - **Detection Rule:** Threshold ≥ 5 failed SSH login attempts in 5 minutes from the same source IP.
   - **Outcome:** Identified suspicious brute force attempts against account root from attacker IP `10.0.0.7 (Kali Linux).`
   - Logs confirm repeated logon-failed actions on host WIN-DHNT661G6BP.
     - **SOC Use Case:** Helps analysts hunt brute force attempts that bypass normal authentication rules and confirm malicious login activity
<img width="1907" height="1006" alt="alert generate" src="https://github.com/user-attachments/assets/c7aa9213-7afc-43e4-82b9-ce4b3272dcd8" />
<img width="1846" height="855" alt="image" src="https://github.com/user-attachments/assets/6dccaec6-64af-4068-b7ae-9ba362de7f9c" />
<img width="760" height="758" alt="check alert" src="https://github.com/user-attachments/assets/491b6063-5e25-4fe1-bfbb-3b27afc34d5f" />

<img width="970" height="435" alt="image" src="https://github.com/user-attachments/assets/efe479e3-a4f7-43e5-a1b3-ecb6812dd72c" />

**Event Viewer Evidence:**  
- **Event ID 4720:** User account created (`JDOE`).  
- **Event ID 4728:** User added to security-enabled global group (Administrators).  
- **Event ID 4672:** Special privileges assigned to a logon session.

<img width="1568" height="948" alt="image" src="https://github.com/user-attachments/assets/5d942563-fa22-47d5-ac9b-75a11cea63c5" />



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
## Applying NIST Incident Response Lifecycle
 **Preparation - Detection & Analysis - Containment - Eradication & Recovery -Post-Incident (Lessons Learned)**

 **Preparation:** Configured Sysmon + Elastic Agent - Snapshots & backup policies
 
 **Detection & Analysis** 
 - SIEM Rules were triggered
 - Alerts generated for brute force + privilege escalation
- Analyst observes and interprets what happened.
 
 <img width="1907" height="874" alt="Screenshot 2025-08-22 224708" src="https://github.com/user-attachments/assets/a484003e-1054-4b2f-a2ec-24fa4c36fd41" />

 
---
## Action Taken: Containment, Eradication & Recovery

- **Blocked Malicious IP:**  
  Blocked SSH/RDP brute-force IP (`10.0.0.7`) 

  <img width="1327" height="913" alt="dddd" src="https://github.com/user-attachments/assets/a9615087-5425-4360-888c-9d3b042d2d76" />
  

- **Disable accounts:** (`JDOE`)
<img width="940" height="769" alt="image" src="https://github.com/user-attachments/assets/fdd0b3d7-5094-484a-b4bc-9767bb0e5990" />


  - **patch systems, Backup & Snapshots:**  
  - Create VM snapshots to revert compromised systems to a clean state.
  - Preserve backed-up SIEM logs as evidence for post-incident forensics. 
  - Ensured Elastic SIEM configurations and pfSense firewall rules were backed up for recovery.  


- **Post-Incident (Lessons Learned)**
  - Added MFA for RDP
  - Enabled account lockout policy
  - Tuned Elastic rules to reduce noise
  - system update 
---

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
- Network Architecture & Segmentation
- SIEM detection engineering (KQL)
- Log correlation across Windows/Linux hosts
- Build dashboards and detection rules
- Network Security & Containment
- Incident Detection & Response
- workflow documentation
- Knowledge of Security Frameworks
- SOC workflow: Detect → Investigate → Respond → Document
- Understanding of Attacks, Brute-force attacks, malware detection, privilege escalation, and lateral movement
---
## Recovery 
  - Restoring from backups or snapshots, patching systems, resetting accounts, and returning operations to normal.
<img width="970" height="676" alt="VMS" src="https://github.com/user-attachments/assets/743f06f6-65d4-4fad-a1e4-e19d8c0d9952" />



