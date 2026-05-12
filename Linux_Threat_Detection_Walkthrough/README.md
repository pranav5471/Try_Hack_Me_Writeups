# Linux Threat Detection

This repository section contains my TryHackMe walkthroughs, investigation notes, and hands-on labs focused on Linux threat detection and SOC analysis.

The goal of these rooms is to understand how attackers interact with Linux systems, how their activities can be identified through logs and process analysis, and how defenders can investigate suspicious behavior using common blue team techniques.

---

# Topics Covered

- Linux system enumeration
- Discovery command monitoring
- auditd log analysis
- SSH brute-force detection
- Process tree investigation
- Threat hunting methodologies
- Cryptominer detection
- Persistence techniques
- Ingress tool transfer detection
- User and privilege analysis
- Internal network reconnaissance detection
- Malware behavior analysis
- Incident investigation workflows

---

# Tools and Commands Practiced

## Linux Investigation Commands
- `ps aux`
- `top`
- `htop`
- `whoami`
- `id`
- `last`
- `hostname`
- `uname -a`
- `systemd-detect-virt`

## Network and Process Monitoring
- `ss -tnlp`
- `netstat -tnlp`
- `ip a`
- `ip r`
- `arp -a`

## Threat Hunting and Log Analysis
- `ausearch`
- `grep`
- `grep -a`
- `cat /proc/cpuinfo`
- `free -m`

---

# Detection Scenarios Investigated

- Suspicious discovery commands
- EDR and antivirus process enumeration
- SSH brute-force attacks
- Cryptominer deployment activity
- Malicious script execution
- SCP and curl/wget file transfers
- Internal network scanning
- Process lineage analysis
- Persistence mechanisms
- Threat actor TTP investigation

---

# Skills Developed

- Linux threat detection
- SOC investigation workflow
- Incident response fundamentals
- Log correlation
- Threat hunting
- Process analysis
- Blue team investigation techniques
- Detection engineering fundamentals
- Linux forensic investigation

---

# Rooms Completed

| Room | Focus Area |
|---|---|
| Linux Threat Detection 1 | Linux discovery and monitoring |
| Linux Threat Detection 2 | Threat hunting and cryptominer investigation |
| Linux Threat Detection 3 | Advanced Linux threat analysis and investigation |

---

# Repository Structure

```text
Linux_Threat_Detection/
│
├── README.md
│
├── Linux_Threat_Detection_1/
│   ├── README.md
│   └── walkthrough.docx
│
├── Linux_Threat_Detection_2/
│   ├── README.md
│   └── walkthrough.docx
│
├── Linux_Threat_Detection_3/
    ├── README.md
    └── walkthrough.docx

