# Linux Threat Detection 1

## Overview

This room focused on detecting Initial Access activity in Linux environments, particularly attacks involving exposed SSH services, password brute-forcing, vulnerable web applications, and reverse shell activity.

The investigation introduced practical SOC analyst techniques such as authentication log analysis, auditd investigations, suspicious command monitoring, and process tree analysis.

---

# Topics Covered

- SSH exposure risks
- SSH brute-force attacks
- Password-based authentication detection
- Public service exploitation
- OS command injection
- Reverse shell investigation
- Process tree analysis
- auditd monitoring
- Initial Access techniques
- Supply chain compromise concepts

---

# Skills Practiced

- Linux threat detection
- Authentication log analysis
- SOC investigation workflow
- Threat hunting
- Reverse shell investigation
- Process lineage tracing
- Suspicious command analysis
- Blue team investigation techniques

---

# Key Commands Used

## Authentication Log Analysis
```bash id="vwf1bn"
cat /var/log/auth.log | grep "sshd"
cat /var/log/auth.log | grep "Accepted"
cat /var/log/auth.log | grep "password"
