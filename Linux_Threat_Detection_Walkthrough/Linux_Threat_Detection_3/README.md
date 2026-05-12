# Linux Threat Detection 3

## Overview

This room focused on advanced Linux attack techniques commonly seen during targeted intrusions. Unlike simple automated attacks such as SSH brute-forcing or cryptomining, this room explored manual attacker behavior including reverse shells, privilege escalation, startup persistence, and account persistence.

The investigation relied heavily on analyzing audit logs, authentication logs, suspicious command execution, and persistence mechanisms to trace attacker activity across the Linux system.

---

# Topics Covered

- Reverse shell detection
- OS command injection
- Privilege escalation
- Credential discovery
- Startup persistence
- Cron job persistence
- Systemd service persistence
- SSH key persistence
- Account persistence
- auditd investigations
- Authentication log analysis
- Threat hunting methodologies

---

# Skills Practiced

- Linux threat hunting
- SOC investigation workflow
- auditd analysis
- Process tracing
- Persistence detection
- Authentication log analysis
- Incident response investigation
- Suspicious command analysis
- Blue team investigation techniques

---

# Key Commands Used

## Log Analysis

```bash
ausearch -i -if /home/ubuntu/scenario/audit.log
grep -a
cat /var/log/auth.log

# Privilege Escalation Investigation

```bash
grep -iR pass .
su root
cat .env.local
```

### `grep -iR pass .`
Recursively searches for files containing the keyword `pass` to identify exposed credentials or sensitive information.

### `su root`
Attempts privilege escalation to the root account.

### `cat .env.local`
Reads environment configuration files that may contain sensitive credentials, API keys, or secrets.

---

# Persistence Investigation

```bash
ausearch -i -x crontab
crontab -l
cat /etc/system/system/tux.service
```

### `ausearch -i -x crontab`
Searches audit logs for cron job-related activity.

### `crontab -l`
Lists scheduled cron jobs configured for the current user.

### `cat /etc/system/system/tux.service`
Reads the systemd service file to investigate suspicious persistence mechanisms.

---

# Account Persistence Investigation

```bash
cat /var/log/auth.log | grep -a useradd
ausearch -i -f /.ssh/authorized_keys
```

### `cat /var/log/auth.log | grep -a useradd`
Searches authentication logs for unauthorized user creation activity.

### `ausearch -i -f /.ssh/authorized_keys`
Investigates modifications to SSH authorized keys used for persistence.
