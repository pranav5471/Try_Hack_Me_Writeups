# 🕷️ ItsyBitsy — TryHackMe Challenge Room Writeup

> **Module:** SIEM Triage for SOC | **Path:** SOC Level 1  
> **Difficulty:** Medium  
> **Tools Used:** Kibana (ELK Stack)  
> **Focus:** C2 Communication Detection, HTTP Log Analysis, OSINT

---

## 📖 Room Overview

**Room Link:** https://tryhackme.com/room/itsybitsy

This is a challenge room — no step-by-step guidance is provided. You are given a scenario and a Kibana instance loaded with HTTP connection logs, and you must investigate the incident independently.

The room tests your ability to:
- Use Kibana to filter and analyse HTTP connection logs
- Identify suspicious traffic patterns and anomalous user agents
- Pivot on IP addresses to identify C2 infrastructure
- Use OSINT to validate findings
- Trace the full C2 communication chain

---

## 🧠 Key Concepts

### ELK Stack
| Component | Role |
|-----------|------|
| **Elasticsearch** | Search and analytics engine that stores and indexes log data |
| **Logstash** | Server-side pipeline that ingests, transforms, and forwards log data |
| **Kibana** | Visualisation interface — the analyst's primary tool for querying and exploring logs |

### Intrusion Detection System (IDS)
A monitoring system that detects suspicious activity and generates alerts. In a SOC, an IDS alert is the starting point — the analyst's job is to validate whether it is a true positive and investigate the full scope of the incident.

### Command & Control (C2) Server
A server controlled by an attacker used to send instructions to compromised machines and receive stolen data. Malware on infected hosts periodically "beacons" back to the C2 server — often using legitimate protocols (like HTTP) to blend in with normal traffic.

---

## 📋 Scenario

> During normal SOC monitoring, Analyst John observed an alert on an IDS solution indicating a **potential C2 communication** from a user **Browne** from the HR department. A suspicious file was accessed containing a malicious pattern `THM{________}`. A week-long HTTP connection log has been pulled to investigate.
>
> Due to limited resources, only the connection logs were pulled and ingested into the `connection_logs` index in Kibana.

**Objective:** Examine the HTTP connection logs, identify the C2 infrastructure, and recover the malicious payload.

**Kibana Credentials:**
```
Username: Admin
Password: elastic123
```
Navigate to the **Discover** tab after logging in.

---

## 🔍 Investigation & Findings

### Step 1 — Set the Time Range

Set the Kibana time filter to cover **March 2022** to scope the investigation to the relevant period.

---

### Q1: How many events were returned for the month of March 2022?

**Answer:** `1482`

**Method:** Set the time filter to March 2022. The total event count is displayed at the top of the Discover tab.

**Takeaway:** Starting with the total event count gives you a baseline — it tells you how much data you're working with and helps detect anomalies in traffic volume.

---

### Step 2 — Analyse Source IPs

Opened the **Fields Pane** on the left in Kibana and clicked on `source_ip` to view the distribution of traffic by source IP.

**Observation:**
| Source IP | % of Traffic | Notes |
|-----------|-------------|-------|
| `192.166.65.52` | 99.6% | Normal traffic |
| `192.166.65.54` | 0.4% | ⚠️ Suspicious — minority traffic |

> Low-volume traffic from a minority IP is a classic C2 beaconing pattern — C2 beacons are designed to be infrequent and blend in.

---

### Q2: What is the IP associated with the suspected user in the logs?

**Answer:** `192.166.65.54`

**Method:** Filtered on `source_ip` in the Fields Pane. The minority IP `192.166.65.54` was flagged as suspicious based on its low traffic volume.

**OSINT Validation:** Searched the destination IP `104.23.99.190` on AlienVault OTX → confirmed as a **Command and Control IP**.
```
https://otx.alienvault.com/indicator/ip/104.23.99.190
```

**Takeaway:** In C2 detection, volume alone can be misleading. C2 beaconing is often low-frequency and designed to blend into normal traffic. Minority traffic deserves close inspection.

---

### Step 3 — Investigate the User Agent

Clicked on the `user_agent` field in the Fields Pane.

**Finding:**
| User Agent | % of Traffic |
|-----------|-------------|
| Normal browser agents | 99.6% |
| `bitsadmin` | 0.4% |

Clicked the **`+` button** next to `bitsadmin` to filter only those events — returned exactly **2 results**, both from `192.166.65.54`.

---

### Q3: The user's machine used a legitimate Windows binary to download a file from the C2 server. What is the name of the binary?

**Answer:** `bitsadmin`

**What is bitsadmin?**
`bitsadmin.exe` is a Microsoft-signed Windows command-line utility for managing Background Intelligent Transfer Service (BITS) jobs — commonly used for Windows Updates. Attackers abuse it because:
- It is signed by Microsoft and trusted by security tools
- It can silently download files from the internet
- It blends in with legitimate OS activity

**MITRE ATT&CK:** T1197 — BITS Jobs

---

### Step 4 — Identify the C2 Domain

With the `bitsadmin` filter active, expanded the log event and read the `host` field.

---

### Q4: The infected machine connected with a famous file-sharing site that also acts as a C2 server. What is the name of the site?

**Answer:** `pastebin.com`

**Method:** `host` field in the filtered events clearly showed `pastebin.com` as the destination.

**Takeaway:** Attackers frequently abuse legitimate platforms like Pastebin as C2 infrastructure — traffic to these sites is rarely blocked by firewalls and looks like normal user activity.

---

### Step 5 — Get the Full C2 URL

Read the `uri` field from the same filtered event and combined it with the `host` field:

```
host : pastebin.com
uri  : /yTg0Ah6a
──────────────────────────
Full URL: pastebin.com/yTg0Ah6a
```

---

### Q5: What is the full URL of the C2 to which the infected host is connected?

**Answer:** `pastebin.com/yTg0Ah6a`

---

### Step 6 — Access the C2 and Recover the Payload

> The `resp_mime_types` field in the log shows `text/plain` — hinting the downloaded file is a `.txt` file before even visiting the URL.

Navigated to the Pastebin URL in a browser:
```
https://pastebin.com/yTg0Ah6a
```

---

### Q6: A file was accessed on the file-sharing site. What is the name of the file accessed?

**Answer:** `secret.txt`

---

### Q7: The file contains a secret code with the format THM{_____}. What is it?

**Answer:** `THM{************}` *(complete the room to recover the flag)*

---

## 🗺️ Full Attack Chain

```
[IDS Alert] C2 Beacon Detected
          │
          ▼
[Infected Host] 192.166.65.54
 User: Browne — HR Department
          │
          │  bitsadmin.exe (LOLBIN) used to make HTTP request
          ▼
[C2 Infrastructure] pastebin.com
          │
          │  Downloads payload from:
          ▼
pastebin.com/yTg0Ah6a ──► secret.txt ──► THM{flag}
          │
          ▼
[Destination IP] 104.23.99.190
 Confirmed C2 — AlienVault OTX
```

---

## 🎯 MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| BITS Jobs | T1197 | `bitsadmin.exe` used to download payload from C2 |
| Web Service (C2) | T1102 | Pastebin.com used as C2 communication channel |
| Ingress Tool Transfer | T1105 | File downloaded from external C2 to infected host |

---

## 🛠️ Kibana Steps & Commands

```
# Step 1 — Scope the investigation
Time filter → March 1, 2022 to March 31, 2022

# Step 2 — Identify suspicious source IPs
Fields Pane → click source_ip
→ Note: 192.166.65.54 accounts for only 0.4% of traffic

# Step 3 — Check user agents
Fields Pane → click user_agent
→ Note: bitsadmin user-agent present in 0.4% of traffic
→ Click [+] next to bitsadmin to filter
→ Result: 2 events, both from 192.166.65.54

# Step 4 — Identify destination domain
Expand filtered event → read host field
→ host: pastebin.com

# Step 5 — Get full C2 URL
Expand filtered event → read uri field
→ uri: /yTg0Ah6a
→ Full URL: pastebin.com/yTg0Ah6a

# Step 6 — Recover the payload
resp_mime_types: text/plain  (hints at a .txt file)
Navigate browser to: https://pastebin.com/yTg0Ah6a
→ File: secret.txt
→ Contents: THM{flag}

# OSINT Validation
Search destination IP on AlienVault OTX:
https://otx.alienvault.com/indicator/ip/104.23.99.190
→ Confirmed: Command and Control IP
```

> **Note:** ItsyBitsy uses Kibana's point-and-click interface — Fields Pane filters and event expansion — rather than typed KQL queries. The steps above reflect the actual investigation workflow used in the room.

---

## 💡 Key Takeaways

1. **C2 traffic is designed to hide.** Low-volume traffic from a minority IP was the key indicator — not something obviously suspicious at first glance.

2. **User-agent strings reveal tool behaviour.** The `bitsadmin` user-agent immediately indicated a Windows binary was being used programmatically, not a browser.

3. **Legitimate platforms get abused.** Pastebin is not inherently malicious — but its open, anonymous nature makes it attractive for hosting C2 payloads. Traffic to it won't be blocked, and it looks like normal user activity.

4. **OSINT validates findings.** Checking the destination IP against AlienVault OTX confirmed the C2 classification — a standard step in real SOC investigations.

5. **The investigative process matters more than the tool.** Filter → Pivot → Correlate → Validate. The same logic works in Splunk, Elastic, or any other SIEM.

---

## 📌 Room Summary

| Field | Detail |
|-------|--------|
| Room | ItsyBitsy |
| Platform | TryHackMe |
| Module | SIEM Triage for SOC |
| SIEM Tool | Kibana (ELK Stack) |
| Log Index | `connection_logs` |
| Log Type | HTTP Connection Logs |
| Attack Type | C2 Communication via LOLBIN |
| C2 Platform | Pastebin.com |
| LOLBIN Used | `bitsadmin.exe` |
| Suspicious IP | `192.166.65.54` |
| C2 URL | `pastebin.com/yTg0Ah6a` |
| Payload File | `secret.txt` |
| MITRE Techniques | T1197, T1102, T1105 |
| Difficulty | Medium |

---

> *"C2 traffic doesn't always look suspicious. You find it by looking at what's unusual relative to everything else."*
