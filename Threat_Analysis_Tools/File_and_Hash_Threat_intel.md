# File and Hash Threat Intel — TryHackMe Walkthrough

## Overview

In this room, I investigated multiple suspicious files that were flagged by an EDR solution during a routine security sweep. The scenario simulated a real SOC workflow where analysts must quickly determine whether files are malicious, benign, or suspicious using threat intelligence platforms and malware analysis techniques.

Throughout the room, I worked with file hashes, malware reputation tools, sandbox analysis platforms, and MITRE ATT&CK mappings to investigate suspicious binaries and understand their behavior.

This room helped me better understand how SOC analysts perform malware triage and correlate indicators across multiple intelligence sources during investigations.

---

# Scenario

Try Daily was preparing a major software release when the EDR platform flagged several suspicious files across employee systems. As part of the SOC investigation process, I analysed these files to determine whether they represented real threats or false positives.

---

# Skills Practiced

- Threat intelligence analysis
- File reputation investigation
- SHA256 hash analysis
- IOC identification
- Malware sandbox analysis
- Process tree investigation
- MITRE ATT&CK mapping
- Malware behavior analysis
- Threat hunting fundamentals

---

# Tools and Platforms Used

| Tool | Purpose |
|---|---|
| VirusTotal | Malware reputation and intelligence lookup |
| Hybrid Analysis | Sandbox behavior analysis |
| MalwareBazaar | Malware intelligence investigation |
| PowerShell | Hash generation and file analysis |
| certutil | SHA256 hash generation |

---

# Suspicious File Investigation

## Identifying Suspicious Indicators

One of the suspicious files displayed a common malware indicator used by attackers to disguise executables as harmless documents.

### File Identified

| File | Indicator |
|---|---|
| payroll.pdf | Double extensions |

### Analysis

While reviewing the file properties, I noticed the use of double extensions. Attackers commonly use this technique to make malicious files appear legitimate to users.

For example:

```text
invoice.pdf.exe
```

may appear as:

```text
invoice.pdf
```

depending on Windows file extension settings.

This behavior is commonly associated with malware delivery and phishing campaigns.

---

# SHA256 Hash Investigation

## Generating File Hashes

To investigate the suspicious executable `bl0gger.exe`, I generated its SHA256 hash using PowerShell and `certutil`.

### Command Used

```powershell
certutil -hashfile bl0gger.exe SHA256
```

### SHA256 Hash

```text
2672b6688d7b32a90f9153d2ff607d6801e6cbde61f509ed36d0450745998d58
```

### Analysis

SHA256 hashes are commonly used in malware investigations because they uniquely identify files and can be searched across threat intelligence platforms.

---

# VirusTotal Investigation

## Threat Label Analysis

After generating the SHA256 hash, I searched the file on VirusTotal to identify its malware classification.

### Threat Label

```text
trojan.graftor/blackmoon
```

### Analysis

VirusTotal classified the file as a trojan associated with the BlackMoon malware family.

This indicates that multiple security vendors had already identified the file as malicious.

---

# File Submission History

## First Submission Date

```text
2025-05-15 12:03:49
```

### Analysis

I located this information under the VirusTotal Details tab.

The first submission date helps analysts understand when the malware was first observed in the wild.

---

# MalwareBazaar Investigation

## Vendor Classification

While investigating another suspicious sample named `Morse-Code-Analyzer`, I searched its SHA256 hash on MalwareBazaar.

### Vendor Result

```text
Cyberfortress
```

### Analysis

The Cyberfortress vendor classified the sample as non-malicious.

This demonstrates how malware classifications can vary across different intelligence vendors.

---

# MITRE ATT&CK Investigation

## Persistence and Privilege Escalation Technique

While reviewing the VirusTotal Behavior tab, I identified the following MITRE ATT&CK technique:

```text
DLL Side-loading
```

### Analysis

DLL Side-loading occurs when attackers place malicious DLL files where legitimate applications will load them automatically.

This technique is commonly used for:
- Persistence
- Privilege escalation
- Defense evasion

---

# Hybrid Analysis Investigation

## Malware Tags

Using Hybrid Analysis, I reviewed the sandbox report for `bl0gger.exe`.

### Tags Identified

```text
BlackMoon, Discovery, windows-server-utility
```

### Analysis

These tags indicate behaviors associated with:
- Information gathering
- System discovery
- Trojan activity

Sandbox reports help analysts understand malware behavior in controlled environments.

---

# Stealth Command Analysis

## Suspicious Command Observed

```cmd
regsvr32 %WINDIR%\Media\ActiveX.ocx /s
```

### Analysis

The malware abused `regsvr32.exe`, which is a legitimate Windows utility commonly used to register DLL files.

Attackers frequently abuse this binary as a LOLBin (Living Off the Land Binary) to evade detection while executing malicious code.

The `/s` flag performs silent execution without displaying prompts to the user.

---

# Process Tree Investigation

## Spawned Process

```text
werfault.exe
```

### Analysis

While reviewing the sandbox process tree, I identified `werfault.exe` as a spawned child process.

Process tree analysis is important because it helps analysts trace malware execution chains and identify suspicious parent-child relationships.

---

# Masquerading Investigation

## Impersonated Windows Process

```text
svchost.exe
```

### Analysis

The suspicious file attempted to masquerade as the legitimate Windows process `svchost.exe`.

Attackers frequently impersonate trusted system processes to avoid suspicion and bypass security monitoring.

---

# Network IOC Investigation

## Associated URL

```text
hxxp://121.182.174.27:3000/server.exe
```

### Analysis

Hybrid Analysis identified this URL as associated network activity linked to the suspicious file.

The `hxxp` format is commonly used in cybersecurity documentation to prevent accidental clicking of malicious URLs.

---

# Extracted Strings Analysis

## Total Strings Identified

```text
454
```

### Analysis

Extracted strings can reveal:
- Hardcoded URLs
- Registry paths
- File names
- Commands
- API references

These indicators are valuable during malware investigations and threat hunting activities.

---

# Challenge.bin.sample Investigation

## SHA256 Hash

```text
43b0ac119ff957bb209d86ec206ea1ec3c51dd87bebf7b4a649c7e6c7f3756e7
```

---

# Malware Family Identification

## Family Labels

```text
akira, filecryptor
```

### Analysis

VirusTotal identified the sample as part of the Akira ransomware family.

Ransomware families often:
- Encrypt victim files
- Drop ransom notes
- Delete backups
- Disable recovery mechanisms

---

# First Seen in the Wild

## Initial Observation Date

```text
2024-10-30 17:17:24 UTC
```

### Analysis

This timestamp indicates when the malware was first observed publicly.

Tracking malware timelines helps analysts understand campaign evolution and outbreak periods.

---

# Ransomware Activity Investigation

## Dropped File

```text
akira_readme.txt
```

### Analysis

The ransomware dropped a ransom note after execution.

Ransom notes are commonly used to:
- Demand payment
- Provide attacker instructions
- Deliver cryptocurrency wallet details

---

# PowerShell Investigation

## Suspicious PowerShell Command

```powershell
Get-WmiObject Win32_Shadowcopy | Remove-WmiObject
```

### Analysis

This command deletes Windows Shadow Copies.

Attackers commonly remove shadow copies to prevent victims from restoring encrypted files after ransomware attacks.

This behavior is strongly associated with ransomware operations.

---

# MITRE ATT&CK Mapping

## Technique ID

```text
T1490 — Inhibit System Recovery
```

### Analysis

This MITRE ATT&CK technique involves deleting or disabling recovery features to make restoration more difficult for victims.

It is frequently observed during ransomware incidents.

---

# Indicators of Compromise (IOCs)

## File Indicators

- Double file extensions
- Suspicious SHA256 hashes
- Masquerading as svchost.exe

## Behavioral Indicators

- DLL Side-loading
- LOLBin abuse using regsvr32
- Shadow copy deletion
- Suspicious process spawning

## Network Indicators

- Malicious outbound URL activity
- External executable downloads

---

# Key Takeaways

- File hashes are critical for malware identification and threat intelligence correlation.
- VirusTotal, Hybrid Analysis, and MalwareBazaar provide valuable threat intelligence insights.
- Sandbox reports help analysts understand malware execution behavior.
- LOLBins such as `regsvr32.exe` are commonly abused during attacks.
- Process tree analysis is essential for understanding malware execution chains.
- MITRE ATT&CK mappings help classify attacker techniques and behaviors.
- Ransomware frequently attempts to inhibit system recovery by deleting shadow copies.

---

# Final Thoughts

This room provided hands-on experience with malware triage and file-based threat intelligence investigations from a SOC analyst perspective.

I particularly enjoyed working with multiple intelligence platforms to correlate indicators, investigate malware behaviors, and identify attacker techniques using real-world analysis workflows.

The room helped strengthen my understanding of:
- malware investigation workflows
- sandbox analysis
- threat intelligence correlation
- IOC investigation
- ransomware behavior analysis
- MITRE ATT&CK mapping

Overall, this was an excellent room for building practical SOC investigation and malware triage skills.

---
