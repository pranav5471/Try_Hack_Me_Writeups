# 🔎 Threat Analysis Tools — TryHackMe Module Writeup

> **Module:** Threat Analysis Tools | **Path:** SOC Level 1  
> **Badge Earned:** 🏅 Lookup Champion  
> **Status:** ✅ Completed

---

## 📖 Overview

This module covers how SOC analysts use **Threat Intelligence (TI) lookups** to investigate suspicious activity, validate indicators of compromise (IOCs), and build context around potential threats. It consists of multiple hands-on rooms that simulate real-world L1 analyst scenarios.

---

## 🗂️ Rooms Covered

| Room | Focus Area |
|------|------------|
| Intro to Cyber Threat Intel | CTI concepts, lifecycle, frameworks (MITRE, STIX, TAXII, Cyber Kill Chain) |
| IP & Domain Threat Intel | Investigating IPs, domains, DNS records, and infrastructure |
| File & Hash Threat Intel | Analysing files and hashes for malicious indicators |
| Invite Only (Challenge) | Full threat investigation and malware analysis scenario |

---

## 🔧 Tools Used

### File & Hash Analysis
| Tool | Purpose |
|------|---------|
| [VirusTotal](https://www.virustotal.com) | Hash/file reputation, threat labels, MITRE ATT&CK mapping |
| [MalwareBazaar](https://bazaar.abuse.ch) | Vendor classifications, malware sample lookup |
| [Hybrid Analysis](https://www.hybrid-analysis.com) | Sandbox reports, process trees, stealth command detection |

### IP & Domain Intelligence
| Tool | Purpose |
|------|---------|
| [Shodan](https://www.shodan.io) | Internet-facing infrastructure and open port analysis |
| [IPinfo](https://ipinfo.io) | IP geolocation and ASN lookup |
| [Cisco Talos Intelligence](https://talosintelligence.com) | IP/domain threat reputation |
| [DNSDumpster](https://dnsdumpster.com) | DNS record mapping and subdomain discovery |
| [MXToolbox](https://mxtoolbox.com) | Mail record and DNS health checks |
| [DNSChecker](https://dnschecker.org) | Global DNS propagation checks |

### Passive Recon & OSINT
| Tool | Purpose |
|------|---------|
| WHOIS | Domain registration and ownership lookup |
| nslookup | DNS resolution queries |
| RIR Lookups | Regional Internet Registry data (IP ownership) |
| CT Logs | Certificate Transparency logs for subdomain enumeration |
| Wayback Machine | Historical snapshots of websites |

---

## 📚 Key Concepts Learned

### CTI Lifecycle
```
Direction → Collection → Processing → Analysis → Dissemination → Feedback
```

### Threat Intelligence Classifications
- **Strategic Intel** — High-level trends for business decisions
- **Tactical Intel** — Adversary TTPs for security control improvements
- **Technical Intel** — Artefacts and IOCs for incident response
- **Operational Intel** — Adversary motives and specific attack intent

### Frameworks & Standards
- **MITRE ATT&CK** — Adversary behaviour and technique mapping
- **STIX** — Structured Threat Information Expression
- **TAXII** — Trusted Automated eXchange of Indicator Information
- **Cyber Kill Chain** — Lockheed Martin's stages of an attack

---

## 📝 Room Notes & Answers

### 🏠 Room 1 — Intro to Cyber Threat Intel
- Covers CTI definitions, classifications, the 6-phase lifecycle, and key frameworks
- Key distinction: Data → Information → Intelligence
- Frameworks covered: MITRE ATT&CK, STIX, TAXII, Cyber Kill Chain, Diamond Model

---

### 🏠 Room 2 — IP & Domain Threat Intel
- Scenario: Investigating suspicious IP addresses and domains from SOC alerts
- Tools used: WHOIS, DNSDumpster, Shodan, Cisco Talos, MXToolbox, IPinfo, DNSChecker
- Skills practiced: DNS record analysis, infrastructure mapping, passive recon

---

### 🏠 Room 3 — File & Hash Threat Intel

**Scenario:** L1 analyst reviewing EDR-flagged binaries within a 60-minute triage window.

Key findings and exercises:
- Identified **double extension** IOC on `payroll.pdf`
- Generated SHA256 hash using `certutil -hashfile <file> SHA256`
- Investigated hashes on VirusTotal, MalwareBazaar, and Hybrid Analysis
- Identified MITRE technique **DLL Side-loading** for persistence/privilege escalation
- Found **Akira ransomware** family labels and associated `akira_readme.txt` drop
- Mapped PowerShell command to **MITRE T1490** (Inhibit System Recovery)
- Discovered `payroll.pdf` masquerading as `svchost.exe`

---

### 🏠 Room 4 — Invite Only (Challenge)
- Full investigation combining hash analysis, phishing techniques, and malware delivery chains
- Applied all tools and concepts from previous rooms in a realistic SOC scenario

---

## 💡 Key Takeaways

- A single IP address or file hash can reveal an entire attacker infrastructure when investigated properly
- Pivoting between tools (VirusTotal → Hybrid Analysis → MalwareBazaar) builds a complete picture of a threat
- The investigative mindset — connecting small, disconnected indicators — is as important as knowing the tools
- MITRE ATT&CK is central to understanding and communicating what malware actually does

---

## 👤 Author

**Pranav** | Aspiring SOC Analyst | Blue Team Enthusiast  
🔗 [GitHub](https://github.com/pranav5471) | 🔗 [TryHackMe Profile](https://tryhackme.com)

---

> *"Security is a process, not a product."* — Bruce Schneier
