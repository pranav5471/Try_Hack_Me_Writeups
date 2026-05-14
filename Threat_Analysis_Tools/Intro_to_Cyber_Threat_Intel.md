# Intro to Cyber Threat Intelligence — TryHackMe Walkthrough

## Overview

In this room, I explored the fundamentals of Cyber Threat Intelligence (CTI) and learned how intelligence is used during security investigations and threat analysis. The room introduced different intelligence classifications, the CTI lifecycle, and common frameworks used by analysts and threat intelligence teams.

What I liked about this room was how it connected technical indicators with real-world investigation workflows. Instead of only focusing on alerts or logs, it explained how analysts turn raw data into actionable intelligence that can help organisations make security decisions.

---

# What I Learned

Throughout this room, I gained a better understanding of:

- The role of Cyber Threat Intelligence in security operations
- Different types of threat intelligence
- The CTI lifecycle and how intelligence is processed
- MITRE ATT&CK, STIX, and TAXII frameworks
- The Cyber Kill Chain model
- Basic threat profiling and IOC analysis

---

# Understanding Cyber Threat Intelligence

One of the key concepts introduced was the difference between data, information, and intelligence.

| Type | Explanation |
|---|---|
| Data | Raw indicators such as IP addresses, hashes, or URLs |
| Information | Processed data that answers investigative questions |
| Intelligence | Correlated and contextualized information used to support decisions |

This helped me understand that threat intelligence is not just collecting logs or indicators, but analysing them in context to understand attacker behavior.

---

# Threat Intelligence Classifications

The room also explained the different classifications of threat intelligence.

| Classification | Purpose |
|---|---|
| Strategic Intelligence | Focuses on organisational risks and high-level threat trends |
| Technical Intelligence | Focuses on IOCs such as hashes, domains, and IPs |
| Tactical Intelligence | Analyses attacker tactics, techniques, and procedures |
| Operational Intelligence | Focuses on attacker motives and campaign objectives |

I found Tactical and Technical Intelligence especially interesting because they relate closely to SOC investigations and detection engineering.

---

# CTI Lifecycle

The room introduced the Cyber Threat Intelligence lifecycle, which analysts follow to transform raw data into useful intelligence.

## 1. Direction
Defining objectives, critical assets, and investigation goals.

## 2. Collection
Gathering intelligence from internal logs, external feeds, and open-source resources.

## 3. Processing
Organising and correlating raw data into usable formats.

## 4. Analysis
Investigating threats, identifying patterns, and producing actionable insights.

## 5. Dissemination
Sharing intelligence with technical teams and management stakeholders.

## 6. Feedback
Improving the intelligence process based on stakeholder responses.

This section helped me understand how intelligence operations work in real-world SOC and threat intelligence environments.

---

# Frameworks and Standards Covered

## MITRE ATT&CK

The room introduced MITRE ATT&CK as a framework used to map adversary tactics and techniques during investigations.

---

## TAXII

TAXII is used for securely sharing threat intelligence between organisations.

### TAXII Sharing Models

| Model | Description |
|---|---|
| Collection | Request-response sharing |
| Channel | Publish-subscribe sharing |

---

## STIX

STIX provides a standardised way of structuring and sharing cyber threat intelligence data.

---

# Cyber Kill Chain

The room also covered the Lockheed Martin Cyber Kill Chain model.

| Phase | Description |
|---|---|
| Reconnaissance | Gathering target information |
| Weaponisation | Preparing malicious payloads |
| Delivery | Delivering malware or phishing payloads |
| Exploitation | Exploiting vulnerabilities |
| Installation | Installing malware or persistence |
| Command & Control | Attacker communication with compromised systems |
| Actions on Objectives | Data theft or achieving attack goals |

Learning this model helped me better understand the progression of cyber attacks and how defenders can identify attacks at different stages.

---

# Practical Investigation

The practical section simulated a threat investigation where I had to analyse alert logs and identify attacker activity.

## Investigation Findings

| Investigation Item | Result |
|---|---|
| Source Email Address | vipivillain@badbank.com |
| Downloaded File | flbpfuh.exe |
| Compromised User Account | Administrator |
| Targeted Victim | John Doe |

---

# Indicators of Compromise (IOCs) Identified

- Suspicious email activity
- Malicious executable download
- Unauthorized account access
- Suspicious outbound traffic
- Potential malware execution

---

# Flag

```text
THM{NOW_I_CAN_CTI}
```

---

# Key Takeaways

- CTI helps security teams understand attacker behavior and improve defenses.
- Intelligence becomes valuable when data is correlated and analyzed in context.
- Frameworks like MITRE ATT&CK, STIX, and TAXII standardize threat analysis and sharing.
- Understanding the Cyber Kill Chain helps identify attack progression during investigations.
- Practical IOC analysis improves threat hunting and SOC investigation skills.

---

# Final Thoughts

This room gave me a solid introduction to Cyber Threat Intelligence and how analysts use intelligence during investigations. I particularly enjoyed learning about the CTI lifecycle and how frameworks like MITRE ATT&CK and the Cyber Kill Chain help analysts map attacker activity.

Overall, this room helped me better understand how intelligence supports threat detection, investigation, and incident response in real-world security operations.

---
