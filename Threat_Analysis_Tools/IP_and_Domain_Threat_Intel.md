# IP and Domain Threat Intel — TryHackMe Walkthrough

## Overview

In this room, I worked through a threat intelligence investigation focused on suspicious IP addresses and domains identified during SOC monitoring activities.

The room simulated a realistic scenario where analysts are provided with limited indicators such as:
- domains
- IP addresses
- DNS records
- outbound traffic

From there, the objective was to enrich these indicators using OSINT and threat intelligence platforms to determine whether the infrastructure was benign or potentially malicious.

Throughout the investigation, I used several intelligence and reconnaissance platforms including:
- WHOIS
- RDAP
- Shodan
- Censys
- VirusTotal
- Passive DNS
- Certificate Transparency logs

This room helped me better understand how SOC analysts pivot from a single IOC into broader infrastructure analysis during investigations.

---

# Scenario

The SOC flagged multiple suspicious domains and IP addresses originating from phishing emails and proxy logs.

The following artefacts were provided for investigation:

## Suspicious Domain

```text
advanced-ip-sccanner[.]com
```

## Suspicious IP Addresses

```text
166[.]1[.]160[.]118
64[.]31[.]63[.]194
69[.]197[.]185[.]26
85[.]188[.]1[.]133
```

The investigation focused on identifying:
- infrastructure ownership
- DNS relationships
- reputation
- exposed services
- historical registrations
- potential malicious behavior

---

# Skills Practiced

- Threat intelligence analysis
- Domain investigation
- IP enrichment
- Passive DNS analysis
- WHOIS investigations
- ASN analysis
- Certificate Transparency investigation
- Service enumeration
- Infrastructure profiling
- IOC enrichment

---

# Tools and Platforms Used

| Tool | Purpose |
|---|---|
| VirusTotal | Reputation and IOC analysis |
| Shodan | Internet-facing service enumeration |
| Censys | TLS and infrastructure analysis |
| RDAP | Registration and ownership lookup |
| crt.sh | Certificate Transparency analysis |
| DNSdumpster | DNS investigation |
| nslookup.io | DNS record analysis |
| ipinfo.io | ASN and geolocation analysis |

---

# Domain Investigation

## Suspicious Domain Analysis

The first artefact investigated was:

```text
advanced-ip-sccanner[.]com
```

### Initial Observation

At first glance, the domain appeared to be a typosquatted version of the legitimate software:

```text
Advanced IP Scanner
```

The attacker intentionally added an extra “c” in:
```text
sccanner
```

Typosquatting domains are commonly used during:
- phishing campaigns
- malware delivery
- fake software distribution attacks

---

# DNS Investigation

## A Record Lookup

Using DNS lookup services, I identified the IPv4 addresses associated with the suspicious domain.

### A Records

```text
172.67.189.143
104.21.9.202
```

### Analysis

A records map domains to IP addresses.

These records help analysts identify:
- hosting infrastructure
- associated services
- linked malicious activity

---

# Nameserver Investigation

## NS Records Identified

```text
jaziel[.]ns[.]cloudflare[.]com
summer[.]ns[.]cloudflare[.]com
```

### Analysis

The domain used Cloudflare nameservers.

Threat actors commonly use CDN and protection services like Cloudflare to:
- hide origin infrastructure
- avoid takedowns
- mask hosting providers

---

# IP Enrichment Investigation

# Investigating IP: 64[.]31[.]63[.]194

When analysts receive suspicious IP addresses, enrichment helps provide additional context about:
- ownership
- geolocation
- ASN information
- registration history

---

# RDAP Investigation

## Registration Date

Using RDAP lookup services, I identified the registration information for the IP block.

### Registration Timestamp

```text
12/27/2010, 3:51:03 PM
```

### Analysis

RDAP provides authoritative registration data directly from Regional Internet Registries.

This information helps analysts determine:
- infrastructure ownership
- registration timelines
- responsible entities

---

# Entity Role Investigation

## Roles Assigned

```text
administrative, technical
```

### Analysis

The entity `NOC2791-ARIN` was assigned administrative and technical responsibilities for the IP range.

This indicates responsibility for:
- infrastructure management
- operational maintenance
- technical support

---

# Geolocation Investigation

## Country Identified

```text
France
```

### Analysis

Geolocation data helps analysts understand:
- regional hosting trends
- infrastructure jurisdictions
- potential legal considerations

Although geolocation is not always precise, it provides valuable context during investigations.

---

# ASN Investigation

## Autonomous System Number

```text
AS136258
```

### Analysis

ASN information identifies the organization responsible for routing the IP range across the internet.

Threat actors often abuse hosting providers and cloud infrastructure associated with large ASNs.

---

# Shodan Investigation

# Investigating IP: 85[.]188[.]1[.]133

Using Shodan, I investigated exposed services and internet-facing infrastructure associated with the suspicious IP.

---

# Primary Service Identified

```text
FTP
```

### Analysis

FTP services are commonly targeted by attackers because:
- they may use weak credentials
- they often expose sensitive files
- older implementations may contain vulnerabilities

---

# Open Ports Investigation

## Number of Open Ports

```text
6
```

### Analysis

Multiple exposed ports increase the attack surface of a system.

Analysts should investigate:
- unnecessary services
- outdated software
- exposed administrative interfaces

---

# TLS Certificate Investigation

## TLS Fingerprint

```text
48d6057099841bd18809fd61aa990b17779176de7799f301dac24879da553456
```

### Analysis

TLS fingerprints help analysts:
- identify reused infrastructure
- correlate servers
- track attacker infrastructure

Certificate reuse is common across malicious campaigns.

---

# Certificate Transparency Investigation

## CT Logs Found

```text
Yay
```

### Analysis

Certificate Transparency logs contain publicly recorded TLS certificates.

Analysts use CT logs to:
- identify malicious domains
- track phishing infrastructure
- discover related attacker assets

---

# Reputation Investigation

# Investigating IP: 166[.]1[.]160[.]118

Using VirusTotal and historical WHOIS records, I investigated the reputation and infrastructure ownership associated with this IP.

---

# File Association Investigation

## Linked File

```text
ff4c287c60ede1990442115bddd68201d25a735458f76786a938a0aa881d14ef.exe
```

### Analysis

VirusTotal identified a suspicious executable communicating with the IP address.

Associating malware samples with infrastructure helps analysts:
- map attacker infrastructure
- identify malware campaigns
- track C2 communication

---

# Historical WHOIS Investigation

## Organization Identified

```text
Ace Data Centers, Inc
```

### Analysis

Historical WHOIS records revealed that the IP range belonged to a hosting provider.

Attackers frequently abuse hosting providers because they allow:
- rapid deployment
- disposable infrastructure
- anonymous hosting

---

# Challenge Investigation

# Investigating IP: 170[.]130[.]202[.]134

---

# Regional Internet Registry

## RIR Identified

```text
ARIN
```

### Analysis

ARIN manages IP allocations primarily within:
- North America
- Canada
- parts of the Caribbean

RIR information helps analysts identify ownership regions and infrastructure registration sources.

---

# ASN Investigation

## ASN Associated

```text
AS62904
```

### Analysis

ASN analysis helps correlate infrastructure and identify hosting relationships between suspicious assets.

---

# Domain Investigation

# Investigating Domain: santagift[.]shop

---

# Nameserver Investigation

## Number of NS Records

```text
4
```

### Analysis

Nameserver records help analysts identify:
- DNS hosting providers
- related infrastructure
- shared malicious domains

---

# SOA Investigation

## Start of Authority

```text
ns-298.awsdns-37.com
```

### Analysis

The SOA record identifies the authoritative DNS server responsible for the domain.

This information can help during infrastructure mapping investigations.

---

# Domain Registration Investigation

## Registration Date

```text
30/10/2022
```

### Analysis

Recently registered domains are often suspicious during phishing and malware investigations.

Threat actors frequently create domains shortly before launching campaigns.

---

# Indicators of Compromise (IOCs)

## Domains

```text
advanced-ip-sccanner[.]com
santagift[.]shop
```

## IP Addresses

```text
166[.]1[.]160[.]118
64[.]31[.]63[.]194
85[.]188[.]1[.]133
170[.]130[.]202[.]134
```

## Infrastructure Indicators

- Typosquatting domains
- Suspicious hosting infrastructure
- FTP exposure
- Malicious file associations
- TLS certificate reuse
- Cloud-hosted infrastructure
- Recent domain registrations

---

# Key Takeaways

- Threat intelligence enrichment provides context around suspicious domains and IP addresses.
- Typosquatting is commonly used during phishing and malware campaigns.
- WHOIS and RDAP records help identify infrastructure ownership and registration timelines.
- ASN analysis helps correlate attacker infrastructure.
- Shodan and Censys are valuable tools for exposed service analysis.
- Certificate Transparency logs help uncover related malicious infrastructure.
- Passive DNS and reputation platforms help correlate malware with attacker infrastructure.

---

# Final Thoughts

This room provided practical experience with IP and domain enrichment workflows commonly used by SOC analysts during investigations.

I particularly enjoyed learning how to pivot from a single IOC into broader infrastructure analysis using multiple OSINT and threat intelligence platforms.

The room helped strengthen my understanding of:
- infrastructure profiling
- passive DNS analysis
- IOC enrichment
- domain intelligence
- ASN analysis
- service enumeration
- threat intelligence correlation

Overall, this was an excellent room for developing practical threat intelligence and SOC investigation skills.

---
