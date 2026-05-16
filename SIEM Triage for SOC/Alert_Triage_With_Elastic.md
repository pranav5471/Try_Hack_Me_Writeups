# Alert Triage With Elastic — TryHackMe

## Room Overview

In this TryHackMe room, I worked on investigating suspicious activity using Elastic and Kibana logs.  
The room focused on analyzing web attacks, account activity, privilege escalation, and attacker command execution.

This lab gave me practical exposure to:
- Investigating logs in Elastic
- Filtering events using KQL queries
- Tracking attacker behavior
- Identifying suspicious PowerShell and Windows events
- Following an attack timeline step-by-step

---

# Scenario Briefing

## Q1. How many logs are available for analysis within the entire time range?

### Answer:
`1467`

---

## Q2. What is the field value for the `client.ip` in the weblogs index?

### Answer:
`203.0.113.55`

---

# Investigating Web Attacks

## Q1. How many POST requests did the IP address `203.0.113.55` make to `proxyLogon.ecp`?

### Query Used
```kql
_index:weblogs and client.ip:203.0.113.55 and http.request.method:POST
```

### Answer:
`3`

### Notes
I filtered the weblog index for POST requests coming specifically from the suspicious IP address.  
This helped identify repeated requests targeting the vulnerable endpoint.

---

## Q2. Which `user.agent` paired with the IP address `203.0.113.55` made the POST requests?

### Answer:
`python-requests/2.25.1`

### Observation
The user agent immediately looked suspicious because attackers commonly use automated scripts and tools with Python request libraries.

---

## Q3. How many logs contain the `cmd=` query parameter in the `url.path` field?

### Query Used
```kql
url.path:*cmd=*
```

### Answer:
`20`

### Notes
Searching for the `cmd=` parameter helped identify possible command execution attempts through the web application.

---

## Q4. Which command was run utilizing `errorEE.aspx` on `Jul 20, 2025 @ 04:45:50.000`?

### Answer:
`hostname`

### Analysis
The attacker appeared to test command execution by running a simple reconnaissance command first.

---

# Uncovering Account Activity

To investigate the suspicious login activity, I focused on:
- Event ID `4624` (successful logon)
- The target host
- The `Administrator` account

### Query Used
```kql
@timestamp >= "2025-07-20T05:11:22" and winlog.event_id:4624 and host.name:winserv2019.some.corp and winlog.event_data.TargetUserName:Administrator
```

---

## Q1. What is the `winlog.record_id` of the Administrator 4624 logon event?

### Query Used
```kql
@timestamp >= "2025-07-20T05:11:22" and winlog.event_id:4624 and winlog.event_data.TargetUserName:"Administrator"
```

### Answer:
`17166`

---

## Q2. What is the `process.pid` of the Sysmon 1 event that occurred on `Jul 20, 2025 @ 05:11:27.996`?

### Query Used
```kql
@timestamp >= "2025-07-20T05:11:27" and winlog.event_id:1 and user.name:"Administrator"
```

### Answer:
`964`

### Notes
Sysmon Event ID 1 helped identify process creation activity linked to the Administrator account.

---

## Q3. What is the `winlog.event_id` for the new user account being created?

### Query Used
```kql
@timestamp >= "2025-07-20T05:11:27" and winlog.channel:"Security" and winlog.task:"User Account Management"
```

### Answer:
`4720`

### Observation
Event ID 4720 indicates that a new user account was created on the system.

---

## Q4. What is the name of the new user account?

### Answer:
`svc_backup`

### Analysis
The username looked like a service account, which attackers often use to blend into normal administrative activity.

---

# Exposing Command Execution

For this section, I focused on commands executed through `cmd.exe` under the Administrator account.

### Base Query
```kql
@timestamp >= "2025-07-20T05:13:15" and process.parent.name:cmd.exe and user.name:Administrator
```

I also added the following fields as columns:
- process.command_line
- process.name
- process.parent.name
- powershell.file.script_block_text

---

## Q1. What command did the attacker use to add the new account to the “Remote Desktop Users” group?

### Answer:
```powershell
net localgroup "Remote Desktop Users" svc_backup /add
```

### Notes
This command allowed the attacker to grant RDP access to the newly created account.

---

## Q2. What is the `winlog.record_id` of the 4732 Security event when the attacker adds the user to the Administrator group?

### Query Used
```kql
@timestamp >= "2025-07-20T05:13:15" and winlog.event_id:4732 and message:*Administrators*
```

### Answer:
`17254`

### Observation
Event ID 4732 confirms that a user was added to a privileged local group.

---

## Q3. What PowerShell command did the attacker run on `Jul 20, 2025 @ 05:16:14.628`?

### Query Used
```kql
@timestamp >= "2025-07-20T05:16:14.628" and event.module:powershell
```

### Answer:
```powershell
net group "Domain Admins" /domain
```

### Analysis
The attacker was likely enumerating privileged domain groups to identify high-value targets.

---

## Q4. What is the name of the archive that the attacker creates using the `Rar.exe` executable?

### Query Used
```kql
process.name:"Rar.exe"
```

### Answer:
`finance_it_archive.rar`

### Notes
Creating an archive is commonly associated with data staging before exfiltration.

---

# Key Takeaways

This room helped me better understand:
- Investigating alerts in Elastic
- Using KQL queries effectively
- Tracking attacker activity through logs
- Identifying privilege escalation behavior
- Detecting suspicious PowerShell usage
- Following an attack chain from initial access to post-exploitation activity

One of the most valuable parts of this room was learning how small indicators in logs can help reconstruct the full attacker timeline.

---

## Final Thoughts

This room gave me more hands-on practice with SIEM investigations and log analysis from a blue-team perspective.  
I’m getting more comfortable navigating Elastic, understanding Windows event logs, and correlating suspicious activity across different data sources.

Still learning every day — but definitely improving my investigation workflow step by step.

---

✍️ Written and documented by M. P. Pranav Kumar as part of my hands-on cybersecurity learning journey.
