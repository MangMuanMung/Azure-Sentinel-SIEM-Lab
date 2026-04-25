# I Built a Cloud SIEM from Scratch — Here's Everything That Went Wrong (and Right)

I wanted to understand how security operations actually work. Not from a course. Not from a certification study guide. From building the thing myself, breaking it, and fixing it until logs were flowing and detections were firing.

This is Part 1 of a larger project. The end goal is a full multi-zone security operations lab — Active Directory attacks, IDS, purple teaming, forensics, incident response — the whole pipeline. But every SOC starts the same way: you need a SIEM that actually works, collecting real data, from real endpoints.

So that's where I started.

---

## What I Built (So Far)

The short version: Microsoft Sentinel collecting Windows Security Events and Sysmon telemetry from a local machine, with analytics rules running automated detections mapped to MITRE ATT&CK.

The longer version involves a lot more troubleshooting than I expected.

```
┌──────────────────────────────────────────────┐
│               Azure Cloud                    │
│                                              │
│   Sentinel    Log Analytics    KQL Rules     │
│  (SIEM/SOAR)  (log storage)  (detect/hunt)  │
│                                              │
└──────────────────┬───────────────────────────┘
                   │ CEF · AMA · Syslog
                   │
┌──────────────────┴───────────────────────────┐
│        DMZ — Log Aggregation Layer           │
│                                              │
│  pfSense FW   Suricata    Log         Log    │
│  (gateway)    (IDS/IPS)   Forwarder   Parser │
│                                              │
└──────────────────┬───────────────────────────┘
                   │ syslog · agents
                   │
┌──────────────────┴───────────────────────────┐
│      Internal Network — Isolated VMs         │
│      (no direct internet · 10.10.10.0/24)    │
│                                              │
│  Windows AD    Ubuntu      Kali      Win 10  │
│  (lab.local    (DVWA       (attack   (target │
│   DC)          web target)  VM)      endpoint)│
│                                              │
│  Agents: Wazuh · Sysmon · Filebeat           │
└──────────────────────────────────────────────┘

        All VMs run inside VirtualBox on the host
```

What's done is the Azure cloud layer and the initial endpoint connection. The DMZ and internal network layers are coming next.

---

## The Boring But Important Stuff: Why These Choices

Before touching anything in Azure, I spent time understanding the options. There are at least six different ways to get Windows logs into Sentinel, and picking the wrong one costs you time, money, or both.

**Azure Monitor Agent (AMA) via Azure Arc** is what I went with. It's the current Microsoft-recommended method, it lets you filter events at the source through Data Collection Rules (so you're not paying to ingest garbage), and it auto-deploys through the Arc extension model. No manual agent installs, no maintenance headaches.

The alternative most guides still reference is the **Legacy Log Analytics Agent (MMA)**. Microsoft deprecated it in August 2024. I actually landed on the legacy connector page by accident early on — the UI doesn't make the distinction obvious. If you're reading an older tutorial and it mentions "Workspace ID and Key," that's the old method. Skip it.

Other methods exist for different use cases: **Windows Event Forwarding** for large fleets where you don't want agents on every box, **Syslog/CEF forwarding** for network devices and Linux, **API ingestion** for custom apps, and **native cloud connectors** for SaaS services. I'll be using several of these as the lab expands.

For a single endpoint talking to a cloud SIEM, AMA + Arc is the right call.

---

## Phase 1: The Foundation

### Log Analytics Workspace + Sentinel

Nothing complicated here. Create a Log Analytics workspace in Azure, add Sentinel on top of it. The workspace stores the data, Sentinel provides the detection and investigation layer. Two clicks, basically.

### The Data Connector

In Sentinel, I set up the **Windows Security Events via AMA** connector and created a Data Collection Rule configured to collect all security events. At this point the connector shows "Disconnected" because no machine is linked yet. That's normal — you need to bring a machine into Azure's world first.

### Azure Arc: Making a Local Machine Visible to Azure

This is the bridge. Since my Windows machine isn't an Azure VM, Azure doesn't know it exists. Azure Arc fixes that by registering the machine as a managed resource.

The process: generate an onboarding script in the Azure Arc portal, download it, run it in PowerShell as admin. It authenticates you, registers the machine, and you're done.

Except I immediately hit this:

```
The file OnboardingScript.ps1 is not digitally signed. 
You cannot run this script on the current system.
```

Standard Windows execution policy block. The fix is one line:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

The `-Scope Process` flag means it only applies to your current terminal session. Doesn't change anything permanently. Run the script again, authenticate, and the machine shows up in Azure Arc as "Connected."

### Linking the Machine to the DCR

Back in the Sentinel connector page, edit the DCR, go to the Resources tab, check the box next to the Arc-enabled machine, save. Azure automatically pushes the AMA extension to the machine. After about five minutes, logs start flowing.

Verification is a simple KQL query:

```kql
SecurityEvent
| take 10
```

Results came back. Pipeline working.

---

## Phase 2: Sysmon — Because Security Events Aren't Enough

Here's something I didn't fully appreciate until I looked at the data: standard Windows Security Events are mostly about authentication. Who logged in. Who got added to a group. Who changed a password. That's useful, but it misses almost everything that matters for actual threat detection.

Sysmon fills the gap. It's a free Microsoft Sysinternals tool that logs process creation with full command lines, network connections per process, file creation, registry changes, DLL loading, DNS queries, process injection — the operational telemetry that maps to the MITRE ATT&CK framework.

Without Sysmon, you can see that someone logged in. With Sysmon, you can see that after logging in, they ran `powershell.exe -enc [base64blob]`, which connected to `185.x.x.x:443`, dropped a file to `C:\Users\Public\payload.exe`, and added a registry key for persistence. That's the difference between knowing something happened and knowing what happened.

### Installing Sysmon

Two ways to do it. PowerShell is faster and scriptable:

```powershell
# Download
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
  -OutFile "$env:USERPROFILE\Downloads\Sysmon.zip"
Expand-Archive "$env:USERPROFILE\Downloads\Sysmon.zip" `
  -DestinationPath "$env:USERPROFILE\Downloads\Sysmon"

# Grab the SwiftOnSecurity config — don't run Sysmon without one
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
  -OutFile "$env:USERPROFILE\Downloads\Sysmon\sysmonconfig.xml"

# Install
cd "$env:USERPROFILE\Downloads\Sysmon"
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

The GUI path works too — download Sysmon from the Sysinternals page, extract, grab the SwiftOnSecurity config from GitHub, save it in the same folder. Either way, the final install step requires an elevated terminal because Sysmon runs as a system driver.

Running Sysmon with no configuration is a mistake. The default settings generate so much noise that the signal-to-noise ratio is terrible. Use SwiftOnSecurity's config as a baseline and tune from there.

---

## Phase 3: Getting Sysmon Logs into Sentinel — Where I Got Stuck

This is where I spent the most time and learned the most.

### The Problem I Didn't Expect

After installing Sysmon, I assumed it would just flow into Sentinel through the existing AMA connector. It didn't. I ran queries, waited, ran more queries — nothing.

Here's the thing nobody tells you upfront: **the Sentinel "Windows Security Events via AMA" connector only collects from the Windows Security log channel.** That's it. One channel. Sysmon writes to a completely different channel called `Microsoft-Windows-Sysmon/Operational`. They're separate pipelines.

To confirm this, I ran a broad search to see which tables were actually receiving data:

```kql
search "[YourMachineName]"
| summarize by $table
```

Result: `SecurityEvent`, `Heartbeat`, `InsightsMetrics`. No `Event` table. No Sysmon data.

### The Fix: A Separate DCR in Azure Monitor

Sysmon needs its own Data Collection Rule, and it has to be created through **Azure Monitor** (not through the Sentinel data connector). The data source type must be **"Windows Event Logs"** — not "Windows Security Events." These sound similar but they go to completely different tables.

| | Sentinel Connector | Azure Monitor DCR |
|---|---|---|
| Collects from | Windows Security log | Any Windows event channel |
| Sends to | SecurityEvent table | Event table |
| Works for Sysmon? | No | Yes |

Steps: Azure Monitor → Data Collection Rules → Create → add the machine as a resource → add data source with type "Windows Event Logs" → Custom tab → enter the XPath:

```
Microsoft-Windows-Sysmon/Operational!*
```

### The XPath Gotcha

My first attempt failed with a validation error because I entered `Microsoft-Windows-Sysmon/Operational` without the `!*` suffix. Azure needs that `!*` to know you want all events from the channel. Without it, the query is syntactically invalid.

If you want to filter by specific event IDs to reduce cost:

```
Microsoft-Windows-Sysmon/Operational!*[System[(EventID=1 or EventID=3 or EventID=11 or EventID=13 or EventID=22)]]
```

### The Portal Compatibility Gotcha

I also tried creating a Sysmon DCR through the Sentinel connector first (seemed logical). It created the rule, but when I tried to edit it later, the portal said "This data collection rule contains properties that are not currently supported in the portal." Had to delete it and recreate through Azure Monitor directly.

### It Worked

After creating the DCR the right way, I waited about 10 minutes and ran the search again:

```kql
search "[YourMachineName]"
| summarize by $table
```

The `Event` table appeared. Then I checked the Sysmon distribution:

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| summarize count() by EventID
| sort by count_ desc
```

Process creation events, registry changes, network connections — all flowing in. Two parallel pipelines feeding Sentinel: Security Events for authentication data, Sysmon for behavioral data.

---

## Phase 4: Analytics Rules — Making Sentinel Actually Detect Things

Up to this point, Sentinel was collecting logs but not doing anything with them. It's just a really expensive log storage system until you turn on analytics rules.

Analytics rules are scheduled KQL queries. They run every few minutes, and when they find something that matches defined conditions, Sentinel creates an Incident. That's the detection engine.

### The Defender Portal Migration

When I went to Sentinel → Analytics in the Azure portal, the page was empty with a redirect notice. Microsoft has been unifying everything under the Defender portal at `security.microsoft.com`. Not a problem — just means analytics rules live there now.

Connected the workspace to Defender, and the full template library showed up — hundreds of rules, each mapped to MITRE ATT&CK tactics and techniques.

### What I Enabled

I started with rules that match the data I'm actually collecting:

| Rule | Severity | What It Catches |
|---|---|---|
| Non Domain Controller AD Replication | High | DCSync attacks — unauthorized AD replication |
| Potential Fodhelper UAC Bypass | Medium | Known technique to bypass User Account Control |
| Gain Code Execution via Build Events | Medium | Code execution through build system abuse |
| Starting or Stopping Windows Services | Medium | Suspicious service manipulation |
| AD FS Remote Auth | Medium | Unusual federation service authentication |
| Microsoft Entra ID Discovery | Medium | Reconnaissance against Azure AD |

I kept it to a small set intentionally. Alert fatigue is a real thing — if you enable 50 rules on day one, you drown in noise before you understand what normal looks like. Better to start small, learn the baseline, then expand.

---

## What I Learned That No Tutorial Taught Me

**The pipeline matters more than the SIEM.** Anyone can open Sentinel and run a query. Understanding why data isn't showing up — is the agent installed? Is it the right DCR type? Is the XPath valid? Is it hitting the right table? — that's the skill that actually matters in production. When something breaks in a real SOC, the analyst who understands the pipeline is the one who fixes it.

**There are two separate log pipelines for Windows, and they're not interchangeable.** Sentinel's data connector handles Security Events. Azure Monitor DCRs handle everything else. Mixing them up is the fastest way to waste an afternoon staring at empty query results.

**The AMA doesn't run as a visible Windows service on Arc machines.** It operates through the Guest Configuration Extension Service. This tripped me up — `Get-Service AzureMonitorAgent` returns nothing, which looks like a broken install. But the Heartbeat table in Sentinel confirms the agent is alive and reporting. The binaries live at `C:\Packages\Plugins\Microsoft.Azure.Monitor.AzureMonitorWindowsAgent\`.

**Microsoft is actively moving features to the Defender portal.** Analytics, incident management, and other Sentinel features are migrating to security.microsoft.com. If a page looks empty or broken in the Azure portal, check Defender before assuming something is wrong.

**Sysmon without a config is useless in practice.** The default settings capture everything, which sounds good until you realize "everything" includes thousands of benign events per minute. SwiftOnSecurity's config is the industry starting point. Tune from there based on your environment.

---

## Where This Is Going

What's running now is just the cloud layer. The full lab has three zones, and the next phases will build out the rest:

**DMZ / Log Aggregation** — pfSense for network segmentation, Suricata for IDS/IPS, a log forwarder handling CEF and Syslog, Logstash or Fluent Bit for parsing and normalization. This layer sits between the internal network and Azure, aggregating and forwarding logs from all sources.

**Internal Network** — isolated VMs on a host-only adapter at `10.10.10.0/24` with no direct internet access. A Windows Server running Active Directory as `lab.local`, an Ubuntu box running DVWA as a web application target, a Kali Linux VM as the attacker, and a Windows 10 endpoint as a target. All running Wazuh agents, Sysmon, and Filebeat/Winlogbeat.

Once the internal network is up, the project shifts from building infrastructure to operating it:

- **AD attack simulation** — Kerberoasting, Pass-the-Hash, DCSync, Golden Ticket using Impacket, Mimikatz, and BloodHound
- **Detection engineering** — writing KQL rules for each attack technique, mapping to ATT&CK, documenting false positive conditions and tuning thresholds
- **Purple team exercises** — running both sides of the attack/defense equation, measuring detection coverage as a number, identifying and closing gaps
- **Digital forensics** — live endpoint analysis with Velociraptor across multiple machines simultaneously
- **Incident response** — full IR cases through TheHive using PICERL methodology
- **Coverage reporting** — MITRE ATT&CK Navigator heatmaps showing exactly what's detected and what isn't

The end goal isn't a lab. It's being the person who has done the work — who can sit in a SOC, or in an interview, and give real answers built on real experience with real tools.

---

## Quick Reference

```powershell
# Fix execution policy (session-scoped, temporary)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Check all services
Get-Service Sysmon64
Get-Service ExtensionService, GCArcService

# Verify AMA extension exists
Test-Path "C:\Packages\Plugins\Microsoft.Azure.Monitor.AzureMonitorWindowsAgent"

# Check Sysmon is logging
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

```kql
-- Which tables are receiving data?
search "[YourMachineName]"
| summarize by $table

-- Security events
SecurityEvent | take 10

-- Sysmon by event type
Event
| where Source == "Microsoft-Windows-Sysmon"
| summarize count() by EventID
| sort by count_ desc

-- Agent health
Heartbeat
| where Computer == "[YourMachineName]"
| take 5
```

---

## Tools

- [Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/) — Cloud SIEM + SOAR
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) — Endpoint telemetry
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config) — Tuned configuration
- [MITRE ATT&CK](https://attack.mitre.org/) — Threat framework
- [KQL Reference](https://learn.microsoft.com/en-us/azure/data-explorer/kql-quick-reference) — Query language docs

---

*Martin — April 2026*
