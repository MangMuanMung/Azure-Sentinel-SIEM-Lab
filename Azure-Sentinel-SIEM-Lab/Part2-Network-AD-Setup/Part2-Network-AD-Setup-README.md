# Part 2: Building the Internal Network and Active Directory

> Wiring up pfSense, standing up a Domain Controller, populating Active Directory, and getting AD telemetry flowing into Sentinel — plus every networking headache along the way.

This is the continuation of [Part 1](../Part1-SIEM-Setup/README.md), where I set up Microsoft Sentinel, connected a local machine via Azure Arc, installed Sysmon, and enabled analytics rules. That gave me a working SIEM with one endpoint. This part builds the actual lab environment that makes attack simulation possible.

---

## What Changed

Part 1 had a single machine talking to Sentinel. Now there's a network:

```
                         INTERNET
                            │
                            │
               ┌────────────┴────────────┐
               │        pfSense          │
               │                         │
               │  Adapter 1: NAT (WAN)   │
               │    → 10.0.2.x (auto)    │
               │                         │
               │  Adapter 2: Host-only   │
               │    (LAN) → 192.168.168.1│
               └────────────┬────────────┘
                            │
                            │ 192.168.168.0/24
           ┌────────────────┼────────────────┬──────────────────┐
           │                │                │                  │
 ┌─────────┴──────┐ ┌───────┴───────┐ ┌──────┴───────┐ ┌───────┴───────┐
 │     ADDC       │ │  Logforwarder │ │    Kali      │ │  Win 10       │
 │  (DC/ad.local) │ │  (Ubuntu Svr) │ │  (Attacker)  │ │  (Target)     │
 │                │ │               │ │              │ │  [future]     │
 │ .168.10        │ │ .168.20       │ │ DHCP/.168.100│ │ DHCP          │
 │ static         │ │ static        │ │              │ │               │
 └────────────────┘ └───────────────┘ └──────────────┘ └───────────────┘

 All VMs run in VirtualBox on the host laptop.
 All traffic routes through pfSense.
 DC runs DNS for ad.local, forwards external queries to pfSense → 8.8.8.8.
```

Four VMs, one firewall, one subnet, everything routing through pfSense. The DC and logforwarder have static IPs because other machines depend on them. Kali and future endpoints use DHCP.

---

## The Networking — Where Most of the Time Went

I'm going to be honest: getting the network right took longer than setting up Active Directory, Sysmon, and Azure Arc combined. If you're building a similar lab, the networking section below will save you hours.

### The VirtualBox Adapter Setup

Every VM except pfSense gets exactly one network adapter. pfSense gets two — one for WAN (internet via NAT) and one for LAN (the internal lab network via Host-only).

```
VM              Adapter 1        Adapter 2       Notes
─────────────────────────────────────────────────────────────
pfSense         NAT              Host-only       Gateway between internet and lab
ADDC            Host-only        OFF             Domain Controller
Logforwarder    Host-only        OFF             Log aggregation
Kali            Host-only        OFF             Attacker VM
Win 10          Host-only        OFF             Target (future)
```

All Host-only adapters must use the same VirtualBox Host-Only network. This acts as a virtual switch connecting all the VMs together.

### Problem 1: VirtualBox's Built-In DHCP

VirtualBox ships with its own DHCP server for Host-only networks. It hands out addresses in the `192.168.56.x` range, which conflicts with pfSense's DHCP running on `192.168.168.x`. When I booted Kali, it got `192.168.56.10` instead of a pfSense address, and couldn't reach anything.

The fix: disable VirtualBox's DHCP. In VirtualBox, go to File → Tools → Network Manager → select the Host-only adapter → DHCP Server tab → uncheck "Enable Server."

### Problem 2: The Host-Only Adapter Subnet

The VirtualBox Host-Only Ethernet Adapter on the host machine had an APIPA address (`169.254.x.x`) — meaning it wasn't configured for the lab subnet. VMs were technically connected to the same virtual switch but couldn't route to each other.

The fix: in Network Manager, set the adapter to manual configuration with IP `192.168.168.2` and mask `255.255.255.0`. This puts the host on the same subnet as the lab. A VirtualBox restart was needed for the change to take effect.

### Problem 3: pfSense LAN Firewall Rules

After connecting VMs to the Host-only network, they could ping each other but not the internet. The pfSense default LAN rules included a "block all" IPv4 rule that was killing outbound traffic. The Anti-Lockout rule above it only allowed access to pfSense's web GUI on ports 80 and 443 — nothing else got through.

The fix: delete the block rule and add a clean "Pass Any" rule on the LAN interface. Action: Pass, Protocol: Any, Source: any, Destination: any. Save, Apply Changes.

I also learned that `pfctl -d` disables the pfSense firewall temporarily from the console — useful for debugging whether a connectivity issue is a firewall problem or a routing problem. Re-enable with `pfctl -e`.

### Problem 4: DNS Resolution

Even after fixing the firewall, DNS didn't work. Machines could ping `8.8.8.8` but not resolve `google.com`. This turned out to be two separate issues:

First, pfSense's DNS Resolver was trying to do recursive resolution directly against root servers, which doesn't work well through VirtualBox's NAT. The fix: enable "Forwarding Mode" in Services → DNS Resolver, and add `8.8.8.8` as a DNS server in System → General Setup. Also had to disable DNSSEC, which was causing validation failures through the NAT.

Second, the Domain Controller had `::1` (IPv6 localhost) as its primary DNS, and IPv6 DNS queries were timing out. It also had stale forwarder entries pointing to IPs from an old network config. I cleaned up the forwarders, set the DC to forward to pfSense (`192.168.168.1`), and the chain worked: DC → pfSense → 8.8.8.8 → internet.

The DNS chain for the final setup:

```
Lab VMs → DC (192.168.168.10) for ad.local resolution
DC → pfSense (192.168.168.1) for external queries
pfSense → 8.8.8.8 (Google DNS) via NAT
```

---

## Active Directory Setup

With networking sorted, Active Directory was the straightforward part. The DC was already promoted to a Domain Controller running `ad.local` from an earlier attempt, so I focused on building a realistic organizational structure.

### Organizational Units

Created four OUs to simulate a real company:

```
ad.local
├── IT
├── HR
├── Finance
└── Executives
```

### Users

Populated each OU with user accounts. All created through Active Directory Users and Computers (Server Manager → Tools → ADUC):

```
IT OU:
  John Smith    (jsmith)   — IT staff
  Tom Davis     (tdavis)   — IT staff, Domain Admin (intentionally overprivileged)

HR OU:
  Sarah Chen    (schen)    — HR staff

Finance OU:
  Mike Johnson  (mjohnson) — Finance staff

Executives OU:
  Lisa Park     (lpark)    — Executive
```

### The Intentional Misconfiguration

Tom Davis (`tdavis`) was added to the Domain Admins group. This is deliberate — it simulates the kind of privilege creep that exists in nearly every real AD environment. When I run attack simulations later, this overprivileged account becomes a target for privilege escalation and lateral movement. Detection rules should catch when this account does things normal IT staff shouldn't.

### Groups

Created a "Domain Admins IT" security group in the IT OU with `jsmith` as a member. This simulates a tiered admin structure where not every IT person has full domain admin rights — except for `tdavis`, who shouldn't have them but does.

---

## Sysmon on the Domain Controller

Same process as Part 1 — download Sysmon, grab the SwiftOnSecurity config, install. The only difference was that the DC initially couldn't resolve domain names (the DNS issue described above), so the `Invoke-WebRequest` commands failed until DNS forwarding was fixed.

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Sysmon.zip"
Expand-Archive "C:\Sysmon.zip" -DestinationPath "C:\Sysmon"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Sysmon\sysmonconfig.xml"
cd C:\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Sysmon on a DC is particularly valuable because it captures process creation and network connections from domain services — LSASS activity, Kerberos ticket operations, LDAP queries, replication traffic. This is the telemetry that lights up during AD attacks like DCSync and Kerberoasting.

---

## Onboarding the DC to Azure Arc and Sentinel

Same Arc onboarding process as the host machine in Part 1:

1. Azure Portal → Azure Arc → Add a machine → Generate script
2. Transfer script to DC via RDP (clipboard sharing just works with RDP — no Guest Additions needed)
3. Run with `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` then `.\OnboardingScript.ps1`
4. Authenticate in the browser popup
5. Machine appears in Azure Arc as "Connected"

Then added the DC to both existing Data Collection Rules:

- **DCR_Testing_1** (Security Events) → Resources → added the DC
- **DCR-Sysmon** → Resources → added the DC

After about 10 minutes, verified data flow:

```kql
search "WIN01"
| summarize by $table
```

Result: `SecurityEvent` and `Event` — both pipelines active.

### What the DC Sends That a Regular Endpoint Doesn't

The DC generates event types you'll never see from a workstation:

- **Event ID 4769** — Kerberos Service Ticket Operations (this is what fires during Kerberoasting)
- **Event ID 4768** — Kerberos TGT Requests (authentication events for every domain logon)
- **Event ID 4662** — Directory Service Access (fires during DCSync)
- **Event ID 4728/4732** — User added to security group (privilege escalation)
- **Event ID 5136** — Directory Service Changes (AD object modifications)

Plus Sysmon on the DC captures LSASS process access (Event ID 10), which is the primary indicator of credential dumping tools like Mimikatz.

---

## RDP Access to the DC

A quick note on workflow: I initially tried to use VirtualBox clipboard sharing (Guest Additions) for copy-pasting commands to the DC, but the Guest Additions CD image wouldn't mount. Instead, I enabled RDP on the DC and connected from the host:

On the DC: Server Manager → Local Server → Remote Desktop → Enable.

From the host:
```
mstsc /v:192.168.168.10
```

Login as `AD\Administrator`. Full clipboard sharing, better performance than the VirtualBox console, and you can resize the window. For any Windows Server VM in a lab, RDP is always the better option over VirtualBox's built-in console.

---

## Current State

Here's what's operational:

```
┌──────────────────────────────────────────────────┐
│                  Azure Cloud                     │
│                                                  │
│  Microsoft Sentinel ← Log Analytics Workspace    │
│       │                                          │
│  ┌────┴──────────────────────────┐               │
│  │ DCR: Security Events         │               │
│  │   → Host laptop              │               │
│  │   → DC (WIN01)               │               │
│  │                              │               │
│  │ DCR: Sysmon                  │               │
│  │   → Host laptop              │               │
│  │   → DC (WIN01)               │               │
│  └───────────────────────────────┘               │
│                                                  │
│  Analytics Rules: Active (7 rules)               │
└──────────────┬───────────────────────────────────┘
               │
    ┌──────────┴──────────┐
    │     pfSense         │
    │  WAN: NAT (internet)│
    │  LAN: 192.168.168.1 │
    └──────────┬──────────┘
               │
    ┌──────────┼──────────────────┬─────────────┐
    │          │                  │             │
  ADDC     Logforwarder        Kali       [Win 10]
  .168.10   .168.20          .168.100     [future]
  DC/DNS   Ubuntu Svr        Attacker
  Sysmon   (ready)           (ready)
  Arc+AMA
```

**What works:**
- All VMs communicate through pfSense
- DNS chain: VMs → DC → pfSense → 8.8.8.8
- DC running AD with realistic OU/user/group structure
- Sysmon collecting on both the host and DC
- Both machines streaming SecurityEvent + Sysmon to Sentinel
- Analytics rules active in Defender portal
- RDP access to DC from host

**What's next:**
- First AD attack from Kali (Kerberoasting)
- Writing KQL detection rules for the attack
- Connecting the logforwarder to receive syslog/CEF
- Adding Suricata IDS on pfSense
- Windows 10 target VM joined to the domain

---

## Lessons From This Phase

**Networking is always the hardest part.** I spent more time debugging VirtualBox adapters, pfSense firewall rules, and DNS forwarding chains than anything else. In a real enterprise, the network team handles this. In a home lab, you are the network team. The upside is that after troubleshooting all of these issues, I now understand routing, NAT, DNS forwarding, and firewall rules at a practical level — not just conceptually.

**pfSense defaults are not lab-friendly.** The default LAN rules block most traffic, DNSSEC breaks forwarding through NAT, and the DNS Resolver tries to do recursive resolution instead of forwarding. For a lab, you want: permissive LAN rules, forwarding mode enabled, DNSSEC off, and an explicit DNS server in General Setup.

**RDP beats VirtualBox console every time** for Windows VMs. Clipboard sharing, resizable window, better keyboard handling. Enable it early and save yourself the headache of trying to type long PowerShell commands in the VirtualBox window.

**DC DNS configuration has layers.** The Windows DNS Server has its own forwarder list, the DNS client has its own server list, and IPv6 adds another layer. When DNS doesn't work on a DC, you need to check all three: `Get-DnsServerForwarder`, `Get-DnsClientServerAddress`, and whether `::1` is being preferred over `127.0.0.1`.

**Build your AD with attack simulation in mind.** The intentionally overprivileged account, the realistic OU structure, the multiple users — these aren't cosmetic. They create the conditions that make attack scenarios realistic and detection rules meaningful. A domain with one admin account and no structure teaches you nothing about how real breaches work.

---

## Quick Reference

### Static IP Configuration

**Windows Server (DC):**
```powershell
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.168.10 -PrefixLength 24 -DefaultGateway 192.168.168.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1
```

**Ubuntu Server (Logforwarder):**
```yaml
# /etc/netplan/50-cloud-init.yaml
network:
  ethernets:
    enp0s3:
      addresses:
        - 192.168.168.20/24
      routes:
        - to: default
          via: 192.168.168.1
      nameservers:
        addresses:
          - 8.8.8.8
  version: 2
```

**Kali (temporary — resets on reboot):**
```bash
sudo ip addr flush dev eth0
sudo ip addr add 192.168.168.100/24 dev eth0
sudo ip route add default via 192.168.168.1
```

### DNS Forwarding Chain
```powershell
# On DC: forward to pfSense
Add-DnsServerForwarder -IPAddress 192.168.168.1

# Verify
Get-DnsServerForwarder
```

### pfSense Key Settings
```
System → General Setup → DNS Server: 8.8.8.8
Services → DNS Resolver → Enable Forwarding Mode: checked
Services → DNS Resolver → DNSSEC: unchecked
Firewall → Rules → LAN → Pass Any rule
```

---

*Martin — April 2026*
