# Hybrid SOC Home Lab

A cloud-hybrid Security Operations Center (SOC) home lab built with Wazuh 4.14.4 SIEM on a Vultr VPS, monitoring Windows 11 Pro and Ubuntu endpoint VMs running locally on UTM (MacBook M4).

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        CLOUD (Vultr VPS)                             │
│                                                                      │
│   ┌──────────────────────────────────────────────────────────────┐   │
│   │                  Wazuh Server (All-in-One)                   │   │
│   │                  Ubuntu 22.04 LTS | 8 GB RAM                 │   │
│   │                                                              │   │
│   │   ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐   │   │
│   │   │   Wazuh      │  │    Wazuh     │  │     Wazuh       │   │   │
│   │   │   Manager    │  │   Indexer    │  │   Dashboard     │   │   │
│   │   │  (port 1514) │  │             │  │  (port 443)     │   │   │
│   │   └─────────────┘  └──────────────┘  └─────────────────┘   │   │
│   └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│   Firewall: Vultr FW Group + UFW (all rules locked to home IP)      │
└──────────────────────┬───────────────────────┬───────────────────────┘
                       │ Port 1514 (events)    │ Port 1514 (events)
                       │ Port 1515 (enroll)    │ Port 1515 (enroll)
                       │                       │
┌──────────────────────┴──────┐  ┌─────────────┴──────────────────────┐
│     LOCAL (UTM - MacBook)   │  │      LOCAL (UTM - MacBook)         │
│                             │  │                                     │
│   ┌───────────────────┐    │  │   ┌───────────────────────────┐    │
│   │  Ubuntu VM         │    │  │   │  Windows 11 Pro VM         │    │
│   │  Agent: ubuntu-    │    │  │   │  Agent: Computer2          │    │
│   │  endpoint          │    │  │   │                             │    │
│   │  Wireshark         │    │  │   │  Attack Simulations:       │    │
│   │  Hydra / Nmap      │    │  │   │  - Windows Login Failures   │    │
│   │                    │    │  │   │  - Audit Log Cleared        │    │
│   │  Attack Simulations│    │  │   │  - Windows System Errors    │    │
│   │  - SSH Brute Force │    │  │   └───────────────────────────┘    │
│   │  - Nmap Recon      │    │  │                                     │
│   │  - Failed Logins   │    │  │                                     │
│   └───────────────────┘    │  │                                     │
└─────────────────────────────┘  └─────────────────────────────────────┘
```

## Components

| Component | Platform | Role |
|---|---|---|
| Wazuh 4.14.4 (All-in-One) | Vultr VPS (Ubuntu 22.04) | SIEM — Manager, Indexer, Dashboard |
| Ubuntu VM (`ubuntu-endpoint`) | UTM on MacBook M4 | Monitored endpoint + attack platform |
| Windows 11 Pro VM (`Computer2`) | UTM on MacBook M4 | Monitored endpoint |
| Wireshark | Ubuntu VM | Network packet analysis |

## Firewall Configuration

Dual-layer firewall architecture — all rules restricted to my home IP only:

### Layer 1: Vultr Firewall Group (`Wazuh-SOC-Lab`)

| Port | Protocol | Purpose |
|---|---|---|
| 22 | TCP | SSH server management |
| 443 | TCP | Wazuh Dashboard |
| 1514 | TCP | Agent event communication |
| 1515 | TCP | Agent enrollment |
| 55000 | TCP | Wazuh REST API |

![Vultr Firewall Group](firewall/vultr-firewall-group.png)

### Layer 2: UFW on the Wazuh Server

Same five rules, same home IP restriction. Defense in depth.

## Attack Simulations & MITRE ATT&CK Mapping

### Linux (Ubuntu VM — `ubuntu-endpoint`)

| Attack | Tool | MITRE Technique | Wazuh Rule IDs |
|---|---|---|---|
| SSH Brute Force | Hydra v9.5 | T1110 — Brute Force | 5710, 5712 |
| Network Reconnaissance | Nmap 7.94 | T1046 — Network Service Discovery | — |
| Failed SSH Login Attempts | Manual / sshd | T1110 — Brute Force | 5710 |

---

#### SSH Brute Force

![Hydra brute force command executed against ubuntu-endpoint](screenshots/brute-force/01-hydra-command.png)
![Wazuh alert fired — brute force attempt detected (Rule 5712)](screenshots/brute-force/02-wazuh-alert.png)
![Alert document details — failed password attempts](screenshots/brute-force/03-alert-details.png)
![Alert details — authentication failure fields](screenshots/brute-force/04-alert-details-2.png)
![MITRE ATT&CK T1110 — Brute Force technique detail](screenshots/brute-force/05-mitre-t1110.png)

#### Network Reconnaissance

#### Failed SSH Login Attempts

![Wazuh alerts — failed login attempts on ubuntu-endpoint (Rule 5710)](screenshots/failed-login/01-wazuh-alerts.png)
![Alert document details — sshd non-existent user](screenshots/failed-login/02-alert-details.png)
![MITRE mapping — T1110.001 Password Guessing, T1021.004 SSH](screenshots/failed-login/03-mitre-mapping.png)

---

### Windows (Windows 11 Pro VM — `Computer2`)

| Attack | Method | MITRE Technique | Wazuh Rule IDs |
|---|---|---|---|
| Login Failures | Manual failed logon attempts | T1110 — Brute Force | 60122 |
| Audit Log Cleared | Windows Event Log cleared | T1070.001 — Indicator Removal: Clear Windows Event Logs | 63103 |
| Windows System Errors | Triggered system error events | Windows System Event Monitoring | 61102 |

---

#### Login Failures

![Windows login screen — incorrect password prompt](screenshots/windows-login-failure/05-windows-login-screen.png)
![Wazuh alerts — logon failures on Computer2 (Rule 60122)](screenshots/windows-login-failure/01-wazuh-alerts.png)
![Alert document details — Windows event data](screenshots/windows-login-failure/02-alert-details.png)
![Alert details — authentication fields](screenshots/windows-login-failure/03-alert-details-2.png)
![Alert details — continued](screenshots/windows-login-failure/04-alert-details-3.png)

#### Audit Log Cleared

![PowerShell — wevtutil cl Security command executed](screenshots/Audit-clean/06-wevtutil-command.png)
![Wazuh alert — audit log cleared on Computer2 (Rule 63103)](screenshots/Audit-clean/01-wazuh-alert.png)
![Alert document details](screenshots/Audit-clean/02-alert-details.png)
![Alert details — event data](screenshots/Audit-clean/03-alert-details-2.png)
![Alert details — continued](screenshots/Audit-clean/04-alert-details-3.png)
![Alert details — continued](screenshots/Audit-clean/05-alert-details-4.png)

#### Windows System Errors

![Wazuh alerts — Windows system error events on Computer2 (Rule 61102)](screenshots/windows-sys-error/01-wazuh-alerts.png)
![Alert document details — TPM driver error](screenshots/windows-sys-error/02-alert-details.png)
![Alert details — continued](screenshots/windows-sys-error/03-alert-details-2.png)
![Alert details — continued](screenshots/windows-sys-error/04-alert-details-3.png)

## Project Structure

```
hybrid-soc-lab/
├── README.md                          # This file
├── architecture/
│   └── diagram.png                    # Lab architecture diagram
├── firewall/
│   └── vultr-firewall-group.png       # Vultr Firewall Group configuration
├── screenshots/
│   ├── Audit-clean/                   # Audit log cleared — screenshots & evidence
│   ├── brute-force/                   # SSH brute force with Hydra
│   │   └── brute-force.md
│   ├── failed-login/                  # Linux SSH failed login attempts
│   ├── nmap-scan/                     # Nmap network reconnaissance
│   │   └── nmap-scan.md
│   ├── windows-login-failure/         # Windows logon failure alerts
│   └── windows-sys-error/             # Windows system error events
├── dashboard/
│   └── dashboard-setup.md             # Wazuh dashboard screenshots & notes
├── setup/
│   ├── agent-setup.md                 # Agent enrollment steps
│   ├── vultr-setup.md                 # Vultr VPS provisioning steps
│   └── wazuh-install.md               # Wazuh all-in-one installation
├── WireShark/                         # Packet capture screenshots
└── SOC_SSH_Brute_Force_Investigation.docx  # SSH brute force investigation report
```

## Key Learnings

- Deployed and managed a cloud-based SIEM (Wazuh) with dual-layer firewall hardening
- Enrolled cross-platform agents (Linux `ubuntu-endpoint` + Windows `Computer2`) for centralized log collection
- Simulated real-world attacks and triaged alerts in the Wazuh dashboard
- Mapped all attack simulations to the MITRE ATT&CK framework
- Detected defense evasion via audit log clearing (T1070.001) in addition to brute force and recon techniques
- Performed packet analysis with Wireshark to observe attack traffic at the network level
- Monitored vulnerability detection across severity levels (Critical, High, Medium, Low)
- Ran CIS Ubuntu 24.04 LTS Benchmark compliance assessment via Wazuh's Security Configuration Assessment module
- Practiced defense-in-depth with Vultr firewall groups + UFW host-based firewall

## Investigation Reports

| Report | Description |
|---|---|
| [SOC SSH Brute Force Investigation](SOC_SSH_Brute_Force_Investigation.docx) | Full investigation report covering the SSH brute force attack simulation — timeline, alert analysis, MITRE ATT&CK mapping, and findings |
