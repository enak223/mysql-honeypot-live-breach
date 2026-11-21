# MySQL Honeypot — Live Ransom Breach: Threat Hunt & Incident Response

**A real, internet-sourced ransomware breach — detected, hunted, scoped, and recovered.**

This repo documents a full-lifecycle incident investigation from the LOG(N) Pacific
Cyber Range (*SecOps 6: Live Breach & Incident Response*). I stood up an
intentionally vulnerable Windows + MySQL VM in Azure, instrumented it into Microsoft
Sentinel, deliberately exposed it to the internet, and then worked the **real** breach
that automated ransom bots carried out — within ~1.5 hours of exposure.

Everything here is my own hunting, analysis, and reporting against live telemetry. All
data in the environment is synthetic lab data.

- **Author:** Eliezer Fuentes — [LinkedIn](https://linkedin.com/in/eliezerfuentes) · [GitHub](https://github.com/enak223)
- **Stack:** Azure VM · MySQL 8.0 · Microsoft Sentinel / Log Analytics (`LAW-Cyber-Range`) · Microsoft Defender for Endpoint · KQL
- **Role:** SOC analyst / detection engineer (build, detect, respond)

---

## At a glance

| | |
|---|---|
| **Incident type** | Automated database ransom / data destruction against an internet-exposed MySQL service |
| **Entry** | Weak, network-enabled `root@'%'` on MySQL/3306 open to the internet — no exploit required |
| **Impact** | `mcgraw_hill_holdings_corp` database read, then dropped; binary logs purged; service shut down; Bitcoin ransom note left |
| **Host compromise** | **None** — proven via Defender investigation-package diff; the OS was never touched |
| **Dwell time** | First malicious login → database destroyed in **~2 minutes** |
| **Recovery** | Restore from off-host backup (binlogs were purged, so no point-in-time recovery) |

---

## Environment & setup

1. **Build** — Windows 11 Azure VM (`corp-aafbc-6962`), MySQL 8.0, loaded with a synthetic
   corporation (customers, orders, payments, refunds, credentials, devices, activity logs,
   plus triggers and honeytoken accounts). The generator I reverse-engineered and rebuilt
   with a local LLM is in [`database/`](database).
2. **Instrument** — MySQL audit log (`MySQLAudit_CL`) and Defender for Endpoint telemetry
   (`DeviceLogonEvents`, `DeviceProcessEvents`, …) shipped into Log Analytics.
3. **Baseline & detect** — Sentinel analytics rules authored *while the box was clean*, so
   detections existed before the attack.
4. **Weaken & expose** — firewall off, NSG allow-all, `root@'%'` reachable on 3306; exact
   exposure timestamp recorded: **2026-11-17 00:42:36 UTC**.
5. **Respond** — wait for the real breach, then detect → analyze → contain → eradicate → recover.

---

## Timeline (first breach)

Times in Eastern (EST), as the Defender portal displays them; raw log timestamps are UTC.

| Time (EST) | Event | Source |
|---|---|---|
| Nov 16, 7:42 PM | VM exposed to the internet (`root@'%'` reachable on 3306) | Phase 5 exposure timestamp |
| Nov 16, 9:18 PM | First `root` login from `64.89.163.93` after one failed attempt | `MySQLAudit_CL` |
| Nov 16, 9:20:28 PM | `GRANT CREATE, DROP ON *.* TO root@%` — self-escalation | `MySQLAudit_CL` |
| Nov 16, 9:20:31–9:21:15 PM | `USE mcgraw_hill_holdings_corp; SELECT *` on all 7 tables (data read) | `MySQLAudit_CL` |
| Nov 16, 9:20:23 PM | `CREATE DATABASE RECOVER_YOUR_DATA` + ransom note inserted | `MySQLAudit_CL` |
| Nov 16, 9:21:17–9:21:42 PM | `DROP` of foreign keys, all 7 tables, then the database | `MySQLAudit_CL` |
| Nov 16, 9:22:03–9:22:05 PM | `RESET MASTER`, `PURGE BINARY LOGS`, `REVOKE … root@%`, `SHUTDOWN` | `MySQLAudit_CL` |
| Nov 17, 1:25–11:24 AM | Re-ransom note re-plants from the same `64.89.163.x` block | `MySQLAudit_CL` |
| Nov 17, 6:20–6:31 AM | Windows `administrator` brute force from `194.180.49.140` — ~32 attempts, **all failed** | `DeviceLogonEvents` |
| Nov 18, 6:24 PM | VM isolated in Microsoft Defender | Phase 8 isolation |

The same box was re-hit by multiple automated actors over ~14 hours — exposure is a
standing invitation, not a one-time event.

---

## Kill chain (MITRE ATT&CK)

| # | Technique | ID | What happened |
|---|---|---|---|
| 1 | Brute Force | T1110 | Automated password spray against MySQL `root` over 3306 |
| 2 | Valid Accounts | T1078 | Logged in as `root` with the weak, exposed password |
| 3 | Account Manipulation | T1098 | `GRANT CREATE, DROP ON *.*` self-escalation |
| 4 | Data from / Exfiltration over Info Repositories | T1005 / T1041 | `SELECT *` across all 7 tables (read in-session; off-host egress not confirmed) |
| 5 | Data Destruction | T1485 | Dropped every table, then the `mcgraw_hill_holdings_corp` database |
| 6 | Indicator Removal | T1070 | `RESET MASTER` / `PURGE BINARY LOGS` — killed point-in-time recovery |
| 7 | Service Stop | T1489 | MySQL `SHUTDOWN` |
| 8 | Financial Theft | T1657 | Bitcoin ransom note (`RECOVER_YOUR_DATA`), 0.0131 BTC, 48-hour deadline |

Entry maps conceptually to **T1133 (External Remote Services)** — a database service
needlessly exposed to the internet.

---

## The hunt

All hunting queries are in [`queries/`](queries) (each with a header comment and a note on
every `let` variable). The reliable pattern throughout: `_ResourceId` is stored lowercase,
so match the VM with `contains`/`=~`, never case-sensitive `==`, and always confirm the
pipeline is flowing before trusting an empty result.

The destruction and anti-forensics sequence — the core of the case — comes from one query:

```kql
// Destructive and anti-forensics MySQL statements on the target VM, oldest first.
// Reconstructs the kill chain: GRANT self-escalation -> DROP -> RESET MASTER / PURGE -> SHUTDOWN.
// MyTag: last 4 of the VM name.
let MyTag = "6962";
MySQLAudit_CL
| where _ResourceId contains MyTag
| extend RawData = replace_string(RawData, "\t", " ")
| where RawData has_any ("DROP DATABASE","DROP TABLE","RESET MASTER","PURGE BINARY","SHUTDOWN","GRANT","RECOVER_YOUR_DATA")
| project TimeGenerated, RawData
| order by TimeGenerated asc
```

| File | Hunt |
|------|------|
| [`01_successful_mysql_logins.kql`](queries/01_successful_mysql_logins.kql) | Successful non-localhost MySQL logins by account + source IP |
| [`02_destruction_and_antiforensics.kql`](queries/02_destruction_and_antiforensics.kql) | Destruction + anti-forensics statement sequence |
| [`03_ransom_notes_recover_your_data.kql`](queries/03_ransom_notes_recover_your_data.kql) | Every `RECOVER_YOUR_DATA` note creation / re-plant |
| [`04_windows_bruteforce_admin_guest.kql`](queries/04_windows_bruteforce_admin_guest.kql) | Windows `administrator`/`guest` brute force (all failed) |
| [`05_host_compromise_check_processes.kql`](queries/05_host_compromise_check_processes.kql) | Non-system processes after exposure (host-compromise check) |

---

## Key finding: the OS was never compromised

The breach lived entirely in the MySQL data layer. I proved the Windows host was clean by
diffing the **pre-breach vs post-breach Defender investigation packages** (same host,
confirmed by machine SID): local users and group membership byte-identical, no new
scheduled tasks / services / autoruns, no attacker binaries, and `Security.evtx` *grew*
(ruling out log clearing). Full analysis in
[`reports/dfir-package-comparison.md`](reports/dfir-package-comparison.md).

Two separate doors: the attacker only ever needed the open one (MySQL/3306). The Windows
`administrator` brute force from `194.180.49.140` failed on every attempt.

---

## Containment, eradication & recovery

- **Contain** — VM isolated in Microsoft Defender; pre/post investigation packages captured.
- **Eradicate** — removed the exposed inbound rule; bound MySQL to `127.0.0.1`; deleted the
  network `root@'%'` account; re-enabled Windows Firewall; removed the weak Windows admin account.
- **Recover** — dropped the whole ransom schema (`DROP SCHEMA recover_your_data;` — dropping
  only the table leaves the schema behind) and restored `mcgraw_hill_holdings_corp` from an
  **off-host backup**. Because the attacker purged the binary logs, the backup was the only
  path back — the single most important control in the whole case.

---

## Lessons learned

1. **Never expose a database service to the internet.** Bind MySQL to `127.0.0.1` and keep
   3306 off any public NSG rule. This one control prevents the entire incident.
2. **Kill weak, network-wide DB accounts.** No `root@'%'`; least privilege, strong passwords,
   host restrictions. Valid credentials over an exposed service — not an exploit — were the whole attack.
3. **Centralize logs.** The attacker purged MySQL binlogs, but every statement had already
   shipped to Sentinel. You can't delete logs that already left the building.
4. **Alert on destructive statements, not just logins.** Add near-real-time rules for
   `DROP DATABASE` / `RESET MASTER` / `RECOVER_YOUR_DATA`, so destruction pages immediately.
5. **An empty result is a claim to verify, not a conclusion** — case-sensitive `==` and a
   too-narrow time picker caused most of my false "nothing's here" moments.

---

## Repo contents

| Path | What's inside |
|------|---------------|
| [`reports/incident-report.md`](reports/incident-report.md) | Full incident report (summary, impact, IOCs, timeline, root cause, response, lessons) |
| [`reports/dfir-package-comparison.md`](reports/dfir-package-comparison.md) | Pre/post Defender package diff proving no host compromise |
| [`queries/`](queries) | The KQL threat-hunting queries, documented |
| [`iocs/iocs.md`](iocs/iocs.md) · [`iocs/ransom-note.txt`](iocs/ransom-note.txt) | Indicators of compromise and the recovered ransom note |
| [`database/`](database) | Synthetic corporate database generator (my own build) |
| [`writeup/build-it-break-it-catch-it.md`](writeup/build-it-break-it-catch-it.md) | First-person reflection on the module |

---

*The less you talk, the more you hear — and these logs had a lot to say.*
