# DFIR Package Comparison: corp-aafbc-6962

Nov 19, 2026 · Eliezer Fuentes

**Bottom line: no evidence of host compromise.** Comparing the pre- and
post-incident MDE investigation packages for corp-aafbc-6962, every
added/removed/changed artifact is benign OS churn, Defender updates, or
the analyst's own activity. No new accounts, persistence, services,
software, or attacker binaries. This is consistent with an incident
confined to the MySQL data layer, with no foothold on the Windows host.

## 1. Baseline Determination

Two MDE investigation packages were provided for the target host
corp-aafbc-6962, confirmed as the same host via machine SID
(…-461569612) and SystemInformation.txt (OS install date 11/16/2026):

| Package (as named)                    | Collected            | Host            | Machine SID | Use          |
|---------------------------------------|----------------------|-----------------|-------------|--------------|
| MDE_Pre_Breach_Investigation_Package  | 2026-11-17 00:33 UTC | CORP-AAFBC-6962 | …-461569612 | **Baseline** |
| MDE_Post_Breach_Investigation_Package | 2026-11-18 21:45 UTC | CORP-AAFBC-6962 | …-461569612 | Comparison   |

**Baseline = the Nov 17 00:33 UTC package.** Basis: it is the earliest
capture of the target host corp-aafbc-6962 (OS install date 11/16/2026),
taken ~9 minutes before the recorded exposure time (00:42:36 UTC), so it
represents the clean, pre-exposure state.

## 2. Summary Verdict

**Compromise indicators on the host: NO. Confidence: High.**

Across every comparable artifact category, the host state is materially
unchanged between baseline and comparison. Local users and group
membership are byte-identical (no new privileged accounts), installed
programs are identical, and no new scheduled task, service, or autorun
persistence was introduced by an attacker. The only security-relevant
configuration — MySQL listening on 0.0.0.0:3306 — is the deliberate
exposure, not a post-compromise artifact. All deltas trace to routine
OS/Defender updates or the analyst's own interactive session. The
database-layer ransom seen in the MySQL audit logs left no footprint on
the Windows host.

## 3. Notable Deltas

| Category             | Item                                                                             | Change                                        | Assessment                                                                                  | Evidence                                      |
|----------------------|----------------------------------------------------------------------------------|-----------------------------------------------|---------------------------------------------------------------------------------------------|-----------------------------------------------|
| Users / Groups       | Local users + all group membership                                               | Unchanged                                     | Benign — **no new/privileged accounts**                                                     | LocalGroups.txt, QueryUser.txt byte-identical |
| Installed programs   | Full list                                                                        | Unchanged                                     | Benign                                                                                      | InstalledPrograms.csv identical               |
| Services             | MicrosoftCopilotElevationService                                                 | Added                                         | Benign — Windows Copilot app update                                                         | Autoruns.txt, Services.csv                    |
| Services             | *UserSvc_111939 instances (clipboard, OneSync, Bluetooth, etc.)                 | Removed                                       | Benign — per-logon-session instances absent because host was logged-off/isolated at capture | Services.csv                                  |
| Scheduled tasks      | SetupCleanupTask                                                                 | Removed                                       | Benign — self-deleting OS setup task                                                        | ScheduledTasks.csv                            |
| Scheduled tasks      | (no new tasks)                                                                   | —                                             | Benign — **no attacker persistence**                                                        | ScheduledTasks.csv                            |
| Autoruns             | Run keys (OneDrive, Edge auto-launch)                                            | Removed                                       | Benign — user-hive keys not loaded with no active session                                   | Autoruns.txt                                  |
| Prefetch             | MYSQLD/MYSQL/MYSQLWORKBENCH/PYTHON/NOTEPAD/TASKLIST/TASKMGR/MMC/POWERSHELL/XCOPY | Added                                         | Benign — analyst's own activity + MySQL service running                                     | Prefetch/ listing                             |
| Prefetch             | AM_DELTA_PATCH_*, VC_REDIST, COPILOT*, SECURITYHEALTHSETUP                    | Added                                         | Benign — Defender/OS updates                                                                | Prefetch/ listing                             |
| Network              | MySQL 0.0.0.0:3306 + :33060 LISTENING (PID 5100 mysqld)                          | Present                                       | **Exposure config** (by design), not post-compromise                                        | ActiveNetConnections.txt (post)               |
| Network              | Attacker IPs (64.89.x, 77.90.x, etc.)                                            | Absent in both                                | Expected — point-in-time snapshots missed the transient DB sessions                         | grep of all Network Connections/*            |
| Firewall / DNS / ARP | Rules, cache                                                                     | Unchanged (only collection-path GUID differs) | Benign                                                                                      | FirewallExecutionLog.txt, DnsCache.txt        |
| Security event log   | Security.evtx 19.99 MB → 21.04 MB                                                | Grew                                          | Benign — **no clearing** (a cleared log would reset/shrink)                                 | file sizes                                    |

## 4. Strongest Indicators (mapped to ATT&CK)

**No host-based compromise indicators were found in these packages.**
Nothing in the added/removed/changed set rises to a confirmed malicious
technique on the endpoint. The only item of security interest is a
pre-existing exposure state, not attacker action:

1.  **MySQL bound to 0.0.0.0:3306 (PID 5100 mysqld)** — *enabling
    condition, not compromise evidence.* This is what made the host
    reachable; it maps conceptually to the attack's entry (T1133
    External Remote Services / exploitation of an exposed service), but
    it is the intended lab exposure and appears in the post package only
    because MySQL was running. No host technique (persistence, priv-esc,
    defense evasion, C2) is evidenced in these artifacts.

For completeness: the actual malicious activity (T1078 valid accounts →
T1485 data destruction → T1070 log purge, by root@64.89.163.93) occurred
entirely within MySQL and is evidenced in the MySQLAudit_CL logs,
**not** in these host packages. The packages' value here is
confirmatory: they show the attacker never pivoted to the OS.

## 5. Probable Incident Type

**From these host packages alone: undetermined / host appears clean.**
The endpoint artifacts show no ransomware behavior (no encryption, no
ransom files, no shadow-copy deletion), no credential-theft tooling, and
no persistence — so they do not, on their own, point to a specific host
incident.

Correlated with the MySQL audit evidence (external context), the
incident is an **automated database ransom / data-destruction event
against an internet-exposed MySQL service**, with **no host
compromise**. The host packages are consistent with and support that
conclusion: the attack began and ended at the database service, never
reaching the operating system.

## 6. Gaps

- **Security event logs not parsed to entry level.** Both packages ship
  Security.evtx as binary only (Security.txt is 0 bytes). File size grew
  baseline→comparison (19.99 → 21.04 MB), which rules out log clearing,
  but 4624/4625/4720/1102 event-level comparison was not performed in
  this pass and should be run through an EVTX parser to confirm.

- **Point-in-time network/process snapshots.** ActiveNetConnections.txt
  and Processes.csv are instantaneous captures taken well after the
  ~2-minute MySQL attack, so the attacker's transient connections are
  not expected to appear and their absence is not exculpatory on its
  own.

- **Loaded modules and SMB sessions** folders were empty in the packages
  — not collected, so DLL side-loading and remote-session analysis could
  not be compared.

- **No MySQL audit data in these packages.** The authoritative breach
  evidence lives in MySQLAudit_CL, which is outside the MDE package
  scope; this comparison speaks only to the host, not the database.
