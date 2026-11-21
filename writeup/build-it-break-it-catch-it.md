# Build It, Break It, Catch It

Nov 19, 2026 · Eliezer Fuentes

This is my favorite module of the course so far — *SecOps 6: Live Breach
& Incident Response*. I built a honeypot, deliberately exposed it to the
internet, and caught the real attackers who showed up. I ended up
running it twice, lost a VM to an early “brick,” created a new one
restored a database from my own backup, reverse-engineered the
synthetic-data generator, and wrote my first real detections. Here's
what it was like.

## The module: build it, break it, catch it

Most labs hand you a pre-made incident to analyze. This one is different
— I created the incident myself, with real attackers. The flow runs the
full defensive lifecycle, in order:

1.  **Build** a Windows VM in Azure, install MySQL, and load it with
    synthetic corporate data.

2.  **Instrument** it — wire the MySQL audit log and Defender for
    Endpoint telemetry into a Log Analytics workspace so every
    connection and query is recorded.

3.  **Baseline and detect** — write your Sentinel analytics rules *while
    the box is still clean*, so your detections exist before the attack
    does.

4.  **Weaken and expose** — deliberately open it to the internet (weak
    root password, firewall off), record the exact exposure timestamp,
    and walk away.

5.  **Respond** — wait for the real breach, then detect, analyze,
    contain, and recover it.

The part that makes it click: the breach is *real*. Within a couple of
hours of going live, actual ransomware bots on the internet found my
open MySQL port and went to work. I wasn't analyzing a canned scenario —
I was doing DFIR on something that genuinely happened to my machine.

## I had to run it twice

My first attempt didn't survive. The VM bricked too early — I lost
access through the Bastion host before I could work the incident end to
end, and that run was a write-off. Frustrating in the moment, but it's
its own lesson: in real IR you don't always get a clean, cooperative
environment, and losing a box mid-investigation is a thing that actually
happens.

The second run went the distance. I built it, exposed it, got breached
for real, and worked it all the way through to **Phase 8 — Contain the
Breach (Isolation)**: isolating the compromised VM in the Defender
portal and capturing a post-incident investigation package. Getting to
actually *pull the plug* on a live-compromised host in the console —
instead of just reading about containment — is the moment the whole
lifecycle stopped being theory.

The second run didn't actually stop at isolation — I pushed on into
**Phase 9 — Eradication and Recovery**. And then, almost on cue, the
Azure VM bricked a *second* time: Bastion wouldn't connect, so I
couldn't finish the cleanup on the original box. Rather than lose the
lesson again, I rebuilt the account-cleanup and hardening steps on a
local VMware machine and followed the module through to the end. Here's
what eradication and recovery actually involved:

1.  **Hardened the host** — deleted the vulnerable inbound rule that had
    left the MySQL port open to the internet. (Azure VM)

2.  **Released the VM from isolation** so it could be worked on normally
    again. (Azure VM)

3.  **Hit the brick wall again** — Bastion wouldn't connect and the
    Azure VM was gone, so I moved the remaining account work onto a
    local VMware box to follow the module's steps. (Azure VM)

4.  **Cleaned up the accounts** — recreated and enabled the
    administrator and guest accounts to mirror the lab, then deleted the
    built-in Administrator account entirely; it shouldn't have existed
    in the first place. (VMWare VM)

5.  **Set a strong password** on my own local account. (VMWare VM)

6.  **Turned the Windows Firewall back on.** (VMWare VM)

7.  **Blocked remote MySQL logins** — opened C:\ProgramData\MySQL\MySQL
    Server 8.x\my.ini, found bind-address = 0.0.0.0, and changed it to
    127.0.0.1 so MySQL only listens locally. (VMWare VM)

8.  **Secured the MySQL root accounts** — I deleted the exposed remote
    root account outright. (VMWare VM)

9.  **Restored the data** — dropping just the ransom table leaves its
    schema behind, so I dropped the whole schema with DROP SCHEMA
    recover_your_data; and restored from my backup. (Azure VM from the
    previous machine)

10. **Ran a full malware scan.** (VMWare VM)

11. **Documented everything I did.**

## Backup, restore, and rolling my own data

Two things in this run I'm genuinely proud of.

First, **recovery actually meant something.** Because the attacker
dropped the whole database *and* purged the MySQL binary logs (killing
point-in-time recovery), the only way back was a real backup. I had made
a full backup of the first database, so eradication wasn't hand-waving —
I restored the data from that backup, the way you'd actually recover in
production. It drove home why off-host backups matter: the attacker can
scorch everything on the box and still not touch a copy I took earlier.

Second, **I wanted to understand the data, not just use it.** The lab
ships a synthetic-data generator that builds a fake corporation —
customers, orders, payments, refunds, credentials, devices, activity
logs, with triggers and honeytoken accounts. Instead of running it
blindly, I dug into how it works and then built my own version with a
local LLM. Writing my own generator taught me more about the schema, the
relationships, and why certain tables make juicy targets than any amount
of just clicking “run.”

## Writing detections — and wanting more

Writing the detections was the most interesting part for me. Authoring
Sentinel analytics rules *before* the attack, then watching them sit
quiet against a clean baseline and only light up once real malicious
logins arrived, is a completely different feeling from reading pre-built
rules. I owned the logic, and I found out quickly whether it actually
fired.

This run leaned on the obvious levers — weak passwords and loose
policies — as the way in. That worked, but it left me wanting to explore
the other side of detection engineering: behavioral rules, not just
credential ones. Detecting the *actions* an attacker takes once inside
(mass DROP statements, RESET MASTER / PURGE BINARY LOGS, a sudden SELECT
* sweep of every table) rather than only the logon. That's the
direction I want to push next — detections that catch what the attacker
does, not just how they got in.

## The challenges that taught me the most

Most of my “stuck” moments weren't the attacker — they were me versus my
own tooling, and each one was a real lesson:

- **KQL punishes small mistakes silently.** == is case-sensitive, and
  Azure stores the device name in lowercase, so matching on
  "CORP-AAFBC-6962" returned *nothing* with no error. Switching to =~ /
  contains fixed it. Lesson: an empty result is a claim that needs
  checking, not a conclusion.

- **The time-range picker is a trap.** Half my “why is this query
  empty?” moments were just the Advanced Hunting window set too narrow
  to include the event. Confirm the pipeline is flowing before you trust
  a zero.

- **MySQL logins aren't Windows logins.** I kept hunting
  DeviceLogonEvents for the administrator account and finding nothing —
  because the breach came in through the *MySQL service* as root, which
  lives in MySQLAudit_CL, not the Windows logon table. Two separate
  doors; the attacker only needed the open one.

- **Getting ransomed once doesn't close the hole.** The box got re-hit
  over and over while it stayed exposed — the same note re-planted by
  multiple bots across ~14 hours. Exposure is a standing invitation, not
  a one-time event.

- **Attackers try to cover their tracks — and centralized logging beats
  them.** The attacker purged the MySQL binary logs and shut the service
  down, but every statement (including the cleanup commands) had already
  shipped to my workspace. You can't delete logs that already left the
  building.

## Why it felt like the real thing

What I'll remember about this module is that it gave me a real-world
perspective you can't fake with a canned dataset. The attackers were
actual bots on the actual internet. The ransom note had a real Bitcoin
address and a real 48-hour deadline. The data loss was real (synthetic
data, but really dropped). And the recovery was real — a genuine restore
from a backup I had the foresight to take. It compressed a full incident
— exposure, breach, detection, analysis, containment, recovery — into
something I lived through instead of read about.

If you want to dig into the artifacts, I'm sharing a few from the run:

- The **pre-breach** and **post-breach** Defender investigation packages
  (the before/after host snapshots I diffed to prove the OS was never
  compromised).

- The **ransom note** the attacker left behind.

- My **incident report** and **DFIR package-comparison report**.

On to the next one. As always — the less you talk, the more you hear,
and these logs had a lot to say.
