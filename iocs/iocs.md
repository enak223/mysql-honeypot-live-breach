# Indicators of Compromise — corp-aafbc-6962 MySQL ransom

All indicators are taken from this incident's own logs (`MySQLAudit_CL`,
`DeviceLogonEvents`). All data in the environment is synthetic lab data. URLs are
defanged.

## Ransom demand

| Field | Value |
|-------|-------|
| BTC wallet | `bc1qgny880a3eew0yk29z58ptw33l6x367alq3fppx` |
| Amount | 0.0131 BTC |
| Contact email | `ak+2mfso@onionmail.org` |
| Note link | `hxxps://is[.]gd/mysql43` |
| DATAID | `2MFSO` |
| Deadline | 48 hours |
| Note container | database `RECOVER_YOUR_DATA`, table `RECOVER_YOUR_DATA` |

## Network indicators

| Type | Value | Role |
|------|-------|------|
| IP | `64.89.163.93` | Primary actor — data read + destruction + ransom (AS401626 / 10gig.host) |
| IP | `64.89.163.176`, `.169`, `.91`, `.154`, `.158` | Same block — re-ransom / note re-plants |
| IP | `77.90.185.21`, `35.210.227.34`, `212.30.37.196`, `213.209.159.115` | Additional successful root logins (spray / revisit) |
| IP | `34.62.41.110`, `46.151.182.191` | Failed root/admin/sa MySQL spray |
| IP | `194.180.49.140` | Windows administrator RDP/SMB brute force — all failed |

## Host / database artifacts

| Type | Value | Role |
|------|-------|------|
| DB artifact | database `RECOVER_YOUR_DATA` / table `RECOVER_YOUR_DATA` | Ransom note container |
| Account | `root@'%'` (network-enabled) | Weak, internet-reachable MySQL account used for entry |
| Victim DB | `mcgraw_hill_holdings_corp` | Database read then dropped |
| Service state | MySQL listening on `0.0.0.0:3306` | Exposure configuration (by design in Phase 5) |
