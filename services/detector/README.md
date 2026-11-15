# Detector and rules (owner M2)

Run: `python main.py` (follow mode, API on port 8200) or `python main.py batch --from 2026-11-12T00:00:00Z --to 2026-11-13T00:00:00Z`.
Endpoints (X-API-Key required except /health): GET /health, GET /v1/rules, POST /v1/run-batch {start, end}.
Response of run-batch: alerts_created (new documents), alerts_total (all alerts found), events_evaluated, per_rule.

## Exclusions and why
| Rule | Exclusion | Why |
| --- | --- | --- |
| HC-002 | host WS-08 and user adm_it | hard negative 1: the admin runs harmless encoded PowerShell about 3 times a day |
| HC-003 | host WS-08 and user adm_it | same hard negative; without it any outbound HTTPS right after the admin script would alert (added by M2, see MANIFEST) |
| HC-004 | host WS-08 and user adm_it | hard negative 2: the admin uses psexec.exe from WS-08 once a day |
| HC-005 | user svc_backup | hard negative 3: the backup account reaches 6 or more hosts on 445 at 02:00 |
| HC-009 | net.dst_ip 198.51.100.77 | hard negative 4: the software updater beacons every 300 s |

Hard negative 5 (long base64 command lines on WS-02) needs no exclusion: HC-002 only looks at powershell.exe with an -e, -enc or -encodedcommand flag followed by base64.
Rules are YAML (Section 5.6). Add `enabled: false` to a rule to switch it off.
