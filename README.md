# Wazuh Detection Lab

A home lab where I run known attack techniques against an instrumented Windows 11 machine, hunt the resulting telemetry in a Wazuh SIEM, and write detection rules for what I find.

The point is not to run attacks. The point is to answer a question for each technique: **did my logging catch it, did a rule fire, and if not, what rule should exist?**

Each technique is recorded with one of three outcomes:

- **detected** - a rule fired
- **ran undetected** - telemetry existed but nothing matched it
- **blocked** - a built-in Windows control stopped the attack

These are kept separate on purpose. An attack can be blocked and undetected at the same time, which means the control worked but I would never have known it happened.

## Lab setup

| Role | System | Purpose |
|---|---|---|
| SIEM | Ubuntu Server 26.04 | Wazuh 4.14.7, single node (indexer, manager, dashboard) |
| Victim | Windows 11 Enterprise (eval) | Wazuh agent, Sysmon, PowerShell logging |

Both run in VirtualBox on a NAT network. The victim reverts to a clean snapshot before every technique so results stay comparable.

### Logging on the victim

Windows by default does not log enough to detect much. Three additions do the heavy lifting:

- **Sysmon v15.21** with the SwiftOnSecurity config. Gives process creation with full command lines and parent process (Event ID 1), registry writes (13), and process access (10).
- **PowerShell Script Block Logging** (Event ID 4104). Logs script text after PowerShell has decoded it, which matters against obfuscated payloads.
- **Windows Defender Operational channel**. Defender's own verdicts, including tamper-blocked events.

Sysmon Event ID 10 for `lsass.exe` had to be enabled manually. The stock SwiftOnSecurity config ships it turned off.

### Archives

Wazuh only indexes alerts by default, so anything that does not match a rule disappears. I turned on `logall_json` and created a `wazuh-archives-*` index so every event is searchable whether it alerted or not.

This is the whole reason the lab works. Without it there is no way to tell the difference between "nothing happened" and "something happened and I am blind to it."

### Endpoint posture

The endpoint stays hardened for the whole campaign. Tamper Protection, Real-Time Protection, and LSA Protection all stay on. Detections are built against attempt telemetry rather than by turning defenses off, because a blocked attack still generates events.

## Status

| # | Technique | ATT&CK | Rule | Type | Level | Telemetry | Outcome |
|---|---|---|---|---|---|---|---|
| 1 | PowerShell | T1059.001 | 92032 | Built-in | 3 | Sysmon 1, PowerShell 4104 | Detected (incidental) |
| 2 | Rundll32 | T1218.011 | | | | | |
| 3 | Discovery | T1087.001 / T1082 / T1057 | | | | | |
| 4 | Impair Defenses | T1562.001 | | | | | |
| 5 | Registry Run Key | T1547.001 | | | | | |
| 6 | Scheduled Task | T1053.005 | | | | | |
| 7 | LSASS Memory | T1003.001 | | | | | |
| 8 | SAM | T1003.002 | | | | | |
| 9 | Archive Collected Data | T1560.001 | | | | | |

## Repo layout

```
detections/     one folder per technique: writeup, raw event JSON, screenshots
rules/          custom Wazuh rules
docs/           build notes and lessons learned
screenshots/    lab setup screenshots
```

## What this lab does not cover

Worth stating up front so the scope is clear:

- No EDR. Detection is log based, not behavioral.
- No network detection. No IDS, no traffic inspection.
- No delivery phase. Initial execution is assumed, so no phishing or C2.
- Single host. No lateral movement, no domain, no cross host privilege escalation.
- Atomic Red Team payloads run from an excluded folder so they execute at all. Not how a real endpoint is configured, and the one deliberate concession to the hardened posture.
- One clean VM is a very small false positive sample compared to a real fleet.

## Future work

- Convert the custom rules to Sigma so the logic is portable to other SIEMs
- ATT&CK Navigator layer showing coverage
- Full kill chain run with all nine techniques in sequence, without reverting between them
