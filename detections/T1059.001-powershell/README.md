# T1059.001 - PowerShell

**Tactic:** Execution
**Outcome:** Detected, but by accident. See notes.

## What I ran

Atomic Red Team test 17 for T1059.001, "PowerShell Command Execution". The payload comes from Red Canary's 2021 Threat Detection Report.

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 17
```

T1059.001 has 22 atomic tests. I picked test 17 because it runs entirely locally with no network dependency, so any missing telemetry would point at my pipeline rather than at a failed download.

![Test inventory](./06-test-inventory.png)

Inspecting the test before running it shows what it actually does:

![Test details](./07-test-details.png)

The test runs this:

```
powershell.exe -e JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIAIgArACIAbwBtACAAUAAiACsAIgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwAbAAhACcAIgApAA==
```

Decoded, that is:

```powershell
& (gcm ('ie{0}' -f 'x')) ("Wr"+"it"+"e-H"+"ost 'H"+"el"+"lo, fr"+"om P"+"ow"+"erS"+"h"+"ell!'")
```

Three layers of obfuscation stacked on top of a payload that just prints "Hello, from PowerShell!":

1. **Base64 encoding** via `-e`, so nothing readable appears on the command line.
2. **Alias construction.** `('ie{0}' -f 'x')` builds the string `iex` at runtime, and `gcm` resolves it to `Invoke-Expression`. The literal string `iex` never appears.
3. **String concatenation.** `"Wr"+"it"+"e-H"+"ost"` assembles `Write-Host` from fragments, so the cmdlet name never appears either.

Each layer defeats a different naive signature. The payload is harmless, the delivery is real tradecraft.

## Telemetry

Two events from `wazuh-archives-*`, same process, PID 6424. This pair is the point of the whole technique.

**PowerShell Event ID 4104** (`t1059-001-4104.json`)

```
scriptBlockText: Write-Host 'Hello, from PowerShell!'
systemTime: 2026-09-01T15:45:32.341Z
processID: 6424
```

![4104 decoded script block](./08-4104-decoded-payload.png)

Fully decoded. All three obfuscation layers gone.

**Sysmon Event ID 1** (`t1059-001-sysmon1.json`)

```
commandLine: powershell.exe -e JgAgACgAZwBjAG0A...
parentCommandLine: "cmd.exe" /c powershell.exe -e JgAgACgAZwBjAG0A...
parentProcessId: 6080
processId: 6424
currentDirectory: C:\Users\mayank\AppData\Local\Temp\
integrityLevel: High
```

![Sysmon command line, still encoded](./09-sysmon-commandline-base64.png)

Still encoded. Same action, same process, two very different views of it.

## Detection

A built-in rule fired.

![Alert fired](./10-alert-fired.png)

```
rule.id: 92032
rule.description: Suspicious Windows cmd shell execution
rule.level: 3
rule.groups: sysmon, sysmon_eid1_detections, windows
rule.mitre.id: T1087, T1059.003
rule.mitre.tactic: Discovery, Execution
```

![Rule metadata](./11-alert-rule-metadata.png)

No custom rule was written for this technique, so there is no false positive assessment.

## Notes

**Obfuscation beats the command line, not the log.** The command line shows base64. The script block shows plaintext. That difference exists because 4104 logs at the PowerShell execution engine, after decoding, rather than at process creation. Any detection built only on command line inspection would have missed what this payload actually did. This is the argument for enabling script block logging, and it is visible in a single pair of events.

**The detection was incidental.** Rule 92032 is a generic rule for suspicious `cmd.exe` execution. It matched the `cmd.exe /c` wrapper that Atomic Red Team uses to launch the test, not the PowerShell payload inside it. Nothing in the rule looks at base64, the `-e` flag, or obfuscation. If the same payload had been launched directly in PowerShell without the cmd wrapper, this rule would not have fired at all.

**The ATT&CK mapping points at the wrong technique.** The rule maps to T1059.003 (Windows Command Shell) and T1087 (Account Discovery). I ran T1059.001 (PowerShell). So the dashboard MITRE view would show this attack under a technique I did not run, and T1059.001 would still look uncovered.

**Level 3 is too low.** Level 3 is informational, the bottom of the scale. An obfuscated base64 payload executing from `AppData\Local\Temp` at high integrity would sit unread in any real alert queue.

Taken together: the technique is marked detected, but the coverage is weaker than the green alert suggests. The right fix is a custom rule matching `powershell.exe` with `-e` or `-EncodedCommand` on the command line, which would catch the technique directly instead of catching its wrapper.

## Limitations

- One test out of the 22 available for T1059.001. Other tests use download cradles or in memory execution and may produce different results.
- The direct execution case (no cmd wrapper) is untested, so the claim that nothing would fire is a hypothesis rather than a measured result.
- Atomic Red Team runs from an excluded folder, so Defender was not evaluating the payload the way it would in a real environment.
