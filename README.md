# Quasar RAT — Red Team Research & Windows Detection Analysis

> **Project type:** Authorized adversary-emulation research, Windows security, malware behavior analysis, and threat hunting  
> **Status:** Research methodology and detection playbook. This repository does **not** claim a successful Microsoft Defender bypass or include an operational RAT payload.

## Overview

This repository examines **Quasar RAT** as a case study in remote-access tooling and adversary tradecraft. Its goal is to explain the architecture and techniques associated with Windows RAT activity, then show how to evaluate their **observable artifacts** using endpoint and network telemetry.

The original study considered the following workflow: obtaining Quasar, building a client, configuring a communications path, enabling startup behavior, changing executable metadata, obfuscating the file, and distributing a package. This revision **preserves those concepts for technical analysis** rather than presenting an unauthorized deployment or antivirus-evasion procedure.

**Intended audience:** Red Team trainees, SOC analysts, malware analysts, blue-team engineers, and students.

**Upstream reference:** [Quasar releases](https://github.com/quasar/Quasar/releases) · [Project source](https://github.com/quasar/Quasar)

## Research objectives

1. Understand the **operator / controller / endpoint agent** model.
2. Explain why an endpoint can make an outbound connection to a remote control endpoint.
3. Identify potential evidence of **persistence, masquerading, obfuscation, and remote execution**.
4. Build a **reproducible, isolated Windows test environment** with protection enabled.
5. Record what Defender, Sysmon, and network captures actually show—without assuming a detection or bypass outcome.

## Architecture

~~~mermaid
flowchart LR
    A["Authorized researcher"] --> B["Controller / C2 concept"]
    B <--> C["Isolated lab network"]
    C <--> D["Windows test VM"]
    D --> E["Defender & Windows Event Logs"]
    D --> F["Sysmon"]
    C --> G["Wireshark capture"]
    E --> H["Evidence & findings"]
    F --> H
    G --> H
~~~

A RAT client (agent) typically communicates with a controller. The operator issues commands and receives responses. The exact transport, authentication, permissions, and available functions depend on the specific implementation and version. **A network connection alone is not proof of malware.**

## Original workflow — technical explanation and defensive implications

The following retains the **same subject areas** as the original notes while separating legitimate lab research from operational deployment.

| Phase discussed in the original notes | Technical meaning | What a defender can investigate |
|---|---|---|
| **1. Quasar release and client creation** | The software has controller and client/agent components; a client is a program that runs on a managed endpoint. | File provenance, signatures, executable metadata, process creation, hashes, and endpoint inventory. |
| **2. TCP tunneling / remote reachability** | A tunnel can forward connections across network boundaries; it does not itself ensure that a client will connect or remain undetected. | Destination addresses, DNS, network flows, unusual relay services, connection frequency, and policy compliance. |
| **3. Startup execution / persistence** | Some software may register to start after login or reboot. This is a behavior to classify, not automatically a malicious event. | Startup folders, Run keys, scheduled tasks, service creation, and associated changes. |
| **4. File name, icon, and metadata changes** | **Masquerading** can make executable metadata misleading; changing a name or icon is not a security bypass. | Signer identity, file origin, hashes, paths, internal metadata, and inconsistencies with trusted software. |
| **5. Packers, crypters, and obfuscation** | Transformation can alter static file characteristics but cannot establish that runtime behavior is invisible. | Reputation, packed-file characteristics, memory behavior, alerts, and post-execution artifacts. |
| **6. Hosting and transfer of binaries** | Distribution creates new delivery and exposure risks. | Download provenance, browser/endpoint alerts, file creation, and security-policy compliance. |

**Important:** This repository does not provide step-by-step instructions for forwarding Quasar through public tunnels, creating covert persistent agents, impersonating trusted applications, deploying crypters, or sharing weaponized executables. Those are discussed as **behaviors for analysis and detection**.

## Safe, reproducible laboratory methodology

### 1. Prepare the environment

Use equipment you own or are explicitly authorized to test:

- A Windows 10 or Windows 11 **virtual machine**, with a clean snapshot.
- An isolated **host-only or internal virtual network**. Do not expose the exercise to the public internet, campus networks, or third-party systems.
- Microsoft Defender enabled on supported Windows versions.
- Optional Sysmon logging and a Wireshark capture on the relevant virtual interface.
- A benign reference application that makes a normal connection and a separate benign application that demonstrates ordinary Windows process creation.

**Windows 7 note:** Windows 7 is out of support. It can be studied as a legacy environment but should not be treated as representative of modern endpoint protection.

### 2. Record the baseline

In PowerShell on a supported Windows VM:

~~~powershell
Get-ComputerInfo | Select-Object WindowsProductName, OsBuildNumber

Get-MpComputerStatus |
    Select-Object AMServiceEnabled, AntivirusEnabled,
                  RealTimeProtectionEnabled, BehaviorMonitorEnabled,
                  AntivirusSignatureVersion
~~~

Save the timestamp, OS build, security configuration, and snapshot identifier before each test. Avoid disabling security controls merely to make a result look successful.

### 3. Observe benign behavior first

For the initial exercise, capture **legitimate application traffic and process execution**. Establish what ordinary outbound TCP sessions, process trees, and expected startup behavior look like before analyzing suspicious cases.

For RAT-specific findings, analyze **published packet captures, documented incidents, or authorized forensic artifacts**. Never upload real credentials, private packet captures, or malware samples to a public repository.

### 4. Collect evidence

Possible data sources:

| Source | Evidence to collect | Limitation |
|---|---|---|
| Windows Defender Operational log | Detections and protective actions (e.g., 1116 and 1117 when present) | Not a general-purpose log of all Windows APIs |
| Sysmon Event ID 1 | Process creation, parent/child context, image and command line when configured | Does not directly record every callback or API invocation |
| Sysmon Event ID 3 | Network connection metadata when enabled and configured | May be disabled or filtered; does not reveal full payload content |
| Sysmon Events 12–14 | Registry object/value creation and modification when configured | A registry modification is not automatically malicious |
| Wireshark | DNS, TCP endpoints, connection patterns, protocol details | Encrypted application payloads may not be inspectable |
| Autoruns / Windows configuration | Persistence-related entries | Requires interpretation and correlation |

Example: query recent Defender detections on a supported system.

~~~powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Windows Defender/Operational'
    Id = 1116, 1117
    StartTime = (Get-Date).AddHours(-24)
} | Select-Object TimeCreated, Id, Message
~~~

If Sysmon is installed:

~~~powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1, 3
    StartTime = (Get-Date).AddHours(-24)
} | Select-Object TimeCreated, Id, Message
~~~

An empty result **does not demonstrate antivirus evasion**. It may reflect configuration, retention, missing telemetry, or a different detection surface.

### 5. Evaluate and report

Every experiment should document:

| Field | Example of what to record |
|---|---|
| Hypothesis | Which behavior or indicator is being examined? |
| Setup | VM, OS build, Defender engine/signature, Sysmon config |
| Action | Benign activity or forensic dataset analyzed |
| Evidence | Event IDs, timestamps, process GUIDs, packet numbers, screenshots |
| Observations | What was recorded, blocked, or not visible? |
| Limitations | Gaps, false positives, unavailable sensors |
| Conclusion | Supported finding—not a generalized claim of bypass |

## MITRE ATT&CK mapping — hypotheses, not confirmed observations

| Technique | ID | When it would apply |
|---|---|---|
| Proxy | [T1090](https://attack.mitre.org/techniques/T1090/) | If a proxy/relay is actually used in a documented case |
| Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | If this persistence mechanism is actually observed |
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | If software deliberately presents itself as something else |
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | If obfuscation is supported by the evidence |
| Command and Scripting Interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) | If the agent launches or uses a command interpreter |

A custom TCP channel does **not** automatically prove use of ATT&CK T1071; the observed protocol must support the mapping.

## Security conclusions

- **Execution ≠ non-detection.** A program can run and still trigger security telemetry or alerts.
- **Encryption ≠ invisibility.** Static obfuscation is not equivalent to behavioral evasion.
- **TCP tunnel ≠ trusted traffic.** Relayed traffic remains subject to monitoring and service policies.
- **A hidden window ≠ hidden process.** Parent/child processes and other artifacts can remain visible.
- **No alert ≠ a successful bypass.** A negative finding requires a defined sensor scope and evidence.

## Planned work and evidence status

- [x] Outline the Quasar architecture and original technique categories.
- [x] Define an isolated Windows research methodology.
- [x] Provide basic Defender and Sysmon log-query examples.
- [ ] Add an anonymized Windows process-tree screenshot from a benign lab.
- [ ] Add a packet capture from an authorized or publicly released forensic dataset.
- [ ] Publish an evidence-backed detection timeline.
- [ ] Add and validate a Sigma or Splunk hunting rule.
- [ ] Publish a short technical report with limitations and reproducible findings.

**Transparency:** This repository currently contains methodology and conceptual analysis. The unchecked items are not completed experiments.

## Responsible use

This project is for **education, authorized adversary emulation, incident response, and defensive research**. It does not contain Quasar client binaries, credential theft components, antivirus bypasses, instructions for covert RAT distribution, or third-party access methods.

## References

- [Quasar source and releases](https://github.com/quasar/Quasar)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Microsoft Defender for Endpoint documentation](https://learn.microsoft.com/en-us/defender-endpoint/)
- [Sysmon — Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)

---

**Maintainer:** [gaddah-yousef](https://github.com/gaddah-yousef)  
**Scope:** Windows malware behavior analysis, Red Team tradecraft research, and Blue Team detection.
