# Hands-on Lab 01 — Benign C2-Traffic Emulation (Windows + Kali)

**Purpose:** Reproduce one narrow behavior relevant to RAT investigations: a Windows test endpoint periodically initiating an outbound connection to a lab server. The requests do **not** provide remote command execution, persistence, hidden execution, privilege escalation, or antivirus evasion.

> **Authorization:** Use only virtual machines that you control, on a VirtualBox/VMware **Internal Network** or **Host-Only** network. Do not use a school, workplace, public, or campus LAN. Do not forward ports to the internet or use public TCP-tunneling services.

## A. Lab topology

```text
Kali VM (HTTP lab server)             Windows 10/11 VM
192.168.56.10:8080  <--- HTTP GET --- 192.168.56.20
       |                                      |
Wireshark/tcpdump                    Defender + optional Sysmon
```

IP addresses above are **examples**. Set both VMs on the same isolated virtual network, use their actual private addresses, and disable any virtual-network adapter that bridges the test to a shared LAN.

## B. Baseline: verify machines and security configuration

On Kali:

```bash
ip -br addr
```

On Windows PowerShell:

```powershell
ipconfig
Get-MpComputerStatus |
  Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, AntivirusSignatureVersion
```

Keep Defender enabled and take a VM snapshot. On Windows 7, PowerShell/Defender commands and security components may not be supported; this walkthrough targets Windows 10/11.

## C. Start the harmless HTTP server (Kali)

Use the address assigned to **Kali's isolated interface**, rather than the example address if yours is different:

```bash
mkdir -p ~/quasar-research-lab
cd ~/quasar-research-lab
printf 'Authorized benign network telemetry lab\n' > index.html
python3 -m http.server 8080 --bind 192.168.56.10
```

Stop the server with `Ctrl+C` after the experiment. Do not host this on a bridged or internet-facing interface.

## D. Run the bounded benign client (Windows)

Download or copy [`benign-heartbeat.ps1`](benign-heartbeat.ps1) into a lab folder on the Windows VM and inspect it before executing.

In PowerShell, from that directory:

```powershell
.\benign-heartbeat.ps1 -ServerUrl "http://192.168.56.10:8080/" -Count 5 -IntervalSeconds 3
```

The script deliberately sends exactly five ordinary HTTP GET requests with an explicitly labeled `lab=benign-heartbeat` query string. It has a timeout, visible console output, and no remote-command or file-transfer capability.

**Do not disable antivirus, hide the process, install persistence, or use crypters.**

## E. Network evidence

Capture on the appropriate virtual network interface. In Wireshark, start with:

```wireshark
ip.addr == 192.168.56.10 && tcp.port == 8080
```

Other useful display filters:

```wireshark
http.request && ip.dst == 192.168.56.10
tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == 8080
```

Record the *actual* packet numbers, source and destination addresses, timestamps, number of GET requests, HTTP status codes, and inter-request intervals. Do not publish identifying information from other networks.

## F. Endpoint evidence

On Windows, check the Defender configuration again and inspect events that occurred in the test window:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Windows Defender/Operational'
  Id = 1116, 1117
  StartTime = (Get-Date).AddMinutes(-30)
} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, Message
```

If Sysmon is installed **and Event ID 3 network connection logging is enabled**:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  Id = 1, 3
  StartTime = (Get-Date).AddMinutes(-30)
} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'powershell.exe|pwsh.exe|8080' } |
  Select-Object TimeCreated, Id, Message
```

Sysmon Event ID **1** is process creation; Event ID **3** is a network connection event if enabled. These do not prove malware on their own. Defender IDs **1116/1117** describe detections/actions, not all Windows activity. Missing events do not prove evasion.

## G. Expected observations vs. interpretation

| Observation | Interpretation |
|---|---|
| Five GET requests in Wireshark | You reproduced a bounded periodic network pattern |
| Request timestamps spaced about three seconds apart | Timing is expected from this benign loop; not malware proof |
| Process/network metadata in Sysmon | Endpoint telemetry is working for the configured rules |
| No Defender malware alert | Expected for a benign sample, **not** a Defender bypass |
| HTTP request fails | Check isolated IP addressing, listener binding, firewall rules, and routing; don't disable protection globally |

This exercise illustrates the **network-beaconing concept** without providing a functioning C2 framework or an implant.

## H. Document your experiment

Copy this table into your own notes and complete it with measured values:

| Measurement | Your result |
|---|---|
| Date and VM snapshot | _Not yet measured_ |
| Windows build and Defender version | _Not yet measured_ |
| Kali listener IP / port | _Not yet measured_ |
| Client IP | _Not yet measured_ |
| Captured GET count | _Not yet measured_ |
| Observed packet numbers | _Not yet measured_ |
| Sysmon events (if enabled) | _Not yet measured_ |
| Defender detection/action events | _Not yet measured_ |
| Interpretation / telemetry limits | _Not yet measured_ |

## I. Cleanup

Stop the Kali server with `Ctrl+C`. Close PowerShell, stop Wireshark, and preserve only sanitized screenshots or PCAPs from your own isolated lab. The client script makes no persistence changes, creates no service, and installs no background task.

## Scope

This lab is appropriate for understanding C2-related **network indicators**, baselining endpoint telemetry, and explaining findings in a responsible Red Team/Blue Team portfolio. It does **not** build Quasar, route Quasar through a tunnel, change executable identity, deploy a RAT, or make any software undetectable.
