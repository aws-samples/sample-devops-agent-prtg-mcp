# Network ports

Every port this integration can need, and which enforcement layer has to allow it.

Two things account for most of the time lost here. The first is that **there are two
independent firewalls** on any AWS-hosted monitored host - the security group and the
guest OS firewall - and opening one does not open the other. A rule present in the
security group and absent from the Windows firewall fails exactly like no rule at all.
The second is that **WMI does not use a single port**. It negotiates on 135 and then
moves to a dynamically assigned high port, so a rule for 135 alone gets you a
successful logon followed by a connection failure.

Traffic direction matters too. WMI and SNMP are **pull** protocols: PRTG opens the
connection to the monitored host, which never initiates anything. So on a monitored
host everything below is an **inbound** rule. Only the alarm notification and remote
probe traffic flow outward from PRTG.

---

## By flow

### PRTG core → monitored Windows host (WMI)

The flow this integration depends on for Windows sensors.

| Port | Proto | Purpose | Security group | OS firewall |
|---|---|---|---|---|
| 135 | TCP | RPC endpoint mapper - DCOM stage 1 | Required | Required |
| 49152–65535 | TCP | RPC dynamic range - DCOM stage 2 | Required | Required, unless using service-scoped rules (below) |
| 445 | TCP | SMB - Remote Registry over named pipe | Required for performance-counter sensors | Required for performance-counter sensors |
| 5985 | TCP | WinRM HTTP, if the probe uses the WSMan transport | Optional | Optional |
| 5986 | TCP | WinRM HTTPS, same | Optional | Optional |
| echo request | ICMP | Ping sensors | Required for Ping sensors | Required for Ping sensors |

`49152-65535` is the Windows Server 2008-and-later default. Confirm rather than assume:

```powershell
netsh int ipv4 show dynamicport tcp
```

Some PRTG sensors read Windows performance counters instead of WMI and need the
**Remote Registry** service running on the target, which is reached over 445. It ships
`Automatic` but is frequently found stopped. Paessler documents this per-sensor - see
the [Windows Network Card sensor](https://www.paessler.com/manuals/prtg/wmi_network_card_sensor)
notes.

### PRTG core → monitored host (SNMP)

| Port | Proto | Purpose | Notes |
|---|---|---|---|
| 161 | **UDP** | SNMP get | Not TCP. A `tcp/161` rule allows nothing useful. |
| 162 | **UDP** | SNMP traps - **inbound to PRTG**, not to the target | Only if you use SNMP Trap Receiver sensors |

### Agent → PRTG (the MCP half)

| Port | Proto | Purpose | Where |
|---|---|---|---|
| 443 | TCP | PRTG web server and API | Egress on the Lambda SG, ingress on the PRTG SG |

The integration refuses plain `http://`, so 80 is deliberately not in this table. If
your PRTG runs on a fallback port - Paessler lists 8443, 8444+ and 8080+ - use that
instead of 443 and set it in `prtg_url`.

### PRTG → AWS (the alarm half)

| Port | Proto | Purpose |
|---|---|---|
| 443 | TCP | Outbound HTTPS from PRTG to API Gateway |

Outbound from PRTG, so usually already permitted. Needs SNI enabled - see
[`prtg-setup.md`](prtg-setup.md#the-four-quirks).

### PRTG remote probe → PRTG core

| Port | Proto | Purpose |
|---|---|---|
| 23560 | TCP | Remote probe to core server. Inbound on the **core**. Configurable. |

---

## The RPC dynamic port trap

This is worth its own section because it produces a distinct, misleading error.

DCOM connects in two stages. Stage one reaches the endpoint mapper on 135; stage two
is redirected to a port the OS assigns from the dynamic range. Open 135 only, and:

- authentication **succeeds** - the target logs a successful `4624` network logon
- the WMI connection then **fails** with `800706BA The RPC server is unavailable`

A successful logon alongside a failing sensor is the signature of this, and it is easy
to misread as a credential problem because the sensor is still down.

Do not narrow the range in the firewall without also narrowing it in the OS. A rule for
`10000-10099` is only correct if the RPC dynamic range has been pinned to those ports
via `HKLM\SOFTWARE\Microsoft\Rpc\Internet`. Without that key the OS still allocates from
`49152-65535` and every connection is dropped.

### Recommended: service-scoped rules

Windows ships firewall rules for this. They are scoped to the `winmgmt` and `rpcss`
services rather than to a port, so the dynamic port is handled however Windows assigns
it - and you avoid opening 16,000 ports.

```powershell
# Scope to the PRTG server first: the built-ins default to any remote address
Get-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" |
    Set-NetFirewallRule -RemoteAddress <prtg-server-ip>

Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)"
```

No reboot. The group covers `WMI-In` (`winmgmt`), `DCOM-In` (`rpcss`, port 135) and
`ASync-In`. The security group still needs `49152-65535`, because a security group
cannot match on a process.

### Alternative: pin the RPC range

Only if policy requires a narrow range. Requires a reboot, and constrains RPC for every
service on the host, not just WMI.

```powershell
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Rpc\Internet" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Rpc\Internet" -Name Ports -Value @("10000-10099") -Type MultiString
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Rpc\Internet" -Name PortsInternetAvailable -Value "Y"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Rpc\Internet" -Name UseInternetPorts -Value "Y"
# reboot, then verify with: netsh int ipv4 show dynamicport tcp
```

Then a `10000-10099` firewall rule is correct, and the security group can be narrowed
to match.

---

## Ports are necessary, not sufficient

Open ports get the connection there; they do not get it authenticated. Two host-level
settings decide that, and both fail in ways that look like a network problem.

**"Domain or Computer Name" must not be empty.** In PRTG's *Credentials for Windows
Systems*, a blank domain field makes the DCOM client fail locally with
`0x80070005 Access is denied` **without sending a packet** - so the target logs no
authentication attempt at all, neither success nor failure. For a host that is not
domain-joined, use the target's computer name. Paessler's
[KB 203](https://kb.paessler.com/knowledgebase/en/topic/203-how-can-i-monitor-wmi-sensors-if-the-target-machine-is-not-part-of-a-domain)
covers this case.

Watch inheritance while you are there. Credentials resolve up the tree, and a probe or
group with its own override shadows anything set above it - so credentials saved on
Root can be silently unused. Setting them directly on the device removes the ambiguity.

**`LocalAccountTokenFilterPolicy`** must be `1` if you monitor with a local account
that is *not* the built-in Administrator. Other local admins receive a filtered token
over the network and WMI returns `0x80070005`. The built-in Administrator is exempt
while `FilterAdministratorToken` is `0`, its default.

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord
```

For a fleet of workgroup hosts, create one local monitoring account with the same
username and password everywhere, set this policy on each, and configure the credential
once at group level.

---

## Verifying

From the PRTG server, which tests the security group and the OS firewall together:

```powershell
Test-NetConnection -ComputerName <target> -Port 135          # must be OPEN
Test-NetConnection -ComputerName <target> -InformationLevel Quiet   # ICMP
```

135 open but the sensor failing means the dynamic range, not the endpoint mapper.

On the target, confirm what is actually permitted rather than what you intended:

```powershell
netsh int ipv4 show dynamicport tcp
Get-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" |
    Select-Object DisplayName, Enabled
Get-Service Winmgmt, RemoteRegistry | Select-Object Name, Status, StartType
```

PRTG's own view of the failure, which names the stage:

```
C:\ProgramData\Paessler\PRTG Network Monitor\Logs\probe\ProbeWMI.log
```

| Error | Stage | Usual cause |
|---|---|---|
| `80070005 Access is denied` **with no logon event on the target** | Before the network | Empty "Domain or Computer Name" |
| `80070005 Access is denied` **with a `4625` on the target** | Authentication | Wrong password, or token filtering |
| `800706BA The RPC server is unavailable` **with a `4624`** | After authentication | Dynamic port range blocked |

The target's Security log distinguishes these. `4624` is a successful network logon,
`4625` a failed one with a status code:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625; StartTime=(Get-Date).AddMinutes(-30)} |
    Where-Object { $_.Message -match '<prtg-server-ip>' }
```

`0xc000006a` is a bad password, `0xc0000064` an account that does not exist,
`0xc0000234` a locked account.

---

## References

**Paessler**

- [Default Ports](https://www.paessler.com/manuals/prtg/list_of_default_ports) - per-sensor port reference
- [Which ports does PRTG use on my system?](https://helpdesk.paessler.com/en/support/solutions/articles/76000041648-which-ports-does-prtg-use-on-my-system) - web server and probe ports
- [Monitoring via WMI](https://www.paessler.com/manuals/prtg/monitoring_via_wmi) - credentials, inheritance, performance guidance
- [Monitoring WMI when the target is not domain-joined](https://kb.paessler.com/knowledgebase/en/topic/203-how-can-i-monitor-wmi-sensors-if-the-target-machine-is-not-part-of-a-domain) - the "Domain or Computer Name" field
- [WMI errors: common codes and messages](https://www.paessler.com/help/wmi-errors) - decoding `ProbeWMI.log`
- [WMI sensors stopped working with error 80070005](https://kb.paessler.com/en/topic/42953)
- [My WMI sensors don't work. What can I do?](https://kb.paessler.com/knowledgebase/en/topic/1043-my-wmi-sensors-don-t-work-what-can-i-do)
- [Windows Network Card sensor](https://www.paessler.com/manuals/prtg/wmi_network_card_sensor) - the Remote Registry dependency
- [Using your own SSL certificate](https://www.paessler.com/manuals/prtg/using_your_own_ssl_certificate)

**Microsoft**

- [Service overview and network port requirements](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements)
- [The default dynamic port range for TCP/IP has changed](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/default-dynamic-port-range-tcpip-chang)
- [Troubleshoot WMI connectivity and access issues](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/scenario-guide-troubleshoot-wmi-connectivity-access-issues)

---

## A worked example you can deploy

Everything above is implemented in the optional demo stack, which is off unless you ask
for it:

```bash
cdk deploy -c demo_prtg=true -c demo_app_server=true '*-demo-prtg'
```

That creates a PRTG server and a Windows host for it to monitor, and configures **both**
firewall layers on the monitored host - which is the part worth reading, because it is
where the two halves have to agree.

Neither host has RDP ingress or a key pair, so **Session Manager is the only way in.** In
`network.mode: nat` the NAT gateway carries the agent's traffic and nothing extra is
needed. In `network.mode: private` there is no route at all, so the demo stack also
creates `ssm`, `ssmmessages` and `ec2messages` interface endpoints with a security group
admitting only these two hosts. All three are required - the first two carry the session,
`ec2messages` carries Run Command - and without them the instances boot, pass their status
checks, look healthy and cannot be administered at all, with nothing reporting why.

Those three belong to the demo stack rather than the derived list in
[Knob 1](deployment-matrix.md#knob-1---networkmode), because they exist for these
instances and not for the integration. A private deployment without the demo stack
does not create them, and does not pay for them. It does mean a private deployment
*with* the demo stack shows three more interface endpoints than the integration alone
needs.

Security group, every rule sourced from PRTG's own security group rather than a CIDR:

| Rule | Why |
|---|---|
| `tcp/135` | RPC endpoint mapper, DCOM stage 1 |
| `tcp/49152-65535` | RPC dynamic range, DCOM stage 2 |
| `tcp/445` | SMB, for Remote Registry and performance counters |
| `udp/161` | SNMP - UDP, not TCP |
| `icmp` echo | Ping sensors |

Host firewall, via user data, scoped to PRTG's address before being enabled:

```
WMI-WINMGMT-In-TCP    Windows Management Instrumentation (WMI-In)      service: winmgmt
WMI-RPCSS-In-TCP      Windows Management Instrumentation (DCOM-In)     service: rpcss
WMI-ASYNC-In-TCP      Windows Management Instrumentation (ASync-In)
FPS-ICMP4-ERQ-In      File and Printer Sharing (Echo Request - ICMPv4-In)
```

Addressed by `-Name` rather than `-DisplayName` so it works on a non-English Windows
installation. The security group still carries the full dynamic range even though these
rules are service-scoped, because a security group cannot match on a process.

What the stack deliberately does **not** configure is credentials - it cannot. That
remains a manual step in PRTG, and it is the one with the trap described above.

Relevant flags: `-c demo_app_server_ip=` to move the monitored host,
`-c prtg_private_ip=` to move PRTG, `-c prtg_installer_s3=` to stage the installer.

---

Ports for the AWS side of the deployment are in
[`deployment-matrix.md`](deployment-matrix.md); symptom-first diagnosis is in
[`troubleshooting.md`](troubleshooting.md).
