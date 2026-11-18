THREAT HUNTING FINDINGS

Author: Wamba José

Lab: Threat Hunting with MITRE ATT&CK, Splunk, Sigma and Atomic Red Team

HUNT 1: T1087.001 LOCAL ACCOUNT DISCOVERY

Tactic: Discovery (TA0007)

Emulation: Atomic Red Team test "Enumerate all accounts on Windows (Local)"

What I found in the Sysmon logs (EventCode 1, process creation):

whoami.exe was launched by powershell.exe.

The commands net user, net localgroup and cmdkey /list were launched by cmd.exe.

All of them ran under the account WIN10-LAB\wamba within a few seconds.

Detection logic: three or more different discovery commands (net, whoami, cmdkey) within five minutes.

Sigma rule: sigma-rules\T1087.001_local_account_discovery.yml

Splunk alert: "T1087.001 - Local Account Discovery", runs every hour, severity Medium.

HUNT 2: T1136.001 CREATE LOCAL ACCOUNT

Tactic: Persistence (TA0003)

Emulation: Atomic Red Team test "Create a new user in a command prompt"

Process chain seen in Sysmon:

cmd.exe ran: net user /add "T1136.001_CMD" "T1136.001_CMD!"

net.exe then ran: net1 user /add "T1136.001_CMD" "T1136.001_CMD!"

Matching Windows Security events:

2026-11-17 03:11:30.905 UTC, Event 4720: the account T1136.001_CMD was created by wamba.

2026-11-17 03:11:30.977 UTC, Event 4732: the account was added to the Users group by wamba.

What this tells us:

The net.exe to net1.exe chain confirms the account was created from the command line.

The backdoor password is visible in clear text in the command line.

The Security event 4720 happens in the same second as the Sysmon event, which confirms the attack from two independent log sources.

Benign finding:

On 2026-11-16, Event 4732 showed an account added to the "Event Log Readers" group.

This was legitimate admin work: giving the Splunk forwarder permission to read event logs.

I investigated it and closed it as benign.

Sigma rule: sigma-rules\T1136.001_create_local_account.yml

Splunk alert: "T1136.001 - Local Account Created", runs every hour, severity High.

