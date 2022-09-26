# Microsoft Windows Hardening - Easy

1. [Understanding General Concepts](#understanding-general-concepts)
2. [Identity & Access Management](#identity--access-management)
3. [Network Management](#network-management)
4. [Application Management](#application-management)
5. [Storage Management](#storage-management)
6. [Updating Windows](#updating-windows)

## Understanding General Concepts

* Windows Services - create and manage critical functions; runs in background.

* Windows Registry - container database that stores config seetings, essential keys and shared preferences.

* Event Viewer - shows log details about events in computer.

* Telemetry - data collection system for identifying security and functional issues in software.

```markdown
1. What is the startup type of App Readiness service in the services panel? - Manual

2. Open Registry Editor and find the key “tryhackme”. What is the default value of the key? - {THM_REG_FLAG}

3. Open the Diagnosis folder and go through the various log files. Can you find the flag? - {THM_1000710}
```

## Identity & Access Management

* Types of accounts:

  * Admin account
  * Standard account

* UAC (User Account Control) - feature that enforces enhanced access control; ensures all services and apps execute in non-admin accounts in order to mitigate malware impact and minimise privesc by bypassing UAC.

* Group Policy Editor - built-in tool that allows to configure and implement local and group policies.

```markdown
1. Find the name of the Administrator Account of the attached VM. - Harden

2. Go to the User Account Control Setting Panel. What is the default level of Notification? - Always Notify

3. How many standard accounts are created in the VM? - 0
```

## Network Management

* Windows Defender Firewall - built-in app that offers protection from malicious attacks and blocks unauthorised traffic through inbound & outbound rules/filters.

* Network hardening:

  * Disable unused networking devices
  * Disable SMB protocol
  * Protect local DNS
  * Mitigate ARP attack
  * Prevent remote access to machine

```markdown
1. Open Windows Firewall and click on Monitoring in the left pane - which of the following profiles is active? Domain, Private, Public? - Private

2. Find the IP address resolved for the website tryhack.me in the Virtual Machine as per the local hosts file. - 192.168.1.140

3. Open the command prompt and enter arp -a. What is the Physical address for the IP address 255.255.255.255? - ff-ff-ff-ff-ff-ff
```

## Application Management

* Safe app installation via Microsoft Store

* Malware removal through Windows Defender Anti Virus

* Hardening of Microsoft Office

* Applocker to block executables, scripts and installers

* Protecting browser through Microsoft Smart Screen

```markdown
1. Windows Defender Antivirus is configured to exclude a particular extension from scanning. What is the extension? - .ps

2. A Word document is received from an unknown email address. It is best practice to open it immediately on your personal computer. - nay

3. What is the flag you received after executing the Office Hardening Batch file? - {THM_1101110}
```

## Storage Management

* Data encryption via BitLocker

* Windows Sandbox to run apps safely

* Secure Boot to check system is running on trusted hardware and firmware before booting up

* Enable file backups

```markdown
1. A security engineer has misconfigured the attached VM and stored a BitLocker recovery key in the same computer. Can you read the last six digits of the recovery key? - 377564

2. How many characters does the BitLocker recovery key have in the attached VM? - 48

3. A backup file is placed on the Desktop of the attached VM. What is the extension of that file? - .bkf
```

## Updating Windows

* Windows Updates ensure all urgent security updates are installed immediately without causing delay.

```markdown
1. What is the CVE score for the vulnerability CVE ID CVE-2022-32230? - 7.8
```
