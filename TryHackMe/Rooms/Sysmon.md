# Sysmon - Easy

1. [Introduction](#introduction)
2. [Cutting out the Noise](#cutting-out-the-noise)
3. [Hunting Metasploit](#hunting-metasploit)
4. [Detecting Mimikatz](#detecting-mimikatz)
5. [Hunting Malware](#hunting-malware)
6. [Hunting Persistence](#hunting-persistence)
7. [Detecting Evasion Techniques](#detecting-evasion-techniques)
8. [Practical Investigations](#practical-investigations)

## Introduction

* ```Sysmon``` is a tool used to monitor and log events on Windows; Sysmon events stored in ```Applications and Services Logs/Microsoft/Windows/Sysmon/Operational```.

* Sysmon uses Event IDs for its config file, to analyze events.

```shell
xfreerdp /u:THM-Analyst /p:5TgcYzF84tcBSuL1Boa%dzcvf /v:10.10.181.158
#connect to machine
```

## Cutting out the Noise

* Sysmon usage is improved by best practices such as prioritizing excluding events rather than including events, using the CLI and understanding the environment.

* Events can be filtered using the Event Viewer or PowerShell.

```ps
Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Metasploit.evtx -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'
#to look for network connections coming from port 4444

Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Filtering.evtx -FilterXPath '*/System/EventID=3' | Measure-Object -Line
#to find number of event ID 3 events
```

```markdown
1. How many event ID 3 events are in C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Filtering.evtx? - 73,591

2. What is the UTC time created of the first network event in C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Filtering.evtx? - 2021-01-06 01:35:50.464
```

## Hunting Metasploit

* We can look for network connections that originate from suspicious ports such as 4444 and 5555.

```ps
Get-WinEvent -path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Metasploit.evtx -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'
```

## Detecting Mimikatz

* Mimikatz can be detected by looking for file creation with the name Mimikatz.

* We can also hunt for abnormal LSASS behaviour to detect Mimikatz.

```ps
Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Mimikatz.evtx -FilterXPath '*/System/EventID=10 and */EventData/Data[@Name="TargetImage"] and */EventData/Data="C:\Windows\system32\lsass.exe"'
```

## Hunting Malware

* Hunting for common back connect ports to detect RATs:

```ps
Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Rats.evtx -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=8080'
```

## Hunting Persistence

* Persistence is used by attackers to maintain access to a machine once it's compromised.

* Some ways used to gain persistence are registry modification and startup scripts.

## Detecting Evasion Techniques

* Examples of evasion techniques are Alternate Data Streams, Injections, Masquerading, Packing/Compression, Recompiling, Obfuscation, Anti-Reversing.

* Detecting Alternate Data Streams:

```ps
Get-WinEvent -Path C:\Users\Administrator\Desktop\Sysmon.evtx -FilterXPath '*/System/EventID=15'
```

* Detecting Remote Thread Creation:

```ps
Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_CreateRemoteThread.evtx -FilterXPath '*/System/EventID=8'
```

## Practical Investigations

```markdown
1. What is the full registry key of the USB device calling svchost.exe in Investigation 1? - HKLM\System\CurrentControlSet\Enum\WpdBusEnumRoot\UMB\2&37c186b&0&STORAGE#VOLUME#_??_USBSTOR#DISK&VEN_SANDISK&PROD_U3_CRUZER_MICRO&REV_8.01#4054910EF19005B3&0#\FriendlyName

2. What is the device name when being called by RawAccessRead in Investigation 1? - \Device\Harddisk\Volume3

3. What is the first exe the process executes in Investigation 1? - rundll32.exe

4. What is the full path of the payload in Investigation 2? - "C:\Users\IEUser\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\S97WTYG7\update.hta

5. What is the full path of the file the payload masked itself as in Investigation 2? - C:\Users\IEUser\Downloads\update.html

6. What signed binary executed the payload in Investigation 2? - C:\Windows\System32\mshta.exe

7. What is the IP of the adversary in Investigation 2? - 10.0.2.18

8. What back connect port is used in Investigation 2? - 4443

9. What is the IP of the suspected adversary in Investigation 3.1? - 172.30.1.253

10. What is the hostname of the affected endpoint in Investigation 3.1? - DESKTOP-O153T4R

11. What is the hostname of the C2 server connecting to the endpoint in Investigation 3.1? - empirec2

12. Where in the registry was the payload stored in Investigation 3.1? - HKLM\SOFTWARE\Microsoft\Network\debug

13. What PowerShell launch code was used to launch the payload in Investigation 3.1? - "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$x=$((gp HKLM:Software\Microsoft\Network debug).debug);start -Win Hidden -A \"-enc $x\" powershell";exit;

14. What is the IP of the adversary in Investigation 3.2? - 172.168.103.188

15. What is the full path of the payload location in Investigation 3.2? - C:\Users\q\AppData:blah.txt

16. What was the full command used to create the scheduled task in Investigation 3.2? -  "C:\WINDOWS\system32\schtasks.exe" /Create /F /SC DAILY /ST 09:00 /TN Updater /TR "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String($(cmd /c ''more < c:\users\q\AppData:blah.txt'''))))\""

17. What process was accessed by schtasks.exe that would be considered suspicious behaviour in Investigation 3.2? - lsass.exe

18. What is the IP of the adversary in Investigation 4? - 172.30.1.253

19. What port is the adversary operating on in Investigation 4? - 80

20. What C2 is the adversary utilizing in Investigation 4? - empire
```
