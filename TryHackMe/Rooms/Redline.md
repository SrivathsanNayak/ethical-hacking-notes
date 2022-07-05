# Redline - Medium

1. [Introduction](#introduction)
2. [Data Collection](#data-collection)
3. [The Redline Interface](#the-redline-interface)
4. [Standard Collector Analysis](#standard-collector-analysis)
5. [IOC Search Collector](#ioc-search-collector)
6. [IOC Search Collector Analysis](#ioc-search-collector-analysis)
7. [Endpoint Investigation](#endpoint-investigation)

## Introduction

* Redline tool can be used to analyze a potentially compromised endpoint through the memory dump.

```markdown
1. Who created Redline? - FireEye
```

## Data Collection

* Data collection using Redline can be done in 3 ways:

  * Standard Collector - configures the script to gather a minimum amount of data for the analysis.

  * Comprehensive Collector - configures the script to gather the most data from your host for further analysis.

  * IOC Search Collector (Windows only) - collects data that matches with the Indicators of Compromise (IOCs) created with the help of IOC Editor.

```markdown
1. What data collection method takes the least amount of time? - Standard Collector

2. What method would you choose to run a granular data collection against the known indicators? - IOC Search Collector

3. What script would you run to initiate the data collection process? - RunRedlineAudit.bat

4. If you want to collect the data on Disks and Volumes, under which option can you find it? - Disk Enumeration

5. What cache does Windows use to maintain a preference for recently executed code? - Prefetch
```

## The Redline Interface

* The types of data analysis can be found in the [Redline User Guide](https://www.fireeye.com/content/dam/fireeye-www/services/freeware/ug-redline.pdf).

```markdown
1. Where in the Redline UI can you view information about the Logged in User? - System Information
```

## Standard Collector Analysis

```markdown
1. Provide the Operating System detected for the workstation. - Windows Server 2019 Standard 17763

2. Provide the BIOS Version for the workstation. - Xen 4.2.amazon

3. What is the suspicious scheduled task that got created on the victim's computer? - MSOfficeUpdateFa.ke

4. Find the message that the intruder left for you in the task. - THM-p3R5IStENCe-m3Chani$m

5. There is a new System Event ID created by an intruder with the source name "THM-Redline-User" and the Type "ERROR". Find the Event ID #. - 546

6. Provide the message for the Event ID. - Someone cracked my password. Now I need to rename my puppy-++-

7. It looks like the intruder downloaded a file containing the flag for Question 8. Provide the full URL of the website. - https://wormhole.app/download-stream/gI9vQtChjyYAmZ8Ody0AuA

8. Provide the full path to where the file was downloaded to including the filename. - C:\Program Files (x86)\Windows Mail\SomeMailFolder\flag.txt

9. Provide the message the intruder left for you in the file. - THM{600D-C@7cH-My-FR1EnD}
```

## IOC Search Collector

```markdown
1. What is the actual filename of the Keylogger? - psylog.exe

2. What filename is the file masquerading as? - THM1768.exe

3. Who is the owner of the file? - WIN-2DET5DP0NPT\charles

4. What is the file size in bytes? - 35400

5. Provide the full path of where the .ioc file was placed after the Redline analysis. - C:\Users\charles\Desktop\Keylogger-IOCSearch\IOCs\keylogger.ioc
```

## IOC Search Collector Analysis

```markdown
1. Provide the path of the file that matched all the artifacts along with the filename. - C:\Users\Administrator\AppData\Local\Temp\8eJv8w2id6IqN85dfC.exe

2. Provide the path where the file is located without including the filename. - C:\Users\Administrator\AppData\Local\Temp\

3. Who is the owner of the file? - BUILTIN\Administrators

4. Provide the subsystem for the file. - Windows_CUI

5. Provide the Device Path where the file is located. - \Device\HarddiskVolume2

6. Provide the hash (SHA-256) for the file. - 57492d33b7c0755bb411b22d2dfdfdf088cbbfcd010e30dd8d425d5fe66adff4

7. The attacker managed to masquerade the real filename. Can you find it having the hash in your arsenal? - PsExec.exe
```

## Endpoint Investigation

```markdown
1. Can you identify the product name of the machine? - Windows 7 Home Basic

2. Can you find the name of the note left on the Desktop for the "Charles"? - _R_E_A_D___T_H_I_S___AJYG1O_.txt

3. Find the Windows Defender service; what is the name of its service DLL? - MpSvc.dll

4. The user manually downloaded a zip file from the web. Can you find the filename? - eb5489216d4361f9e3650e6a6332f7ee21b0bc9f3f3a4018c69733949be1d481.zip

5. Provide the filename of the malicious executable that got dropped on the user's Desktop. - Endermanch@Cerber5.exe

6. Provide the MD5 hash for the dropped malicious executable. - fe1bc60a95b2c2d77cd5d232296a7fa4

7. What is the name of the ransomware? - Cerber
```
