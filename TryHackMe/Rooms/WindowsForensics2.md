# Windows Forensics 2 - Medium

1. [The FAT file systems](#the-fat-file-systems)
2. [The NTFS file system](#the-ntfs-file-system)
3. [Recovering deleted files](#recovering-deleted-files)
4. [Evidence of Execution](#evidence-of-execution)
5. [File/folder knowledge](#filefolder-knowledge)
6. [External devices/USB device forensics](#external-devicesusb-device-forensics)

## The FAT file systems

* FAT (File Allocation Table) creates a table that indexes the location of bits that are allocated to different files.

* It supports three data structures - clusters (basic unit), directory (file info) and file allocation table (linked list of clusters).

* Different variations of FAT file system include FAT12, FAT16 and FAT32.

* exFAT file system is used for SD cards larger than 32GB, as an alternative to NTFS file system.

```markdown
1. How many addressable bits are there in the FAT32 file system? - 28 bits

2. What is the maximum file size supported by the FAT32 file system? - 4GB

3. Which file system is used by digital cameras and SD cards? - exFAT
```

## The NTFS file system

* Some features of NTFS (New Technology File System) include journaling, access controls, volume shadow copy (system restore) and alternate data streams.

* NTFS uses MFT (Master File Table) as a structured database that tracks the objects stored in a volume. Some critical files include:

  * $MFT - first record in volume; contains directory of all files present on volume.

  * $LOGFILE - stores transactional logging of file system to maintain integrity.

  * $UsnJrnl - Update Sequence Number Journal, in $Extend record; also called change journal.

```shell
#in elevated CMD, we can use CLI version of MFT explorer tool
cd C:\Users\THM-4n6\Desktop\EZtools

MFTECmd.exe
#shows options

MFTECmd.exe -f C:\Users\THM-4n6\Desktop\triage\C\$MFT --csv C:\Users\THM-4n6\Desktop
#this creates a csv file for MFT analysis
#we can go through that csv using EZViewer tool

MFTECmd.exe -f C:\Users\THM-4n6\Desktop\triage\C\$Boot --csv C:\Users\THM-4n6\Desktop
#parsing through $Boot to get info about boot sector of volume
```

```markdown
1.  Parse the $MFT file placed in C:\users\THM-4n6\Desktop\triage\C\ and analyze it. What is the Size of the file located at .\Windows\Security\logs\SceSetupLog.etl? - 49152

2. What is the size of the cluster for the volume from which this triage was taken? - 4096
```

## Recovering deleted files

* Disk image file - file containing bit-by-bit copy of a disk drive.

* Autopsy tool can be used for recovering deleted files from a disk.

```markdown
1. There is another xlsx file that was deleted. What is the full name of that file? - TryHackme.xlsx

2. What is the name of the TXT file that was deleted from the disk? - TryHackMe2.txt

3. What was written in this TXT file? - THM-4n6-2-4
```

## Evidence of Execution

* Prefetch Parser (PECmd.exe) tool can be used for parsing Prefetch files (.pf) and extracting data.

* Similarly, WxTCmd.exe tool can be used for parsing Windows 10 timeline to get an idea about recently used apps and files.

* JLECmd.exe can be used to parse Windows Jump Lists.

```shell
cd C:\Users\THM-4n6\Desktop\EZtools

PECmd.exe

PECmd.exe -d C:\Users\THM-4n6\Desktop\triage\C\Windows\prefetch --csv C:\Users\THM-4n6\Desktop
#analyzes the prefetch files and stores results in csv file

WxTCmd.exe -f C:\Users\THM-4n6\Desktop\triage\C\Users\THM-4n6\AppData\Local\ConnectedDevicesPlatform\L.THM-4n6\ActivitiesCache.db --csv C:\Users\THM-4n6\Desktop

JLECmd.exe -d C:\Users\THM-4n6\Desktop\triage\C\Users\THM-4n6\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations --csv C:\Users\THM-4n6\Desktop
```

```markdown
1. How many times was gkape.exe executed? - 2

2. What is the last execution time of gkape.exe? - 12/01/2021 13:04

3. When Notepad.exe was opened on 11/30/2021 at 10:56, how long did it remain in focus? - 00:00:41

4. What program was used to open C:\Users\THM-4n6\Desktop\KAPE\KAPE\ChangeLog.txt? - Notepad.exe
```

## File/folder knowledge

* LECmd.exe (Lnk Explorer) can be used to parse Shortcut files.

* The 'Recent Activity' in the Autopsy tool can be used to analyze IE/Edge history of the system, which also includes system files.

```shell
cd C:\Users\THM-4n6\Desktop\EZtools

LECmd.exe -d ..\triage\C\Users\THM-4n6\AppData\Roaming\Microsoft\Windows\Recent --csv ..\
#this does not include any useful data so we have to consider other options

JLECmd.exe -d ..\triage\C\Users\THM-4n6\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations --csv ..\
#checking Jump Lists
```

```markdown
1. When was the folder C:\Users\THM-4n6\Desktop\regripper last opened? - 12/1/2021 13:01

2. When was the above-mentioned folder first opened? - 12/1/2021 12:31
```

## External devices/USB device forensics

* When any new device is attached to system, the device info is stored in a log file at ```C:\Windows\inf\setupapi.dev.log```.

* Similarly, Shortcut files can also provide info about connected USB devices.

```markdown
1. Which artifact will tell us the first and last connection times of a removable drive? - setupapi.dev.log
```
