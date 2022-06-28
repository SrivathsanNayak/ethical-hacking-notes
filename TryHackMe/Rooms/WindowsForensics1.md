# Windows Forensics 1 - Medium

1. [Introduction to Windows Forensics](#introduction-to-windows-forensics)
2. [Windows Registry and Forensics](#windows-registry-and-forensics)
3. [Accessing registry hives offline](#accessing-registry-hives-offline)
4. [System Information and System Accounts](#system-information-and-system-accounts)
5. [Usage or knowledge of files/folders](#usage-or-knowledge-of-filesfolders)
6. [Evidence of Execution](#evidence-of-execution)
7. [External Devices/USB device forensics](#external-devicesusb-device-forensics)
8. [Hands-on Challenge](#hands-on-challenge)

## Introduction to Windows Forensics

```markdown
1. What is the most used Desktop Operating System right now? - Microsoft Windows
```

## Windows Registry and Forensics

* Windows Registry - collection of databases that contains system's config data.

* Registry Hive - group of keys, subkeys and values stored in a single file on the disk.

* Windows Registry has the following root keys structure:

  * HKEY_CURRENT_USER
  * HKEY_USERS
  * HKEY_LOCAL_MACHINE
  * HKEY_CLASSES_ROOT
  * HKEY_CURRENT_CONFIG

```markdown
1. What is the short form for HKEY_LOCAL_MACHINE? - HKLM
```

## Accessing registry hives offline

* In case of registry hives in a disk image, they are mostly located in ```C:\Windows\System32\Config``` and are:

  * DEFAULT (mounted on ```HKEY_USERS\DEFAULT```)
  * SAM (mounted on ```HKEY_LOCAL_MACHINE\SAM```)
  * SECURITY (mounted on ```HKEY_LOCAL_MACHINE\Security```)
  * SOFTWARE (mounted on ```HKEY_LOCAL_MACHINE\Software```)
  * SYSTEM (mounted on ```HKEY_LOCAL_MACHINE\System```)

* Besides these, there are hives containing user information, mostly located in ```C:\Users\<username>``` as hidden files, and are:

  * NTUSER.DAT (mounted on ```HKEY_CURRENT_USER``` when user logs in)
  * USRCLASS.DAT (mounted on ```HKEY_CURRENT_USER\Software\CLASSES```)

* Another hive is the AmCache hive, located in ```C:\Windows\AppCompat\Programs\Amcache.hve```, to store info on programs recently run.

```markdown
1. What is the path for the five main registry hives, DEFAULT, SAM, SECURITY, SOFTWARE, and SYSTEM? - C:\Windows\System32\Config

2. What is the path for the AmCache hive? - C:\Windows\AppCompat\Programs\Amcache.hve
```

## System Information and System Accounts

* OS Version - ```SOFTWARE\Microsoft\Windows NT\CurrentVersion```

* Current control set - ```SYSTEM\Select\Current```

* Last known good config - ```SYSTEM\Select\LastKnownGood```

* Computer Name - ```SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName```

* Time Zone info - ```SYSTEM\CurrentControlSet\Control\TimeZoneInformation```

* Network interfaces - ```SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces```

* Past networks - ```SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged```, ```SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed```

* Autostart Programs - ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run```, ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce```, ```SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce```, ```SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run```, ```SOFTWARE\Microsoft\Windows\CurrentVersion\Run```

* Services - ```SYSTEM\CurrentControlSet\Services```

* User info - ```SAM\Domains\Account\Users```

```markdown
1. What is the Current Build Number of the machine whose data is being investigated? - 19044

2. Which ControlSet contains the last known good configuration? - 1

3. What is the Computer Name of the computer? - THM-4N6

4. What is the value of the TimeZoneKeyName? - Pakistan Standard Time

5. What is the DHCP IP address? - 192.168.100.58

6. What is the RID of the Guest User account? - 501
```

## Usage or knowledge of files/folders

* Recent files - ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs```

* Recent PDFs - ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.pdf```

* Office recent files - ```NTUSER.DAT\Software\Microsoft\Office\VERSION```, ```NTUSER.DAT\Software\Microsoft\Office\VERSION\UserMRU\LiveID_####\FileMRU```

* ShellBags - ```USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags```, ```USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU```, ```NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU```, ```NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags```

* Open/Save and LastVisited - ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU```, ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU```

* Windows Explorer Address/Search - ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths```, ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery```

```markdown
1. When was EZtools opened? - 2021-12-01 13:00:34

2. At what time was My Computer last interacted with? - 2021-12-01 13:06:47

3. What is the Absolute Path of the file opened using notepad.exe? - C:\Program Files\Amazon\Ec2ConfigService\Settings

4. When was this file opened? - 2021-11-30 10:56:19
```

## Evidence of Execution

* UserAssist - ```NTUSER.DAT\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\{GUID}\Count```

* ShimCache (AppCompatCache) - ```SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache```

* Last executed programs (AmCache) - ```Amcache.hve\Root\File\{Volume GUID}\```

* BAM (Background Activity Monitor) - ```SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}```

* DAM (Desktop Activity Monitor) - ```SYSTEM\CurrentControlSet\Services\dam\UserSettings\{SID}```

```markdown
1. How many times was the File Explorer launched? - 26

2. What is another name for ShimCache? - AppCompatCache

3. Which of the artifacts also saves SHA1 hashes of the executed programs? - AmCache

4. Which of the artifacts saves the full path of the executed programs? - BAM/DAM
```

## External Devices/USB device forensics

* USB identification - ```SYSTEM\CurrentControlSet\Enum\USBSTOR```, ```SYSTEM\CurrentControlSet\Enum\USB```

* First/Last time - ```SYSTEM\CurrentControlSet\Enum\USBSTOR\Ven_Prod_Version\USBSerial#\Properties\{83da6326-97a6-4088-9453-a19231573b29}\####``` (the '####' part can be replaced with 0064, 0066 or 0067 for first connection, last connection and last removal time, respectively)

* USB device name - ```SOFTWARE\Microsoft\Windows Portable Devices\Devices```

```markdown
1. What is the serial number of the device from the manufacturer 'Kingston'? - 1C6F654E59A3B0C179D366AE&0

2. What is the name of this device? - Kingston Data Traveler 2.0 USB Device

3. What is the friendly name of the device from the manufacturer 'Kingston'? - USB
```

## Hands-on Challenge

```markdown
1. How many user created accounts are present on the system? - 3

2. What is the username of the account that has never been logged in? - thm-user2

3. What's the password hint for the user THM-4n6? - count

4. When was the file 'Changelog.txt' accessed? - 2021-11-24 18:18:48

5. What is the complete path from where the Python 3.8.2 installer was run? - Z:\setups\python-3.8.2.exe

6. When was the USB device with the friendly name 'USB' last connected? - 2021-11-24 18:40:06
```
