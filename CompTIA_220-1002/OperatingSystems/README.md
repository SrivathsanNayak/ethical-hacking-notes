# Operating Systems

## Overview

* OS features:

    1. File management
    2. App support
    3. Input/output support
    4. OS Management tools

* Microsoft Windows - large industry support; security exploitation.

* Apple macOS - compatible; fewer security concerns; costly; less industry support.

* Linux - free Unix-compatible system; many distributions; active community; limited driver support.

* OS versions are processor-specific (32-bit, 64-bit).

* Hardware drivers are specific to OS version (32-bit - x86, 64-bit - x64).

* Google Android - OS for mobile; open-source (based on Linux); uses Android apps.

* Apple iOS - based on Unix; closed-source; iOS apps.

* Chrome OS - Google's OS; centers around Chrome browser; relies on cloud.

* Vendor-specific limitations - EOL; updating; compatibility.

## Microsoft Windows

* Windows 7 editions - Starter, Home Basic, Home Premium, Ultimate, Professional, Enterprise.

* Windows 8/8.1 editions - Core, Pro, Enterprise.

* Windows 10 editions - Home, Pro, Education, Enterprise.

## Installing Operating Systems

* Boot methods - USB; CD/DVD-ROM; PXE; SSD/HDD.

* Installation types:

    1. Unattended installation
    2. In-place upgrade
    3. Clean install
    4. Image
    5. Repair installation
    6. Multiboot
    7. Recovery partition
    8. Refresh/restore

## The Windows Command Line

```shell
help <command> #gives information about command

<command> /? #alternative to help

exit #close prompt

dir #list file, directories

cd #change working directory, used with \(backslash)

shutdown /s /t nn #wait nn seconds, then shutdown

shutdown /r /t nn #shutdown and restart after nn seconds

shutdown /a #abort shutdown

sfc #System File Checker

chkdsk /f #fixes logical file system errors on disk

chkdsk /r #implies /f, locates bad sectors, recovers readable info

diskpart #manage disk config

tasklist #displays list of currently running processes

taskkill #terminate tasks by PID or image name

format #formats disk

ipconfig #IP details

ping #test reachability

tracert #trace route of packet

netstat #network stats

netstat -a #shows all active connections

nslookup #lookup info from DNS servers
```

## Windows Features

* Windows Administrative Tools:

    1. Microsoft Management Console
    2. Device Manager
    3. Local users and groups
    4. Local Security Policy
    5. Performance Monitor
    6. Services
    7. Task Scheduler
    8. Memory Diagnostics
    9. Event Viewer

* Windows Defender - firewall integrated into OS.

* System Configuration (msconfig) - manage boot processes, startup, services, etc; can be found in Task Manager.

* Task Manager - real-time system stats.

* Disk Management - manage disk operations.

* Storage Spaces - storage for data centers, cloud infra.

* System Utilities:

    1. Run line
    2. Command line
    3. Windows Registry (regedit)
    4. Services
    5. Microsoft Terminal Services Client
    6. DirectX Diagnostic Tool
    7. Disk Defragmentation

* Windows HomeGroup - share files between devices; works on single private network.

* Windows Workgroups - Logical groups of network devices.

* Windows Domain - Business network; centralized authentication.

## macOS and Linux

* macOS tools:

    1. Time Machine backups
    2. Image recovery
    3. Disk Utility
    4. Terminal
    5. Keychain
    6. iCloud

* Linux commands:

```shell
man #manual help

ls #list directory contents

cd /var/log #change current directory

grep failed auth.log #find text 'failed' in file 'auth.log'

su #or sudo, for elevated rights; super user

shutdown #system shutdown 2

sudo shutdown 2 #shuts down in 2 minutes

sudo shutdown -r 2 #shuts down and reboots in 2 minutes

sudo shutdown -c #cancel shutdown

pwd #print working directory

passwd #change user account password

mv #move a file, rename

mv first.txt second.txt #renames first.txt to second.txt

cp #copy file

rm #remove file, use -r to remove non-empty directory

mkdir #make directory

chmod #change mode of file system object

chown #change file owner and group

iwconfig #view wireless network config

ifconfig #view wired network interface

apt-get #advanced packaging tool

sudo apt-get install wireshark #install wireshark using apt-get

ps #view current processes

ps -e | more #view all processes

vi #visual mode editor

dd #convert and copy a file; backup and restore partition

sudo killall firefox #close firefox program

xkill #graphical kill

kill <pid> #kill process
```
