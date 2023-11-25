# Windows Fundamentals

1. [Operating System Structure](#operating-system-structure)
1. [File System](#file-system)
1. [NTFS vs Share Permissions](#ntfs-vs-share-permissions)
1. [Windows Services & Processes](#windows-services--processes)
1. [Interacting with Windows](#interacting-with-windows)
1. [Windows Security](#windows-security)

## Operating System Structure

* Directory structure of boot partition (C:\):

  * Perflogs - can hold Windows performance logs; empty by default
  * Program Files - on 32-bit systems, all 16-bit & 32-bit programs are installed here; on 64-bit systems, only 64-bit programs are installed here
  * Program Files (x86) - on 64-bit systems, 16-bit & 32-bit programs are installed here
  * ProgramData - hidden folder containing data required for certain programs to run
  * Users - contains user profiles for each user that logs onto system; includes folders Public & Default
  * Default - default user profile template for all created users
  * Public - for users to share files; accessible to all users by default
  * AppData - hidden user subfolder to store per user app data & settings; contains subfolders Roaming, Local and LocalLow
  * Windows - stores majority of files required for operating system
  * System, System32 & SysWOW64 - contains all DLLs required for core features of Windows & Windows API
  * WinSxS - Windows Component Store; includes copy of all Windows components, updates & service packs.

## File System

* 5 types of Windows file systems - FAT12, FAT16, FAT32, NTFS & exFAT; FAT12 & FAT16 are no longer used on modern Windows OS.

* FAT32:

  * File Allocation Table; uses 32 bits of data for identifying data clusters on a storage device
  * used in storage devices like USB pendrives, SD cards and is compatible with many devices
  * OS cross-compatibility
  * can only be used with files less than 4GB
  * no built-in data protection or file compression features
  * must use 3rd party tools for file encryption

* NTFS:

  * New Technology File System; default Windows file system
  * reliable and secure
  * supports large-sized partitions and has built-in journaling
  * files & folders inherits the permissions of their parent folder for ease of administration
  * most mobile devices do not support NTFS natively

* ```icacls```:

  * Integrity Control Access Control List
  * to manage NTFS file permissions from CLI

  ```cmd
  icacls
  # prints NTFS permissions in current directory

  icacls C:\Users
  # for specific directory

  icacls C:\Users /grant joe:f
  # grant 'joe' user full control over directory
  # use /remove to remove permissions
  ```

## NTFS vs Share Permissions

* SMB (Server Message Block) - used in Windows to connect shared resources like files & printers.

* NTFS permissions and share permissions are not the same but often apply to the same shared resource.

* Share permissions include Full Control, Change & Read; NTFS Permissions include a lot more like Full Control, Modify, Read & Execute, etc.

* Similar to NTFS permissions, there is an ACL (access control list) for shared resources - this ACL contains ACEs (access control entries), made up of users & groups (security principals).

```shell
# connecting to a share
smbclient -L 10.10.10.100 -U htb-student

# mounting to share
sudo mount -t cifs -o username=htb-student,password=Academy_WinFun! //10.10.10.100/"Company Data" /home/user/Desktop/
```

## Windows Services & Processes

* Windows services allow for the creation & management of long-running processes; the services can be managed via SCM (Service Control Manager), accessible via ```services.msc``` or using ```Get-Service``` cmdlet

* Service statuses can appear as Running, Stopped, or Paused, and they can be set to start manually, automatically, or on a delay at system boot.

* Windows has 3 categories of services - Local Services, Network Services & System Services.

* There are some critical system services as well, that cannot be stopped & restarted without a system restart.

* Processes run in the background on Windows systems, either as a part of the OS or started by other apps.

* LSASS (Local System Authority Subsystem Service) - ```lsass.exe``` is the process responsible for enforcing security policy on Windows.

* Tools like Process Explorer (from Sysinternals Suite) and Task Manager can be used to analyze processes.

* To query a service we can use the ```sc qc``` command - we need to know the service name for this; we can also use ```sc``` to stop/start services.

## Interacting with Windows

* Interactive sessions - local logon sessions initiated by user authenticating to local or domain system; by logging directly into system, requesting secondary logon session (runas), or via RDP.

* Non-interactive sessions - for non-interactive accounts (don't need login creds), of which there are 3 types - Local System account (NT AUTHORITY\SYSTEM), Local Service account (NT AUTHORITY\LocalService) & Network Service account (NT AUTHORITY\NetworkService).

* WMI (Windows Management Instrumentation) - subset of PowerShell, provides sysadmins with tools for monitoring.

* MMC (Microsoft Management Console) - used to group snap-ins or admin tools, to manage components in Windows host.

* WSL (Windows Subsystem for Linux) - allows Linux binaries to be run natively on Windows.

## Windows Security

* Security Identifier (SID) -

  * variable-length string values stored in security database
  * SID is added to user's access token to identify all actions that user is authorized for
  * consists of Identifier Authority & RID (Relative ID); in AD domain, SID also includes domain SID

* SAM (Security Accounts Manager) - grants rights to a network to execute specific processes

* ACE (Access Control Entries) - ACEs (found in ACLs) manage & define access rights for users/groups/processes

* 2 types of ACLs - DACL (Discretionary ACL) and SACL (System ACL)

* UAC (User Acccount Control):

  * Windows security feature to prevent malware from running destructive processes
  * Admin Approval Mode - prevent unwanted software from being installed without admin approval

* Registry:

  * hierarchical database to store low-level settings
  * divided into computer-specific & user-specific data
  * tree-strucutured data - contains main folders (rootkeys) in which subfolders (subkeys) with their entries (values) are located
  * entire system registry is stored in files under ```C:\Windows\System32\Config\```
  * user-specific registry hive (HKCU) is stored in user folder (```C:\Users\<username>\Ntuser.dat```)
  * there are certain registry hives loaded into memory when OS boots up or user logs in - these are called Run & RunOnce registry keys

* Application whitelisting - list of approved software apps allowed to be present & run on a system; based on zero trust principle.

* AppLocker - Microsoft's app whitelisting solution; gives sysadmins control over which apps & files users can run.

* Local Group Policy -

  * Group Policy allows admins to set & configure settings
  * In domain environment, group policies are pushed down from Domain Controller onto all domain-joined machines that GPOs (Group Policy Objects) are linked to
  * These settings can be defined on individual machines too using Local Group Policy

* Windows Defender Antivirus -

  * built-in AV with features like real-time protection & cloud-delivered protection
  * managed from Security Center - allows additional security features & settings
  * Powershell cmdlet ```Get-MpComputerStatus``` can be used to check which protection settings are enabled
