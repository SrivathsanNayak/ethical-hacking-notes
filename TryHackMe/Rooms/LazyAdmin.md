# Lazy Admin - Easy

<details>
<summary>nmap scan</summary>

```nmap -T4 -p- -A 10.10.76.249```

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
ssh-hostkey:
    2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
    256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
    256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    http-title: Apache2 Ubuntu Default Page: It works
    http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

</details>

<br>

* ffuf scan: ```ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.76.249/FUZZ -s```

```markdown
.htaccess
content
.htpasswd
.hta
```

* ffuf scan for /content: ```ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.76.249/content/FUZZ -s```

```markdown
.hta
_themes
images
.htaccess
.htpasswd
js
inc
as
attachment
```

* Now, the /content directory leads us to a website for SweetRice, a website management system. We can explore and check for any exploits.

* We can observe that the SweetRice website is powered by Basic CMS; we will have to keep that in mind while searching for exploits.

* One directory that can be used is /content/as, which can be used for Login

* Also, the /content/inc directory contains a mySQL backup file, which contains credentials manager:42f749ade7f9e195bf475f37a44cafcb

* The hash can be cracked and gives the password as Password123

* These creds can be used for the Login page we found earlier.

* As we have the login access now, we can use exploits for file upload.

* Once we exploit the page and get the reverse shell, we can stabilize the shell: ```python -c 'import pty; pty.spawn("/bin/bash")'```

* We get the user.txt file: ```THM{63e5bce9271952aad1113b6f1ac28a07}```

* Now we have to look for privilege escalation.

* ```sudo -l``` shows us what commands we can run as sudo, and it shows that we can run a particular Perl script as sudo.

* We can also use this command to check for files with SUID bit set: ```find / -perm -u=s -type f 2>/dev/null```

* Now, the backup.pl file executes another file /etc/copy.sh, which can be modified by us; so we replace it with a simple Netcat reverse shell script

* Then, all we are supposed to do is run the following: ```sudo /usr/bin/perl /home/itguy/backup.pl```

* This executes the script, and if we are listening on the specified port in attacking machine, we get root access.

* We get the root.txt file: ```THM{6637f41d0177b6f37cb20d775124699f}```
