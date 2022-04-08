# Agent Sudo - Easy

<details>
<summary>nmap scan</summary>

```nmap -T4 -p- -A 10.10.142.89```

PORT      STATE    SERVICE    VERSION
21/tcp    open     ftp        vsftpd 3.0.3
22/tcp    open     ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
ssh-hostkey:
    2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
    256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
    256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp    open     http       Apache httpd 2.4.29 ((Ubuntu))
http-title: Annoucement
    http-server-header: Apache/2.4.29 (Ubuntu)
936/tcp   filtered unknown
1899/tcp  filtered mc2studios
2370/tcp  filtered l3-hbmon
9468/tcp  filtered unknown
12438/tcp filtered unknown
14079/tcp filtered unknown
15510/tcp filtered unknown
16379/tcp filtered unknown
19594/tcp filtered unknown
29861/tcp filtered unknown
34168/tcp filtered unknown
35147/tcp filtered unknown
37016/tcp filtered unknown
40288/tcp filtered unknown
51526/tcp filtered unknown
54321/tcp filtered unknown
56448/tcp filtered unknown
65066/tcp filtered unknown
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

</details>

<br>

* According to given instruction on webpage, we have to change user-agent to codename to access the site.

* So we can use  a tool like Burp Suite or curl to intercept and change the user-agent: ```curl -A "R" http://10.10.142.89```

* This gives us a message saying that this is only for the 25 employees. Here, 25 employees could mean 25/26 letters of the alphabet.

* So we can replace "R" with each letter of the alphabet and try to access the site: ```curl -A "A" -L http://10.10.142.89```

* For "C", we get to know that there's a weak password.

1. How many open ports? - 3

2. How you redirect yourself to a secret page? - user-agent

3. What is the agent name? - chris

* We now need to brute-force ftp

```shell
hydra -l chris -P /usr/share/wordlists/rockyou.txt 10.10.142.89 ftp
```

* After getting the ftp password, we can transfer the files to our local system and follow the clues

* We have to use steganography to crack the password hidden in the image files

```shell
stegbrute -f cute-alien.jpg -w rockyou_length6.txt
```

* [This blog](https://0xrick.github.io/lists/stego/) contains useful references for steganography.

* This gives us the password "Area51"

* Also gives us the file contents, which contains the login password "hackerrules"

* Also, the file cutie.png, when analyzed using hexdump, gives us the letters "PK" near the end of the file, which shows that this could be a zip file: ```hexdump -C cutie.png```

* This is verified by binwalk as well, so now we need to convert it to zip file format: ```binwalk -e cutie.png```

* Now, we get a zip file, which can be cracked using zip2john

1. FTP password - crystal

2. Zip file password - alien

3. steg password - Area51

4. Who is the other agent? - james

5. SSH password - hackerrules!

* Now we need to SSH to find the flags

* The image found in james directory can be reverse searched to find the name of the incident

1. What is the user flag? - b03d975e8c92a7c04146cfa7a5a313c7

2. What is the incident of the photo called? - roswell alien autopsy

* Now we need to escalate our privileges. We can use tools such as ```linenum.sh``` and ```linpeas``` to discover privilege escalation exploits.

* We have sudo version 1.8.21p2 and there are some exploits for that, so we can use that as a PE vector.

1. CVE number for the escalation - CVE-2019-14287

2. What is the root flag? - b53a02f55b57d4439e3341834d70c062

3. Who is Agent R? - DesKel
