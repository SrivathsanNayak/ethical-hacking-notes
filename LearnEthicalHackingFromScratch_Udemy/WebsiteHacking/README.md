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

## SQL Injection Vulnerabilities

---

## Cross Site Scripting Vulnerabilities

---

## Discovering Vulnerabilities Automatically

---
