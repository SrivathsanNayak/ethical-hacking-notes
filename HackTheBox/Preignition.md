# Preignition - Very Easy

```shell
rustscan -a 10.129.194.154 --range 0-65535 --ulimit 5000 -- -sV

gobuster dir -u http://10.129.194.154 -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,bak -t 50
```

```markdown
Open ports & services:

  * 80 - http - nginx 1.14.2

We can continue by scanning directories using Gobuster; we get a page /admin.php

It leads to a login page; we can try default creds admin:admin here.

It works and we are able to login; root flag can be found on login.
```

1. Directory brute-forcing is a technique used to check a lot of paths on a web server to find hidden pages. Which is another name for this? - dir busting

2. What switch do we use for nmap's scan to specify that we want to perform version scanning? - -sV

3. What does Nmap report is the service identified as running on port 80/tcp? - http

4. What server name and version of service is running on port 80/tcp? - nginx 1.14.2

5. What switch do we use to specify to Gobuster we want to perform dir busting specifically? - dir

6. When using gobuster to dir bust, what switch do we add to make sure it finds PHP pages? - -x php

7. What page is found during our dir busting activities? - admin.php

8. What is the HTTP status code reported by Gobuster for the discovered page? - 200

9. Submit root flag - 6483bee07c1c1d57f14e5b0717503c73
