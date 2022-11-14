# Capstone Challenge

1. [Arctic](#arctic)
2. [Bastard](#bastard)
3. [Alfred](#alfred)
4. [Bastion](#bastion)
5. [Querier](#querier)

## Arctic

* Open ports & services includes fmtp on port 8500.

* Checking the webpage on port 8500 leads us to two directories - /CFIDE and /cfdocs

* There is a login page for Adobe ColdFusion 8 on /CFIDE/administrator; we can check for vulnerabilities.

* We can use any of the multiple exploits on Google to get the password (via directory traversal) and eventually, reverse shell.

* We get reverse shell as 'tolis'; we can use windows-exploit-suggester tool to check for possible exploits in order to escalate privileges.

* MS10-059 (Chimichurri) is shown as a possible exploit, and when we run the exploit, we get root.

## Bastard

* There is a webpage on port 80 which uses Drupal CMS, version 7.

* We can search for exploits for this version; we can get RCE exploits based on CVE-2018-7600.

* Using this exploit, we can get a shell as 'iusr'.

* We can use any tool such as Sherlock or PowerUp or windows-exploit-suggester to check for exploits.

* We get a possible exploit MS15-051; we can Google for the exploit files.

* Running the exploit accordingly will give us shell as system.

## Alfred

* There are webpages on both port 80 and 8080.

* Inspecting the webpages does not show anything significant; however there is a login page at port 8080.

* We can log into using admin:admin, and this leads to the Jenkins Dashboard.

* We can get a reverse shell from this dashboard by going to Build History > project > Configure > Execute Windows batch command.

* Here, we can run the powershell reverse-shell command, setup a listener and server on attacker machine.

* After saving the project, we need to select 'Build Now'.

* This gives us a reverse shell on our listener as bruce.

* Checking privileges, we can see that it has SeImpersonatePrivilege enabled.

* We can migrate to meterpreter by creating a ```windows/x64/meterpreter/reverse_tcp``` payload using msfvenom, setup 'multi/handler' listener on msfconsole, and download & execute the payload on our reverse shell.

* This gives us the Meterpreter shell.

* Using ```load incognito```, we can use the incognito module.

* ```list_tokens -u``` shows that we have the SYSTEM token available.

* ```impersonate_token "NT AUTHORITY\SYSTEM"``` helps us in privesc.

* We can later ```migrate``` to any other process if the shell is unstable.

## Bastion

## Querier
