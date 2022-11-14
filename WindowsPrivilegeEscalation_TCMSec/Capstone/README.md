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

* We can start by enumerating the SMB shares using ```smbclient``` tool.

* There is a Backups share which can be accessed, and it includes backups in the form of .vhd files.

* We can go through the main .vhd file by [mounting it on our Kali machine through remote share](https://medium.com/@klockw3rk/mounting-vhd-file-on-kali-linux-through-remote-share-f2f9542c1f25); this would use the ```guestmount``` tool.

* Once we complete mounting, we can go through the .vhd file as if we are in the Windows file system.

* Next, we can [extract the local SAM database from the file system](https://infinitelogins.com/2020/12/11/how-to-mount-extract-password-hashes-vhd-files/).

* We can use ```impacket-secretsdump``` to dump the extracted SAM database; this gives us a few hashes.

* We can crack one of the hashes, which gives us the password for the user 'L4mpje'.

* Using these creds, we can log into the machine via SSH.

* We have to enumerate now; using automated tools do not help a lot.

* We can go through the installed programs in ```C:\Program Files``` and ```C:\Program Files (x86)```.

* This shows that there is a program called mRemoteNG; we can look for exploits on Google.

* By searching, we can see that mRemoteNG stores passwords in a certain location, and they can be cracked using a mRemoteNG decryptor script from GitHub.

* By doing this, we get the password for Administrator, and we can login as admin now.

## Querier

* We can start by enumerating the SMB shares using ```smbclient``` - this includes a Reports share.

* This contains a .xlsm file; we can move it to our machine.

* We can extract the info from the file by using ```binwalk```; this contains multiple folders and files.

* By manual enumeration, we have a file inside the xl folder, vbaProject.bin

* This .bin file contains creds, it can be viewed using ```strings```.

* Now, we have the password for user 'reporting'; we can use ```mssqlclient.py``` to try to connect to the MSSQL service, with the windows-auth flag.

* We do not have enough privileges to use ```enable_xp_cmdshell```; so we can attempt to enumerate the tables, but it does not contain anything useful.

* We can attempt to [capture MSSQL creds with the help of ```responder```](https://medium.com/@markmotig/how-to-capture-mssql-credentials-with-xp-dirtree-smbserver-py-5c29d852f478)

* Using ```xp_dirtree``` in the mssql client, we manage to capture NTLMv2 hashes on ```responder```.

* We can crack the NTLMv2 hash using ```hashcat```; this gives us the password for the user 'mssql-svc'.

* With the password for 'mssql-svc', we can log into the MSSQL service again using ```mssqlclient.py```.

* This time, as we have more privileges, we can run ```enable_xp_cmdshell``` and then ```xp_cmdshell whoami``` - this works.

* To get a reverse shell, we can upload ```nc.exe``` from attacker machine using Python server; we can download the nc binary using ```xp_cmdshell``` and Powershell IWR command.

* After setting up listener on attacker machine, and then executing the netcat command for connection, we get a shell - we have received reverse shell from ```mssqlclient.py```

* We can use ```PowerUp.ps1``` for basic enumeration of the machine; transfer it to the victim machine.

* Using ```Invoke-AllChecks```, we can go through the findings.

* The output includes cached GPP files - this includes the password for Administrator.

* We can use these creds to log into as Administrator using ```evil-winrm``` and get root flag.
