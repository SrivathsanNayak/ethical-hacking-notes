# Scanning And Enumeration

* For this section, we are using Kioptrix, a vulnerable machine from [Vulnhub](https://www.vulnhub.com/) for beginners.

* To log in to Kioptrix machine:

```shell
#on Kali Linux

ifconfig
#to get IP address 10.0.2.7

netdiscover -r 10.0.2.0/24
#using ARP to detect all machines on network
#gives us the IP address of Kioptrix, 10.0.2.4

nmap -T4 -p- -A 10.0.2.4
#-T4 is for speed, -p- for scanning all ports, -A for scanning everything
#analyze scan results and lookup exploits
```

* Enumerating HTTP and HTTPS:

  * We can visit the links <http://10.0.2.4> and <https://10.0.2.4> for port 80 and 443. It shows that the default webpage uses Apache and PHP.

  * Information disclosure - Apache documentation link given in <http://10.0.2.4> leads to 404 page with Apache version 1.3.20.

  * Using a web vulnerability scanner:

  ```shell
  apt install nikto #web vuln scanner tool

  nikto -h http://10.0.2.4 #scans website, shows vuln

  dirbuster #tool for directory scanning
  ```

  * Burp Suite can be used to see and modify response in real-time using the Repeater window.

  * Information disclosure - Server headers reveal version information.

* Enumerating SMB:

  * SMB (Samba) is used for fileshare services, here it used on port 139.

  * For enumeration:

  ```shell
  msfconsole #loads the Metasploit framework

  search smb #search for exploits related to smb
  #choose one of the exploits

  use auxiliary/scanner/smb/smb_version #use particular module

  info #get information

  options #get only options

  set RHOSTS 10.0.2.4 #from options, set RHOSTS (Remote Host) as 10.0.2.4

  run #run exploit
  #This gives us the version of SMB - Unix (Samba 2.2.1a)

  #In a new terminal tab, we can use another tool called smbclient to connect to fileshare service
  smbclient -L \\10.0.2.4\\ #-L to list all, the slashes are for escaping characters

  #this gives us more information about the sharename and servers
  #we can attempt to connect
  smbclient \\\\10.0.2.4\\ADMIN$
  #cannot connect as we do not have password

  smbclient \\\\10.0.2.4\\IPC$ #this works and we get access to smb

  help

  ls #not allowed

  exit
  ```

* Enumerating SSH:

  * From the nmap scan, we know that the SSH version on port 22 is OpenSSH 2.9p2. We can attempt to connect using ```ssh 10.0.2.4``` but it would not work unless we know the password.

* After enumeration, we can research the vulnerabilities using Google and find if there are any exploits related to it. Examples of resources include [Rapid7](https://www.rapid7.com/db/) and [Exploit Database](https://www.exploit-db.com/). For offline searches, use ```searchsploit``` in the terminal.

* Vulnerability scanning with Nessus:

  * To setup Nessus:

  ```shell
  #After downloading Nessus package
  cd Downloads/

  dpkg -i Nessus-10.1.1-ubuntu910_amd64.deb

  /bin/systemctl start nessusd.service #start Nessus scanner
  #now go to <https://kali:8834/> to configure the scanner
  ```

  * Once Nessus is configured, we can launch a basic network scan or an advanced network scan of the Kioptrix machine.

  * After the scan is completed, we can check all the vulnerabilities and based on that we can find exploits.
