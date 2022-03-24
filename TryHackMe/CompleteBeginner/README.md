# Complete Beginner

1. [Network Exploitation Basics](#network-exploitation-basics)
2. [Web Hacking Fundamentals](#web-hacking-fundamentals)
3. [Cryptography](#cryptography)
4. [Windows Exploitation Basics](#windows-exploitation-basics)
5. [Basic Computer Exploitaton](#basic-computer-exploitation)

## Network Exploitation Basics

---

* OSI Model layers - Application, Presentation, Session, Transport, Network, Data Link, Physical.

* TCP/IP Model layers - Application, Transport, Internet, Network Interface.

* Common Networking commands - ```ping```, ```traceroute```, ```whois```, ```dig```.

* ```nmap``` can be used to scan networks.

* Network services can be enumerated and exploited using various tools such as ```nmap``` (for preliminary scan), ```enum4linux``` (enumeration) and ```metasploit``` (exploitation).

## Web Hacking Fundamentals

---

* Making HTTP requests using ```cURL```:

  ```shell
  curl https://10.10.80.227:8081
  #performs GET requests by default and retrieves page

  curl -X POST https://10.10.80.227:8081
  #-X to specify request type
  ```

* OWASP Top 10:

  1. Injection:

     * Occurs because user input is interpreted as actual command.

     * Injection attacks can be prevented by using an allow list or stripping input.

     * Command injection - server-side code in web app makes system call on host machine; executes OS commands on server.

     * Detect active command injection - occurs when response from system call is seen; in PHP, ```passthru()``` can lead to active command injection, for example.

     * We can try commands such as ```whoami```, ```id```, ```ifconfig```, ```uname -a``` for Linux or ```whoami```, ```ver```, ```ipconfig```, ```netstat -an``` for Windows.

  2. Broken Authentication:

     * Due to flaws in authentication mechanism; examples include brute force attacks and weak session cookies.

     * Mitigation techniques include using a strong password policy, automatic lockout after n attempts, and implementing MFA.

  3. Sensitive Data Exposure:

     * Occurs when a webapp accidentally reveals sensitive data.

      ```shell
      #example scenario of getting a .db file (flat-file database)

      file example.db
      #shows that it is an sqlite db

      sqlite3 example.db
      #check the file

      .tables #check tables

      PRAGMA table_info(users); #check 'users' table info

      SELECT * FROM users; #dump 'users' data
      #crack hashed passwords
      ```

  4. XML External Entity:

     * Vulnerability that abuses features of XML parsers, data; allows attacker to interact with backend of app, and can allow attacker to read files, cause DoS or SSRF attacks.

     * Two types of XXE attacks - in-band XXE and out-of-band XXE (blind XXE).

     * Examples of XXE payloads:

      ```xml
      <!DOCTYPE replace [<!ENTITY name "feast"> ]>
         <userInfo>
            <firstName>falcon</firstName>
            <lastName>&name;</lastName>
         </userInfo>
      <!--ENTITY called name as "feast", used in code-->
      ```

      ```xml
      <?xml version="1.0"?>
      <!DOCTYPE root [<!ENTITY read SYSTEM 'file///etc/passwd'>]>
      <root>&read;</root>
      <!--website vulnerable to XXE would display contents of '/etc/passwd'-->
      ```

  5. Broken Access Control:

     * If website visitor is able to access protected pages in unauthorised manner, the access controls are broken.

     * IDOR (Insecure Direct Object Reference), is exploiting a misconfiguration related to user input, to access resources which require a higher privilege. It is an access control vulnerability.

     * For example, <https://example.com/bank?account=1234> can be modified by replacing the bank account number, and if site is misconfigured, it can result in IDOR.

  6. Security Misconfiguration:

     * Includes poorly configured permissions, having unnecessary features enabled, default accounts with unchanged passwords and overly detailed error messages.

  7. Cross-site Scripting:

     * XSS is a type of injection, allowing attacker to execute malicious scripts on victim machine.

     * Webapps are vulnerable to XSS if it uses unsanitized user input.

     * Three types of XSS are:

       * Stored XSS - malicious string originates from website's database.

       * Reflected XSS - payload is part of victim's request to website.

       * DOM-based XSS - webpage document can be displayed in browser or as code.

     * Common XSS payloads include pop-ups, HTML overriding, port scanning, etc.

  8. Insecure Deserialization:

     * Occurs when untrusted data is used to abuse app logic; it leverages legit serialization and deserialization process used by webapps.

     * Serialization is the process of converting programming objects into compatible formatting for further processing. Deserialization is converting serialized info into their complex form.

  9. Components with Known Vulnerabilities:

     * Occurs when a program is being used which already has a well-documented vulnerability.

  10. Insufficient Logging and Monitoring:

      * In webapps, every action performed by user should be logged in order to trace actions in the event of an incident.

      * Logs can store info such as HTTP status codes, timestamps, usernames, page locations and IP addresses.

* Upload vulnerabilities:

  * Overwriting existing files - if files are uploaded with the same name as files on the website, and there are no checks being conducted, there is a chance that we can overwrite the existing files.

  * Remote code execution -

    * Webshells -

      ```shell
      gobuster dir -u http://demo.uploadvulns.thm -w /usr/share/wordlists/directory-list.txt
      #scan website directories using gobuster
      #check for directories where files can be uploaded
      #if found, try to upload files like images

      #if the upload works, we can attempt to upload webshells
      #the webshell should be in the same language as the backend of the website
      #an example of a basic PHP webshell if <?php echo system($_GET["cmd"]);?>
      #this can let us execute commands
      ```

    * Reverse shells -

      ```shell
      #similar process to uploading a webshell
      #we can use any reverse shell, and change the IP address and port

      nc -nvlp 1234
      #attacker machine listening on port 1234
      #once shell has been uploaded, navigate to that directory
      #this will give us RCE from our shell
      ```

  * Bypassing client-side filtering - this would require intercepting using Burp Suite and modifying the incoming page to remove the functions that filter the files using MIME types (or other filters), and then upload the reverse shell.

  * Bypassing server-side filtering - if the server-side code checks for file extensions and blacklists ```.php``` extensions, we can try alternatives such as naming the file with the extension ```.png.php``` so as to attempt to bypass the filter. If this does not work, we can also tweak the magic numbers (file signatures) of the file being uploaded; ```hexeditor``` can be used to edit in this way.

  * Methodology:

    1. Go through website, look at headers
    2. Inspect website through source-code for client-side filters
    3. Use ```gobuster``` with ```-x``` switch to find directories with particular extensions
    4. Upload any file and check if it gets uploaded
    5. Attempt malicious file upload

## Cryptography

---

## Windows Exploitation Basics

---

## Basic Computer Exploitation

---
