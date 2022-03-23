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

## Cryptography

---

## Windows Exploitation Basics

---

## Basic Computer Exploitation

---
