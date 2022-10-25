# Bike - Very Easy

```shell
rustscan -a 10.129.47.123 --range 0-65535 --ulimit 5000 -- -sV
```

```markdown
Open ports & services:

  * 22 - ssh - OpenSSH 8.2p1 (Ubuntu)
  * 80 - http - Node.js

We can access the webpage on port 80; it seems to be under construction.

We have an option to enter input (email) and submit.

We can try to enter the given input {{7*7}} - this gives us an error page.

Searching for this input example gives us the search results for SSTI; we can research about it.

From HackTricks -

    A server-side template injection occurs when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side.

Now, we can detect the templating engine from the error message; the path contains the term 'handlebars' - this is included in the HackTricks page as well.

The handlerbars section includes an URL-encoded exploit as well; we can give that a try.

We enter our previous payload, and intercept the request using Burp Suite, and send it to Repeater; here, we can see that the payload gets URL-encoded.

We can add the URL-encoded payload from HackTricks and send; the response contains a "ReferenceError: require is not defined"

As the current payload gives us an error, we will have to modify it by replacing 'require' with something else.

By getting code from other engines' payloads (for example, nunjucks), we are able to get a response:

    "return global.process.mainModule.require('child_process').execSync('whoami')"

We can replace the 'require' snippet with this, and URL-encode it; the response contains 'root'.

As we are root, we can get flag in a similar manner using command 'cat /root/flag.txt'
```

1. What TCP ports does nmap identify as open? - 22,80

2. What software is running the service listening on the http/web port identified? - Node.js

3. What is the name of the web framework according to Wappalyzer? - Express

4. What is the name of the vulnerability we test for by submitting {{7*7}}? - Server Side Template Injection

5. What is the templating engine being used within Node.JS? - handlebars

6. What is the name of the BurpSuite tab used to encode text? - Decoder

7. In order to send special characters in our payload in an HTTP request, we'll encode the payload. What type of encoding do we use? - URL

8. When we use a payload from HackTricks to try to run system commands, we get an error back. What is "not defined" in the response error? - require

9. What variable is the name of the top-level scope in Node.JS? - global

10. By exploiting this vulnerability, we get command execution as the user that the webserver is running as. What is the name of that user? - root

11. Submit root flag - 6b258d726d287462d60c103d0142a81c
