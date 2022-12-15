# Extending Python

1. [Package manager and virtual environments](#package-manager-and-virtual-environments)
2. [sys](#sys)
3. [requests](#requests)
4. [pwntools](#pwntools)

## Package manager and virtual environments

* We can use existing code packages (modules) to extend the functionality in Python.

* Package manager ```pip``` can be used to install packages:

```shell
pip install pwntools

pip list
#view installed libraries

pip freeze
#view libraries and version

pip install -r requirements.txt
#install from requirements.txt
```

* A virtual environment enables in creation of an isolated Python environment, independent of other environments and installed packages; this allows us to use multiple dependencies & versions.

```shell
pip install virtualenv

mkdir virtual-demo

cd virtual-demo

#start virtual env
python3 -m venv env

#activate virtual env
source env/bin/activate
#prompt includes 'env' now

python3

#in virtual env, check python used
which python3
#different from /usr/bin/python3

pip install pwntools
#install package in virtual env

deactivate
#deactivate virtual env
```

## sys

```python
import sys
import time

print(sys.version)
#version of Python interpreter

print(sys.executable)
#view Python binary used

print(sys.platform)
#linux

for line in sys.stdin:
  if line.strip() == "exit":
    break
  sys.stdout.write(">> {}".format(line))
#takes input and prints it, until "exit"

for i in range(1,5):
  sys.stdout.write(str(i))
  sys.stdout.flush()
  #clears internal buffer of file

#to simulate a progress bar
for i in range(0,51):
  time.sleep(0)
  sys.stdout.write("{} [{}{}]\r".format(i, '#'*i, "."*(50 - i)))
  sys.stdout.flush()
sys.stdout.write("\n")

print(sys.argv)
#list arguments supplied to script
#first name will always be name of script

if len(sys.argv) != 3:
  print("[X] To run {} enter username and password".format(sys.argv[0]))
  sys.exit(5)
  #exit with particular exit code

username = sys.argv[1]
password = sys.argv[2]

#access path for modules
print(sys.path)

#list of modules
print(sys.modules)

#exit with particular exit code
sys.exit(0)
```

## requests

```python
import requests

x = requests.get('http://httpbin.org/get')

print(x.headers)
print(x.headers['Server'])
print(x.status_code)
print(x.elapsed)
#time elapsed
print(x.cookies)
print(x.content)
#in bytes
print(x.text)
#in unicode

x = requests.get('http://httpbin.org/get', params={'id':'1'})
print(x.url)

x = requests.get('httpL//httpbin.org/get?id=2')
print(x.url)

x = requests.get('http://httpbin.org/get', params={'id':'3'}, headers={'Accept':'application/json', 'test_header':'test'})
print(x.text)
#print response in json format

x = requests.delete('http://httpbin.org/delete')
print(x.text)

x = requests.post('http://httpbin.org/post', data={'a':'b'})
print(x.text)

files = {'file': open('google.jpg', 'rb')}
x = requests.post('http://httpbin.org/post', files=files)
print(x.text)

#handle basic auth
x = requests.get('http://httpbin.org/get', auth=('username','password'))
print(x.text)

x = requests.get('https://expired.badssl.com', verify=False)
#gives SSL error unless 'verify=False'

x = requests.get('http://github.com', allow_redirects=False)
print(x.headers)

x = requests.get('http://httpbin.org/get'. timeout=0.01)
print(x.content)

#sessions and cookies
x = requests.get('http://httpbin.org/cookies', cookies={'a':'b'})
print(x.content)

x = requests.Session()
x.cookies.update({'a':'b'})
print(x.get('http://httpbin.org/cookies').text)

x = requests.get('https://api.github.com/events')
print(x.json())

#get images
x = requests.get('https://www.google.com/images/googlelogo.png')
with open('google2.png', 'wb') as f:
  f.write(x.content)
```

## pwntools

```python
from pwn import *

print(cyclic(50))
print(cyclic_find("laaa"))
#example functions for buffer overflow

print(shellcraft.sh())

#start local process
p = process("/bin/sh")
p.sendline("echo hello;")
p.interactive()
#interactive session

r = remote("127.0.0.1", 1234)
r.sendline("hello")
r.interactive()
r.close()

#packing and unpacking
print(p32(0x13371337))
print(hex(u32(p32(0x13371337))))

#load files
l = ELF('/bin/bash')
print(hex(l.address))
print(hex(l.entry))
print(hex(l.got['write']))
print(hex(l.plt['write']))

for address in l.search(b'/bin/sh\x00'):
  print(hex(address))

print(hex(next(l.search(asm('jmp esp')))))

#encoding, hashing
print(xor("A", "B"))
print(b64e(b"test"))
print(md5sumhex(b"hello"))

#low level functions
print(bits(b'a'))
```
