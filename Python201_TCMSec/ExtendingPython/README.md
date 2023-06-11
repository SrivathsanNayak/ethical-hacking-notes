# Extending Python

1. [BeautifulSoup](#beautifulsoup)
2. [Py2exe](#py2exe)
3. [Sockets](#sockets)
4. [Scapy](#scapy)
5. [Subprocess](#subprocess)
6. [Threading](#threading)
7. [Pycryptodome](#pycryptodome)
8. [Argparse](#argparse)

## BeautifulSoup

```py
import requests
from bs4 import BeautifulSoup

page = requests.get("https://247ctf.com/scoreboard")
# get html of page

# analyze html structure of page
# install and use bs4 to parse html

soup = BeautifulSoup(page.content, "html.parser")
print(soup.text)
# print only text, not the html elements

print(soup.title.string)
# print title string of webpage

print(soup.find("a"))
# find first link in page

for link in soup.find_all("a"):
  print(link)
  print(link.get("href"))
  # print the link and the href

print(soup.find(id="fetch-error"))
# fetch elements with particular id

print(soup.find(class_="nav-link"))
# print elements with particular class
# class_ is used as class is keyword in Python

# to get the table from page
table = soup.find("table")
table_body = table.find("tbody")
rows = table_body.find_all("tr")

for row in rows:
  cols = [x.text.strip() for x in row.find_all("td")]
  # multiple columns in each row of table
  # .text.strip() cleans out the contents
  print("{} is in {} place with {}".format(cols[2], cols[0], cols[4]))
```

## Py2exe

```py
'''
py2exe can be used to bundle Python program to an exe
to be run in machine without Python environment

assume we have the program to be bundled
'hello.py' written already
'''

from py2exe import freeze
freeze(
  console = [{'script':'hello.py'}],
  options = {'py2exe': {'bundle_files': 1, 'compressed': True}},
  zipfile = None
)
# creates .exe in destination subfolder specified on running program
```

## Sockets

```py
import socket

ip = socket.gethostbyname('247ctf.com')
print(ip)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# first parameter is for transport protocol, IPv4
# second parameter is for TCP

s.connect(("247ctf.com", 80))
# open socket connection to host on port 80

s.sendall(b"HEAD / HTTP/1.1\r\nHost: 247ctf.com\r\n\r\n")
# send HEAD request
print(s.recv(1024).decode())
# print received data
# 1024 bytes is max amount of data received at once

s.close()
# close socket connection

# for creating & binding socket connections

client = False
server = False
port = 8080
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

if server:
  s.bind(("127.0.0.1", port))
  s.listen()
  while True:
    connect, addr = s.accept()
    connect.send(b"Connected to socket")
    # send data to socket connection
    connect.close()

if client:
  s.connect(("127.0.0.1", port))
  print(s.recv(1024))
  s.close()

'''
check if server is able to send data
using client = False, server = True
then test if client is able to receive data
using client = True, server = False

we can also scan common ports and connect to any open port
'''

for port in [22, 80, 139, 443, 445, 8080]:
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  socket.setdefaulttimeout(1)
  # wait for only 1 second
  result = s.connect_ex(("127.0.0.1", port))
  # similar to connect, but it raises an error instead of exception
  if result == 0:
    print("Port {} is open".format(port))
  else:
    print("Port {} is closed".format(port))
  s.close()

```

## Scapy

```py
from scapy.all import *

'''
library for packet manipulation
we can craft packets at different layers as well
'''

ip_layer = IP(dst="247ctf.com")
icmp_layer = ICMP()
packet = ip_layer / icmp_layer
# used to stack layers

r = send(packet)
print(packet.show())
# print crafted packet details

# to review the exact packet on Wireshark
# wireshark(packet)

# send and receive packets to broadcast destination
# using ARP target address
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.10.0/24"), timeout=3, verbose=False)
# to print hosts which answered to sent packets
for i in ans:
  # print(i) gives verbose data
  print(i[1].psrc)
  # prints only IP


# port scanner
# by identifying 3 way handshake
SYN = 0x02
RST = 0x04
ACK = 0x10

for port in [22, 80, 139, 443, 445, 8080]:
  # sending SYN to destination
  # source port randomly generated
  tcp_connect = sr1(IP(dst="127.0.0.1")/TCP(sport=RandShort(), dport=port, flags="S"), timeout=1, verbose=False)

  # successful handshake
  if tcp_connect and tcp_connect.haslayer(TCP):
    response_flags = tcp_connect.getlayer(TCP).flags
    if response_flags == (SYN + ACK):
      snd_rst = send(IP(dst="127.0.0.1")/TCP(sport=RandShort(), dport=port, flags="AR"), verbose=False)
      print("Port {} is open".format(port))
    elif response_flags == (RST + ACK):
      print("Port {} is closed".format(port))
  else:
    print("Port {} is closed".format(port))


# packet sniffing
from scapy.layers.http import HTTPRequest

def process(packet):
  if packet.haslayer(HTTPRequest):
    print(packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode())

# use inbuilt sniff function for packet sniffing based on callback
sniff(filter="port 80", prn=process, store=False)


# analyze pcap file
scapy_cap = rdpcap("test.pcap")
for packet in scapy_cap:
  if packet.getlayer(ICMP):
    print(packet.load)
    # extract data from ICMP packets
```

## Subprocess

```py
import subprocess

# pass commands to be run as list
# use shell=True for invoking a shell
subprocess.call(["calc"])

# check_call checks for errors
out = subprocess.check_call(["cmd", "/c" "asd"])

out = subprocess.check_output(["cmd", "/c", "whoami"])
print("Output: {}".format(out.decode()))
```

## Threading

```py
import threading, time
from datetime import datetime

def sleeper(i):
  print("hello from %d!" % i)
  time.sleep(i)
  print("goodbye from %d!" % i)

print(datetime.now().strftime("%H:%M:%S"))

"""
if we call sleeper() multiple times
we have to wait until it is completed

by using threading, we can run it
on parallel threads
for concurrent execution
"""

threading.Thread(target=sleeper, args=(0,)).start()
threading.Thread(target=sleeper, args=(2,)).start()
threading.Thread(target=sleeper, args=(4,)).start()

# we can add a delay to it
threading.Timer(1, sleeper, [1]).start()

print(datetime.now().strftime("%H:%M:%S"))

"""
print output and get input
at the same time
"""

stop = False

def input_thread():
  global stop
  while True:
    user_input = input("Should we stop?: ")
    print("User says: {}".format(user_input))
    if user_input == "yes":
      stop = True
      break

def output_thread():
  global stop
  count = 0
  while not stop:
    print(count)
    count += 1
    time.sleep(1)

t1 = threading.Thread(target=input_thread).start()
t2 = threading.Thread(target=output_thread).start()
```

```py
import threading, time

"""
thread locking demo
pop elements from list
using synced threads
so that no two threads pop the same element
this follows a sequential order
"""

data_lock = threading.Lock()
data = [x for x in range(1000)]

def sync_consume_thread():
  global data_lock, data
  while True:
    data_lock.acquire()
    if len(data) > 0:
      print(threading.current_thread().name, data.pop())
    data_lock.release()

threading.Thread(target=sync_consume_thread).start()
threading.Thread(target=sync_consume_thread).start()
threading.Thread(target=sync_consume_thread).start()
```

## Pycryptodome

```py
# install pycryptodome using pip
from Crypto.Random import get_random_bytes

# generate random 256-bit key
key = get_random_bytes(32)
print(key)

from Crypto.Protocol.KDF import PBKDF2

salt = get_random_bytes(32)
# we can also use a fixed salt
# so the key will behave as a function of password
password = "password123"
key = PBKDF2(password, salt, dkLen=32)
print(key)

# encryption using AES

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

to_encrypt = b"encrypt this string"
cipher = AES.new(key, AES.MODE_CBC)
print(cipher.iv)
ciphered_data = cipher.encrypt(pad(to_encrypt, AES.block_size))
print(ciphered_data)

# cipher object is stateful
# we cannot use same object for both encryption and decryption

cipher = AES.new(key, AES.MODE_CBC, iv=cipher.iv)
plaintext_data = unpad(cipher.decrypt(ciphered_data), AES.block_size)
print(plaintext_data)

# using stream ciphers

from Crypto.Cipher import ARC4
cipher = ARC4.new(key)
encrypted = cipher.encrypt(to_encrypt)
print(encrypted)

cipher = ARC4.new(key)
plaintext = cipher.decrypt(encrypted)
print(plaintext)

# using asymmetric encryption

from Crypto.PublicKey import RSA

# generate 1024-bit RSA key
key = RSA.generate(1024)
encrypted_key = key.exportKey(passphrase=password)
print(encrypted_key)

pub = key.publickey()
print(pub.exportKey())

# inbuilt functions
print(key.can_encrypt())
print(key.can_sign())
print(key.has_private())
print(pub.has_private())

from Crypto.Cipher import PKCS1_OAEP

cipher = PKCS1_OAEP.new(pub)
encrypted = cipher.encrypt(to_encrypt)
print(encrypted)

cipher = PKCS1_OAEP.new(key)
plaintext = cipher.decrypt(encrypted)
print(plaintext)

# verifying digital signatures

from Crypto.Hash import SHA512

plain_hash = SHA512.new(to_encrypt).digest()
hashed = int.from_bytes(plain_hash, byteorder='big')
print(hashed)

signature = pow(hashed, key.d, key.n)
print(signature)

signature_hash = pow(signature, key.e, key.n)
print(signature_hash)

print(hashed == signature_hash)
# if True, the signature is valid
```

## Argparse

```py
import argparse

parser = argparse.ArgumentParser(description="Example Python CLI")

# positional args
parser.add_argument("name", help="Enter name", type=str)
parser.add_argument("power", help="Enter power",type=int)

# optional args
parser.add_argument("-bh", "--blackhat", default=False, action="store_true")
parser.add_argument("-wh", "--whitehat", default=True, action="store_false")
# can add required=True if parameter required

# arg type
parser.add_argument("-ht", "--hackertype", choices=["whitehat", "blackhat", "greyhat"])

args = parser.parse_args()
print(args)

if args.blackhat:
  hacker_type = "blackhat"
elif args.whitehat:
  hacker_type = "whitehat"
else:
  hacker_type = "unknown"

print("{} is a {} hacker".format(args.hacker_name, hacker_type))
```
