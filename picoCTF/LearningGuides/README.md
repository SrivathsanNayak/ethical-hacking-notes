# picoCTF Learning Guides

Topics:

1. [General Skills](#general-skills)
2. [Cryptography](#cryptography)
3. [Web Exploitation](#web-exploitation)
4. [Forensics](#forensics)
5. [Binary Exploitation](#binary-exploitation)
6. [Reversing](#reversing)

## General Skills

* Learn to use [SSH](https://www.hostinger.com/tutorials/ssh-tutorial-how-does-ssh-work) and [Netcat](https://www.poftut.com/netcat-nc-command-tutorial-examples/).

* Learn about number systems such as Decimal (base-10), Binary (base-2), Octal (base-8) and Hexadecimal (base-16).

* Big Endian - big end first; the most significant byte is stored at the smallest memory location; commonly used in networking.

* Little Endian - little end first; least significant byte stored at the smallest memory address; used in processors.

## Cryptography

* Examples of ciphers include Caesar cipher, Affine cipher, Vignere cipher and Hill cipher.

* Authentication - refers to authenticity of message; to confirm if the message is from a particular user.

* Encryption - encoding a message so only a particular user can read it.

* Use tools such as ```hashcat``` and ```John the Ripper``` for password cracking.

## Web Exploitation

* We can understand the website code by viewing the page source and using Developer Tools.

* SQLi (SQL Injection) - injection attack where an attacker can execute SQL commands and control a web app's database server.

## Forensics

* Metadata - data about file itself like length, time created, author, etc.

* File carving - technique to extract data from a disk drive without having the normal file system to easily recover files.

* When a file gets deleted, the data does not get deleted but just the reference to that data.

## Binary Exploitation

* GDB (GNU Project Debugger) - software for debugging.

* GDB contains two major parts - the symbol side (the program) and the target side (the manipulations done to program).

* ```gcc -g filename.c -o executablename``` to compile the code in C, ```gdb executablename``` to start debugging.

## Reversing

* To understand reversing, we need to have a basic idea of programming languages such as C, Assembly, and Python.
