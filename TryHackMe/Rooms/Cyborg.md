# Cyborg - Easy

```shell
rustscan -a 10.10.137.113 --range 0-65535 --ulimit 5000 -- -sV

feroxbuster -u http://10.10.137.113 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

hashcat -a 0 -m 1600 apachehash.txt /usr/share/wordlists/rockyou.txt
#crack the hash

#install borgbackup
sudo apt install borgbackup

#inside extracted folder dev
borg extract final_archive::music_archive

#get into alex's Documents folder for creds

ssh alex@10.10.137.113

cat user.txt

sudo -l
#we can run sudo command for a script

cat /etc/mp3backups/backup.sh

cd /etc/mp3backups

#use -c to pass and execute command
sudo ./backup.sh -c id
#prints id for root

sudo ./backup.sh -c "chmod +s /bin/bash"
#SUID bit set for bash

bash -p
#privileged flag
#gives us root shell
```

```markdown
Open ports & services:

  * 22 - ssh - OpenSSH 7.2p2 (Ubuntu)
  * 80 - http - Apache httpd 2.4.18

We can start by exploring the webpage, and use feroxbuster to enumerate the web directories in background.

Port 80 hosts the default landing page for Apache, so we can go and check the enumerated directories for hints.

Now, with the help of feroxbuster, two directories /admin and /etc are found.

We find three files of interest:

  * archive.tar, downloaded from /admin
  * /etc/squid/passwd, contains some creds
  * /etc/squid/squid.conf, a config file for something

We can extract archive.tar and take a look at every file inside.

The archive seems to be a BorgBackup repo, or at least that's what's given in the README file found inside.

Now, going to /etc/squid/passwd, this contains a username "music_archive" and a hash; from online services, we can see that it is a Apache MD5 hash.

We can crack the hash using Hashcat, and we get the cleartext "squidward".

We can attempt to log into SSH using these creds, but we are unable to; maybe there are a few more steps left.

Going back to the downloaded archive, we can check the BorgBackup documentation; knowing that the username is "music_archive", there could be something related to 'archive' or 'extract'.

The documentation for BorgBackup includes a 'borg extract' command; we can try this for the final-archive folder from archive.tar.

Now, using the 'borg extract' command for the username 'music_archive', we are asked a passphrase; we can use the passphrase we cracked earlier, and this extracts another folder 'home'.

This folder contains files for 'alex'; in the Documents folder there is a note.txt file which contains creds alex:S3cretP@s3

We can login to SSH using these creds and get user flag.

Now, we can run one command as sudo, which runs a backup script.

We can take a look at the backup script; it uses 'getopts', and what the code block does is that it gets argument -c from command line, and executes it.

So, we can assign /bin/bash SUID bit and then use the privileged flag to get root shell.
```

1. How many ports are open? - 2

2. What service is running on port 22? - ssh

3. What service is running on port 80? - http

4. What is the user.txt flag? - flag{1_hop3_y0u_ke3p_th3_arch1v3s_saf3}

5. What is the root.txt flag? - flag{Than5s_f0r_play1ng_H0p£_y0u_enJ053d}
