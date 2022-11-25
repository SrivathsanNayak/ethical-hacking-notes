# Synced - Very Easy

```shell
nmap -T4 -A -v 10.129.167.28

rsync --list-only rsync://10.129.167.28
#list shares

rsync -av --list-only rsync://10.129.167.28/public
#list files of public share

rsync -av rsync://10.129.167.28/public /home/sv
#transfer files to local machine
```

* Open ports & services:

  * 873 - rsync - protocol version 31

* We can enumerate rsync - we can check for anonymous login.

* Using rsync, we can list shares and files.

* We can see that the public share in remote machine contains flag.txt - we can transfer this to our machine and view it.

```markdown
1. What is the default port for rsync? - 873

2. How many TCP ports are open on the remote host? - 1

3. What is the protocol version used by rsync on the remote machine? - 31

4. What is the most common command name on Linux to interact with rsync? - rsync

5. What credentials do you have to pass to rsync in order to use anonymous authentication? - None

6. What is the option to only list shares and files on rsync? - list-only

7. Submit root flag - 72eaf5344ebb84908ae543a719830519
```
