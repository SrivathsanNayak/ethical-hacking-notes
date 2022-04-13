# ffuf

* ```ffuf``` - Fuzz Faster U Fool - used for web enumeration, fuzzing, directory brute forcing:

```shell
ffuf -u http://10.10.99.194/FUZZ -w /usr/share/SecLists/Discovery/Web-Content/big.txt
#to inject wordlist entries at end of URL

#to find pages and directories
ffuf -u http://10.10.99.194/FUZZ -w /usr/share/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt

#we can save time by using shorter wordlists for extensions for particular webpages such as index
ffuf -u http://10.10.99.194/indexFUZZ -w /usr/share/SecLists/Discovery/Web-Content/web-extensions.txt
#this gives us an idea of extensions, then we can use longer wordlists

ffuf -u http://10.10.99.194/FUZZ -w /usr/share/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt -e .php,.txt
#-e for extensions

#we can use filters
ffuf -u http://10.10.99.194/FUZZ -w /usr/share/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt -fc 403
#-fc to filter code 403

ffuf -u http://10.10.99.194/FUZZ -w /usr/share/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt -mc 200
#-mc to match code 200
#-mc 500 can be used to find what requests server does not handle

ffuf -u http://10.10.99.194/FUZZ -w /usr/share/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt -fc 403 -fs 0
#-fs to filter size 0

ffuf -u http://10.10.99.194/FUZZ -w /usr/share/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt -fr '/\..*'
#-fr to filter regex, match files beginning with dot
```

* Fuzzing parameters:

```shell
ffuf -u 'http://10.10.63.223/sqli-labs/Less-1/?FUZZ=1' -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fw 39
#to find vulnerable parameters
#-fw is for filtering response based on number of words

#we can also fuzz the values for parameters

for i in {0..255}; do echo $i; done | ffuf -u 'http://10.10.63.223/sqli-labs/Less-1/?id=FUZZ' -c -w - -fw 3
#the initial part is to generate numbers from 1 to 255
#ffuf command reads the numbers and fuzzes using the numbers as a wordlist
#the -w - option allows it to read wordlist from stdout
#can also use 'seq 0 255' to make it shorter

#to brute-force login pages
ffuf -u http://10.10.63.223/sqli-labs/Less-11/ -c -w /usr/share/seclists/Passwords/Leaked-Databases/hak5.txt -X POST -d 'uname=Dummy&passwd=FUZZ&submit=Submit' -fs 1435 -H 'Content-Type: application/x-www-form-urlencoded'
#-X is for specifying POST method
#-d is for data, where FUZZ is used for password
#-H is for header type

ffuf -u http://FUZZ.mydomain.com -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
#subdomain enumeration

ffuf -u http://mydomain.com -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.mydomain.com' -fs 0
#vhost enumeration
#use host HTTP header, as that might be accepted by server

ffuf -u http://10.10.63.223/ -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -x http://127.0.0.1:8080
#to send ffuf traffic through proxy (can be used for BurpSuite plugins)
```
