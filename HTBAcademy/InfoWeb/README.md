# Information Gathering - Web

1. [Passive Information Gathering](#passive-information-gathering)
1. [Active Information Gathering](#active-information-gathering)
1. [Skills Assessment](#skills-assessment)

## Passive Information Gathering

* ```whois``` - TCP-based transaction-oriented query-response protocol listening on TCP/43 by default; used for querying DBs containing domain names, IPs and other info.

  ```shell
  whois facebook.com
  # gives lot of essential info
  ```

* DNS info:

  ```shell
  nslookup facebook.com
  # to check if target uses hosting providers
  # we can use whois against the IP

  dig facebook.com @1.1.1.1
  # add nameserver
  ```

  ```shell
  # querying A records for subdomain
  nslookup -query=A www.facebook.com

  dig a www.facebook.com @1.1.1.1

  # querying PTR records for IP
  nslookup -query=PTR 31.13.92.36

  dig -x 31.13.92.36 @1.1.1.1

  # querying ANY existing records
  nslookup -query=ANY google.com

  dig any google.com @8.8.8.8

  # querying TXT records
  nslookup -query=TXT facebook.com

  dig txt facebook.com @1.1.1.1

  # querying MX records
  nslookup -query=MX facebook.com

  dig mx facebook.com @1.1.1.1
  ```

* Passive subdomain enumeration:

  * [VirusTotal](https://www.virustotal.com) - search for a domain and go to 'Relations'

  * Certificate Transparency:

    ```shell
    export TARGET="facebook.com"

    # enumerate subdomains and store in file
    curl -s "https://crt.sh/?q=${TARGET}&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u > "${TARGET}_crt.sh.txt"
    ```
  
  * [TheHarvester](https://github.com/laramies/theHarvester):

    ```shell
    vim sources.txt
    # include passive search modules like baidu, crtsh, urlscan
    # full list found in github repo

    export TARGET="facebook.com"

    cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done
    # extracts subdomains from given sources

    cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "${TARGET}_theHarvester.txt"
    # extract and sort subdomains

    cat facebook.com_*.txt | sort -u > facebook.com_subdomains_passive.txt
    # put all subdomains in one file
    ```

* Passive infra identification:

  * [Netcraft](https://www.netcraft.com/)
  * [Internet Archive](https://archive.org/)
  * [waybackurls](https://github.com/tomnomnom/waybackurls)

## Active Information Gathering

* Active infra identification:

  ```shell
  curl -I "http://192.168.10.10"
  # to fingerprint web servers from response headers
  # check for headers such as X-Powered-By and Cookies
  ```

  ```shell
  whatweb -a3 https://www.facebook.com -v
  # used to recognize web tech used
  # -a3 for aggression level 3 and -v for verbose
  
  # on browser, we can use Wappalyzer too
  ```

  ```shell
  # tool to check if WAF (web app firewall) is used
  wafw00f -v https://www.tesla.com

  # tools like aquatone and eyewitness can be used
  # to automate taking screenshots of subdomains
  ```

* Active subdomain enumeration:

  * Zone transfers:

    ```shell
    # used for secondary DNS server to receive info from primary DNS server

    # identify nameserver
    nslookup -type=NS zonetransfer.me

    # perform zone transfer using ANY and AXFR
    nslookup -type=any -query=AXFR zonetransfer.me nsztm1.digi.ninja
    # extracts required info
    ```
  
  * gobuster:

    ```shell
    # for example, during previous enumeration
    # we found subdomains in format lert-api-shv-{NUMBER}-sin6.facebook.com and atlas-pp-shv-{NUMBER}-sin6.facebook.com

    # create patterns file, -n for linebreak
    echo "lert-api-shv-{GOBUSTER}-sin6\natlas-pp-shv-{GOBUSTER}-sin6" > patterns.txt

    export TARGET="facebook.com"
    export NS="d.ns.facebook.com"
    export WORDLIST="numbers.txt"
    # wordlist for numbers

    # use dns module with custom dns server -r
    # -d for target domain and -p to pattern wordlist
    gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"
    ```
  
  * Challenge:

    ```shell
    # map given IP to given domain in /etc/hosts
    # we need to find FQDN for given domain

    dig inlanefreight.htb @10.129.5.119
    # query subdomain

    dig a inlanefreight.htb @10.129.5.119
    # query A records

    dig -x inlanefreight.htb @10.129.5.119
    # query PTR records

    dig any inlanefreight.htb @10.129.5.119
    # query ANY records
    # ns.inlanefreight.htb
    ```

    ```shell
    # find zones
    # do not forget to add ns.inlanefreight.htb to /etc/hosts

    nslookup -type=any -query=AXFR inlanefreight.htb ns.inlanefreight.htb
    # gives list of domains
    # includes two zones inlanefreight.htb and root.inlanefreight.htb

    # to check if zone transfer is possible, use each domain and test
    dig axfr admin.inlanefreight.htb @10.129.5.119
    # check for all subdomains
    # one of the subdomains contains the flag in TXT record
    # also includes other FQDNs and IPs

    # find total number of A records from all zones
    dig axfr inlanefreight.htb @10.129.5.119
    dig axfr internal.inlanefreight.htb @10.129.5.119
    ```

* Virtual hosts:

  * vHosts allow several websites to be hosted on a single server; it can be IP-based (host with multiple network interfaces, and so, IPs), or name-based (domain names separated using diff folders)

  ```shell
  # vhost discovery
  # do not forget to map vhost to IP in /etc/hosts
  
  ffuf -s -w /usr/share/seclists/Discovery/DNS/namelist.txt -u http://www.inlanefreight.htb -H "HOST: FUZZ.inlanefreight.htb"
  # check size to be filtered

  ffuf -s -w /usr/share/seclists/Discovery/DNS/namelist.txt -u http://www.inlanefreight.htb -H "HOST: FUZZ.inlanefreight.htb" -fs 10918
  # continue to add domain names found to hosts file
  ```

* Crawling:

  * We can use a tool like ```ZAP``` and use the Spider option to list all found webpages; we can also use ```ffuf```

  ```shell
  ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt

  # we can also check for sensitive info disclosure

  # extract some keywords from website
  cewl -m5 --lowercase -w wordlist.txt http://192.168.10.10

  ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt:FOLDERS,wordlist.txt:WORDLIST,/usr/share/seclists/Discovery/Web-Content/raft-small-extensions-lowercase.txt:EXTENSIONS -u http://192.168.10.10/FOLDERS/WORDLISTEXTENSIONS
  # if this takes a lot of time
  # we can use a few folders to check - wp-admin, wp-content, wp-includes
  # and a small set of extensions
  ```

## Skills Assessment

  ```shell
  whois githubapp.com
  # to find IANA ID

  dig mx githubapp.com
  # query MX records

  whatweb -a3 https://i.imgur.com -v
  # active infra identification

  # for passive subdomain enumeration, use crt.sh
  ```
