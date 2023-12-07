# Reconnaissance

* Fingerprinting web technologies:

  * [BuiltWith](https://builtwith.com/)
  * [Wappalyzer](https://www.wappalyzer.com/)
  * [Security Headers](https://securityheaders.com)

* Directory enumeration:

  ```shell
  ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://10.0.0.10/FUZZ

  dirb http://10.0.0.10
  # scans recursively by default

  # can use other tools as well like dirbuster and gobuster
  ```

* Subdomain enumeration:

  ```shell
  # we can use resources like Google or crt.sh on web
  # but they give limited results

  subfinder -d azena.com -o azena.txt
  
  assetfinder azena.com

  assetfinder azena.com | grep azena.com | sort -u > azena-subdomains.txt
  # only print unique and required subdomains

  amass enum -d azena.com >> azena-subdomains.txt

  # after gathering all subdomains
  # need to check if they are up or not
  cat azena-subdomains.txt | grep azena.com | sort -u | httprobe -prefer-https | grep https > azena-alive.txt

  mkdir azenapics

  # screenshot automation for each page
  # need to remove 'https://' string from final subdomains file for gowitness to work
  gowitness file -f azena-alive.txt -P azenapics --no-http
  ```
