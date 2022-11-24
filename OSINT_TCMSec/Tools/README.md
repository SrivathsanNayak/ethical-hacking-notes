# Tools

1. [OSINT Tools](#osint-tools)
2. [OSINT Automation](#osint-automation)
3. [Report Writing](#report-writing)

## OSINT Tools

* [Trace Labs OSINT VM](https://www.tracelabs.org/initiatives/osint-vm) is used for the setup.

* Image and location OSINT:

```shell
sudo apt install libimage-exiftool-perl
#install exiftool

exiftool dog.jpg
#prints metadata, location info
```

* Hunting emails & breached data:

```shell
theHarvester --help
#tool for hunting data

theHarvester -d tesla.com -b all -l 500
#search on all browsers, limiting to 500 searches

#this gives us subdomains, emails
```

```shell
h8mail -t shark@tesla.com -bc "/opt/breach-parse/BreachCompilation/" -sk
#similar to theHarvester tool
#needs API keys for services
```

* Username and account OSINT:

```shell
whatsmyname -u thecybermentor

sherlock thecybermentor
```

* Phone number OSINT:

```shell
phoneinfoga --help

phoneinfoga scan -n 14082492815

phoneinfoga serve -p 8080
#hosts a web interface
#we can scan phone numbers here as well
```

* Social media OSINT:

```shell
#upgrade twint
pip3 install --upgrade -e git+https://github.com/twintproject/twint.git@origin/master#egg=twint

pip3 install --upgrade aiohttp_socks

twint -u cybermentor
#scrapes tweets for twitter user

twint -u cybermentor -s dog
#-s for string in tweet

#we can download and use other osint tools as well
```

* Website OSINT:

```shell
#we can use Wappalyzer extension in browser

whois tcm-sec.com
```

```shell
#config & install a few tools

#in root shell, as sudo

nano ~/.bashrc
#add following lines to the file (uncomment it)
#export GOPATH=$HOME/go
#export GOROOT=/usr/lib/go
#export PATH=$PATH:$GOROOT/bin:$GOPATH/bin

source ~/.bashrc
#enable changes

#install the tools
#subfinder, assetfinder, httprobe, amass, gowitness
```

```shell
subfinder -d tcm-sec.com
#finds subdomains

assetfinder tcm-sec.com | grep tcm-sec.com | sort -u
#finds related websites

amass enum -d tcm-sec.com
#enumerate using amass
```

* OSINT frameworks:

```shell
recon-ng

#inside framework
marketplace search
#search for tools

marketplace install hackertarget

modules load hackertarget

info
#see info for module

options set SOURCE tesla.com

run
#runs the module

show hosts
#tabular form

back
#exit module

#install another module
marketplace install profiler

modules load profiler

info

options set SOURCE thecybermentor

run
#checks for usernames

show profiles

back

#maltego is another osint framework that can be used
```

## OSINT Automation

```shell
#!/bin/bash

#automation for recon tool
#checks whois and find subdomains
#screenshots of alive subdomains

domain=$1
#first argument (input)

#colors
RED="\033[1;31m"
RESET="\033[0m"

#folder structure

info_path=$domain/info
subdomain_path=$domain/subdomains
screenshot_path=$domain/screenshots

if [ ! -d "$domain" ];then
    mkdir $domain
fi

if [ ! -d "$info_path" ];then
    mkdir $info_path
fi

if [ ! -d "$subdomain_path" ];then
    mkdir $subdomain_path
fi

if [ ! -d "$screenshot_path" ];then
    mkdir $screenshot_path
fi

#using colored output
echo -e "${RED} [+] Using whois...${RESET}"
whois $domain > $info_path/whois.txt

echo -e "${RED} [+] Checking subdomains...${RESET}"
subfinder -d $domain > $subdomain_path/found.txt

echo -e "${RED} [+] Running assetfinder...${RESET}"
assetfinder $domain | grep $domain >> $subdomain_path/found.txt

#echo -e "${RED} [+] Running amass. This will take a while...${RESET}"
#amass enum -d $domain >> $subdomain_path/found.txt

echo -e "${RED} [+] Checking alive subdomains...${RESET}"
cat $subdomain_path/found.txt | grep $domain | sort -u | httprobe -prefer-https | grep https | sed 's/https\?:\/\///' | tee -a $subdomain_path/alive.txt
#checks for alive subdomains from found.txt
#and strips the 'https' part for gowitness to work
#tee prints to terminal and saves to file as well

echo -e "${RED} [+] Screenshots of alive domains...${RESET}"
gowitness file -f $subdomain_path/alive.txt -P $screenshot_path/ --no-http
```

## Report Writing

* Key components of OSINT report:

  * Summary
  * Key findings, artefacts
  * Personal info, usernames, emails
  * Technical evidence (detailed)
