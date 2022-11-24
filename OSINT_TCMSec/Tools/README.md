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

## OSINT Automation

## Report Writing
