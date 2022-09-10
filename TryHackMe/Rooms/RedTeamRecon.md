# Red Team Recon - Easy

1. [Built-in Tools](#built-in-tools)
2. [Advanced Searching](#advanced-searching)
3. [Specialized Search Engines](#specialized-search-engines)
4. [Recon-ng](#recon-ng)
5. [Maltego](#maltego)

## Built-in Tools

```shell
whois thmredteam.com
#whois is a request and response protocol
#queries whois server to provide domain names saved records

nslookup clinic.thmredteam.com
#dns queries

dig @1.1.1.1 clinic.thmredteam.com
#alt tool for dns queries

host clinic.thmredteam.com
#alt tool for dns queries

traceroute clinic.thmredteam.com
#discover hops between our system and target host
```

```markdown
1. When was thmredteam.com created (registered)? - 2021-09-24

2. To how many IPv4 addresses does clinic.thmredteam.com resolve? - 2

3. To how many IPv6 addresses does clinic.thmredteam.com resolve? - 2
```

## Advanced Searching

* [Advanced](https://support.google.com/websearch/answer/2466433) [Googling](https://www.exploit-db.com/google-hacking-database)

```markdown
1. How would you search using Google for xls indexed for http://clinic.thmredteam.com? - filetype:xls site:clinic.thmreadteam.com

2. How would you search using Google for files with the word passwords for http://clinic.thmredteam.com? - passwords site:clinic.thmreadteam.com
```

## Specialized Search Engines

* WHOIS and DNS related:

  * [ViewDNS.info](https://viewdns.info/)
  * [Threat Intelligence Platform](https://threatintelligenceplatform.com/)

* Specialized search engines:

  * [Censys](https://search.censys.io/)
  * [Shodan](https://www.shodan.io/)

```markdown
1. What is the shodan command to get your Internet-facing IP address? - shodan myip
```

## Recon-ng

```shell
recon-ng
#osint framework

workspaces create thmredteam
#create new workspace for investigation

db schema
#check table names in database

db insert domains
#insert domain name into domains table
#enter domain name on prompt

marketplace search virustotal
#search for modules containing 'virustotal'

marketplace search
#list of all modules

marketplace search domains-

marketplace info google_site_web
#view info about module

marketplace install google_site_web
#installs module

modules search
#view all installed modules

modules load viewdns_reverse_whois
#load module

options list
#view options

options set Name thmredteam.com
#set option value

run
#run the module

exit
```

```markdown
1. How do you start recon-ng with the workspace clinicredteam? - recon-ng -w clinicredteam

2. How many modules with the name virustotal exist? - 2

3. There is a single module under hosts-domains. What is its name? - migrate_hosts

4. censys_email_address is a module that “retrieves email addresses from the TLS certificates for a company.” Who is the author? - Censys Team
```

## Maltego

* Maltego is a combo of mind-mapping and OSINT.

* In Maltego, a transform is code that would query an API to get info related to a specific entity.

```markdown
1. What is the name of the transform that queries NIST’s National Vulnerability Database? - NIST NVD

2. What is the name of the project that offers a transform based on ATT&CK? - MISP Project
```
