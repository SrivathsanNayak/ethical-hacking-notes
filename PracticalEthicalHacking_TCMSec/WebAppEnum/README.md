# Web Application Enumeration

* [assetfinder](https://github.com/tomnomnom/assetfinder):

```shell
#subdomain finder tool
./assetfinder tesla.com >> tesla-subs.txt

./assetfinder --subs-only tesla.com
#only subdomains
```

* [Amass](https://github.com/OWASP/Amass):

```shell
#another subdomain finder tool
amass enum -d tesla.com
```

* [httprobe](https://github.com/tomnomnom/httprobe):

```shell
#tool for finding alive domains
cat tesla.com/recon/final.txt | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443'
#checks if subdomain responds
#then formats and prints it
```

* [gowitness](https://github.com/sensepost/gowitness):

```shell
#screenshot utility
gowitness single https://tesla.com
#can take screenshot of multiple websites as well
```

* Custom script for filtering subdomains:

```shell
#!/bin/bash

url=$1

if [ ! -d "$url" ];then
    mkdir $url
fi

if [ ! -d "$url/recon" ];then
    mkdir $url/recon
fi

echo "[+] Harvesting subdomains with asset-finder..."
./assetfinder $url >> $url/recon/assets.txt
cat $url/recon/assets.txt | grep $1 >> $url/recon/final.txt
rm $url/recon/assets.txt

echo "[+] Harvesting subdomains with Amass..."
amass enum -d $url >> $url/recon/f.txt
sort -u $url/recon/f.txt >> $url/recon/final.txt
rm $url/recon/f.txt

echo "[+] Probing for alive subdomains..."
cat $url/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> $url/recon/alive.txt

```

```shell
chmod +x subdomain-script.sh

./subdomain-script.sh tesla.com
#creates file final.txt containing all filtered subdomains
```

* [Reference script for subdomain enumeration](https://github.com/Gr1mmie/sumrecon/blob/master/sumrecon.sh)
