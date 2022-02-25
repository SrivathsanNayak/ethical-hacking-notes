# Reconnaissance

* Passive recon steps for Web/Host:

    1. Target validation
    2. Finding subdomains
    3. Fingerprinting
    4. Data breaches

* We can use [BugCrowd](https://www.bugcrowd.com/) as a platform for practicing recon.

* Tools for discovering email addresses:

  * [Hunter](https://hunter.io/)
  * [Phonebook.cz](https://phonebook.cz/)
  * [VoilaNorbert](https://www.voilanorbert.com/)
  * [Clearbit Connect](https://connect.clearbit.com/)
  * [Email Hippo](https://tools.emailhippo.com/)

* [DeHashed](https://www.dehashed.com/) can be used to find breached credentials.

* Hunting subdomains:

```shell
apt install sublist3r #tool for finding subdomains

sublist3r -d tesla.com
```

* [crt.sh](https://crt.sh/) can be used for certificate fingerprinting.

* Tools such as [BuiltWith](https://builtwith.com/) and [Wappalyzer](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/) can be used for identifying technologies used in a website. ```whatweb``` can be used as an alternative, and can be used from the Kali Linux terminal itself.

* ```Burp Suite``` can be used for information gathering by intercepting requests.

* [Google Advanced Search](https://ahrefs.com/blog/google-advanced-search-operators/) can be used for efficient Googling.
