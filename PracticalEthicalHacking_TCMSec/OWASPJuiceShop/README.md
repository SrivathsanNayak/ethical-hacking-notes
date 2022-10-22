# OWASP Juice Shop

1. [Installation](#installation)
2. [SQL Injection](#sql-injection)
3. [Broken Authentication](#broken-authentication)
4. [Sensitive Data Exposure](#sensitive-data-exposure)
5. [XML External Entities (XXE)](#xml-external-entities-xxe)
6. [Broken Access Control](#broken-access-control)
7. [Security Misconfiguration](#security-misconfiguration)
8. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)

## Installation

```shell
#install docker
sudo apt-get update && sudo apt-get install -y docker.io

#pull docker image
sudo docker pull bkimminich/juice-shop

#run docker image
sudo docker run --rm -p 3000:3000 bkimminich/juice-shop
#now we can access website on <http://127.0.0.1:3000>
```

* References (to be used throughout this section):

  * [Pwning OWASP Juice Shop](https://pwning.owasp-juice.shop/)
  * [OWASP Juice Shop GitHub Repo](https://github.com/juice-shop/juice-shop)

* While using Burp Suite for intercepting requests, we can add the target website to scope under the Target section, and enable 'show only in-scope items under 'Filter settings'.

* Similarly, under 'Options' in Proxy section, we can enable 'And URL is in target scope' for both 'Intercept Client Requests' and 'Intercept Server Responses' for granular control.

* The scoreboard for OWASP Juice shop can be found at <http://localhost:3000/#/score-board>

## SQL Injection

* Common SQL verbs include ```SELECT```, ```INSERT```, ```DELETE```, ```UPDATE```, ```DROP``` and ```UNION```; other common terms include ```WHERE```, ```AND/OR/NOT```, ```ORDER BY```.

* SQLi Login Bypass:

  ```markdown
  Navigate to /login, intercept the login request with dummy creds using Burp Suite.

  In Burp Suite, send the request to Repeater; we can edit the request here.

  We will be editing the creds for SQLi, currently it looks like this:

    {"email":"user","password":"pwd"}

  If we add a single-quote at the end of user, we will get an error; errors give info about the DB:

    {"email":"user'","password":"pwd"}

  For basic SQLi, we can append 'OR 1=1; --' to the username, which ends the username prematurely with single-quote, and then uses TRUE statement with OR so that it is always TRUE.

    {"email":"user' OR 1=1; --","password":"pwd"}

  This logs us in as admin of Juice Shop.
  ```

* SQLi Defenses:

  * Parameterized statements
  * Sanitizing input

## Broken Authentication

* Due to poor design & implementation of identity & access controls.

* Includes weaknesses such as credential stuffing, default/weak passwords, ineffective MFA and session fixation.

* A simple example of broken authentication in Juice Shop is logging in with the credentials ```admin@juice-sh.op:admin123```.

* Broken authentication defenses:

  * Implement MFA
  * Proper password policies
  * Limit failed login attempts
  * New random session ID after login

## Sensitive Data Exposure

* Due to lack of encryption, weak password hashing storage techniques, and transmission of data in cleartext.

  ```shell
  #example of checking SSL ciphers
  nmap --script=ssl-enum-ciphers -p 443 tesla.com
  #this checks the level of encryption

  #we can also check security headers using securityheaders.com
  ```

* Sensitive data exposure defenses:

  * Identify & apply controls to sensitive data
  * Do not store unnecessary data
  * Encrypt all data
  * Store passwords using strong hashing functions

## XML External Entities (XXE)

* XXE abuses systems that pass XML input; attacks include DoS, local file disclosure, RCE, etc.

* XXE is carried out by exploiting the SYSTEM parameter.

## Broken Access Control

* Due to lack of automated detection and absence of access control; detected usually with the help of manual means.

* Common vulnerabilities include bypassing access control checks, viewing other users' records, privilege escalation and metadata manipulation.

* Broken access control defenses:

  * Deny by default, except for public resources
  * Disable web server directory listing
  * Implement access control mechanisms

## Security Misconfiguration

* Exploiting unpatched flaws, accessing default accounts and unprotected directories are a few examples of exploiting security misconfigurations.

* It is due to lack of security hardening, usage of default creds, or disabled security features.

* Security misconfiguration defenses:

  * Automation of security
  * Minimal platform without unnecessary features
  * Verify effectiveness of configurations

## Cross-Site Scripting (XSS)

* Types of XSS:

  * Reflected XSS
  * Stored XSS
  * DOM XSS

* An example of a simple payload for reflected XSS is ```<iframe src="javascript:alert(`xss`)">```; this can be inserted as input or as query in URL.

* XSS defenses:

  * Encoding
  * Filtering
  * Validating
  * Sanitization
