# Ignition - Very Easy

```shell
rustscan -a 10.129.195.18 --range 0-65535 --ulimit 5000 -- -sV

sudo vim /etc/hosts
#add ignition.htb

gobuster dir -u http://ignition.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,bak -t 50
```

```markdown
Open ports & services:

  * 80 - http - nginx 1.14.2

On attempting to visit the webpage, we get an error; by using Gobuster we get the same error (status code 302).

The website expects to be accessed by the virtual hostname ignition.htb, so we will have to add this to /etc/hosts.

Now, we can start directory enumeration using Gobuster to look for hidden directories.

We can access Magento login page at /admin, we can try default creds here.

As admin:admin does not work, and furthermore, since we cannot brute-force this page, we will have to try common passwords for username 'admin'.

As the minimum password requirements for Magento is both letters and numbers - we will have to look for passwords like 'password123'.

Eventually, we find out login is possible with admin:qwerty123

We get the flag on login.
```

1. Which service version is found to be running on port 80? - nginx 1.14.2

2. What is the 3-digit HTTP status code returned when you visit <http://10.129195.18/>? - 302

3. What is the virtual host name the webpage expects to be accessed by? - ignition.htb

4. What is the full path to the file on a Linux computer that holds a local list of domain name to IP address pairs? - /etc/hosts

5. What is the full URL to the Magento login page? - http://ignition.htb/admin

6. What password provides access as admin to Magento? - qwerty123

7. Submit root flag - 797d6c988d9dc5865e010b9410f247e0
