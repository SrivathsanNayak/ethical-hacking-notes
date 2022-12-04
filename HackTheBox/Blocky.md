# Blocky - Easy

```shell
nmap -T4 -p- -A -Pn -v blocky.htb

ftp blocky.htb
#anonymous login does not work

cmseek
#check blocky.htb

feroxbuster -u http://blocky.htb -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500 --silent

ssh notch@blocky.htb
#use phpmyadmin password

cat user.txt

sudo -l
#we can run all commands as all users

sudo cat /root/root.txt
```

* Open ports & services:

  * 21 - ftp - ProFTPD 1.3.5a
  * 22 - ssh - OpenSSH 7.2p2 (Ubuntu)
  * 80 - http - Apache httpd 2.4.18
  * 25565 - minecraft - Minecraft 1.11.2

* We can start by enumerating ```ftp```, but anonymous login is not allowed.

* The webpage on port 80 is a blog page for 'blockycraft'; it does not contain anything important.

* We can see that it is using ```Wordpress```; to detect the exact version, we can use ```cmseek``` tool.

* Using ```cmseek```, we find out that the webpage is using WordPress 4.8; it also enumerates the username 'notch'.

* Now, using ```wfuzz``` to check for subdomains or using ```wpscan``` to bruteforce login does not work.

* We can check for any hidden directories using ```feroxbuster```.

* This gives us a lot of directories, but the ones we can access and have clues include:

  * /wiki
  * /wp-includes
  * /plugins
  * /phpmyadmin

* In the /plugins page, we have two .jar files; we can download and inspect them.

* We can view the contents of a .jar file using the ```JD-GUI``` tool.

* Now, opening the 'BlockyCore.jar' file in ```JD-GUI```, we can view ```BlockyCore.class```, which contains the creds "root:8YsqfCTnvxAUeduzjNSXe22"

* Using these creds, we can log into the /phpmyadmin login page.

* In ```phpmyadmin```, in the ```wordpress``` database, we have the 'wp_users' table, which includes the password hash for 'notch'.

* We can attempt to crack this hash using ```hashcat```, but we do not get any password.

* We can use the password for 'phpmyadmin' to log into SSH as 'notch' - this surprisingly works.

* Checking ```sudo -l```, we can see that all commands can be run as all users - so we can get both user flag and root flag.

```markdown
1. User flag - 409192ab09bf68029f28aa6a48961c9f

2. Root flag - 7d4a68e2e581758c980bd14e56f05856
```
