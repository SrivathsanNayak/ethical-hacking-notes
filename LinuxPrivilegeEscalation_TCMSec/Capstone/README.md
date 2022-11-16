# Capstone Challenge

1. [Lazy Admin](#lazy-admin)
2. [Anonymous](#anonymous)
3. [Tomghost](#tomghost)
4. [ConvertMyVideo](#convertmyvideo)
5. [Brainpan1](#brainpan1)

## Lazy Admin

* We have two open ports - 22 and 80 - and we can begin by enumerating the webpage on port 80.

* The webpage is a default landing page for Apache; we can use ```feroxbuster``` to enumerate the directories, which gives us /content directory.

* The page is for SweetRice CMS; we can search for exploits for this on Exploit-DB.

* We can run directory brute-forcing tools for the /content page; we get a lot of directories in return as it is a CMS.

* One of the directories /content/inc/mysql_backup, contains a .sql backup file which contains the MD5 hash of an admin user 'manager'.

* The hash can be cracked using online services; and this gives us access to the admin dashboard of SweetRice.

* Now, we have an exploit on Exploit-DB, which helps us in uploading a shell file in the directory /content/attachment

* By modifying and running the Python script, we are able to add a .phtml reverse-shell to /content/attachment

* After setting up a listener and activating the shell, we get reverse-shell as 'www-data'.

* Using ```sudo -l```, we can see that we can run /usr/bin/perl for a particular Perl script as sudo.

* Inspecting the Perl script, we can see that it runs another .sh script in /etc

* By checking the file permissions, we can see that the script in /etc is editable by us, so we can edit it to launch a reverse-shell using the reverse-shell one-liner.

* After setting up another listener, we can run the command to execute the Perl script as sudo; we get shell as root on our listener.

## Anonymous

* FTP anonymous login is allowed, and we also have SMB shares that can be accessed.

* Logging into FTP, we have a scripts folder with a few files; we can transfer all files using ```mget```.

* Now, the clean.sh script in the scripts folder is writable by our user; so we can overwrite it by adding a reverse-shell one-liner.

* After setting up our listener, we can upload the modified clean.sh script to the scripts directory.

* In a minute, we get shell as 'namelessone'.

* Using the command ```find / -type f -perm -04000 -ls 2>/dev/null```, we can find files with SUID bit set.

* /usr/bin/env has SUID bit set, and there is an exploit for it on GTFObins.

* Following the exploit for 'env', we get root access.

## Tomghost

* Ports 22, 8009 and 8080 are open; the machine is using Apache Tomcat/9.0.30 on port 8080.

* On port 8009, we have Apache Jserv (protocol v1.3).

* We can Google the version numbers and check for exploits; we get results for the Ghostcat vulnerability.

* We get a script on Exploit-DB for the Ghostcat vulnerability.

* On running the Python script, we get the ```WEB-INF/web.xml``` file.

* The output includes the creds for the 'skyfuck' user; we can log into SSH using these creds.

* Checking the files, we have a .asc file and a .pgp file; we can transfer it to attacker machine using ```scp```.

* The passphrase for .pgp file can be found by decrypting the .asc file - we can do this using ```gpg2john``` to get a hash, and then cracking the hash using ```john```.

* This gives us the passphrase, which can be used to decrypt the .pgp file; this gives us creds for another user 'merlin'.

* We can log into SSH as 'merlin' this time.

* Checking for privesc, running ```sudo -l```, we can see that 'zip' can be run as sudo.

* Getting the exploit from GTFObins and running it, we get root access.

## ConvertMyVideo

## Brainpan1
