# Pre Security

1. [Networking](#networking)
2. [Web](#web)
3. [Linux](#linux)
4. [Windows](#windows)

## Networking

---

* A public IP address is used to identify a device on the Internet, whereas a private address is used to identify a device amongst other devices.

* Ping uses ICMP (Internet Control Message Protocol) packets to determine the performance of a connection between devices.

* Addresses in subnetting:

  * Network address - identifies the start of actual network; to identify network's existence.
  * Host address - IP address is used to identify device on subnet.
  * Default gateway - special address assigned to device on network, capable of sending info to another network.

* ARP (Address Resolution Protocol) - allows device to associate its MAC address with IP address on network.

* DHCP (Dynamic Host Configuration Protocol) - Discover, Offer, Request and ACK.

* OSI Model (Open Systems Interconnection Model) -

  * Layer 7 - Application layer - protocols and rules are in place to determine how user should interact with data sent or received.
  * Layer 6 - Presentation layer - acts as a translator for data to and from layer 7; data encryption occurs.
  * Layer 5 - Session layer - creates a connection to the other computer that the data is destined for; syncs the two computers.
  * Layer 4 - Transport layer - TCP and UDP.
  * Layer 3 - Network layer - rerouting and reassembling of data takes place; OSPF (Open Shortest Path First) and RIP (Routing Information Protocol).
  * Layer 2 - Data link layer - focuses on physical addressing of transmission.
  * Layer 1 - Physical layer - physical components of hardware used in networking.

* Frame - piece of information at layer 2.

* Packet - piece of information, encapsulated with IP address, at layer 3.

* Layers of TCP/IP Protocol - Application, Transport, Internet and Network interface.

* TCP three-way handshake - SYN, SYN/ACK, ACK.

* Port forwarding opens specific ports; on the other hand, firewalls determine if traffic can travel across these ports.

* VPN (Virtual Private Networks) allow devices on separate networks to communicate securely by creating a dedicated path between each other over the Internet (tunneling).

## Web

---

* TLD (Top-Level Domain) - rightmost part of domain name; gTLD (generic TLD) and ccTLD (country code TLD).

* Subdomain - leftmost part of domain name.

* Second-level domain - core part of domain name; limited to 63 chars; domain name cannot be more than 253 chars.

* DNS (Domain Name System) Record types:

  * A Record - resolve to IPv4 addresses.
  * AAAA Record - resolve to IPv6 addresses.
  * CNAME Record - resolve to another domain name.
  * MX Record - resolve to address of servers that handle the email for queried domain; includes priority flag.
  * TXT Record - free text fields where text-based data can be stored.

* DNS Request Procedure:

  1. When domain name is requested, the computer first checks its local cache for previous results; else a request to our recursive DNS server is made.
  2. Recursive DNS server (usually provided by ISP) includes a local cache for recently looked up domain names. If result found locally, it is sent back to computer and request ends here; else request is made to root DNS servers.
  3. Internet root DNS servers redirect us to correct TLD server depending on request.
  4. TLD server holds records for where to find authorative server (nameserver) to answer the DNS request.
  5. Nameserver responsible for storing DNS records for a particular domain name. Depending on record type, DNS record is sent back to recursive DNS server, where local copy is cached for future requests, and relayed back to original client. DNS Records have TTL (Time To Live) value, so local copies save DNS requests.

* HTTP - set of rules used for communicating with web servers for transmission of webpage data.

* HTTPS (HyperText Transfer Protocol Secure) - secure version of HTTP; encrypted.

* HTTP Status Code ranges:

  * 100-199 - Information response
  * 200-299 - Success
  * 300-399 - Redirection
  * 400-499 - Client errors
  * 500-599 - Server errors

* Common HTTP Status Codes:

  * 200 - OK; request completed successfully.
  * 201 - Created; resource has been created.
  * 301 - Permanent Redirect.
  * 302 - Temporary Redirect.
  * 400 - Bad Request; something wrong or missing in request.
  * 401 - Not Authorised; not logged in.
  * 403 - Forbidden.
  * 404 - Page Not Found.
  * 405 - Method Not Allowed.
  * 500 - Internal Service Error.
  * 503 - Service Unavailable.

* Common request headers:

  * Host - website required from server.
  * User-Agent - browser software and version number.
  * Content-Length - length of data to be expected.
  * Accept-Encoding - types of compression methods supported by browser.
  * Cookie - data sent to server to remember info.

* Common response headers:

  * Set-Cookie - Info to store; gets sent back to web server on each request.
  * Cache-Control - How long to store content of response in browser cache before requested again.
  * Content-Type - type of data being returned.
  * Content-Encoding - Method used to compress data.

* Web server - software that listens for incoming connections and then utilises the HTTP protocol to deliver web content to its clients.

## Linux

---

* ssh:

```shell
ssh tryhackme@10.10.19.63 #here, username is tryhackme, with IP address of machine 
```

* su:

```shell
su user2 #switch user
```

* wget:

```shell
wget https://www.google.com/robots.txt #download files from web via HTTP
```

* scp:

```shell
scp imp.txt ubuntu@192.168.1.30:/home/ubuntu/transfer.txt
#scp or secure copy is used to transfer files from host using SSH
#this is for copying imp.txt from our machine to remote machine, where we want to save it as transfer.txt

scp ubuntu@192.168.1.30:/home/ubuntu/docs.txt notes.txt
#to copy docs.txt from remote machine to our machine as notes.txt
```

* http.server:

```shell
python3 -m http.server
#to start http.server module; turns our computer into a web server to serve our files

#to download a file from our webserver, we can use wget
wget http://127.0.0.1:8000/file
```

* ps:

```shell
ps #view a list of running processes

ps aux #more detailed view, including other users' processes
```

* systemctl:

```shell
sudo systemctl start apache2
#systemctl allows us to interact with systemd process (or daemon)
#the four options with systemctl for any service are - start, stop, enable, disable
```

* To push a process into background, use ```&``` at end of command or press ```Ctrl+Z``` (stops the process).

* To bring a process to foreground, use ```fg```.

* crontab:

```shell
#crontab is a special file with formatting recognized by 'cron' process for automation
0 *12 * * * cp -R /home/username1/Documents /var/backups/ #min hour dom mon dow cmd - format
#this is used to backup Documents every 12 hours

crontab -e
#to edit crontabs
```

## Windows

---

* NTFS (New Technology File System) - File system used in modern versions of Windows; can set permissions to grant/deny access to files; journaling file system; supports EFS (Encryption File System) and ADS (Alternate Data Streams).

* The NTFS permissions are - full control, modify, read & execute, list folder contents, read, and write.

* Environment variables - store information about OS environment; includes OS path, number of processors used, and location of temporary folders.

* System variable for Windows folder - %windir%

* ```lusrmgr.msc``` can be used to check and control Users and Groups.

* System Configuration (MSConfig) - utility for advanced troubleshooting and diagnosing startup issues.

* Task Manager (taskmgr) - to manage startup items.

* Command Prompt (cmd):

```shell
hostname #outputs computer name

whoami #name of logged-in user

ipconfig #show network address settings

ipconfig /? #get manual page for ipconfig
#use cls to clear screen

netstat #protocol stats and current tcp/ip connections
```

* Windows Registry (regedit) - central hierarchical database; stores info required to configure system for users, applications and hardware devices.

* Volume Shadow Copy Service (VSS) - creates a consistent shadow copy (snapshot) of data to be backed up; copies stored on System Volume Information folder on each drive with protection enabled.
