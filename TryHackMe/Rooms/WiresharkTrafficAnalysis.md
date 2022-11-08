# Wireshark: Traffic Analysis - Medium

1. [Nmap Scans](#nmap-scans)
2. [ARP Poisoning & Man In The Middle](#arp-poisoning--man-in-the-middle)
3. [Identifying Hosts: DHCP, NetBIOS and Kerberos](#identifying-hosts-dhcp-netbios-and-kerberos)
4. [Tunneling Traffic: DNS and ICMP](#tunneling-traffic-dns-and-icmp)
5. [Cleartext Protocol Analysis: FTP](#cleartext-protocol-analysis-ftp)
6. [Cleartext Protocol Analysis: HTTP](#cleartext-protocol-analysis-http)
7. [Encrypted Protocol Analysis: Decrypting HTTPS](#encrypted-protocol-analysis-decrypting-https)
8. [Bonus: Hunt Cleartext Credentials](#bonus-hunt-cleartext-credentials)
9. [Bonus: Actionable Results](#bonus-actionable-results)

## Nmap Scans

* We can probe Nmap scan behavior on network with the help of Wireshark.

* TCP flags:

  * Only SYN flag - ```tcp.flags == 2```

  * SYN flag is set (rest of the bits are not important) - ```tcp.flags.syn == 1```

  * Only ACK flag - ```tcp.flags == 16```

  * ACK flag is set - ```tcp.flags.ack == 1```

  * Only SYN, ACK flags - ```tcp.flags == 18```

  * SYN and ACK are set - ```(tcp.flags.syn == 1) and (tcp.flags.ack == 1)```

* Filter to get patterns:

  * TCP connect scan - ```tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024```

  * TCP SYN scan - ```tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024```

  * UDP scan - ```icmp.type==3 and icmp.code==3```

* To find UDP ports open in the port range 55-70:

  ```udp.dstport >= 55 and udp.dstport <= 70 and !(icmp.type==3 and icmp.code==3)```

```markdown
1. What is the total number of the "TCP Connect" scans? - 1000

2. Which scan type is used to scan the TCP port 80? - TCP Connect

3. How many "UDP close port" messages are there? - 1083

4. Which UDP port in the 55-70 port range is open? - 68
```

## ARP Poisoning & Man In The Middle

* ARP packets:

  * ARP requests - ```arp.opcode == 1```

  * ARP responses - ```arp.opcode == 2```

  * ARP scanning - ```arp.dst.hw_mac==00:00:00:00:00:00```

  * Possible ARP poisoning detection - ```arp.duplicate-address-detected or arp.duplicate-address-frame```

  * Possible ARP flooding detection - ```((arp) && (arp.opcode == 1)) && (arp.src.hw_mac == target-mac-address)```

* Now, for the given exercise, we first need to find the attacker; we can use the filter for possible ARP poisoning detection.

* This gives us the attacker with MAC address ```VMware_e2:18:b4``` (00:0c:29:e2:18:b4).

* Filter to find number of ARP requests by attacker:

  ```arp.src.hw_mac == 00:0c:29:e2:18:b4 and arp.opcode==1```

* Now, we need to find the IP address of attacker; we know that it would be in the format of 192.168.1.x, looking at the previous ARP filter.

* Looking at HTTP packets, there is a significant amount of activity; we can add destination MAC address as column (from Ethernet section in packet details).

* This shows that for HTTP activity, all destination MAC addresses are the attacker MAC address, and corresponding destination is 192.168.1.12

* Filter to find HTTP packets received by attacker:

  ```http and eth.dst == 00:0c:29:e2:18:b4```

* Filter to find POST requests received by attacker:

  ```eth.dst == 00:0c:29:e2:18:b4 and http.request.method=="POST"```

* Going through the 10 POST requests captured above, we can find 6 username-password entries; we can find the required password and comment in these requests.

```markdown
1. What is the number of ARP requests crafted by the attacker? - 284

2. What is the number of HTTP packets received by the attacker? - 90

3. What is the number of sniffed username&password entries? - 6

4. What is the password of the "Client986"? - clientnothere!

5. What is the comment provided by the "Client354"? - Nice work!
```

## Identifying Hosts: DHCP, NetBIOS and Kerberos

* DHCP analysis (filter packet type, then apply required option as column/filter):

  * DHCP request (contain hostname info) - ```dhcp.option.dhcp == 3```

  * DHCP ACK (accepted requests) - ```dhcp.option.dhcp == 5```

  * DHCP NAK (denied requests) - ```dhcp.option.dhcp == 6```

  * DHCP request options - ```dhcp.option.hostname contains "keyword"```

  * DHCP ACK options - ```dhcp.option.domain_name contains "keyword"```

* NetBIOS (NBNS) analysis:

  * NBNS options - ```nbns.name contains "keyword"```

* Kerberos analysis:

  * User account search - ```kerberos.CNameString contains "keyword"```

  * User account search, filter hostname info - ```kerberos.CNameString contains "keyword" and !(kerberos.CNameString contains "$")```

  * Kerberos protocol version - ```kerberos.pvno == 5```

  * Kerberos realm domain name - ```kerberos.realm contains ".org"```

  * Kerberos service name - ```kerberos.SNameString == "krbtg"```

* Filter DHCP packets with hostname containing "Galaxy":

  ```dhcp.option.hostname contains "Galaxy"```

* Filter NBNS registration requests for workstation "LIVALJM":

  ```nbns.name contains "LIVALJM" and nbns.flags.opcode==5```

* Filter hosts requesting particular IP address:

  ```dhcp.option.requested_ip_address == 172.16.13.85```

* Filter Kerberos requests by username:

  ```kerberos.CNameString contains "u5"```

* Filter Kerberos requests containing hostname:

  ```kerberos.CNameString contains "$"```

```markdown
1. What is the MAC address of the host "Galaxy A30"? - 9a:81:41:cb:96:6c

2. How many NetBIOS registration requests does the "LIVALJM" workstation have? - 16

3. Which host requested the IP address "172.16.13.85"? - Galaxy-A12

4. What is the IP address of the user "u5"? - 10[.]1[.]12[.]2

5. What is the hostname of the available host in the Kerberos packets? - xp1$
```

## Tunneling Traffic: DNS and ICMP

* ICMP analysis:

  * Abnormal packet length - ```data.len > 64 and icmp```

* DNS analysis:

  * Anomalous packets - ```dns contains dnscat```

  * Long DNS addresses with encoded subdomain addresses - ```dns.qry.name.len > 15 and !mdns```

```markdown
1. Investigate the anomalous packets. Which protocol is used in ICMP tunnelling? - SSH

2. Investigate the anomalous packets. What is the suspicious main domain address that receives anomalous DNS queries? - dataexfil[.]com
```

## Cleartext Protocol Analysis: FTP

* FTP analysis (use FTP commands and their response codes for filters):

  * System status - ```ftp.response.code = 211```

  * Entering passive mode - ```ftp.response.code = 227```

  * User login - ```ftp.response.code == 230```

  * Username - ```ftp.request.command == "USER"```

  * Password - ```ftp.request.command == "PASS"``` or ```ftp.request.arg == "password"```

  * List failed login attempts and target usernames (bruteforce signal) - ```(ftp.response.code == 530) and (ftp.response.arg contains "username")```

  * List targets for static password (password spray signal) - ```(ftp.request.command == "PASS" ) and (ftp.request.arg == "password")```

* Filter incorrect login attempts:

  ```ftp.response.code == 530```

* Filter file accessed attempts in FTP (we can follow TCP stream for more details):

  ```ftp.response.code == 213```

```markdown
1. How many incorrect login attempts are there? - 737

2. What is the size of the file accessed by the "ftp" account? - 39424

3. The adversary uploaded a document to the FTP server. What is the filename? - resume.doc

4. The adversary tried to assign special flags to change the executing permissions of the uploaded file. What is the command used by the adversary? - CHMOD 777
```

## Cleartext Protocol Analysis: HTTP

* HTTP analysis:

  * HTTP request methods - ```http.request.method == "GET"```

  * HTTP response status code 200 OK - ```http.response.code == 200```

  * HTTP user agent - ```http.user_agent contains "nmap"```

  * HTTP request URI - ```http.request_uri contains "admin"```

  * HTTP parameters - ```http.server contains "apache"```

* User agent analysis:

  * Global search - ```http.user_agent```

  * Detect audit tools - ```(http.user_agent contains "sqlmap") or (http.user_agent contains "Nmap") or (http.user_agent contains "Wfuzz") or (http.user_agent contains "Nikto")```

* Log4j analysis:

  * HTTP POST request - ```http.request.method == "POST"```

  * Cleartext patterns - ```(ip contains "jndi") or (ip contains "Exploit")``` or ```(frame contains "jndi") or (frame contains "Exploit")```

```markdown
1. Investigate the user agents. What is the number of anomalous  "user-agent" types? - 6

2. What is the packet number with a subtle spelling difference in the user agent field? - 52

3. Locate the "Log4j" attack starting phase. What is the packet number? - 444

4. Locate the "Log4j" attack starting phase and decode the base64 command. What is the IP address contacted by the adversary? - 62[.]210[.]130[.]250
```

## Encrypted Protocol Analysis: Decrypting HTTPS

* HTTPS analysis:

  * HTTP requests - ```http.request```

  * TLS client request - ```tls.handshake.type == 1```

  * TLS server response - ```tls.handshake.type == 2```

  * Client Hello - ```(http.request or tls.handshake.type == 1) and !(ssdp)```

  * Server Hello - ```(http.request or tls.handshake.type == 2) and !(ssdp)```

* Encryption key log files can be used to decrypt encrypted traffic session; they can be added/removed using 'right-click menu' or Edit > Preferences > Protocols > TLS

* After decryption, we can filter these requests using ```http``` or ```http2```.

```markdown
1. What is the frame number of the "Client Hello" message sent to "accounts.google.com"? - 16

2. Decrypt the traffic with the "KeysLogFile.txt" file. What is the number of HTTP2 packets? - 115

3. Go to Frame 322. What is the authority header of the HTTP2 packet? - safebrowsing[.]googleapis[.]com

4. Investigate the decrypted packets and find the flag! What is the flag? - FLAG{THM-PACKETMASTER}
```

## Bonus: Hunt Cleartext Credentials

* Using Wireshark dissectors, we can view detected creds using Tools > Credentials menu.

```markdown
1. What is the packet number of the credentials using "HTTP Basic Auth"? - 237

2. What is the packet number where "empty password" was submitted? - 170
```

## Bonus: Actionable Results

* We can create firewall rules using Tools > Firewall ACL Rules.

```markdown
1. Select packet number 99. Create a rule for "IPFirewall (ipfw)". What is the rule for "denying source IPv4 address"? - add deny ip from 10.121.70.151 to any in

2. Select packet number 231. Create "IPFirewall" rules. What is the rule for "allowing destination MAC address"? - add allow MAC 00:d0:59:aa:af:80 any in
```
