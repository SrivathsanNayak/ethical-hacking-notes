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

```markdown
1. What is the total number of the "TCP Connect" scans?

2. Which scan type is used to scan the TCP port 80?

3. How many "UDP close port" messages are there?

4. Which UDP port in the 55-70 port range is open?
```

## ARP Poisoning & Man In The Middle

```markdown
1. What is the number of ARP requests crafted by the attacker?

2. What is the number of HTTP packets received by the attacker?

3. What is the number of sniffed username&password entries?

4. What is the password of the "Client986"?

5. What is the comment provided by the "Client354"?
```

## Identifying Hosts: DHCP, NetBIOS and Kerberos

```markdown
1. What is the MAC address of the host "Galaxy A30"?

2. How many NetBIOS registration requests does the "LIVALJM" workstation have?

3. Which host requested the IP address "172.16.13.85"?

4. What is the IP address of the user "u5"?

5. What is the hostname of the available host in the Kerberos packets?
```

## Tunneling Traffic: DNS and ICMP

```markdown
1. Investigate the anomalous packets. Which protocol is used in ICMP tunnelling?

2. Investigate the anomalous packets. What is the suspicious main domain address that receives anomalous DNS queries?
```

## Cleartext Protocol Analysis: FTP

```markdown
1. How many incorrect login attempts are there?

2. What is the size of the file accessed by the "ftp" account?

3. The adversary uploaded a document to the FTP server. What is the filename?

4. The adversary tried to assign special flags to change the executing permissions of the uploaded file. What is the command used by the adversary?
```

## Cleartext Protocol Analysis: HTTP

```markdown
1. Investigate the user agents. What is the number of anomalous  "user-agent" types?

2. What is the packet number with a subtle spelling difference in the user agent field?

3. Locate the "Log4j" attack starting phase. What is the packet number?

4. Locate the "Log4j" attack starting phase and decode the base64 command. What is the IP address contacted by the adversary?
```

## Encrypted Protocol Analysis: Decrypting HTTPS

```markdown
1. What is the frame number of the "Client Hello" message sent to "accounts.google.com"?

2. Decrypt the traffic with the "KeysLogFile.txt" file. What is the number of HTTP2 packets?

3. Go to Frame 322. What is the authority header of the HTTP2 packet?

4. Investigate the decrypted packets and find the flag! What is the flag?
```

## Bonus: Hunt Cleartext Credentials

```markdown
1. What is the packet number of the credentials using "HTTP Basic Auth"?

2. What is the packet number where "empty password" was submitted?
```

## Bonus: Actionable Results

```markdown
1. Select packet number 99. Create a rule for "IPFirewall (ipfw)". What is the rule for "denying source IPv4 address"?

2. Select packet number 231. Create "IPFirewall" rules. What is the rule for "allowing destination MAC address"?
```
