# Introduction to Networking

1. [Networking Structure](#networking-structure)
1. [Networking Workflow](#networking-workflow)
1. [Addressing](#addressing)
1. [Protocols & Terminology](#protocols--terminology)
1. [Connection Establishment](#connection-establishment)

## Networking Structure

* Common network terminology:

  * WAN - Wide Area Network - usually accessed by Internet - IP not in private addressing scheme (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  * LAN/WLAN - Local Area Network / Wireless Local Area Network - assigned IP for local use (private)
  * VPN - Virtual Private Networks - can be Site-to-Site (both client & server are network devices), Remote Access or even SSL VPN (within browser)

* Network topology components:

  * Connections - Wired (coaxial cabling, glass fiber cabling, twisted-pair cabling, etc.) and Wireless (WiFi, cellular, satellite, etc.)
  * Nodes - switch, router, repeater, hub, gateway, bridge, firewall
  * Classifications - point-to-point, star, mesh, hybrid, bus, ring, tree, daisy chain

* Network proxy - device/service in middle of connection - can act as mediator - usually operate at Layer 7 of OSI model; types include dedicated/forward, reverse and transparent proxy.

## Networking Workflow

* Networking models:

![OSI Model and TCP/IP Model](/Assets/htb-osi-tcpip.png)

* TCP/IP (Transmission Control Protocol / Internet Protocol) - communication protocol that allows hosts to connect to Internet.

* OSI (Open Systems Interconnection) - communication gateway between network & end-users.

* PDU (protocol data unit) - different formats used in different layers to exchange data; with reference to OSI model:

  * L1 - bits
  * L2 - frame
  * L3 - packet
  * L4 - segment/datagram
  * L5 and above - data

* During data transmission, each layer adds a header to the PDU from upper layer to control & identify the packet - this process is called encapsulation.

## Addressing

* Network layer (L3 in OSI model) is responsible for logical addressing & routing.

* Each host in a network is identified by MAC address and IP address (IPv4/IPv6).

* IPv4 address is divided into a host part and a network part; additionally, it is associated with subnet mask, network & gateway addresses, and broadcast address.

* Subnet - logical segment of network that uses IP address with same network address; division of range of IPv4 addresses is called subnetting.

* MAC address - 48-bit physical address for network interfaces.

* ARP (Address Resolution Protocol) - used to map IP address (L3) to MAC address (L2).

* IPv6 address is 128-bits long; unlike in IPv4, an interface can have multiple IPv6 addresses.

## Protocols & Terminology

* Key terminology:

  * Wired Equivalent Privacy (WEP) - type of security protocol that was commonly used to secure wireless networks.
  * Secure Shell (SSH) - secure network protocol used to log into and execute commands on a remote system.
  * File Transfer Protocol (FTP) - network protocol used to transfer files from one system to another.
  * Simple Mail Transfer Protocol (SMTP) - protocol used to send and receive emails.
  * Hypertext Transfer Protocol (HTTP) - client-server protocol used to send and receive data over the internet.
  * Server Message Block (SMB) - protocol used to share files, printers, and other resources in a network.
  * Network File System (NFS) - protocol used to access files over a network.
  * Simple Network Management Protocol (SNMP) - protocol used to manage network devices.
  * Wi-Fi Protected Access (WPA) - wireless security protocol that uses a password to protect wireless networks from unauthorized access.
  * Temporal Key Integrity Protocol (TKIP) - security protocol used in wireless networks but less secure.
  * Network Time Protocol (NTP) - used to synchronize the timing of computers on a network.
  * Virtual Local Area Network (VLAN) - to segment a network into multiple logical networks.
  * VLAN Trunking Protocol (VTP) - Layer 2 protocol that is used to establish and maintain a VLAN spanning multiple switches.
  * Routing Information Protocol (RIP) - distance-vector routing protocol used in local area networks (LANs) and wide area networks (WANs).
  * Open Shortest Path First (OSPF) - an interior gateway protocol (IGP) for routing traffic within a single Autonomous System (AS) in an Internet Protocol (IP) network.
  * Interior Gateway Routing Protocol (IGRP) - a Cisco proprietary interior gateway protocol designed for routing within autonomous systems.
  * Enhanced Interior Gateway Routing Protocol (EIGRP) - an advanced distance-vector routing protocol that is used to route IP traffic within a network.
  * Pretty Good Privacy (PGP) - an encryption program that is used to secure emails, files, and other types of data.
  * Network News Transfer Protocol (NNTP) - used for distributing and retrieving messages in newsgroups across the internet.
  * Cisco Discovery Protocol (CDP) - a proprietary protocol developed by Cisco Systems that allows network administrators to discover and manage Cisco devices connected to the network.
  * Hot Standby Router Protocol (HSRP) - protocol used in Cisco routers to provide redundancy in the event of a router or other network device failure.
  * Virtual Router Redundancy Protocol (VRRP) - used to provide automatic assignment of available Internet Protocol (IP) routers to participating hosts.
  * Spanning Tree Protocol (STP) - to ensure a loop-free topology in Layer 2 Ethernet networks.
  * Terminal Access Controller Access-Control System (TACACS) - provides centralized authentication, authorization, and accounting for network access.
  * Session Initiation Protocol (SIP) - a signaling protocol used for establishing and terminating real-time voice, video and multimedia sessions over an IP network.
  * Voice Over IP (VOIP) - allows for telephone calls to be made over the internet.
  * Extensible Authentication Protocol (EAP) - framework for authentication that supports multiple authentication methods, such as passwords, digital certificates, one-time passwords, and public-key authentication.
  * Lightweight Extensible Authentication Protocol (LEAP) - proprietary wireless authentication protocol developed by Cisco Systems. It is based on the Extensible Authentication Protocol (EAP) used in the Point-to-Point Protocol (PPP).
  * Protected Extensible Authentication Protocol (PEAP) - security protocol that provides an encrypted tunnel for wireless networks and other types of networks.
  * Systems Management Server (SMS) - systems management solution that helps organizations manage their networks, systems, and mobile devices.
  * Microsoft Baseline Security Analyzer (MBSA) - free security tool from Microsoft that is used to detect potential security vulnerabilities in Windows computers, networks, and systems.
  * Supervisory Control and Data Acquisition (SCADA) - industrial control system that is used to monitor and control industrial processes, such as those in manufacturing, power generation, and water and waste treatment.
  * Virtual Private Network (VPN) - allows users to create a secure, encrypted connection to another network over the internet.
  * Internet Protocol Security (IPsec) - used to provide secure, encrypted communication over a network. It is commonly used in VPNs, or Virtual Private Networks, to create a secure tunnel between two devices.
  * Point-to-Point Tunneling Protocol (PPTP) - used to create a secure, encrypted tunnel for remote access.
  * Network Address Translation (NAT) - allows multiple devices on a private network to connect to the internet using a single public IP address. NAT works by translating the private IP addresses of devices on the network into a single public IP address, which is then used to connect to the internet.
  * Carriage Return Line Feed (CRLF) - combines two control characters to indicate the end of a line and a start of a new one for certain text file formats.
  * Asynchronous JavaScript and XML (AJAX) - web development technique that allows creating dynamic web pages using JavaScript and XML/JSON.
  * Internet Server Application Programming Interface (ISAPI) - to create performance-oriented web extensions for web servers using a set of APIs.
  * Uniform Resource Identifier (URI) - syntax used to identify a resource on the Internet.
  * Uniform Resource Locator (URL) - identifies a web page or another resource on the Internet, including the protocol and the domain name.
  * Internet Key Exchange (IKE) - to set up a secure connection between two computers. It is used in virtual private networks (VPNs) to provide authentication and encryption for data transmission, protecting the data from outside eavesdropping and tampering.
  * Generic Routing Encapsulation (GRE) - used to encapsulate the data being transmitted within the VPN tunnel.
  * Remote Shell (RSH) - program under Unix that allows executing commands and programs on a remote computer.

* Wireless networks:

  * use RF (radio frequency) technology to transmit data between devices
  * device must be within range of network and configured with correct settings to connect
  * in WiFi, communication occurs in 2.4 GHz or 5 GHz bands
  * device communicates with WAP (wireless access point) to request permission to transmit data

* Wireless hardening:

  * disabling broadcasting
  * WPA (WiFi protected access)
  * MAC filtering
  * deploying EAP-TLS

* Virtual Private Networks (VPNs):

  * allow secure & encrypted connection between private network & remote device
  * uses ports TCP/1723 for PPTP VPN and UDP/500 for IKEv1, IKEv2 VPN
  * requirements - VPN client, VPN server, encryption, authentication

* IPsec (Internet Protocol Security):

  * protocol that provides encryption & authentication for internet communications
  * works by encrypting data payload of each IP packet and adding an AH (authentication header), used to verify integrity & authenticity of header
  * uses 2 protocols combined - AH (Authentication Header) & ESP (Encapsulating Security Payload)
  * IPsec can be used in Transport mode (end-to-end communication) or Tunnel mode (VPN tunnel)

* Cisco specific information:

  * Cisco IOS - operating system of Cisco network devices
  * VLAN IDs 1-4094 can be used in Cisco switches
  * 802.1Q protocol used in trunking; used for VLAN identification
  * Possible VLAN attacks - VLAN hopping, double-tagging VLAN hopping
  * CDP - Cisco Discovery Protocol - L2 protocol used by Cisco devices to gather info about other directly connected Cisco devices

## Connection Establishment

* Key exchange mechanisms:

  * used to exchange cryptographic keys between 2 parties securely
  * Diffie-Hellman - allows 2 parties to agree on a shared secret key without any prior communication; vulnerable to MITM attacks
  * RSA - uses properties of large prime numbers to generate shared secret key; used in many apps, protocols which need secure communication & data protection
  * ECDH (Elliptic Curve Diffie-Hellman) - uses elliptic curve cryptography to generate shared secret key; provides forward secrecy
  * ECDSA (Elliptic Curve Digital Signature Algorithm) - uses elliptic curve cryptography to generate digital signs to authenticate parties involved in key exchange
  * IKE (Internet Key Exchange) - to establish & maintain secure communication sessions (used in VPNs); operates either in main mode or aggressive mode
