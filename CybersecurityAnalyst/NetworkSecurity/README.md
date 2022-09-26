# Network Security & Database Vulnerabilities

1. [TCP/IP Framework](#tcpip-framework)
2. [Basics of IP Addressing and the OSI Model](#basics-of-ip-addressing-and-the-osi-model)
3. [Introduction to Databases](#introduction-to-databases)
4. [Deep Dive - Injection Vulnerability](#deep-dive---injection-vulnerability)

## TCP/IP Framework

* IDS (Intrusion Detection System) - network security tech built for detecting vulnerability exploits against the system; listen-only device as it monitors traffic and reports results to administrator.

* IPS (Intrusion Prevention System) - network security and threat prevention tech that examines network traffic flows to detect & prevent vulnerability exploits; it is placed inline (unlike IDS), behind firewall, and in direct communication path for active prevention.

* Threat detection types:

  * Signature-based
  * Anomaly-based
  * Host-based
  * Network-based

* NAT (Network Address Translation) - remapping one IP address space into another for security.

* Types of NAT:

  * Static - one-to-one mapping between local & global addresses.

  * Dynamic - maps unregistered IP addresses to registered IP addresses from a pool.

  * Overloading - maps multiple unregistered IP addresses to a single registered IP address, many-to-one, using different ports; also known as Port Address Translation.

* ARP (Address Resolution Protocol) - process of using layer 3 addresses (IP address) to determine layer 2 addresses (MAC address).

## Basics of IP Addressing and the OSI Model

* IPv4 - 32 bits address, divided in 4 octets.

* Classful addressing:

  * Class A - 0.0.0.0 - 127.255.255.255 - unicast/special

  * Class B - 128.0.0.0 - 191.255.255.255 - unicast/special

  * Class C - 192.0.0.0 - 223.0.0.0 - unicast/special

  * Class D - 224.0.0.0 - 239.255.255.255 - multicast

  * Class E - 240.0.0.0 - 255.255.255.255 - reserved

* IPv6 - 128 bits address, divided in 8 hexadecimal values (16 bits each).

* TCP (Transmission Control Protocol) - connection-oriented, reliable; ordered, segmented data with flow control.

* UDP (User Datagram Protocol) - connectionless, unreliable; unordered, datagram data without flow control.

* NGFW (next-generation firewall) - combines traditional firewall with other network device filtering functionality, such as IPS and website filtering; able to monitor the traffic from layer 2 to layer 7.

## Introduction to Databases

## Deep Dive - Injection Vulnerability
