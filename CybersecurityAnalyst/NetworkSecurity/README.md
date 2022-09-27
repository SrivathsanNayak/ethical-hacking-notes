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

* Data source types:

  * Distributed databases (Structured)
  * Data warehouses (Structured)
  * Big data (Semi-structured)
  * File shares (Unstructured)

* Types of structured data:

  * Flat file databases - all info is stored in one table

  * Relational databases - data in multiple tables, linked to each other using keys

## Deep Dive - Injection Vulnerability

* Injection flaws allow attackers to relay malicious code through vulnerable app to another system; may allow full takeover of system.

* OS command injection - abuse of vulnerable app functionality that causes execution of specified OS commands; due to lack of input sanitization, and unsafe execution of OS commands.

* Prevention of OS command injection:

  * Do not execute OS commands, use built-in commands or 3rd party libraries
  * Run at least possible privilege level
  * Do not run commands through shell interpreters
  * Use explicit paths when running executables
  * Use safer functions when running system commands
  * Do not let user input reach command execution unchanged
  * Sanitize user input with strict whitelists, not blacklists

* SQL injection - abuse of vulnerable app functionality that causes execution of specified SQL queries.

* Types of SQL injection:

  * Error-based
  * UNION-based
  * Blind injection
  * Out of Band

* Prevention of SQL injection:

  * Use prepared statements
  * Sanitize user input
  * Do not expose native database errors to the user
  * Limit database user permissions
  * Use stored procedures
  * Use ORM (Object-relational mapping) libraries
