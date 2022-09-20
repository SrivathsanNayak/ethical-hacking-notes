# Introduction to Cybersecurity Tools & Cyber Attacks

1. [Introduction](#introduction)
2. [Actors and Motives](#actors-and-motives)
3. [Security Concepts](#security-concepts)
4. [Security Tools](#security-tools)

## Introduction

* Information security (CIA triad) - "The protection of information systems from unauthorized access, use, disclosure, disruption, modification, or destruction in order to provide confidentiality, integrity, and availability."

* Definitions:

  * Vulnerability - flaw, loophole or error that can be exploited.

  * Threat - event (natural or man-made) able to cause negative impact to organization.

  * Exploit - defined way to breach IT system security through a vulnerability.

  * Risk - situation involving exposure to danger.

* Considerations for a cybersecurity program:

  * Security program
  * Admin controls
  * Asset management
  * Tech controls

* Security:

  * Confidentiality
  * Authentication
  * Message integrity
  * Access and availability

## Actors and Motives

* Types of actors:

  * Hackers
  * Internal users
  * Governments
  * Hacktivists

* Motives include desire for money or a job, politicial motives or just to demonstrate capabilities.

* Types of security attacks:

  * Passive attacks - eavesdropping attacks, traffic analysis.

  * Active attacks - explicit interception and modification; types include masquerade, replay, modification, and denial of service.

* Security service - process or service provided by system for protection of a resource; security services implement security policies, implemented by security mechanisms.

* Security mechanisms - combo of hardware, software and processes that implement a specific security policy, using security services; can be specific or pervasive.

* Threats to a data communication system include destruction, corruption or modification, theft or removal or loss, disclosure and interruption of information services.

* Security architecture - Attack models:

  * Interruption
  * Interception
  * Modification
  * Fabrication
  * Diversion

* Malware - software to disrupt computer operations, gather sensitive info, gain unauthorized access or display unwanted advertising.

* Types of malware:

  * Virus
  * Worms
  * Trojans
  * Spyware
  * Adware
  * RATs
  * Rootkit

* Protection against threats:

  * Technical control - AV, IPS, IDS, UTM, updates.

  * Administrative control - policies, training, revision and tracking.

* Security threats:

  * Network mapping - scanning network and finding services; host scanners as countermeasure.

  * Packet sniffing - promiscuous NIC reads packets broadcasted.

  * IP spoofing - generate raw IP packets from application; ingress filtering can be used as countermeasure.

  * Denial of Service (DoS) - flooding malicious packets to receiver.

  * Host insertions - computer host with malicious intent is inserted in sleeper mode in network; as countermeasure, maintain accurate inventory of computer hosts.

* Phases of the Cyber Kill Chain:

  * Recon
  * Weaponization
  * Delivery
  * Exploitation
  * Installation
  * Command and Control
  * Actions on Objective

## Security Concepts

* CIA triad - Confidentiality, Integrity, Availability.

* Non-repudiation - valid proof of the identity of the data sender/receiver; implemented in digital signatures, logs.

* Access management - access criteria:

  * Groups
  * Time frame, specific dates
  * Physical location
  * Transaction type

* Authentication concepts:

  * Identity proof
  * Kerberos (Single Sign On)
  * Mutual authentication
  * SIDs (Security ID), DACL (Discretionary Access Control List)

* Incident management - monitoring and detection of security events; components include events, incidents, response team and investigation.

* Incident Response - key concepts:

  * E-discovery - data inventory; helps to understand current status

  * Automated systems - using SIEM, SOA, UBA, big data analysis, etc.

  * BCP & Disaster Recovery - business continuity plan

  * Post-incident - root-cause analysis

* Incident Response Phases - Prepare, Respond, Follow-up

* Security standards and compliance:

  * Best practices, baselines and frameworks - to improve controls, methodologies, performance.

  * Normative and compliance - enforcement for industry; common compliance policies include SOX, HIPAA, GLBA, PCI/DSS.

* IT governance components - policies, procedures, strategic and tactic plans, and other documentation.

* Audits can be internal or external.

* Pentest (ethical hacking) - method of evaluating computer & network security by simulating an attack from internal and external threats.

## Security Tools

* Firewalls - isolate organization's network from larger Internet.

* Uses of firewalls:

  * Prevent denial of service attacks
  * Prevent illegal modification/access of internal data
  * Allow only authorized access to internal network

* Types of firewalls on basis of packet-filtering:

  * Application-level - filters packets on application data as well as on IP/TCP/UDP fields.

  * Packet-filtering - routers filters packet-by-packet; decision to drop packet based on:

    * source and destination IP address
    * TCP/UDP source and destination port numbers
    * ICMP message type
    * TCP SYN and ACK bits

* Types of firewalls on basis of state:

  * Stateless firewalls:

    * no concept of 'state'
    * also known as packet filter
    * filters packets based on Layer 3,4 info (IP, port)
    * less secure

  * Stateful firewalls:

    * have state tables
    * slower but more secure
    * application firewalls can make decisions based on layer 7 info

* Proxy firewalls - act as intermediary servers; proxies terminate connections and initiate new ones.

* Limitations of firewalls and gateways:

  * IP spoofing
  * Each specialized application needs its own gateway
  * Client software must know how to contact of gateway
  * Cannot fully protect from attacks

* Antivirus/Antimalware - specialized software that detects, prevents and removes computer virus or malware; scans system and searches for matches against constantly updated malware definitions.

* Types of ciphers:

  * Stream cipher - encrypt/decrypt bit-by-bit

  * Block cipher - encrypt/decrypt in blocks

* Types of cryptography:

  * Symmetric encryption:

    * uses same key to encrypt and decrypt
    * strengths include speed and cryptographic strength per bit of key
    * key needs to be shared via a secure, out-of-band method
    * examples are DES, triple DES and AES

  * Asymmetric encryption:

    * uses two keys, public and private key
    * one key for encryption and other key for decryption
    * uses 'one-way' algorithms to generate the two keys
    * used in digital certificates and PKI (public key infrastructure)
    * slower than symmetric encryption

  * Hash functions:

    * provides encryption using algorithm, no key
    * for integrity verification
    * commonly used hash function is SHA-2

* Cryptographic attacks:

  * Brute force
  * Rainbow tables
  * Social engineering
  * Known plaintext
  * Known ciphertext

* Penetration testing - testing a computer system, network or app to find security vulnerabilities that an attacker could exploit.

* Threat actors - entities that are partially or wholly responsible for an incident that affects an organization's security.

* Pentest methodologies:

  * OSSTMM - Open Source Security Testing Methodology Manual

  * NIST (SP 800-42) - National Institute of Standards and Technology, Guideline on Network Security Training

  * FFIEC - Federal Financial Institutions Examination Council Information Technology Examination

  * ISSAF - Information Systems Security Assessment Framework

* Digital forensics - identification, recovery, investigation, validation and presentation of facts regarding digital evidence found on computers.

* Chain of custody - chronological documentation (paper trail) that records sequence of custody, control, transfer, analysis and disposition of evidence; required for evidence to be shown in court.
