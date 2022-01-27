# Network Security

## Access Control

* AAA framework - Authentication, authorization and accounting; RADIUS (Remote Authentication Dial-in User Service) protocol used commonly; TACACS/XTACACS/TACACS+ used alternatively.

* Kerberos - network authentication protocol; mutual authentication; SSO (Single Sign On).

* LDAP (Lightweight Directory Access Protocol) - for reading, writing directories over IP network; used to update X.500 directory.

* Auditing - log all access details; usage auditing, restrictions.

* NAC (Network Access Control) - port-based NAC (IEE 802.1X); makes use of EAP (Extensible Authentication Protocol) and RADIUS.

* Port security - prevent unauthorized users from connecting to a switch interface; based on MAC address; configure max source MAC addresses on an interface.

* MAC filtering - limit access through MAC address; through packet captures; security through obscurity.

* Captive portals - authentication to a network.

* ACLs (Access Control Lists) - used to allow/deny traffic; defined on ingress/egress of interface; evaluated on certain criteria.

## Wireless Network Security

* EAP (Extensible Authentication Protocol) - authentication framework; used by WPA and WPA2.

* Types of EAP:

    1. EAP-FAST - Flexible Authentication via Secure Tunneling.
    2. EAP-TLS - Transport Layer Security; strong security, wide adoption.
    3. EAP-TTLS - Tunneled TLS; support other authentication protocols in TLS tunnel.
    4. PEAP - Protected EAP; encapsulates EAP in TLS tunnel; commonly implemented as PEAPv0/EAP-MSCHAPv2.

* Wireless security modes - open system, WPA2-Personal (WPA2-PSK), and WPA2-Enterprise (WPA2-802.1X).

* Geofencing - restrict/allow features when device is in particular area.

## Network Attacks

* Denial of Service - overload a service to fail; network DoS, bandwidth DoS, DDoS (Distributed DoS) and DDoS amplification.

* Social engineering principles - authority, intimidation, consensus, scarcity, urgency, familiarity, and trust.

* Insider threats - phishing innocent employees, careless or disgruntled employees; requires defense in depth.

* Logic bomcs - malware waiting for a predefined event; time bombs, user events; tough to identify.

* Rogue access points - significant potential backdoor; easy to plug in a wireless access point; use 802.1X.

* Wardriving - WiFi monitoring combined with GPS; huge intel in short period of time.

* Phishing - social engineering combined with spoofing; spear phishing.

* Ransomware - data unavailable until ransom is provided; malware encrypts data files; crypto-malware; use offline backups, updated apps.

* DNS poisoning - modify DNS server, modify client host file, send fake response to valid DNS request.

* Spoofing - pretend to be something you are not; email address spoofing, caller ID spoofing, MITM attacks, MAC spoofing, IP spoofing.

* Wireless deauthentication - significant wireless DoS attack.

* Brute force attacks - keep trying the login process until password is cracked.

* VLAN hopping - switch spoofing and double tagging.

* MITM attacks - redirects traffic; ARP poisoning; man-in-the-browser attack, using malware.

* Vulnerability - weakness in a system; may or may not be discovered; types such as data injection, sensitive data exposure, security misconfiguration, etc.

* Exploits - take advantage of a vulnerability; multiple exploit methods.

## Device Hardening

* Methods to harden device security:

    1. Change default credentials
    2. Use strong, random passwords
    3. Upgrade firmware
    4. Patch management
    5. File hashing
    6. Disable unnecessary services
    7. Watch the network
    8. Use secure protocols
    9. Generate new keys
    10. Disable unused TCP and UDP ports, and unused interfaces

## Mitigation

* Mitigation techniques:

    1. IPS signature management
    2. Device hardening
    3. Privileged accounts
    4. FIM (File Integrity Monitoring)
    5. Access Control Lists
    6. Honeypots
    7. Pentests

* Switch Port Protection:

    1. Spanning Tree Protocol
    2. BPDU guard  - Bridge Protocol Data Unit; STP control.
    3. Root guard - spanning tree determines root bridge; root guard allows you to pick root.
    4. Flood guard - configure max MAC addresses on an interface.
    5. DHCP spoofing - IP tracking on layer 2 device; firewall for DHCP.
