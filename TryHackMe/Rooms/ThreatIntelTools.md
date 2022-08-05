# Threat Intelligence Tools - Easy

1. [UrlScan.io](#urlscanio)
2. [Abuse.ch](#abusech)
3. [PhishTool](#phishtool)
4. [Cisco Talos Intelligence](#cisco-talos-intelligence)
5. [Scenario 1](#scenario-1)
6. [Scenario 2](#scenario-2)

## UrlScan.io

* Threat intelligence classifications:

  * Strategic intel
  * Technical intel
  * Tactical intel
  * Operational intel

* [Urlscan.io](https://urlscan.io/) is a service for scanning and analysing websites.

* The key areas in scan results include Summary, HTTP, Redirects, Links, Behaviour and Indicators.

```markdown
1. What is TryHackMe's Cisco Umbrella Rank? - 345612

2. How many domains did UrlScan.io identify? - 13

3. What is the main domain registrar listed? - NAMECHEAP INC

4. What is the main IP address identified? - 2606:4700:10::ac43:1b0a
```

## Abuse.ch

* [Abuse.ch](https://abuse.ch/) is used to identify and track malware and botnets. The platforms under it are:

  * Malware Bazaar - for sharing malware samples

  * Feodo Tracker - to track botnet C2 (command & control) infra linked with Emotet, Dridex and TrickBot

  * SSL Blacklist - for providing blocklist for malicious SSL certificates and JA3/JA3s fingerprints

  * URL Haus - for sharing malware distribution sites

  * Threat Fox - for sharing IOCs (indicators of compromise)

```markdown
1. The IOC 212.192.246.30:5555 is linked to which malware on ThreatFox? - Katana

2. Which malware is associated with the JA3 Fingerprint 51c64c77e60f3980eea90869b68c58a8 on SSL Blacklist? - Dridex

3. From the statistics page on URLHaus, what malware-hosting network has the ASN number AS14061? - DIGITALOCEAN-ASN

4. Which country is the botnet IP address 178.134.47.166 associated with according to FeodoTracker? - Georgia
```

## PhishTool

* [PhishTool](https://www.phishtool.com/) is used for response and prevention of phishing emails.

* This is done through email analysis and helps in uncovering IOCs, preventing breaches and providing forensic reports.

```markdown
1. What organisation is the attacker trying to pose as in the email? - LinkedIn

2. What is the senders email address? - darkabutla@sc500.whpservers.com

3. What is the recipient's email address? - cabbagecare@hotsmail.com

4. What is the Originating IP address? Defang the IP address. - 204[.]93[.]183[.]11

5. How many hops did the email go through to get to the recipient? - 4
```

## Cisco Talos Intelligence

* [Talos Intelligence](https://talosintelligence.com) provides intelligence, visibility on indicators and protection against threats. Its key teams are:

  * Threat Intelligence & Interdiction
  * Detection Research
  * Engineering & Development
  * Vulnerability Research & Discovery
  * Communities
  * Global Outreach

```markdown
1. What is the listed domain of the IP address from the previous task? - scnet.net

2. What is the customer name of the IP address? - Complete Web Reviews
```

## Scenario 1

* We can analyze the given email file using PhishTool. It includes a .zip attachment, whose file hash (SHA-256) can be checked in Talos.

```markdown
1. According to Email2.eml, what is the recipient's email address? - chris.lyons@supercarcenterdetroit.com

2. From Talos Intelligence, the attached file can also be identified by the Detection Alias that starts with an H... - HIDDENEXT/Worm.Gen
```

## Scenario 2

```markdown
1. What is the name of the attachment on Email3.eml? - Sales_Receipt 5606.xls

2. What malware family is associated with the attachment on Email3.eml? - Dridex
```
