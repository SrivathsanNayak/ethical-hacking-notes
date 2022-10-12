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

```markdown
1. What does an IPS stand for?

2. What do you call a system that can detect malicious activity but not stop it?
```

## IDS Engine Types

```markdown
1. What kind of IDS engine has a database of all known malicious packets’ contents?

2. What kind of IDS engine needs to learn what normal traffic looks like instead of malicious traffic?

3. What kind of IDS engine needs to be updated constantly as new malicious packets and activities are discovered?
```

## IDS/IPS Rule Triggering

```markdown
1. What is the IP address running the port scan?
```

## Evasion via Protocol Manipulation

```markdown
1. What is the option we need to add to set the source port to 161?

2. Using ncat, how do we set a listener on the Telnet port?

3. We want to fragment the IP packets used in our Nmap scan so that the data size does not exceed 16 bytes. What is the option that we need to add?

4. Which of the above three arguments would return meaningful results when scanning MACHINE_IP?

5. What is the option in hping3 to set a custom TCP window size?
```

## Evasion via Payload Manipulation

```markdown
1. Using base64 encoding, what is the transformation of cat /etc/passwd?

2. The base32 encoding of a particular string is NZRWC5BAFVWCAOBQHAYAU===. What is the original string?

3. You created a certificate, which we gave the extension .crt, and a private key, which we gave the extension .key. What is the first line in the certificate file?

4. What is the last line in the private key file?

5. Once you connect to the bind shell using ncat MACHINE_IP 1234, find the user’s name.
```

## Evasion via Route Manipulation

```markdown
1. Which protocols are currently supported by Nmap?
```

## Evasion via Tactical DoS

## C2 and IDS/IPS Evasion

```markdown
1. Which variable would you modify to add a random sleep time between beacon check-ins?
```

## Next-Gen Security
