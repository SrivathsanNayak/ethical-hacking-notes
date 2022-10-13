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

```markdown
1. If you want to block telnet, which TCP port number would you deny?

2. You want to allow HTTPS, which TCP port number do you need to permit?

3. What is an alternate TCP port number used for HTTP? It is described as “HTTP Alternate.”

4. You need to allow SNMP over SSH, snmpssh. Which port should be permitted?
```

## Types of Firewalls

```markdown
1. What is the most basic type of firewall?

2. What is the most advanced type of firewall that you can have on company premises?
```

## Evasion via Controlling the Source MAC/IP/Port

```markdown
1. What is the size of the IP packet when using a default Nmap stealth (SYN) scan?

2. How many bytes does the TCP segment hold in its data field when using a default Nmap stealth (SYN) scan?

3. Approximately, how many packets do you expect Nmap to send when running the command nmap -sS -F MACHINE_IP?

4. Approximately, how many packets do you expect Nmap to send when running the command nmap -sS -Pn -D RND,10.10.55.33,ME,RND -F MACHINE_IP?

5. What do you expect the target to see as the source of the scan when you run the command nmap -sS -Pn --proxies 10.10.13.37 MACHINE_IP?

6. What company has registered the following Organizationally Unique Identifier (OUI), i.e., the first 24 bits of a MAC address, 00:02:DC?

7. To mislead the opponent, you decided to make your port scans appear as if coming from a local access point that has the IP address 10.10.0.254. What option needs to be added to your Nmap command to spoof your address accordingly?

8. What do you need to add to your Nmap command to set the source port number to 53?
```

## Evasion via Forcing Fragmentation, MTU, and Data Length

```markdown
1. What is the size of the IP packet when running Nmap with the -f option?

2. What is the maximum size of the IP packet when running Nmap with the -ff option?

3. What is the maximum size of the IP packet when running Nmap with --mtu 36 option?

4. What is the maximum size of the IP packet when running Nmap with --data-length 128 option?
```

## Evasion via Modifying Header Fields

```markdown
1. Scan the attached MS Windows machine using --ttl 2 option. How many ports appear to be open?

2. Scan the attached MS Windows machine using the --badsum option. How many ports appear to be open?
```

## Evasion using Port Hopping

```markdown
1. Discover which port number of the following destination TCP port numbers are reachable from the protected system.
```

## Evasion using Port Tunneling

```markdown
1. Using port tunneling, browse to the web server and retrieve the flag.
```

## Evasion using Non-Standard Ports

```markdown
1. What is the user name associated with which you are logged in?
```

## Next-Generation Firewalls

```markdown
1. What is the number of the highest OSI layer that an NGFW can process?
```
