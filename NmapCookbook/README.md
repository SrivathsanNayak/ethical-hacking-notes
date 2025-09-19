# Nmap 6 Cookbook - The Fat-free Guide to Network Scanning

1. [Basic Scanning Techniques](#basic-scanning-techniques)
1. [Discovery Options](#discovery-options)
1. [Advanced Scanning Options](#advanced-scanning-options)
1. [Port Scanning Options](#port-scanning-options)
1. [Operating System and Service Detection](#operating-system-and-service-detection)
1. [Timing Options](#timing-options)
1. [Evading Firewalls](#evading-firewalls)
1. [Output Options](#output-options)
1. [Troubleshooting and Debugging](#troubleshooting-and-debugging)
1. [Zenmap](#zenmap)
1. [Nmap Scripting Engine (NSE)](#nmap-scripting-engine-nse)
1. [Ndiff](#ndiff)
1. [Nping](#nping)
1. [Ncat](#ncat)
1. [Tips and Tricks](#tips-and-tricks)

## Basic Scanning Techniques

* Basic, single target scan (scans top 1000 TCP ports) - ```nmap 192.168.1.1```

* Scan multiple targets - ```nmap 192.168.1.1 192.168.1.155 192.168.1.105```; we can also use shorthand if all targets are on same subnet - ```nmap 192.168.1.1,105,155```

* Scan IP range - ```nmap 192.168.1.1-100```

* Scan multiple subnets - ```nmap 192.168.1-100.* | more``` (scans networks from 192.168.1.1 to 192.168.100.255, and ```more``` to display output one page at a time)

* Scan an entire subnet - ```nmap 192.168.1.1/24 | more```

* Scan a list of targets - ```nmap -iL list.txt```

* Scan random targets - ```nmap -iR 3```

* Exclude targets from scan - ```nmap 192.168.1.0/24 --exclude 192.168.1.1```; we can exclude range of targets from scan as well - ```nmap 192.168.1.0/24 --exclude 192.168.1.1-100```

* Exclude targets using list - ```nmap 192.168.1.0/24 --excludefile list.txt```

* Aggressive scan - ```nmap -A 10.10.4.31```

* Scan IPv6 target - ```nmap -6 fe80::2572:dd3a:34fe:daa9```

## Discovery Options

* By default, nmap attempts to send ICMP echo requests before scanning a target to check if it is alive; as ICMP requests are commonly blocked by firewalls, nmap also checks ports 80 & 443

* Custom discovery options -

    * ```-Pn``` - don't ping
    * ```-sn``` - perform a ping only scan
    * ```-PS``` - TCP SYN ping
    * ```-PA``` - TCP ACK ping
    * ```-PU``` - UDP ping
    * ```-PE``` - ICMP echo ping (default)
    * ```-PP``` - ICMP timestamp ping
    * ```-PM``` - ICMP address mask ping
    * ```-PO``` - IP protocol ping
    * ```-PR``` - ARP ping
    * ```--disable-ARP-ping``` - to disable ARP ping; used by default on LANs
    * ```--traceroute``` - traceroute
    * ```-n``` - disable reverse DNS resolution
    * ```--system-dns``` - Alternative DNS lookup
    * ```--dns-servers``` - specify DNS servers
    * ```-sL``` - create host list

## Advanced Scanning Options

* Advanced scan types -

    * ```-sS``` - TCP SYN scan (default scan for privileged users)
    * ```-sT``` - TCP Connect scan (default scan for non-privileged users)
    * ```-sU``` - UDP scan
    * ```-sN``` - TCP NULL scan
    * ```-sF``` - TCP FIN scan
    * ```-sX``` - Xmas scan
    * ```-sA``` - TCP ACK scan (used to check if target is protected by firewall)
    * ```--scanflags``` - custom TCP scan
    * ```-sO``` - IP protocol scan

## Port Scanning Options

* Port scan options -

    * ```-F``` -  perform a fast scan (only top 100 ports)
    * ```-p``` - scan specific ports by port number or name; we can use wildcards here
    * ```-p U:161,T:80``` - scan ports by protocol (need to specify ```-sU -sT``` option in scan as well)
    * ```-p-``` or ```-p "*"``` - scan all ports
    * ```--top-ports 50``` - scan top 50 ports
    * ```-r``` - sequential port scan
    * ```--open``` - only display open ports

## Operating System and Service Detection

## Timing Options

## Evading Firewalls

## Output Options

## Troubleshooting and Debugging

## Zenmap

## Nmap Scripting Engine (NSE)

## Ndiff

## Nping

## Ncat

## Tips and Tricks