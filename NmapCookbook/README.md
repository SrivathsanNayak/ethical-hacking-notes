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
1. [Nmap Scripting Engine (NSE)](#nmap-scripting-engine-nse)
1. [Ndiff](#ndiff)
1. [Nping](#nping)
1. [Ncat](#ncat)

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

* For GUI-based tool, use zenmap

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

* ```-F``` -  perform a fast scan (only top 100 ports)
* ```-p``` - scan specific ports by port number or name; we can use wildcards here
* ```-p U:161,T:80``` - scan ports by protocol (need to specify ```-sU -sT``` option in scan as well)
* ```-p-``` or ```-p "*"``` - scan all ports
* ```--top-ports 50``` - scan top 50 ports
* ```-r``` - sequential port scan
* ```--open``` - only display open ports
* ```--stats-every``` - display status of current scan periodically
* ```?``` - enter during nmap runtime to view runtime interaction commands

## Operating System and Service Detection

* ```-O``` - detects OS
* ```-O --osscan-guess``` - force to guess OS
* ```-sV``` - detects service
* ```-sV --allports``` - to not skip problematic ports (like 9100-9107 for printers)
* ```-sV --version-trace``` - verbose version scan

## Timing Options

* ```-T[0-5]``` - timing templates (-T0 for slowest, -T5 for fastest)
* ```--min-parallelism``` - minimum number of parallel port scans
* ```--max-parallelism``` - maximum number of parallel port scans
* ```--min-hostgroup``` - minimum number of targets to be scanned in parallel
* ```--max-hostgroup``` - maximum number of targets to be scanned in parallel
* ```--initial-rtt-timeout``` - to control initial RTT timeout value (1s by default)
* ```--max-rtt-timeout``` - to control maximum RTT timeout for packet response (10s by default)
* ```--max-retries``` - maxmimum probe retransmissions
* ```--ttl``` - to set IP TTL
* ```--host-timeout``` - to give up on target if it fails to complete after specified timeout interval
* ```--scan-delay``` - pause for specified time interval between probes; useful in rate limiting
* ```--max-scan-delay``` - maximum time to wait between probes
* ```--min-rate``` - minimum number of packets to be sent per second
* ```--max-rate``` - maximum number of packets to be sent per second
* ```--defeat-rst-ratelimit``` - to defeat targets that apply rate limiting to RST packets

## Evading Firewalls

* ```-f``` - fragment packets
* ```--mtu``` - specify custom MTU value
* ```-D``` - use decoy addresses
* ```-sI``` - idle zombie scan
* ```--source-port``` - manually specify source port for a probe
* ```--data-length``` - append random data to probe packets
* ```--randomize-hosts``` - randomize scanning order of targets
* ```--spoof-mac``` - spoof MAC address
* ```--badsum``` - send packets with incorrect checksums to target

## Output Options

* ```-oN``` - save scan output to text file (use ```--append-output``` for appending to existing file)
* ```-oX``` - save scan output to XML file
* ```-oG``` - to enable grepable output
* ```-oA``` - save output in all supported file types

## Troubleshooting and Debugging

* ```-h``` - view help
* ```-V``` - view nmap version
* ```-v``` - verbose output (```-vv``` for more verbose)
* ```-d``` - enables debugging output
* ```--reason``` - shows reason why port is in given state
* ```--packet-trace``` - shows summary of all packets sent & received
* ```--iflist``` - shows network interfaces & routes configured on local system
* ```-e``` - manually specify network interface to be used by nmap

## Nmap Scripting Engine (NSE)

* ```--script``` - execute NSE scripts
* ```--script smtp*``` - execute all SMTP scripts (using wildcard)
* ```--script default``` - execute multiple scripts based on their category
* ```--script-help``` - show help info for script
* ```--script-trace``` - to trace NSE scripts
* ```--script-updatedb``` - update script DB

## Ndiff

* ```ndiff scan1.xml scan2.xml``` - compare two scan files
* ```ndiff -v``` - for verbose output
* ```ndiff --xml``` - to generate XML output

## Nping

* ```nping 192.168.1.1``` - sends 5 ICMP pings to target
* ```-H``` - to hide sent ping packets (in output)
* ```-q``` - hides all sent & received ping packets
* ```-c 10``` - send 10 pings (```-c 0``` to run continuously)
* ```--rate``` - specify ping rate (number of pings per second)
* ```--delay``` - specify delay between ping probes
* ```--data-length``` - send random data as payload
* ```--[tcp|udp]``` - ping TCP or UDP ports, rather than using ICMP
* ```-p``` - specify TCP or UDP ports
* ```--arp``` - ARP ping

## Ncat

* ```ncat 192.168.1.2 80``` - connect to port 80, to test webserver
* ```ncat 192.168.1.2 25``` - test SMTP server
* ```ncat -l > test.png``` - setting up receiving system to listen for a file
* ```ncat --send-only 192.168.1.103 < test.png``` - transferring the file from the sending system
* ```ncat -l 80 < web.server``` - set up to listen on port 80 ('web.server' is a HTML file in this case), acts as a webserver
