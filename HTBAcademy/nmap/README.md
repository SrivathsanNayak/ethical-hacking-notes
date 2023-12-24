# Network Enumeration with nmap

1. [Host Enumeration](#host-enumeration)
1. [Bypass Security Measures](#bypass-security-measures)

## Host Enumeration

* Usecases of ```nmap``` include host discovery, port scanning, service enumeration & detection, OS detection, and scriptable interaction with target.

* Scan network range:

  ```shell
  sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
  # -sn for disabling port scanning
  # -oA tnet for storing results in all formats starting with name 'tnet'
  
  # this scanning method works only if firewalls of host allow it
  # as other hosts ignore default ICMP echo requests, due to which they are marked inactive

  # scan an ip list, from file with IPs in newlines
  sudo nmap 10.129.2.0/24 -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
  # -iL is to perform scans against targets in list
  # similarly, we can also define multiple addresses or a range of addresses
  ```

* Scan single IP:

  ```shell
  sudo nmap 10.129.2.18 -sn -oA host
  # -sn to disable port scanning
  # -oA is to save results in all formats starting with name 'host'

  # use -PE flag to perform ping scan using ICMP echo requests against target
  ```

* Possible states for a scanned port:

  * open - connection to scanned port established
  * closed - packet received from target contains RST flag (used in TCP); also used to check if target is up or not
  * filtered - cannot identify open/closed; either no response from target or error code received
  * unfiltered - only occurs during TCP-ACK scan; port is accessible, but can't identify open/closed
  * open | filtered - no response; firewall or filter could be used
  * closed | filtered - only occurs in IP ID idle scans; can't determine if port is closed or filtered (firewall)

* Discovering open TCP ports:

  ```shell
  # by default, nmap scans top 1000 tcp ports with SYN scan -sS
  # needs sudo
  # otherwise TCP scan -sT is done by default

  # scanning top 10 tcp ports
  sudo nmap 10.129.2.28 --top-ports=10
  ```

  ```shell
  # trace packets
  sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping
  # view request-response messages with flags
  # can be used for filtered ports to get reason
  ```

* Discovering open UDP ports:

  ```shell
  # UDP is connectionless, means longer timeouts and slower scans

  sudo nmap 10.129.2.28 -F -sU
  # -F to scan top 100 ports
  # -sU for UDP scan
  ```

* Scans can be saved in multiple formats:

  * ```-oN``` - normal output in .nmap file
  * ```-oG``` - grepable output in .gnmap file
  * ```-oX``` - XML output in .xml file (tools like ```xsltproc``` can be used to convert XML to HTML)
  * ```-oA``` - saves result in all formats

* For service version detection, we can use the ```-sV``` flag:

  ```shell
  sudo nmap 10.129.2.28 -p- -sV -v --stats-every=30s
  # -v for verbosity

  # to get specific info from port
  sudo nmap 10.129.2.28 -p 25 -sV -Pn -n --disable-arp-ping --packet-trace
  # -n to disable DNS resolution
  ```

  ```shell
  # alternatively, we can try to manually connect to port
  # for banner grabbing

  sudo tcpdump -i eth0 host 10.10.14.2 and 10.129.2.8
  # intercept network traffic

  # in another tab, use nc to connect with service
  nc -nv 10.129.2.28 25

  # we can check the intercepted traffic for service info
  ```

* NSE (Nmap Scripting Engine) - to create scripts in Lua for interacting with services in ```nmap```:

  ```shell
  # default scripts
  sudo nmap 10.129.185.88 -sC

  # specific scripts category
  # categories like auth, brute, fuzzer, version, etc.
  sudo nmap 10.129.185.88 --script <category>

  # defined scripts
  sudo nmap 10.129.185.88 -p 25 --script banner,smtp-commands

  # aggressive scan -A
  # combines multiple options like -sV, -O, --traceroute and -sC
  sudo nmap 10.129.185.88 -p- -A
  ```

  ```shell
  # for vuln assessment
  sudo nmap 10.129.185.88 -p 80 -sV --script vuln
  ```

## Bypass Security Measures

* ```nmap``` TCP ACK scan (```-sA```) is harder to filter for firewalls and IDS/IPS as they only send a TCP packet with only ACK flag - the firewall cannot determine whether the connection was first established from external or internal network.

* To detect if IDS/IPS is being used by target, we can trigger certain security measures like aggressively scanning a single port and its service, or to scan from a single host. If we do not have access to target network after this, that means we can continue with another host.

* Decoys:

  ```shell
  # generates random IP addresses in IP header to disguise origin of packet
  # the decoy IPs need to be alive, otherwise target service can be unreachable due to SYN-flooding security mechanisms

  sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5

  # to test firewall rule
  sudo nmap 10.129.2.28 -n -Pn -p 445 -O
  # filtered

  # scan using different source IP
  sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0
  # open
  ```

* By default, ```nmap``` performs reverse DNS resolution for target enumeration; these queries are made over UDP/53. If we are in a DMZ (demilitarized zone), we can specify to use the target company's internal DNS servers:

  ```shell
  sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
  # SYN scan
  # use TCP/53 as source port for scans

  # connect to filtered port using TCP/53
  ncat -nv --source-port 53 10.129.2.28 50000
  ```

* Easy Lab:

  ```shell
  nmap -T4 10.129.2.80 -A -Pn --stats-every=30s
  # scanning with -O did not work, so went with aggressive scan
  ```

* Medium Lab:

  ```shell
  # to find version of dns server
  sudo nmap -T4 10.129.2.48 -A -p 53 -Pn --stats-every=30s
  ```

* Hard Lab:

  ```shell
  # tried both TCP and UDP scan for top 50 ports
  # but got banned
  sudo nmap -T4 10.129.78.54 -sTUV -A --top-ports 50 -Pn --stats-every=30s

  sudo nmap -T3 10.129.78.54 -sTUV --top-ports 25 -Pn --disable-arp-ping --packet-trace --stats-every=30s

  sudo nmap -T4 10.129.78.54 -sUV -Pn --stats-every=30s

  # using snippet from earlier notes
  # to use TCP/53 as source port for scans
  sudo nmap -T5 10.129.193.95 -p 50000 -sS -Pn -n --source-port 53 --stats-every=30s
  # gives 50000/tcp as open for ibm-db2

  ncat -nv 10.129.193.95 50000 --source-port 53
  # we get flag
  ```
