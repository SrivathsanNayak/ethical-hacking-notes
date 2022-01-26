# Networking Concepts

## Ports and Protocols

* TCP and UDP protocols are encapsulated by the IP protocol.

* TCP and UDP operate at the OSI Layer 4 (transport layer).

* TCP (Transmission Control Protocol) - connection-oriented; flow control.

* UDP (User Datagram Protocol) - connectionless; no flow control.

* Non-ephemeral ports  - 0-1023; permanent.

* Ephemeral ports - 1024-65535; temporary.

* ICMP (Internet Control Message Protocol) - for administrative requests; not for data transfer.

## The OSI Model

* The OSI (Open Systems Interconnection Reference) Model is used as a reference:

    1. Layer 1 - Physical Layer (cables, fiber)
    2. Layer 2 - Data Link Layer
    3. Layer 3 - Network Layer (IP address, router, packet)
    4. Layer 4 - Transport Layer (TCP segment, UDP datagram)
    5. Layer 5 - Session Layer
    6. Layer 6 - Presentation Layer (app encryption - SSL/TLS)
    7. Layer 7 - Application Layer

## Routing and Switching

* MAC (Media Access Control) address - address of network adapter; unique; 6 bytes long.

* Half-duplex - device can't send and receive simultaneously.

* Full-duplex - data can be sent and received at the same time.

* Collision - two devices communicating simultaneously.

* CSMA/CD - Carrier Sense Multiple Access / Collision Detect; used for half-duplex Ethernet.

* CSMA/CA - Collision Avoidance; collision detection isn't possible.

* Switch - forward/drop frames; gather list of MAC addresses; maintain loop-free environment using STP (Spanning Tree Protocol).

* Switches examine incoming traffic and adds unknown MAC addresses to MAC address table.

* When in doubt, switch sends the frame to everyone.

* ARP (Address Resolution Protocol) - determine MAC address based on IP address.

* Broadcast frames - sent to all (e.g. - ARP requests); passed by switch/bridge; stops at router.

* Unicast - one station sending info to another (e.g. - web surfing, file transfers); not scalable for real-time streaming media.

* Broadcast - send info to all at once; limited scope (broadcast domain); not used in IPv6.

* Multicast - info sent to required systems (e.g. - multimedia delivery); specialized.

* PDU (Protocol Data Unit) - unit of transmission; different for different OSI layers; Ethernet - frame of data; IP - packet of data; TCP - segment; UDP - datagram.

* MTU (Maximum Transmission Unit) - max IP packet to transmit without fragmentation (as it slows the process).

* STP port states:

    1. Blocking - not forwarding to prevent loop.
    2. Listening - not forwarding and cleaning MAC table.
    3. Learning - not forwarding and adding to MAC table.
    4. Forwarding - data passes through it, operational.
    5. Disabled - admin has turned off port.

* RSTP (Rapid Spanning Tree Protocol, 802.1w) - Latest standard of STP; faster convergence; backwards-compatible.

* Basic interface config - speed and duplex; IP address management.

* Trunking - connecting switches together; connects multiple VLANs in a single link.

* DMZ (Demilitarized Zone) - additional layer of security.

* Port mirroring - examine a copy of the traffic; SPAN port.

* Routers - send IP packets across network; forwarding decisions based on destination IP address.

* Each router only knows next step; list of directions in routing table.

* Static routing - admin defines the routes; easy to configure on smaller networks; no overhead from routing protocols; secure but no automatic method to prevent routing loops or reroute in case of outage.

* Dynamic routing - routers send routes to other routers; no manual routing; scalable; router overhead required; initial config required.

* Default route - route when no route matches.

* AS (Autonomous System) - group of IP routes under common control.

* IGP (Interior Gateway Protocol) - used within single AS; e.g. - OSPFv2, RIPv2 for IPv4 dynamic routing; OSPFv3, RIPng for IPv6 dynamic routing.

* EGP (Exterior Gateway Protocol) - used to route between multiple AS; e.g. - BGP (Border Gateway Protocol).

* Dynamic routing protocols:

    1. Distance-vector routing protocol - info passed between routers containing routing tables; chooses route on the basis of number of hops; good for smaller networks; e.g. - RIPv2, EIGRP.
    2. Link-state routing protocols - info passed between routers related to current connectivity; faster connectivity has higher priority; scalable; e.g. - OSPF.
    3. Hybrid routing protocols - both routing protocols combined; e.g. - BGP.

* IP address - network ID + host ID; subnet mask determines which part is network ID and which part is host ID.

* Default gateway - router that allows you to communicate outside of the local subnet.

* IPv4 addresses are 4 bytes long (4 octets of a byte each).

* IPv6 addresses are 16 bytes long (8 hexadecimal parts of 2 bytes each).

* Dual-stack IPv4 and IPv6 to run both at same time.

* Tunneling IPv6:

    1. 6to4 addressing - requires relay routers; no support for NAT.
    2. 4in6 tunneling - tunnel IPv4 traffic on IPv6 network.
    3. Teredo/Miredo - tunnel IPv6 through NATed IPv4.

* NDP (Neighbor Discovery Protocol) - no broadcasts; uses multicast with ICMPv6; uses SLAAC, DAD; router discovery using RS (Router Solicitation) and RA (Router Advertisement); NS and NA used to find neighbors in IPv6.

* Prioritizing traffic:

    1. Packet shaping
    2. QoS (Quality of Service)
    3. Managing QoS through CoS (Class of Service) and DiffServ

* Port forwarding - access to service hosted internally; external IP/port maps to internal IP/port; also called destination or static NAT.

* ACL (Access Control Lists) - packet filtering to allow/deny traffic; can evaluate on certain criteria; used in firewall rules (top-to-bottom); implicit deny.

* Circuit switching - circuit is established between endpoints before data passes; POTS, PSTN, ISDN.

* Packet switching - data grouped into packets; shared media; SONET, ATM, DSL, cable modem.

* SDN (Software Defined Networking) - networking devices have 2 functional planes of operation (control plane, data plane); directly programmable and agile; centrally managed.

## Network Addressing

* Loopback address (127.0.0.1) - address to yourself.

* A subnet can be constructed by using the network address, the first usable host address, the network broadcast address, and the last usable host address. Examples

```markdown
Given IP address = 10.74.222.11

We know that this is a Class A address.
As this is Class A, only first octet will be network bit.

So, subnet mask = 255.0.0.0
Therefore, network address = 10.0.0.0
First host address = 10.0.0.1
Broadcast address = 10.255.255.255
Last host address = 10.255.255.254
```

```markdown
Given IP address = 172.16.88.200

As this is a Class B address, first two octets will be network bits.

Subnet mask = 255.255.0.0
Network address = 172.16.0.0
First host address = 172.16.0.1
Broadcast address = 172.16.255.255
Last host address = 172.16.255.254
```

* VLSM (Variable Length Subnet Masks) - allow network admins to define masks; class-based networks inefficient.

```markdown
Given IP address = 10.1.1.0/24
As this is class A address,
number of network bits = 8
number of subnet bits = 16
and number of host bits = 8

So, total subnets = 2^16 = 65536
Also, hosts per subnet = (2^8) - 2 = 254
```

## Network Topologies

* Network maps - high level views of network; can be physical or logical.

* Common network topologies:

    1. Star - all devices connected to central device.
    2. Ring - dual-ring; built-in fault tolerance.
    3. Mesh - multiple links to same place; redundancy; fault-tolerance; load-balancing.
    4. Bus - simple but prone to errors.

* Wireless topologies:

    1. Infrastructure - all devices communicate through access point.
    2. Ad hoc networking - devices communicate amongst themselves; no structure.
    3. Mesh - ad hoc devices form a mesh structure; self-form and self-heal.

* Common network types:

    1. LAN (Local Area Network) - High-speed connectivity; e.g. - Ethernet, 802.11 wireless.
    2. WLAN (Wireless LAN) - 802.11 tech; expand coverage with extra access points.
    3. MAN (Metropolitan Area Network) - commonly owned by government.
    4. WAN (Wide Area Network) - slower than LAN; point-to-point serial, MPL3, etc.
    5. CAN (Campus Area Network) - fiber-connected; high speed Ethernet.
    6. NAS (Network Attached Storage) - connect to shared storage device across network; file-level access.
    7. SAN (Storage Area Network) - block-level access; efficient.
    8. PAN (Personal Area Network) - private network; Bluetooth, IR, wireless headset, etc.

* IoT topologies:

    1. Z-Wave - home automation networking; wireless mesh network; 900 MHz ISM band.
    2. ANT/ANT+ - wireless sensor network protocol; 2.4 GHz ISM band; fitness devices, heart rate monitors; spectrum jamming for denial of service.
    3. Bluetooth - high speed communication over short distances (PAN); connects mobile devices.
    4. NFC (Near Field Communication) - two-way wireless; payment systems, access token.
    5. IR (Infrared) - used in gadgets and devices.
    6. RFID (Radio-frequency identification) - radar tech; bidirectional; access badges, trackers.
    7. IEEE 802.11 - wireless networking standard.

## Wireless Technologies

* 802.11 networking standards include 802.11a, 802.11b, 802.11g, 802.11n, and 802.11ac.

* Cellular network standards include GSM (uses TDMA), CDMA and 4G/LTE.

## Cloud Technologies

* Common cloud services include SaaS, IaaS, PaaS.

* Cloud deployment models can be private, public, hybrid or community.

* CASB (Cloud Access Security Broker) - integrated with cloud for security policies; visibility, compliance, threat prevention and data security.

## Network Services

* DNS (Domain Name System) - translates names into IP addresses; hierarchical; distributed database.

* RR (Resource Records) - database records of domain name services.

* DNS record types:

    1. Address records (A) (AAAA) - defines IP address of host; A records for IPv4 and AAAA for IPv6.
    2. Canonical name records (CNAME) - for aliases.
    3. Service records (SRV) - for specific services.
    4. Mail exchanger record (MX) - determines host name for mail server.
    5. Name server records (NS) - list name servers for a domain.
    6. Pointer record (PTR) - reverse of A/AAAA record.
    7. Text records (TXT) - readable text info; contains SPF protocol and DKIM.

* DHCP (Dynamic Host Configuration Protocol) - provides automatic IP configuration.

* DHCP relay used in enterprises to overcome limited communication range, redundancy and scalability issues.

* DHCP address allocation ways:

    1. Dynamic allocation
    2. Automatic allocation
    3. Static allocation
    4. Table of MAC addresses (static DHCP)

* NTP (Network Time Protocol) - for configuring synchronization of clock.

* NTP server - responds to time requests from NTP clients; doesn't modify their own time.

* NTP clients - request time updates from NTP server.

* NTP client/server - requests time updates from an NTP server; responds to time requests from other NTP clients.
