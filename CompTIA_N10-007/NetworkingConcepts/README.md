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
