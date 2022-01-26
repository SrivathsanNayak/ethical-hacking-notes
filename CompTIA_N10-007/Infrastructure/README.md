# Infrastructure

## Cabling

* Cabling is foundational to network communication; twisted pair copper cabling is very common, with 2 types - UTP (Unshielded Twisted Pair) and STP.

* Common copper connectors - RJ11, RJ45, BNC, DB-9, DB-25 and F-connector.

* Fiber communication - transmission by light; no RF signal so difficult to monitor; signal slow to degrade; immune to interference.

* Multimode fiber - short-range; cheap.

* Single-mode fiber - long-range; costly.

* Common optical fiber connectors - ST, SC, LC and MT-RJ.

* Common copper termination standards are T568A and T568B.

* Straight-through cables - patch cables; common Ethernet cable; connect workstations to network devices; opposite type is cross-over cables.

* Common network termination points - 66 block, 110 block, copper patch panel and fiber distribution panel.

* Transceiver - transmitter and receiver in single component; provides a modular interface; duplex or BiDi (bidirectional) communication; e.g. - GBIC, SFP/SFP+, QSFP.

* Common Ethernet standards - 100BASE-TX, 1000BASE-T, 1000BASE-SX, 1000BASE-LX, 10GBASE-T

## Networking Devices

* Hub - multi-port repeater; half-duplex; less efficient; OSI layer 1.

* Bridge - connects physical networks to distribute traffic; similar to wireless access points; OSI layer 2.

* Switch - bridging done in hardware; OSI layer 2.

* Router - routes traffic between IP subnets; OSI layer 3.

* Firewall - filters traffic by port number; can encrypt and proxy traffic; OSI layer 4 (layer 7 for next-gen firewalls).

* Wireless access point - extends wired network onto wireless network; OSI layer 2.

* Modem - modulator/demodulator; converts analog to digital signals.

* Media converter - physical layer signal conversion; OSI layer 1.

## Advanced Networking Devices

* Multilayer switch - switch and router in same device.

* Wireless LAN controllers - centralized management of WAPs.

* Load balancer - distributes load through multiple servers; fault-tolerance; TCP and SSL offload; caching, prioritization and content-switching.

* IDS/IPS - detect and prevent intrusions; identifies on the basis of signature, anomaly, behaviour and heuristics.

* Proxy - sits between users and external network; receives user requests and sends request on their behalf; for caching, access control, URL filtering and content scanning.

* VPN concentrator - encrypted data traversing public networks; can be deployed through cryptographic hardware or software.

* AAA framework - provides authentication, authorization and accounting; RADIUS protocol used commonly.

* UTM (Unified Threat Management) - all-in-one security appliance; web security gateway.

* NGFW (Next-gen Firewalls) - OSI Layer 7; application layer gateway; stateful multilayer inspection.

* VoIP PBX (Private Branch Exchange) - VoIP with corporate phone switch.

* Content filter - control traffic based on data in content; anti-malware, anti-virus.

## Virtualization

* Hypervisor - VM Manager; requires virtualization support.

* Jumbo frames - Ethernet frames with more than 1500 bytes of overload (upto 9216 bytes); increased efficiency.

* FC (Fibre Channel) - high-speed topology; supported over both fiber and copper; servers and storage connect to FC switch.

* FC over data network - FCoE (FC over Ethernet), FCIP (FC over IP).

* iSCSI (Internet Small Computer Systems Interface) - send SCSI commands over IP network; RFC standard.

* InfiniBand - high-speed switching topology; used in research, supercomputers.

## WAN Technologies

* Common types of WAN services:

    1. ISDN (Integrated Services Digital Network) - delivered through BRI, PRI; for phone systems.
    2. T1/E1 - time-division multiplexing.
    3. T3/DS3/E3 - delivered on coax (BNC connectors).
    4. SONET (Synchronous Optical Networking) - through OC (Optical Carrier).
    5. ADSL (Asymmetric Digital Subscriber Line) - uses telephone lines; download speed faster than upload speed.
    6. Metro Ethernet
    7. Cable broadband
    8. Dialup

* Common WAN transmission mediums:

    1. Satellite networking - costly; high latency.
    2. Copper - cheaper; limited bandwidth.
    3. Fiber - high-speed; costly.
    4. Wireless - cellular; intermittent and roaming communication; limited by coverage.

* Frame relay - LAN traffic encapsulated into frame relay frames.

* ATM (Asynchronous Transfer Mode) - used for SONET; high throughput, real-time, low latency.

* MPLS (Multiprotocol Label Switching) - packets through WAN are labelled.

* PPP (Point-to-point protocol) - OSI layer 2 protocol; creates connection between 2 devices; data link functionality with authentication, compression, error detection and multilink.

* PPPoE - PPP over Ethernet; easy to implement.

* DMVPN (Dynamic Multipoint VPN) - VPN built itself; tunnels built dynamically, on-demand.

* SIP (Session Initiation Protocol) trunking - control protocol for VoIP; more efficient.

* Demarcation point - point of connection with outside world.

* CSU/DSU (Channel Service Unit/Data Service Unit) - sits between router and circuit; CSU connects to network provider and DSU to DTE (data terminal equipment).

* NIU (Network Interface Unit) - smartjack; built-in diagnostics.
