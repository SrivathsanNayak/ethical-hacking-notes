# Networking

## Ports & Protocols

* TCP and UDP data transported inside of IP, encapsulated by IP, is a part of the transport layer. This is also called multiplexing, as we're using multiple applications at the same time.

* TCP (Transmission Control Protocol) is connected-oriented, 'reliable' and has flow control.

* UDP (User Datagram Protocol) is connectionless, 'unreliable' and has no flow control.

* IPv4 sockets - server IP address, protocol, server application port no.; client IP address, protocol, client port no.

* Non-ephermeral ports - permanent; 0 to 1023

* Ephemeral ports - temporary; 1024 to 65535

* Common network ports include:

    1. FTP - tcp/20 (active mode data), tcp/21 (control)
    2. SSH - tcp/22
    3. Telnet - tcp/23
    4. SMTP - tcp/25
    5. DNS - udp/53
    6. HTTP - tcp/80
    7. HTTPS - tcp/443
    8. POP3 - tcp/110
    9. IMAP4 - tcp/143
    10. RDP - tcp/3389
    11. DHCP - udp/67, udp/68

## Network Devices

* NIC (Network Interface Card) - fundamental device; inside every device on the network; specific to network type.

* Repeater - receive signal, regenerate, resend.

* Hub - multi-port repeater; half-duplex.

* Bridge - connects different networks and distributes traffic based on MAC address.

* Switches - bridging done in hardware; can be managed or unmanaged.

* Routers - routes traffic between IP subnets; connects different network types.

* WAP (Wireless Access Point) - extends wired network onto wireless network.

* Firewalls - filters traffic by port number; encrypts traffic into/out of the network.

## SOHO Networks

* SOHO Router - all-in-one device; used for routing, switching local devices.

* SOHO routers have the functionality of firewalls as well.

## Wireless Networks

* Wireless standards are usually associated with 802.11 networking.

* Common frequency bands are 2.4 GHz and/or 5 GHz.

## Network Services

* Common network services include:

    1. Web server
    2. File server
    3. Print server
    4. DHCP server
    5. DNS server
    6. Mail server
    7. SIEM
    8. IDS and IPS

## Network Configurations

* IPv4 - 32-bit address; IPv6 - 128-bit address.

* Subnet mask - used by the local device to determine its subnet.

* Default gateway - the router that allows you to communicate outside the local subnet.

* SSL (Secure Sockets Layer) VPN - Uses common SSL/TLS protocol (tcp/443).

* Client-to-site VPN - remote access VPN; requires software on user device.

* LAN - group of devices in the same broadcast domain.

* NAT (Network address translation) - translates one IP address to another.

## Internet Connections

* Cable modem - broadband; transmission across multiple frequencies.

* DSL modem - ADSL; uses existing telephone lines.

* Fiber optics - high speed networking.

* Line-of-sight services - covers many homes simultaneously.

## Network Tools

* Cable crimpers - connects the modular connector to the Ethernet cable.

* Multimeters - check AC voltage, DC voltage, perform continuity tests.

* Tone generator - track wires by following the tone.

* Cable tester - continuity test; can identify missing pins or crossed wires.

* Loopback plugs - useful for testing physical ports.

* Punch-down tools - punch a wire into a wiring block.
