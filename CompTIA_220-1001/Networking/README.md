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
