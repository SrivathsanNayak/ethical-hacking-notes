# 200-301 CCNA

Notes for the [200-301 CCNA Training from YouTube](https://www.youtube.com/playlist?list=PLh94XVT4dq02frQRRZBHzvj2hwuhzSByN):

1. [Network Fundamentals](#network-fundamentals)
2. [IP Address](#ip-address)

## Network Fundamentals

* Network - multiple computers linked to share resources and communicate; common types include LAN (Local Area Network) and WAN (Wide Area Network).

* OSI Model and TCP-IP Model:

  ![OSI Model - TCP-IP Model](Images/osi-tcpip.png)

* Layers of the OSI (Open Systems Interconnection) model:

  * Application layer - PoC for all network-aware apps
  * Presentation layer - converts data from session layer and sends it to application layer; offers encryption services
  * Session layer - creates and maintains sessions
  * Transport layer - uses segments as data unit, and adds header to segments for encapsulation; can use reliable (TCP) or unreliable (UDP) communication - also adds source port numbers
  * Network layer - uses packets as data unit; responsible for IP addressing and finding best path
  * Data link layer - uses frames as data unit; responsible for MAC addressing and error checking
  * Physical layer - uses bits as data unit; actual data transfer and hardware connections

* Simplified working of OSI model:

```markdown
Suppose we send an email to someone; this email would first pass through application layer towards presentation layer - this will compress the data.

The session layer is responsible for communication and encryption. Then, the data is divided into segments in transport layer - this layer also adds a transport header to the data.

Now, the segments are sent to the network layer, which adds a header of its own to the segments, thus creating packets.

These packets are forwarded to data link layer, which adds a data link header to it, where it would be called a frame now.

Finally, this frame is converted into bits (0s and 1s) in the physical layer.

Once the physical layer sends these bits to the recipient physical layer, the receiving layers strip the headers of the corresponding layers until it gets all the segments, which is then taken care of by the upper layers.
```

## IP Address

* An IP address consists of 4 octets, with numbers in each octet ranging from 0-255; the address is of 32 bits in binary format.

* IP address has two parts - network (all 1s) and host (all 0s); this can be determined using the subnet mask.

* If an IP address needs to communicate with another IP address, it has to go through the gateway.

* IP address classes identified by first octet:

  * Class A - 1-126
  * Class B - 128-191
  * Class C - 192-223
  * Class D - 224-239
  * Class E - 240-255

* Example:

```markdown
IP address - 192.168.100.225 (/24)

Subnet mask - 255.255.255.0

Gateway - 192.168.100.1

Network Id (first) - 192.168.100.0

Broadcast Id (last) - 192.168.100.255

Number of valid hosts - 254
```

* Number of valid IP addresses in network is ```2^(number of host bits) - 2```

* Private IP addresses - IP addresses which can communicate only on local network:

  * Class A - 10.0.0.0 - 10.255.255.255
  * Class B - 172.16.0.0 - 172.31.255.255
  * Class C - 192.168.0.0 - 192.168.255.255

* Subnetting - dividing network into smaller subnets; uses CIDR (Classless Inter Domain Routing) notation. We can divide a network only in even numbers of subnets.

* Subnetting examples:

```markdown
IP address - 192.168.100.225
Subnet mask - 255.255.255.0

Suppose we need to divide this network into 2 subnets.
We can denote subnet mask in binary format - 11111111.11111111.11111111.00000000

To divide in 2 subnets, extend network bits by 1, such that we have total of 25 network bits now.
New subnet mask - 11111111.11111111.11111111.10000000 (or 255.255.255.128)

Using this format, we have -

  Network Id 1 - 192.168.100.0/25
  Network Id 2 - 192.168.100.128/25

  Broadcast Id 1 - 192.168.100.127/25
  Broadcast Id 2 - 192.168.100.255/25
```

```markdown
IP address - 192.168.100.225
Subnet mask - 255.255.255.192 - 11111111.11111111.11111111.11000000

We have 24+2=26 network bits here; so the number of possible subnets is 2^2=4

Network Id 1 - 192.168.100.0/26
Network Id 2 - 192.168.100.64/26
Network Id 3 - 192.168.100.128/26
Network Id 4 - 192.168.100.192/26

Broadcast Id 1 - 192.168.100.63/26
Broadcast Id 2 - 192.168.100.127/26
Broadcast Id 3 - 192.168.100.191/26
Broadcast Id 4 - 192.168.100.255/26
```

```markdown
Given IP - 192.168.225.212/27

Here, /27 means we have 27 (24+3) network bits, so number of possible subnets would be 8 (2^3); each subnet would have 30 (256/8 - 2) hosts.

Therefore, Network Id is 192.168.225.192/27 and Broadcast Id is 192.168.225.223/27
```

```markdown
We need to design a network with 3 subnets with requirements of 60, 100 and 34 computers for each subnet (VLSM).

For the requirement of 100 computers, we can use the subnet with 126 hosts such that Network Id - 192.168.1.0/25, and Broadcast Id - 192.168.1.127/25

For the next requirement of 60 computers, we can use a subnet with 62 hosts, that is, with Network Id - 192.168.1.128/26 and Broadcast Id - 192.168.1.191/26

Similarly, for the final 34 computers, we can use the Network Id 192.168.1.192/26 and Broadcast Id 192.168.1.255/26
```
