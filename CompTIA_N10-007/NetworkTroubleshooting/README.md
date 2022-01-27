# Network Troubleshooting and Tools

## Network Troubleshooting

* Troubleshooting process:

    1. Identify the problem
    2. Establish a theory
    3. Test the theory
    4. Create plan of action
    5. Implement the solution
    6. Verify full system functionality
    7. Document findings

## Network Tools

* Common hardware tools include cable crimpers, cable testers, TDR/OTDR (Time Domain Reflectometer/Optical TDR), punch-down tools, light meter, tone generator, loopback plugs, multimeters, and spectrum analyzers.

* Common software tools include protocol analyzers, network/port scanners, wireless packet analyzers, and speed test sites.

* Command line tools:

```shell
ping 9.9.9.9 #test reachability

tracert 9.9.9.9 #determine route of packet, traceroute in UNIX-based systems

nslookup #lookup info from DNS servers, use dig instead

dig #domain info groper, advanced domain info

ipconfig #ifconfig for UNIX, shows interface config

iptables #stateful firewall, filter packets in kernel

netstat #network stats

tcpdump #capture packets, apply filters

pathping 9.9.9.9 #combines ping and traceroute

nmap #network mapper, port scan, OS scan, service scan

route print #view routing table

arp -a #view local ARP table
```

## Wired Network Troubleshooting

* Attenuation - signal loss; electrical signals through copper, light through fiber.

* dB loss symptoms - no connectivity, intermittent connectivity, poor performance; test distance and signal loss.

* Latency - delay between the request and response; waiting time.

* Jitter - time measured between frames; excessive jitter can cause data loss.

* Excessive jitter troubleshooting - confirm available bandwidth; check infrastructure; apply QoS.

* Crosstalk (XT) - signals on one circuit affects another circuit; leaking of circuit; XT can be measured with TDR.

* NEXT (Near End XT) - interference measured at transmitting end.

* FEXT (Far End XT) - interference measured away from transmitter.

* XT troubleshooting - wiring issues; maintain twists; use category 6A cable to increase cable diameter; test and certify installation.

* EMI (Electromagnetic Interference) can be avoided by cable handling; avoid power cords, fluorescent lights, electrical systems; test after installation.

* Short circuit - two connections are touching; wires inside connection/cable.

* Open circuit - break in connection; no communication.

* Troubleshooting opens and shorts - replace cable; use TDR.

* Incorrect cable type - excessive physical errors; check cable outer part; confirm with TDR, cable tester.

* Troubleshooting interfaces - bad cable, hardware problem; verify config, two-way traffic.

* Damaged cables - check physical layer, check TDR, replace cable.

## Wireless Network Troubleshooting

* Reflection - too much reflection can weaken signal; position antennas to avoid excessive reflection.

* Refraction - data rates are affected as signal is less directional; happens in outdoor long-distance wireless links.

* Absorption - signal passes through object and loses signal strength; changes with frequency; put antennas on ceiling, avoid going through walls.

* Latency and jitter can cause wireless interference, signal and capacity issues.

* Attenuation issues - control power output on access point; use receive antenna with higher gain; move closer to antenna.

* Incorrect antenna placements - antennas placed too close can cause interference due to overlapping channels; if placed too far, it can cause slow throughput.

* Overcapacity issues - device saturation; bandwidth saturation.

## Network Service Troubleshooting

* Troubleshooting DNS issues - check IP configuration; use nslookup or dig to test.

* Troubleshooting IP configurations - check documentation, check devices around; monitor traffic, use tracert and ping.

* Rogue DHCP server - client assigned an invalid/duplicate address; disable rogue DHCP communication; disable rouge; renew IP leases.

* Blocked TCP/UDP ports - apps not working; firewall or ACL configuraion; confirm with packet capture; run TCP/UDP based traceroute tool.
