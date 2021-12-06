# Network Hacking

* To list all network interfaces available, we can use `ifconfig`. The MAC address can be viewed under _ether_ in _wlan0_.

* To change the MAC address:

```console
ifconfig wlan0 down #disables wlan0

ifconfig wlan0 hw ether 00:11:22:33:44:55 #sets hardware address of wlan0

ifconfig wlan0 up #enables wlan0
```
