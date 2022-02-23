# Linux Basics

* Common network commands:

```shell
ifconfig
#IP addresses, interfaces, etc.

ip
#alt to ifconfig, as it is deprecated
#'ip a' shows IP addresses
#'ip n' shows ARP table
#'ip r' shows routing table

iwconfig
#wireless interfaces

ping 10.0.0.5
#ping any address

arp -a
#IP addresses and MAC addresses communicating with our machine

netstat -ano
#to check ports, services

route
#prints routing table
```

* Installing and updating tools:

```shell
apt update && apt upgrade
#update and upgrade tools

apt install python-pip
#install a tool

git clone https://github.com/Dewalt-arch/pimpmykali.git
#clone a repo
#can store this in /opt

./pimpmykali.sh
#run a shell script
```

* Creating and editing files:

```shell
echo "hello"
#print hello in terminal

echo "hey" > hey.txt
#write hey to a file called hey.txt

cat hey.txt
#reads file content

echo "hey again" >> hey.txt
#append to file
```

* Bash scripts examples:

```shell
#!/bin/bash
if [ "$1" == "" ] #to check if user gave any input or not
then
        echo "You forgot IP address!"
        echo "Syntax: ./ipsweep.sh 10.0.2"

else
        for ip in `seq 1 254`; do #uses ip value from 1 to 254
                ping -c 1 $1.$ip | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
                #ping -c 1 is used for sending exactly one packet, $1.$ip concatenates to form ip
                #grep to print line with "64 bytes"
                #cut command to find 4th field with space set as delimiter
                #tr delimits at ":"
                #ampersand used to run command in background; async
        done
fi


#chmod +x ipsweep.sh - for allowing script to be executed
#script output can be stored in a file
#./ipsweep.sh 10.0.2 > iplist.txt
```

```shell
#one-liner

for ip in $(cat iplist.txt); do nmap -p 80 -sS -T4 $ip & done

#nmap scan for each ip from iplist.txt
```
