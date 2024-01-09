# Intro to Network Traffic Analysis

1. [Intro](#intro)
1. [Tcpdump](#tcpdump)
1. [Wireshark](#wireshark)

## Intro

* Network traffic analysis (NTA) - detailed examination of event/process to determine its origin and impact.

* NTA can be passive or active - with passive, we are copying data but not interacting with it; while active is in-line traffic capture.

* Sample analysis workflow for NTA:

  * Descriptive analysis - describe issue, scope, objective and targets (network/hosts/protocol)
  * Diagnostic analysis - capture network traffic, identify & filter required traffic components, analysis of capture
  * Predictive analysis - identify trends, detect deviations from baseline, summary of analysis

## Tcpdump

* ```tcpdump``` - command-line packet sniffer that can capture and interpret data frames from a file or network interface.

  ```shell
  sudo tcpdump -D
  # -D to list available interfaces
  # sudo used for hardware access is reqd
  ```

  ```shell
  sudo tcpdump -i eth0 -nn
  # selecting interface eth0 to capture traffic
  # -nn is to not resolve hostnames and ports
  ```

  ```shell
  sudo tcpdump -i eth0 -e
  # -e used to include ethernet headers in capture
  # so that L2 info is seen
  ```

  ```shell
  sudo tcpdump -i eth0 -X
  # includes ascii & hex output
  ```

  ```shell
  sudo tcpdump -i eth0 -nnvXX
  # we can chain multiple switches
  # -v is for verbosity
  # -XX is for ascii & hex output, and Ethernet headers included
  # -XX is same as -Xe
  ```

  ```shell
  # save as pcap output
  sudo tcpdump -i eth0 -w ~/output.pcap

  # to read output from file
  sudo tcpdump -r ~/output.pcap
  ```

* ```tcpdump``` packet filtering:

  ```shell
  sudo tcpdump -i eth0 host 172.16.146.2
  # filter by host

  sudo tcpdump -i eth0 src host 172.16.146.2
  # src to filter by source
  # dest to filter by destination

  sudo tcpdump -i eth0 tcp src port 80
  # source port as filter
  # only tcp protocol
  # we can use protocol numbers with 'proto' for the same
  ```

  ```shell
  sudo tcpdump -i eth0 dest net 172.16.146.0/24
  # net grabs anything matching slash notation
  # so anything destined to 172.16.146.0/24 network
  ```

  ```shell
  sudo tcpdump -i eth0 portrange 0-1024
  # everything in port range captured
  ```

  ```shell
  sudo tcpdump -i eth0 less 64
  # for packets less than 64 bytes in size

  sudo tcpdump -i eth0 greater 500
  # packets greater than 500 bytes
  ```

  ```shell
  sudo tcpdump -i eth0 host 192.168.0.1 and port 23
  # AND modifier used to show packets that meet both conditions

  sudo tcpdump -r sus.pcap icmp or host 172.16.146.1
  # OR modifier

  sudo tcpdump -r sus.pcap not icmp
  # NOT modifier, negates all ICMP traffic here
  ```

  ```shell
  sudo tcpdump -Ar http.cap -l | grep 'mailto:*'
  # -l used to pipe contents to utilities like grep
  ```

  ```shell
  sudo tcpdump -i eth0 'tcp[13] &2 != 0'
  # counting to 13th byte in structure and looking at 2nd bit
  # if it is set to 1 or ON, SYN flag is set
  ```

## Wireshark

* Wireshark - network traffic analyzer with a graphical interface; allows a deeper inspection of network packets compared to other tools.

* Similar to ```tcpdump```, we have options for pre-capture (capture filters) and post-capture (display filters) processing and filtering.

* Useful plugins:

  * Statistics & Analyze
  * Following TCP streams
  * Extracting files from a capture

* Dissect ```ftp``` data:

  * Identify FTP traffic using ```ftp``` display filter
  * Checks commands using ```ftp.request.command``` filter
  * Choose a file and filter for ```ftp-data``` - select a packet corresponding to the file and follow the TCP stream
  * Change 'show and save data as' to 'Raw' and save content as original filename; validate extraction by checking file type

* Decrypting ```rdp``` connections:

  * Identify RDP traffic using ```rdp``` filter or ```tcp.port == 3389``` (in case RDP is using TLS to encrypt data)
  * Provide RDP key to Wireshark for decrypting traffic; navigate to Edit > Preferences > Protocols > TLS > Edit RSA keys list
  * Import RSA server key by adding a new key - add IP address of RDP server, port used, protocol (```tpkt``` in this case), key file - save and refresh pcap
  * Analyze clear RDP traffic
