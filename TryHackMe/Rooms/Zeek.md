# Zeek - Medium

1. [Network Security Monitoring and Zeek](#network-security-monitoring-and-zeek)
2. [Zeek Logs](#zeek-logs)
3. [CLI Kung-Fu](#cli-kung-fu)
4. [Zeek Signatures](#zeek-signatures)
5. [Zeek Scripts | Fundamentals](#zeek-scripts--fundamentals)
6. [Zeek Scripts | Scripts and Signatures](#zeek-scripts--scripts-and-signatures)
7. [Zeek Scripts | Frameworks](#zeek-scripts--frameworks)
8. [Zeek Scripts | Packages](#zeek-scripts--packages)

## Network Security Monitoring and Zeek

* Network Monitoring - set of management actions to watch and save network traffic for further investigation.

* Zeek is a Network Monitoring tool and offers in-depth traffic investigation; its frameworks are used to provide extended functionality in scripting layer.

* Default log path: ```/opt/zeek/logs```

```shell
zeek -v
#check version

cd Desktop/Exercise-Files/TASK-2

sudo su
#root

zeekctl
#ZeekControl module
#commands - status, start, stop

exit

zeek -C -r sample.pcap
#-r for reading a pcap file
#-C for ignoring checksum errors
#to process pcap files with Zeek

ls -l
#view generated logs
```

```markdown
1. What is the installed Zeek instance version number? - 4.2.1

2. What is the version of the ZeekControl module? - 2.4.0

3. Investigate the sample.pcap file. What is the number of generated alert files? - 8
```

## Zeek Logs

* Zeek generates log files according to the traffic data, some of which are:

  * Overall info - conn.log, files.log, intel.log, loaded_scripts.log

  * Protocol-based - http.log, dns.log, ftp.log, ssh.log

  * Detection - notice.log, signatures.log, pe.log, traceroute.log

  * Observation - known_host.log, known_services.log, software.log, weird.log

* ```zeek-cut``` tool helps in extracting specific columns from log files.

```shell
cd Desktop/Exercise-Files/TASK-3

ls

sudo su

zeek -C -r sample.pcap
#generates log files

cat dhcp.log
#note dowwn fields of interest
#in this case, hostname

cat dhcp.log | zeek-cut host_name
#gives hostname

cat dns.log

cat dns.log | zeek-cut query

cat conn.log

cat conn.log | zeek-cut duration
```

```markdown
1. Investigate the sample.pcap file. Investigate the dhcp.log file. What is the available hostname? - Microknoppix

2. Investigate the dns.log file. What is the number of unique DNS queries? - 2

3. Investigate the conn.log file. What is the longest connection duration? - 332.319364
```

## CLI Kung-Fu

```shell
#view command history
history

#execute 10th command in history
!10

#execute previous command
!!

#cut 1st field
cat test.txt | cut -f 1

#cut 1st column
cat test.txt | cut -c1

#show line numbers
cat test.txt | nl

#print line 23
cat test.txt | sed -n '23p'

#print lines 20-25
cat test.txt | sed -n '20-25p'

#print lines below 11
cat test.txt | awk 'NR < 11 {print $0}'

#remove duplicates and count frequencies
cat test.txt | sort | uniq -c

#search 'Testvalue1' string, organise column spaces and view output
grep -rin Testvalue1 * | column -t | less -S
```

## Zeek Signatures

```markdown
1. Investigate the http.pcap file. Create the  HTTP signature shown in the task and investigate the pcap. What is the source IP of the first event?

2. What is the source port of the second event?

3. Investigate the conn.log. What is the total number of the sent and received packets from source 38706?

4. Investigate the notice.log. What is the number of unique events?

5. What is the number of ftp-brute signature matches?
```

## Zeek Scripts | Fundamentals

```markdown
1. Investigate the smallFlows.pcap file. Investigate the dhcp.log file. What is the domain value of the "vinlap01" host?

2. Investigate the bigFlows.pcap file. Investigate the dhcp.log file. What is the number of identified unique hostnames?

3. Investigate the dhcp.log file. What is the identified domain value?

4. Investigate the dns.log file. What is the number of unique queries?
```

## Zeek Scripts | Scripts and Signatures

```markdown
1. Investigate the sample.pcap file with 103.zeek script. Investigate the terminal output. What is the number of the detected new connections?

2. Investigate the ftp.pcap file with ftp-admin.sig signature and  201.zeek script. Investigate the signatures.log file. What is the number of signature hits?

3. Investigate the signatures.log file. What is the total number of "administrator" username detections?

4. Investigate the ftp.pcap file with all local scripts, and investigate the loaded_scripts.log file. What is the total number of loaded scripts?

5. Investigate the ftp-brute.pcap file with "/opt/zeek/share/zeek/policy/protocols/ftp/detect-bruteforcing.zeek" script. Investigate the notice.log file. What is the total number of brute-force detections?
```

## Zeek Scripts | Frameworks

```markdown
1. Investigate the case1.pcap file with intelligence-demo.zeek script. Investigate the intel.log file. Look at the second finding, where was the intel info found?

2. Investigate the http.log file. What is the name of the downloaded .exe file?

3. Investigate the case1.pcap file with hash-demo.zeek script. Investigate the files.log file. What is the MD5 hash of the downloaded .exe file?

4. Investigate the case1.pcap file with file-extract-demo.zeek script. Investigate the "extract_files" folder. Review the contents of the text file. What is written in the file?
```

## Zeek Scripts | Packages

```markdown
1. Investigate the http.pcap file with the zeek-sniffpass module. Investigate the notice.log file. Which username has more module hits?

2. Investigate the case2.pcap file with geoip-conn module. Investigate the conn.log file. What is the name of the identified City?

3. Which IP address is associated with the identified City?

4. Investigate the case2.pcap file with sumstats-counttable.zeek script. How many types of status codes are there in the given traffic capture?
```
