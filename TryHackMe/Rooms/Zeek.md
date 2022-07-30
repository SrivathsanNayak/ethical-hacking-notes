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

* Zeek signatures are composed of 3 logical paths - signature id, conditions and action.

* The filters for Zeek accept string, numeric and regex values.

* HTTP signature:

```shell
signature http-password {
     ip-proto == tcp
     dst_port == 80
     payload /.*password.*/
     event "Cleartext Password Found!"
}
```

* FTP signature:

```shell
signature ftp-username {
    ip-proto == tcp
    ftp /.*USER.*/
    event "FTP Username Input Found!"
}

signature ftp-brute {
    ip-proto == tcp
     payload /.*530.*Login.*incorrect.*/
    event "FTP Brute-force Attempt!"
}
```

```shell
cd Desktop/Exercise-Files/TASK-5

ls

cd http

ls
#shows incomplete signature file and pcap file
#we need to create http signature as shown in task

vim http-signature.sig
#add http signature

zeek -C -r http.pcap -s http-password.sig
#-s to use signature file
#this generates signatures.log and notice.log

ls

cat notice.log | zeek-cut id.orig_h id.orig_p id.resp_h msg

head conn.log
#note fields

cat conn.log | zeek-cut id.orig_p orig_pkts resp_pkts

#now we need to analyze ftp.pcap

cd ../ftp/

vim ftp-bruteforce.sig
#edit ftp global rule signature

zeek -C -r ftp.pcap -s ftp-bruteforce.sig

ls

head notice.log
#note fields

cat notice.log | zeek-cut uid | sort | uniq | wc -l
#counts number of unique events

cat notice.log | zeek-cut msg | grep "Brute-force" | wc -l
```

```markdown
1. Investigate the http.pcap file. Create the HTTP signature shown in the task and investigate the pcap. What is the source IP of the first event? - 10.10.57.178

2. What is the source port of the second event? - 38712

3. Investigate the conn.log. What is the total number of the sent and received packets from source 38706? - 20

4. Investigate the notice.log. What is the number of unique events? - 1413

5. What is the number of ftp-brute signature matches? - 1410
```

## Zeek Scripts | Fundamentals

* Base scripts (not to be modified) - ```opt/zeek/share/zeek/base```

* User-generated scripts - ```/opt/zeek/share/zeek/site```

* Policy scripts - ```/opt/zeek/share/zeek/policy```

* Configuration file - ```/opt/zeek/share/zeek/site/local.zeek```

* We can use scripts in live monitoring mode by loading them with ```load @/script/path``` or ```load @script-name``` in local.zeek file.

* Zeek is an event-oriented language.

```shell
cd Desktop/Exercise-Files/TASK-6

ls

cd smallflow

ls
#we are given pcap file and zeek file

zeek -C -r smallFlows.pcap

head dhcp.log
#shows domain value for 'vinlap01'

cd ../bigflow

ls

zeek -C -r bigFlows.pcap

head dhcp.log

cat dhcp.log | zeek-cut host_name | sort -nr | uniq

head dns.log
#many queries contain '*' and '-' characters

cat dns.log | zeek-cut query | grep -v -e '*' -e '-' | sort -nr | uniq | wc -l
```

```markdown
1. Investigate the smallFlows.pcap file. Investigate the dhcp.log file. What is the domain value of the "vinlap01" host? - astaro_vineyard

2. Investigate the bigFlows.pcap file. Investigate the dhcp.log file. What is the number of identified unique hostnames? - 17

3. Investigate the dhcp.log file. What is the identified domain value? - jaalam.net

4. Investigate the dns.log file. What is the number of unique queries? - 1109
```

## Zeek Scripts | Scripts and Signatures

```shell
cd Desktop/Exercise-Files/TASK-7

ls

cd 101

zeek -C -r sample.pcap 103.zeek > output.txt
#generates a lot of output so redirected to text file

cat 103.zeek
#view script

cat output.txt | grep "New Connection Found" | wc -l
#shows number of new connections

cd ../201

ls

zeek -C -r ftp.pcap -s ftp-admin.sig 201.zeek > output.txt

ls

cat output.txt | grep "Signature hit!" | wc -l

cat signatures.log | grep "administrator" | wc -l

zeek -C -r ftp.pcap local
#load all local scripts

cat loaded_scripts.log | grep ".zeek" | wc -l

cd ../202

ls

zeek -C -r ftp-brute.pcap /opt/zeek/share/zeek/policy/protocols/ftp/detect-bruteforcing.zeek

cat notice.log | grep "Bruteforcing" | wc -l
```

```markdown
1. Investigate the sample.pcap file with 103.zeek script. Investigate the terminal output. What is the number of the detected new connections? - 87

2. Investigate the ftp.pcap file with ftp-admin.sig signature and  201.zeek script. Investigate the signatures.log file. What is the number of signature hits? - 1401

3. Investigate the signatures.log file. What is the total number of "administrator" username detections? - 731

4. Investigate the ftp.pcap file with all local scripts, and investigate the loaded_scripts.log file. What is the total number of loaded scripts? - 498

5. Investigate the ftp-brute.pcap file with "/opt/zeek/share/zeek/policy/protocols/ftp/detect-bruteforcing.zeek" script. Investigate the notice.log file. What is the total number of brute-force detections? - 2
```

## Zeek Scripts | Frameworks

* Frameworks are used to discover different events of interest; scripts can call frameworks as ```@load PATH/base/frameworks/framework-name```.

```shell
cd Desktop/Exercise-Files/TASK-8

zeek -C -r case1.pcap intelligence-demo.zeek
#now we have to investigate intel file and script

head intel.log

cat intel.log | zeek-cut seen.indicator seen.where matched

head http.log

cat http.log | zeek-cut uri

zeek -C -r case1.pcap hash-demo.zeek

ls

head files.log

cat files.log | zeek-cut mime_type md5

zeek -C -r case1.pcap file-extract-demo.zeek

cd extract_files/

ls

file * | nl
#shows file type
#print file content using cat
```

```markdown
1. Investigate the case1.pcap file with intelligence-demo.zeek script. Investigate the intel.log file. Look at the second finding, where was the intel info found? - IN_HOST_HEADER

2. Investigate the http.log file. What is the name of the downloaded .exe file? - knr.exe

3. Investigate the case1.pcap file with hash-demo.zeek script. Investigate the files.log file. What is the MD5 hash of the downloaded .exe file? - cc28e40b46237ab6d5282199ef78c464

4. Investigate the case1.pcap file with file-extract-demo.zeek script. Investigate the "extract_files" folder. Review the contents of the text file. What is written in the file? - Microsoft NCSI
```

## Zeek Scripts | Packages

* Zeek Package Manager (zkg) helps users install third-party scripts & plugins to extend Zeek functionalities.

* Packages can be either used as frameworks and call specific paths, or called from a script with the '@load' method; if the packages have been installed with ```zkg install``` we can call their package names directly.

```shell
cd Desktop/Exercise-Files/TASK-9

zkg list
#view installed zkg packages

cd cleartext-pass

ls

zeek -Cr http.pcap zeek-sniffpass

cat notice.log | zeek-cut note msg | sort -nr | uniq
#shows two usernames - ZeekBro and BroZeek

cat notice.log | grep "BroZeek" | wc -l

cat notice.log | grep "ZeekBro" | wc -l

cd ../geoip-conn/

zeek -Cr case2.pcap geoip-conn

head conn.log

zeek -Cr case2.pcap sumstats-counttable.zeek
```

```markdown
1. Investigate the http.pcap file with the zeek-sniffpass module. Investigate the notice.log file. Which username has more module hits? - BroZeek

2. Investigate the case2.pcap file with geoip-conn module. Investigate the conn.log file. What is the name of the identified City? - Chicago

3. Which IP address is associated with the identified City? - 23.77.86.54

4. Investigate the case2.pcap file with sumstats-counttable.zeek script. How many types of status codes are there in the given traffic capture? - 4
```
