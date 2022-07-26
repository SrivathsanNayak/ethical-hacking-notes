# Zeek - Medium

## Network Security Monitoring and Zeek

```markdown
1. What is the installed Zeek instance version number?

2. What is the version of the ZeekControl module?

3. Investigate the sample.pcap file. What is the number of generated alert files?
```

## Zeek Logs

```markdown
1. Investigate the sample.pcap file. Investigate the dhcp.log file. What is the available hostname?

2. Investigate the dns.log file. What is the number of unique DNS queries?

3. Investigate the conn.log file. What is the longest connection duration?
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
