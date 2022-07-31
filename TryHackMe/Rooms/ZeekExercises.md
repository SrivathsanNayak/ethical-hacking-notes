# Zeek Exercises - Medium

1. [Anomalous DNS](#anomalous-dns)
2. [Phishing](#phishing)
3. [Log4J](#log4j)

## Anomalous DNS

```shell
cd Desktop/Exercise-Files/anomalous-dns

ls

zeek -Cr dns-tunneling.pcap

head dns.log

#AAAA record maps to IPv6 address
cat dns.log | zeek-cut qtype_name | grep "AAAA" | wc -l

head conn.log

cat conn.log | zeek-cut duration | sort -n | uniq

cat dns.log | zeek-cut query | grep -v -e "update.com" | sort -nr | uniq
#this shows 15 addresses
#we can see unique domain queries by simply checking the address
```

```markdown
1. Investigate the dns-tunneling.pcap file. Investigate the dns.log file. What is the number of DNS records linked to the IPv6 address? - 320

2. Investigate the conn.log file. What is the longest connection duration? - 9.420791

3. Investigate the dns.log file. Filter all unique DNS queries. What is the number of unique domain queries? - 6

4. Investigate the conn.log file. What is the IP address of the source host? - 10.20.57.3
```

## Phishing

```shell
cd Desktop/Exercise-Files/phishing

zeek -Cr phishing.pcap

ls

head conn.log
#to defang IP address, cover the delimiter '.' in square brackets

head http.log

./clear-logs.sh

zeek -Cr phishing.pcap hash-demo.zeek
#extract files hashes in log file

zeek -Cr phishing.pcap file-extract-demo.zeek
#create dir for extracted files

ll

cd extract_files/

ls

file *
#check file type
#here, the two malicious files can be the doc and the exe file

md5sum extract-1561667889.703239-HTTP-FB5o2Hcauv7vpQ8y3
#gives md5 b5243ec1df7d1d5304189e7db2744128

md5sum extract-1561667899.060086-HTTP-FOghls3WpIjKpvXaEl
#gives md5 cc28e40b46237ab6d5282199ef78c464
#we can use VirusTotal to look it up

#for the malicious doc file, we can view Relations on VirusTotal
#this shows that the related filetype is vba
#the malicious shell command can be found in Behaviour - Process and Service Actions

#for the exe, the domain name can be found in network communication

cd ..

cat http.log | zeek-cut uri
```

```markdown
1. Investigate the logs. What is the suspicious source address? - 10[.]6[.]27[.]102

2. Investigate the http.log file. Which domain address were the malicious files downloaded from? - smart-fax[.]com

3. Investigate the malicious document in VirusTotal. What kind of file is associated with the malicious document? - vba

4. What is the executed Shell Command by the malicious document? - c:/analyse/1564071314.9150934_80fc752d-3099-4df0-9c50-4d7c0e228e26

5. Investigate the extracted malicious .exe file. What is the given file name in Virustotal? - PleaseWaitWindow.exe

6. Investigate the malicious document in VirusTotal. What is the contacted domain name? - hopto[.]org

7. Investigate the http.log file. What is the request name of the downloaded malicious .exe file? - knr.exe
```

## Log4J

```shell
cd Desktop/Exercise-Files/log4j

zeek -Cr log4shell.pcapng detection-log4j.zeek

ls

head signatures.log

cat signatures.log | zeek-cut ts | wc -l

head http.log
#shows the log4j exploit file

cat http.log | zeek-cut user_agent
#shows Nmap Scripting Engine

head log4j.log

echo d2hpY2ggbmMgPiAvdG1wL3B3bmVkCg== | base64 -d
#decodes the base64 command
#this shows us the file name
```

```markdown
1. Investigate the log4shell.pcapng file with detection-log4j.zeek script. Investigate the signature.log file. What is the number of signature hits? - 3

2. Investigate the http.log file. Which tool is used for scanning? - Nmap

3. Investigate the http.log file. What is the extension of the exploit file? - .class

4. Investigate the log4j.log file. Decode the base64 commands. What is the name of the created file? - pwned
```
