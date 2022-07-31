# Zeek Exercises - Medium

1. [Anomalous DNS](#anomalous-dns)
2. [Phishing](#phishing)
3. [Log4J](#log4j)

## Anomalous DNS

```markdown
1. Investigate the dns-tunneling.pcap file. Investigate the dns.log file. What is the number of DNS records linked to the IPv6 address?

2. Investigate the conn.log file. What is the longest connection duration?

3. Investigate the dns.log file. Filter all unique DNS queries. What is the number of unique domain queries?

4. Investigate the conn.log file. What is the IP address of the source host?
```

## Phishing

```markdown
1. Investigate the logs. What is the suspicious source address?

2. Investigate the http.log file. Which domain address were the malicious files downloaded from?

3. Investigate the malicious document in VirusTotal. What kind of file is associated with the malicious document?

4. What is the executed Shell Command by the malicious document?

5. Investigate the extracted malicious .exe file. What is the given file name in Virustotal?

6. Investigate the malicious document in VirusTotal. What is the contacted domain name?

7. Investigate the http.log file. What is the request name of the downloaded malicious .exe file?
```

## Log4J

```markdown
1. Investigate the log4shell.pcapng file with detection-log4j.zeek script. Investigate the signature.log file. What is the number of signature hits?

2. Investigate the http.log file. Which tool is used for scanning?

3. Investigate the http.log file. What is the extension of the exploit file?

4. Investigate the log4j.log file. Decode the base64 commands. What is the name of the created file?
```
