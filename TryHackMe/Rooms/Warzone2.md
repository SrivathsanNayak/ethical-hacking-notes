# Warzone 2 - Medium

* First, we can open the provided .pcap file in Brim to analyze.

* From the given queries, we can choose ```Suricata Alerts by Category``` - modify the query to show alert signature:

  ```event_type=="alert" | cut alert.category, alert.signature, alert.severity, src_ip```

* Now, we can choose the query for ```HTTP Requests``` - this needs to be modified as we need to find the URI and user-agent:

  ```_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method,host, uri, user_agent | id.resp_h == 185.118.164.8```

* To get the full URI, we need to concatenate 'host' and 'uri'.

* Now, we can get the hash for the downloaded file using the query ```File Activity``` - get the MD5 hash and search it on ```VirusTotal``` to get the name of the payload within the .cab file.

* To get all the domains from the network traffic, we can use this query:

  ```_path=="http" | count() by host```

* We have 7 domains; ```VirusTotal``` can be used to check if these domains are malicious or not.

* Also, after getting the IP addresses from "Not Suspicious Traffic", we can check them on ```VirusTotal``` - the domains associated with these IP address can be found in the 'Relations' tab.

```markdown
1. What was the alert signature for "A Network Trojan was Detected"? - ET MALWARE Likely Evil EXE download from MSXMLHTTP non-exe extension M2

2. What was the alert signature for "Potential Corporate Privacy Violation"? - ET POLICY PE EXE or DLL Windows file download HTTP

3. What was the IP to trigger either alert? - 185[.]118[.]164[.]8

4. Provide the full URI for the malicious downloaded file. - awh93dhkylps5ulnq-be[.]com/czwih/fxla[.]php?l=gap1[.]cab

5. What is the name of the payload within the cab file? - draw.dll

6. What is the user-agent associated with this network traffic? - Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/8.0; .NET4.0C; .NET4.0E)

7. What other domains do you see in the network traffic that are labelled as malicious by VirusTotal? - a-zcorner[.]com,knockoutlights[.]com

8. There are IP addresses flagged as "Not Suspicious Traffic". What are the IP addresses? - 64[.]225[.]65[.]166,142[.]93[.]211[.]176

9. For the first IP address flagged as "Not Suspicious Traffic". According to VirusTotal, there are several domains associated with this one IP address that was flagged as malicious. What were the domains you spotted in the network traffic associated with this IP address? - safebanktest[.]top,tocsicambar[.]xyz,ulcertification[.]xyz

10. Now for the second IP marked as "Not Suspicious Traffic". What was the domain you spotted in the network traffic associated with this IP address? - 2partscow[.]top
```
