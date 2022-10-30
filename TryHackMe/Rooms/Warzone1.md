# Warzone 1 - Medium

* We can start by importing zone1.pcap file in Brim.

* Using the query 'Suricata Alerts by Category', we can check the alert category 'Malware Command and Control Activity Detected'; the query looks like this:

  ```event_type=="alert" | count() by alert.severity,alert.category | sort count```

* To get the alert signature, we need to append alert.signature to the command:

  ```event_type=="alert" | count() by alert.severity,alert.category,alert.signature | sort count```

* Now, we can use the query for 'Unique Network Connections', which will give us the source IP address:

  ```_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h | sort | uniq```

* In order to get the destination IP address in the alert, we can use the query 'Suricata Alerts by Source and Destination':

  ```event_type=="alert" | alerts := union(alert.category) by src_ip, dest_ip```

* Now, we need to use VirusTotal and search for the destination IP address; we have to check the Passive DNS Replaction section and the Community section.

* We also need to search for "fidufagios.com" in VirusTotal.

* We can inspect the web traffic using the following query:

  ```_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method,host, uri, user_agent```

* Now, we can check the Alerts on Brim again in order to get the multiple IP addresses involved in the attack:

  ```_path=="http" | cut id.orig_h, id.resp_h, host | uniq -c```

* For the filenames, the first filename can be found in Brim using 'File Activity' filter.

* The second filename can be found by opening the .pcap file in Wireshark; Export Objects > HTTP

* In order to look for the file paths for both files, we have to inspect the HTTP streams in Wireshark.

```markdown
1. What was the alert signature for Malware Command and Control Activity Detected? - ET MALWARE MirrorBlast CnC Activity M3

2. What is the source IP address? - 172[.]16[.]1[.]102

3. What IP address was the destination IP in the alert? - 169[.]239[.]128[.]11

4. Inspect the IP address in VirsusTotal. Under Relations > Passive DNS Replication, which domain has the most detections? - fidufagios[.]com

5. Still in VirusTotal, under Community, what threat group is attributed to this IP address? - TA505

6. What is the malware family? - MirrorBlast

7. What was the majority file type listed under Communicating Files? - Windows Installer

8. Inspect the web traffic for the flagged IP address; what is the user-agent in the traffic? - REBOL View 2.7.8.3.1

9. Retrace the attack; there were multiple IP addresses associated with this attack. What were two other IP addresses? - 185[.]10[.]68[.]235,192[.]36[.]27[.]92

10. What were the file names of the downloaded files? - filter.msi,10opd3r_load.msi

11. Inspect the traffic for the first downloaded file. Two files will be saved to the same directory. What is the full file path of the directory and the name of the two files? - C:\ProgramData\001\arab.bin,C:\ProgramData\001\Action1_arab.exe

12. Inspect the traffic from the second downloaded file. Two files will be saved to the same directory. What is the full file path of the directory and the name of the two files? - C:\ProgramData\Local\Google\rebol-view-278-3-1.exe,C:\ProgramData\Local\Google\exemple.rb
```
