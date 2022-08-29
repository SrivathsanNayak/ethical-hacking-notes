# Brim - Medium

1. [What is Brim?](#what-is-brim)
2. [The Basics](#the-basics)
3. [Default Queries](#default-queries)
4. [Use Cases](#use-cases)
5. [Exercise: Threat Hunting with Brim | Malware C2 Detection](#exercise-threat-hunting-with-brim--malware-c2-detection)
6. [Exercise: Threat Hunting with Brim | Crypto Mining](#exercise-threat-hunting-with-brim--crypto-mining)

## What is Brim?

* Brim is an open-source app that processes pcap files and log files for analytics.

* Brim supports Zeek log formats, Zeek signatures and Suricata rules for detection.

* Common best practice is to handle medium-sized pcaps with Wireshark, creating logs and events with Zeek, and processing multiple logs in Brim.

## The Basics

```markdown
1. Process the "sample.pcap" file and look at the details of the first DNS log that appear on the dashboard. What is the "qclass_name"? - C_INTERNET

2. Look at the details of the first NTP log that appear on the dashboard. What is the "duration" value? - 0.005

3. Look at the details of the STATS packet log that is visible on the dashboard. What is the "reassem_tcp_size"? - 540
```

## Default Queries

* The 12 premade queries in Brim can be used for packet analysis.

* We can modify the default queries as well, to find the answers to certain questions.

```markdown
1. Investigate the files. What is the name of the detected GIF file? - cat01_with_hidden_text.gif

2. Investigate the conn logfile. What is the number of the identified city names? - 2

3. Investigate the Suricata alerts. What is the Signature id of the alert category "Potential Corporate Privacy Violation"? - 2,012,887
```

## Use Cases

* Queries for particular use cases:

  * Communicated hosts - ```_path=="conn" | cut id.orig_h, id.resp_h | sort | uniq```

  * Frequently communicated hosts - ```_path=="conn" | cut id.orig_h, id.resp_h | sort | uniq -c | sort -r```

  * Most active ports - ```_path=="conn" | cut id.orig_h, id.resp_h, id.resp_p, service | sort id.resp_p | uniq -c | sort -r```

  * Long connections - ```_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h, duration | sort -r duration```

  * Transferred data - ```_path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes```

  * DNS queries - ```_path=="dns" | count () by query | sort -r```

  * HTTP queries - ```_path=="http" | count () by uri | sort -r```

  * Suspicious hostnames - ```_path=="dhcp" | cut host_name, domain```

  * Suspicious IP addresses - ```_path=="conn" | put classnet := network_of(id.resp_h) | cut classnet | count() by classnet | sort -r```

  * Detect files - ```filename!=null```

  * SMB activity - ```_path=="dce_rpc" OR _path=="smb_mapping" OR _path=="smb_files"```

  * Known patterns - ```event_type=="alert" OR _path=="notice" OR _path=="signatures"```

## Exercise: Threat Hunting with Brim | Malware C2 Detection

* We need to use queries for threat hunting, similar to previous use cases:

  * Activity Overview - ```count() by _path | sort -r```

  * Frequently communicated hosts - ```_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h | sort | uniq -c | sort -r count``` - shows us that 10.22.X.X and 104.168.X.X are frequently communicated.

  * Active ports - ```_path=="conn" | cut id.resp_p, service | sort | uniq -c | sort -r count``` - shows SSL and DNS as active services on port 443.

  * DNS queries - ```_path=="dns" | count() by query | sort -r``` - shows certain queries with higher counts.

  * We can use VirusTotal to search for malicious domains and IPs noted earlier.

  * HTTP queries - ```_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c``` - shows the file downloaded from the CobaltStrike C2 connection (104.168.44.45).

  * Count number of CobaltStrike connections using port 443 - ```_path=="conn" | cut id.orig_h, id.resp_h, id.resp_p | id.resp_p==443 AND id.resp_h==104.168.44.45 | count() by id.resp_h```

  * Suricata rules - ```event_type=="alert" | cut alert.signature | sort | uniq -c | sort -r``` - shows multiple C2 channels

```markdown
1. What is the name of the file downloaded from the CobaltStrike C2 connection? - 4564.exe

2. What is the number of CobaltStrike connections using port 443? - 328

3. There is an additional C2 channel in used the given case. What is the name of the secondary C2 channel? - IcedID
```

## Exercise: Threat Hunting with Brim | Crypto Mining

* Queries:

  * Frequently communicated hosts - ```_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h | sort | uniq -c | sort -r count``` - 192.168.X.X

  * Connections using port 19999 - ```_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h | id.resp_p==19999 | count() by id.resp_p```

  * Active ports - ```_path=="conn" | cut id.resp_p, service | sort | uniq -c | sort -r count```

  * Transferred data - ```_path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes```

  * Suricata rules - ```event_type=="alert" | count() by alert.severity, alert.category | sort count``` - Crypto Currency Mining Activity Detected

  * View connection logs - ```_path=="conn" | 192.168.1.100``` - search for destination IPs on VirusTotal

  * Map MITRE ATT&CK techniques - ```event_type=="alert" | cut alert.category, alert.metadata.mitre_technique_name, alert.metadata.mitre_technique_id, alert.metadata.mitre_tactic_name, alert.metadata.mitre_tactic_id | sort | uniq -c```

```markdown
1. How many connections used port 19999? - 22

2. What is the name of the service used by port 6666? - irc

3. What is the amount of transferred total bytes to "101.201.172.235:8888"? - 3,729

4. What is the detected MITRE tactic id? - TA0040
```
