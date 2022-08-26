# Brim - Medium

1. [What is Brim?](#what-is-brim)
2. [The Basics](#the-basics)
3. [Default Queries](#default-queries)
4. [Use Cases](#use-cases)
5. [Exercise: Threat Hunting with Brim | Malware C2 Detection](#exercise-threat-hunting-with-brim--malware-c2-detection)
6. [Exercise: Threat Hunting with Brim | Crypto Mining](#exercise-threat-hunting-with-brim--crypto-mining)

## What is Brim?

## The Basics

```markdown
1. Process the "sample.pcap" file and look at the details of the first DNS log that appear on the dashboard. What is the "qclass_name"?

2. Look at the details of the first NTP log that appear on the dashboard. What is the "duration" value?

3. Look at the details of the STATS packet log that is visible on the dashboard. What is the "reassem_tcp_size"?
```

## Default Queries

```markdown
1. Investigate the files. What is the name of the detected GIF file?

2. Investigate the conn logfile. What is the number of the identified city names?

3. Investigate the Suricata alerts. What is the Signature id of the alert category "Potential Corporate Privacy Violation"?
```

## Use Cases

## Exercise: Threat Hunting with Brim | Malware C2 Detection

```markdown
1. What is the name of the file downloaded from the CobaltStrike C2 connection?

2. What is the number of CobaltStrike connections using port 443?

3. There is an additional C2 channel in used the given case. What is the name of the secondary C2 channel?
```

## Exercise: Threat Hunting with Brim | Crypto Mining

```markdown
1. How many connections used port 19999?

2. What is the name of the service used by port 6666?

3. What is the amount of transferred total bytes to "101.201.172.235:8888"?

4. What is the detected MITRE tactic id?
```
