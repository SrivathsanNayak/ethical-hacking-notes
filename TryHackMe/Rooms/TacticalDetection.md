# Tactical Detection

1. [Unique Threat Intel](#unique-threat-intel)
2. [Publicly Generated IOCs](#publicly-generated-iocs)
3. [Leveraging "Know Your Environment": Tripwires](#leveraging-know-your-environment-tripwires)
4. [Purple Teaming](#purple-teaming)

## Unique Threat Intel

* ```Sigma``` - open-source, generic signature language, used to describe log events in a structured manner; allows for sharing of detection methods by security analysts.

* Given example of a Sigma rule:

```yml
title: Executable Download from Suspicious Domains
status: test
description: Detects download of executable types from hosts found in the IOC spreadsheet
author: Mokmokmok
date: 2022/08/23
modified: 2022/08/23
logsource:
  category: proxy
detection:
  selection:
    c-uri-extension:
      - 'exe'
    r-dns:
      - 'bad3xe69connection.io'
      - 'kind4bad.com'
      - 'nic3connection.io'
  condition: selection
fields:
  - c-uri
falsepositives:
  - Unkown
level: medium
```

```markdown
1. What did we use to transform IOCs as detection rules in a vendor-agnostic format? - Sigma

2. What is the original indicator found by the authors of the documentation? Write it as written in the spreadsheet. - bad3xe69connection.io

3. What is the full file path of the malicious file downloaded from the internet? - C:\Downloads\bad3xe69.exe

4. In the Sigma Rule baddomains.yml, what is the logsource category used by the author? - proxy
```

## Publicly Generated IOCs

* We can use tools such as [Uncoder](https://uncoder.io/) to convert Sigma rules to queries (Elastic Query, Splunk, etc.) that can be immediately used within SIEMs.

```markdown
1. Upon translating the Follina Sigma Rule, what is the index name that the rule will be using, as shown in the output? - winlogbeat-*

2. What is the Alerter subclass, as shown in the output? - debug

3. Which part of the ElastAlert output looks exactly like the Elastic Query? - filter

4. What is the alert severity, as shown in the output? - 3

5. What is the dispatch.earliest_time value, as shown in the output? - -60m@m

6. What is the source, as shown in the output? - WinEventLog:
```

## Leveraging "Know Your Environment": Tripwires

* "Tripwires" are used to supplement defence mechanisms implemented; examples include Honeypots and Hidden Files; these files do not serve any purpose, so any activity concerning them should raise alerts.

* An example of setting up a tripwire:

  * Local Security Policy app > Security Settings > Local Policies > Audit Policy

  * Open 'Audit object access' policy and tick boxes for 'Success' and 'Failure', and apply these changes

  * Create .txt file > Name it 'Secret Document'

  * Right-click document > Properties > Security > Advanced > Auditing > Add > Select a principal > Enter 'Everyone' as object name to be selected > Click 'Apply' and OK all changes

* We can now monitor for events and alerts using apps like ```FullEventLogView```.

* Event ID 4663 indicates Security event logging when someone accesses a tripwire created above.

```markdown
1. What is the "Accesses" value in the log details when you try reading our Secret Document's contents via cmd? - ReadData (or ListDirectory)

2. Event ID 4663 is always preceded by? - 4656

3. What Event ID signifies the closure of an "object"? - 4658

4. Event ID 4658 helps determine how long a specific object was open. What description field will you check in between events to be able to do so? - Handle ID
```

## Purple Teaming

```markdown
1. Fill in the Blanks: The Tempest and Follina rooms are examples of leveraging ______ ____ tactics. - purple team

2. What CVE is the Follina MSDT room about? - CVE-2022-30190
```
