# PrintNightmare - Medium

1. [Windows Print Spooler Service](#windows-print-spooler-service)
2. [Remote Code Execution Vulnerability](#remote-code-execution-vulnerability)
3. [Try it yourself](#try-it-yourself)
4. [Indicators of Compromise](#indicators-of-compromise)
5. [Detection: Windows Event Logs](#detection-windows-event-logs)
6. [Detection: Packet Analysis](#detection-packet-analysis)
7. [Mitigation: Disable Print Spooler](#mitigation-disable-print-spooler)

## Windows Print Spooler Service

```markdown
1. Where would you enable or disable Print Spooler Service?
```

## Remote Code Execution Vulnerability

```markdown
1. Provide the CVE of the Windows Print Spooler Remote Code Execution Vulnerability that doesn't require local access to the machine.

2. What date was the CVE assigned for the vulnerability?
```

## Try it yourself

```markdown
1. What is the flag residing on the Administrator's Desktop?
```

## Indicators of Compromise

```markdown
1. Provide the first folder path where you would likely find the dropped DLL payload.

2. Provide the function that is used to install printer drivers.

3. What tool can the attacker use to scan for vulnerable print servers?
```

## Detection: Windows Event Logs

```markdown
1. Provide the name of the dropped DLL, including the error code.

2. Provide the event log name and the event ID that detected the dropped DLL.

3. Find the source name and the event ID when the Print Spooler Service stopped unexpectedly and how many times was this event logged?

4. Provide the log name, event ID, and destination port.

5. Provide the attacker's IP address and the hostname.

6. Provide the full path to the dropped DLL and the earliest creation time in UTC.
```

## Detection: Packet Analysis

```markdown
1. What is the host name of the domain controller?

2. What is the local domain?

3. What user account was utilized to exploit the vulnerability?

4. What was the malicious DLL used in the exploit?

5. What was the attacker's IP address?

6. What was the UNC path where the malicious DLL was hosted?

7. What was the associated protocol?
```

## Mitigation: Disable Print Spooler

```markdown
1. Provide two ways to manually disable the Print Spooler Service.

2. Where can you disable the Print Spooler Service in Group Policy?

3. Provide the command in PowerShell to detect if Print Spooler Service is enabled and running.
```
