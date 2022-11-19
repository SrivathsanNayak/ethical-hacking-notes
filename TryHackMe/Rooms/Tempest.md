# Tempest - Medium

1. [Preparation - Log Analysis](#preparation---log-analysis)
2. [Preparation - Tools and Artifacts](#preparation---tools-and-artifacts)
3. [Initial Access - Malicious Document](#initial-access---malicious-document)
4. [Initial Access - Stage 2 execution](#initial-access---stage-2-execution)
5. [Initial Access - Malicious Document Traffic](#initial-access---malicious-document-traffic)
6. [Discovery - Internal Reconnaissance](#discovery---internal-reconnaissance)
7. [Privilege Escalation - Exploiting Privileges](#privilege-escalation---exploiting-privileges)
8. [Actions on Objective - Fully-owned Machine](#actions-on-objective---fully-owned-machine)

## Preparation - Log Analysis

## Preparation - Tools and Artifacts

```markdown
1. What is the SHA256 hash of the capture.pcapng file?

2. What is the SHA256 hash of the sysmon.evtx file?

3. What is the SHA256 hash of the windows.evtx file?
```

## Initial Access - Malicious Document

```markdown
1. The user of this machine was compromised by a malicious document. What is the file name of the document?

2. What is the name of the compromised user and machine?

3. What is the PID of the Microsoft Word process that opened the malicious document?

4. Based on Sysmon logs, what is the IPv4 address resolved by the malicious domain used in the previous question?

5. What is the base64 encoded string in the malicious payload executed by the document?

6. What is the CVE number of the exploit used by the attacker to achieve a remote code execution?
```

## Initial Access - Stage 2 execution

```markdown
1. The malicious execution of the payload wrote a file on the system. What is the full target path of the payload?

2. The implanted payload executes once the user logs into the machine. What is the executed command upon a successful login of the compromised user?

3. Based on Sysmon logs, what is the SHA256 hash of the malicious binary downloaded for stage 2 execution?

4. The stage 2 payload downloaded establishes a connection to a c2 server. What is the domain and port used by the attacker?
```

## Initial Access - Malicious Document Traffic

```markdown
1. What is the URL of the malicious payload embedded in the document?

2. What is the encoding used by the attacker on the c2 connection?

3. The malicious c2 binary sends a payload using a parameter that contains the executed command results. What is the parameter used by the binary?

4. The malicious c2 binary connects to a specific URL to get the command to be executed. What is the URL used by the binary?

5. What is the HTTP method used by the binary?

6. Based on the user agent, what programming language was used by the attacker to compile the binary?
```

## Discovery - Internal Reconnaissance

```markdown
1. The attacker was able to discover a sensitive file inside the machine of the user. What is the password discovered on the aforementioned file?

2. The attacker then enumerated the list of listening ports inside the machine. What is the listening port that could provide a remote shell inside the machine?

3. The attacker then established a reverse socks proxy to access the internal services hosted inside the machine. What is the command executed by the attacker to establish the connection?

4. What is the SHA256 hash of the binary used by the attacker to establish the reverse socks proxy connection?

5. What is the name of the tool used by the attacker based on the SHA256 hash?

6. The attacker then used the harvested credentials from the machine. Based on the succeeding process after the execution of the socks proxy, what service did the attacker use to authenticate?
```

## Privilege Escalation - Exploiting Privileges

```markdown
1. After discovering the privileges of the current user, the attacker then downloaded another binary to be used for privilege escalation. What is the name and the SHA256 hash of the binary?

2. Based on the SHA256 hash of the binary, what is the name of the tool used?

3. The tool exploits a specific privilege owned by the user. What is the name of the privilege?

4. Then, the attacker executed the tool with another binary to establish a c2 connection. What is the name of the binary?

5. The binary connects to a different port from the first c2 connection. What is the port used?
```

## Actions on Objective - Fully-owned Machine

```markdown
1. Upon achieving SYSTEM access, the attacker then created two users. What are the account names?

2. Prior to the successful creation of the accounts, the attacker executed commands that failed in the creation attempt. What is the missing option that made the attempt fail?

3. Based on windows event logs, the accounts were successfully created. What is the event ID that indicates the account creation activity?

4. The attacker added one of the accounts in the local administrator's group. What is the command used by the attacker?

5. Based on windows event logs, the account was successfully added to a sensitive group. What is the event ID that indicates the addition to a sensitive local group?

6. After the account creation, the attacker executed a technique to establish persistent administrative access. What is the command executed by the attacker to achieve this?
```
