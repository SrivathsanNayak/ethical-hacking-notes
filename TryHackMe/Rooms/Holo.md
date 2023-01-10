# Holo - Hard

1. [Flag Submission Panel](#flag-submission-panel)
2. [.NET Basics](#net-basics)
3. [Initial Recon](#initial-recon)
4. [Web App Exploitation - 1](#web-app-exploitation---1)
5. [Post Exploitation - 1](#post-exploitation---1)
6. [Situational Awareness - 1](#situational-awareness---1)
7. [Docker Breakout](#docker-breakout)
8. [Privilege Escalation - 1](#privilege-escalation---1)
9. [Post Exploitation - 2](#post-exploitation---2)
10. [Pivoting](#pivoting)
11. [Command and Control](#command-and-control)
12. [Web App Exploitation - 2](#web-app-exploitation---2)
13. [AV Evasion](#av-evasion)
14. [Post Exploitation - 3](#post-exploitation---3)
15. [Situtational Awareness - 2](#situational-awareness---2)
16. [Privilege Escalation - 2](#privilege-escalation---2)
17. [Persistence](#persistence)
18. [NTLM Relay](#ntlm-relay)

## Flag Submission Panel

```markdown
1. What flag can be found inside of the container?

2. What flag can be found after gaining user on L-SRV01?

3. What flag can be found after rooting L-SRV01?

4. What flag can be found on the Web Application on S-SRV01?

5. What flag can be found after rooting S-SRV01?

6. What flag can be found after gaining user on PC-FILESRV01?

7. What flag can be found after rooting PC-FILESRV01?

8. What flag can be found after rooting DC-SRV01?
```

## .NET Basics

## Initial Recon

```markdown
1. What is the last octet of the IP address of the public-facing web server?

2. How many ports are open on the web server?

3. What CME is running on port 80 of the web server?

4. What version of the CME is running on port 80 of the web server?

5. What is the HTTP title of the web server?
```

## Web App Exploitation - 1

```markdown
1. What domains loads images on the first web page?

2. What are the two other domains present on the web server?

3. What file leaks the web server's current directory?

4. What file loads images for the development domain?

5. What is the full path of the credentials file on the administrator domain?

6. What file is vulnerable to LFI on the development domain?

7. What parameter in the file is vulnerable to LFI?

8. What file found from the information leak returns an HTTP error code 403 on the administrator domain?

9. What file found from the information leak returns an HTTP error code 403 on the administrator domain?

10. What file is vulnerable to RCE on the administrator domain?

11. What parameter is vulnerable to RCE on the administrator domain?

12. What user is the web server running as?
```

## Post Exploitation - 1

## Situational Awareness - 1

```markdown
1. What is the Default Gateway for the Docker Container?

2. What is the high web port open in the container gateway?

3. What is the low database port open in the container gateway?

4. What is the server address of the remote database?

5. What is the password of the remote database?

6. What is the username of the remote database?

7. What is the database name of the remote database?

8. What username can be found within the database itself?
```

## Docker Breakout

```markdown
1. What user is the database running as?
```

## Privilege Escalation - 1

```markdown
1. What is the full path of the binary with an SUID bit set on L-SRV01?

2. What is the full first line of the exploit for the SUID bit?
```

## Post Exploitation - 2

```markdown
1. What non-default user can we find in the shadow file on L-SRV01?

2. What is the plaintext cracked password from the shadow hash?
```

## Pivoting

## Command and Control

## Web App Exploitation - 2

```markdown
1. What user can we control for a password reset on S-SRV01?

2. What is the name of the cookie intercepted on S-SRV01?

3. What is the size of the cookie intercepted on S-SRV01?

4. What page does the reset redirect you to when successfully authenticated on S-SRV01?
```

## AV Evasion

## Post Exploitation - 3

```markdown
1. What domain user's credentials can we dump on S-SRV01?

2. What is the domain user's password that we can dump on S-SRV01?

3. What is the hostname of the remote endpoint we can authenticate to?
```

## Situational Awareness - 2

```markdown
1. What anti-malware product is employed on PC-FILESRV01?

2. What anti-virus product is employed on PC-FILESRV01?

3. What CLR version is installed on PC-FILESRV01?

4. What PowerShell version is installed on PC-FILESRV01?

5. What Windows build is PC-FILESRV01 running on?
```

## Privilege Escalation - 2

```markdown
1. What is the name of the vulnerable application found on PC-FILESRV01?
```

## Persistence

```markdown
1. What is the first listed vulnerable DLL located in the Windows folder from the application?
```

## NTLM Relay

```markdown
1. What host has SMB signing disabled?
```
