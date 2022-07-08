# Windows Privilege Escalation - Medium

1. [Introduction](#introduction)
2. [Harvesting Passwords from Usual Spots](#harvesting-passwords-from-usual-spots)
3. [Other Quick Wins](#other-quick-wins)
4. [Abusing Service Misconfigurations](#abusing-service-misconfigurations)
5. [Abusing Dangerous Privileges](#abusing-dangerous-privileges)
6. [Abusing Vulnerable Software](#abusing-vulnerable-software)

## Introduction

```markdown
1. Users that can change system configurations are part of which group?

2. The SYSTEM account has more privileges than the Administrator user (aye/nay)?
```

## Harvesting Passwords from Usual Spots

```markdown
1. A password for the julia.jones user has been left on the Powershell history. What is the password?

2. A web server is running on the remote host. Find any interesting password on web.config files associated with IIS. What is the password of the db_admin user?

3. There is a saved password on your Windows credentials. Using cmdkey and runas, spawn a shell for mike.katz and retrieve the flag from his desktop.

4. Retrieve the saved password stored in the saved PuTTY session under your profile. What is the password for the thom.smith user?
```

## Other Quick Wins

```markdown
1. What is the taskusr1 flag?
```

## Abusing Service Misconfigurations

```markdown
1. Get the flag on svcusr1's desktop.

2. Get the flag on svcusr2's desktop.

3. Get the flag on the Administrator's desktop.
```

## Abusing Dangerous Privileges

```markdown
1. Get the flag on the Administrator's desktop.
```

## Abusing Vulnerable Software

```markdown
1. Get the flag on the Administrator's desktop.
```
