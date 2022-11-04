# Enumerating Active Directory - Medium

1. [Credential Injection](#credential-injection)
2. [Enumeration through Microsoft Management Console](#enumeration-through-microsoft-management-console)
3. [Enumeration through Command Prompt](#enumeration-through-command-prompt)
4. [Enumeration through PowerShell](#enumeration-through-powershell)
5. [Enumeration through Bloodhound](#enumeration-through-bloodhound)

## Credential Injection

```markdown
1. What native Windows binary allows us to inject credentials legitimately into memory?

2. What parameter option of the runas binary will ensure that the injected credentials are used for all network connections?

3. What network folder on a domain controller is accessible by any authenticated AD account and stores GPO information?

4. When performing dir \\za.tryhackme.com\SYSVOL, what type of authentication is performed by default?
```

## Enumeration through Microsoft Management Console

```markdown
1. How many Computer objects are part of the Servers OU?

2. How many Computer objects are part of the Workstations OU?

3. How many departments (OUs) does this organisation consist of?

4. How many Admin tiers does this organisation have?

5. What is the value of the flag stored in the description attribute of the t0_tinus.green account?
```

## Enumeration through Command Prompt

```markdown
1. Apart from the Domain Users group, what other group is the aaron.harris account a member of?

2. Is the Guest account active?

3. How many accounts are a member of the Tier 1 Admins group?

4. What is the account lockout duration of the current password policy in minutes?
```

## Enumeration through PowerShell

```markdown
1. What is the value of the Title attribute of Beth Nolan (beth.nolan)?

2. What is the value of the DistinguishedName attribute of Annette Manning (annette.manning)?

3. When was the Tier 2 Admins group created?

4. What is the value of the SID attribute of the Enterprise Admins group?

5. Which container is used to store deleted AD objects?
```

## Enumeration through Bloodhound

```markdown
1. What command can be used to execute Sharphound.exe and request that it recovers Session information only from the za.tryhackme.com domain without touching domain controllers?

2. Apart from the krbtgt account, how many other accounts are potentially kerberoastable?

3. How many machines do members of the Tier 1 Admins group have administrative access to?

4. How many users are members of the Tier 2 Admins group?
```
