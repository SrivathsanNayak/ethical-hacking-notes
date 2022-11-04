# Enumerating Active Directory - Medium

1. [Credential Injection](#credential-injection)
2. [Enumeration through Microsoft Management Console](#enumeration-through-microsoft-management-console)
3. [Enumeration through Command Prompt](#enumeration-through-command-prompt)
4. [Enumeration through PowerShell](#enumeration-through-powershell)
5. [Enumeration through Bloodhound](#enumeration-through-bloodhound)

## Credential Injection

* We can use Runas, a legit Windows binary, to inject AD creds into memory.

* To verify if creds injection is working, we can read contents of the SYSVOL directory.

```shell
ssh za.tryhackme.com\\kimberley.smith@thmjmp1.za.tryhackme.com
#ssh using given creds

runas.exe /netonly /user:za.tryhackme.com\kimberley.smith cmd.exe
#creds injection using runas
```

```markdown
1. What native Windows binary allows us to inject credentials legitimately into memory? - runas.exe

2. What parameter option of the runas binary will ensure that the injected credentials are used for all network connections? - /netonly

3. What network folder on a domain controller is accessible by any authenticated AD account and stores GPO information? - SYSVOL

4. When performing dir \\za.tryhackme.com\SYSVOL, what type of authentication is performed by default? - Kerberos authentication
```

## Enumeration through Microsoft Management Console

* To view the AD structure, we can go to Start > Windows Administrative Tools > Active Directory Users and Computers

```shell
xfreerdp /u:kimberley.smith /v:10.200.14.248
#rdp into THMJMP1 using given creds
```

```markdown
1. How many Computer objects are part of the Servers OU? - 2

2. How many Computer objects are part of the Workstations OU? - 1

3. How many departments (OUs) does this organisation consist of? - 7

4. How many Admin tiers does this organisation have? - 3

5. What is the value of the flag stored in the description attribute of the t0_tinus.green account? - THM{Enumerating.Via.MMC}
```

## Enumeration through Command Prompt

* The ```net``` command can be used to enumerate users in AD.

```shell
#SSH to THMJMP1
#in command prompt

net user /domain
#list all users

net user aaron.harris /domain
#info for particular user

net user Guest /domain
#info for Guest account

net group /domain
#enumerate groups

net group "Tier 1 Admins" /domain
#get info for particular group

net accounts /domain
#enumerate password policy
```

```markdown
1. Apart from the Domain Users group, what other group is the aaron.harris account a member of? - Internet Access

2. Is the Guest account active? - Nay

3. How many accounts are a member of the Tier 1 Admins group? - 7

4. What is the account lockout duration of the current password policy in minutes? - 30
```

## Enumeration through PowerShell

```ps
#from previous command prompt in SSH, start powershell
powershell

Get-ADUser -Identity beth.nolan -Server za.tryhackme.com -Proper
ties *
#cmdlet to enumerate user

Get-ADUser -Filter 'Name -like "*manning"' -Server za.tryhackme.
com | Format-Table Name,DistinguishedName
#filter info for users

Get-ADGroup -Identity "Tier 2 Admins" -Server za.tryhackme.com
#enumerate AD groups

Get-ADGroup -Identity "Tier 2 Admins" -Server za.tryhackme.com
#enumerate complete info

Get-ADGroupMember -Identity "Tier 2 Admins" -Server za.tryhackme.com
#enumerate group membership

$ChangeDate = New-Object DateTime(2022, 02, 28, 12, 00, 00)
Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects -Server za.tryhackme.com
#search for AD objects changed after a date

Get-ADObject -Filter 'badPwdCount -gt 0' -Server za.tryhackme.com
#enumerate accounts to be avoided in password-spraying attack

Get-ADDomain -Server za.tryhackme.com
#get info about domain

#force changing password of AD user
Set-ADAccountPassword -Identity kimberley.smith -Server za.tryhackme.com -OldPassword (ConvertTo-SecureString -AsPlaintext "old" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "new" -Force)
```

```markdown
1. What is the value of the Title attribute of Beth Nolan (beth.nolan)? - Senior

2. What is the value of the DistinguishedName attribute of Annette Manning (annette.manning)? - CN=annette.manning,OU=Marketing,OU=People,DC=za,DC=tryhackme,DC=com

3. When was the Tier 2 Admins group created? - 2/24/2022 10:04:41 PM

4. What is the value of the SID attribute of the Enterprise Admins group? - S-1-5-21-3330634377-1326264276-632209373-519

5. Which container is used to store deleted AD objects? - CN=Deleted Objects,DC=za,DC=tryhackme,DC=com
```

## Enumeration through Bloodhound

* Sharphound is the enumeration tool of Bloodhound, and it's used to enumerate AD info that can then be visually displayed in Bloodhound (GUI to display AD attack graphs).

```shell
copy C:\Tools\Sharphound.exe ~\Documents\

cd ~\Documents\

Sharphound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs
#generates zip file

#to get zip file in attacker machine
scp kimberley.smith@THMJMP1.za.tryhackme.com:C:/Users/kimberley.smith/Documents/20220316191229_BloodHound.zip .
#we can open it with Bloodhound and inspect it
```

```markdown
1. What command can be used to execute Sharphound.exe and request that it recovers Session information only from the za.tryhackme.com domain without touching domain controllers? - Sharphound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs

2. Apart from the krbtgt account, how many other accounts are potentially kerberoastable? - 4

3. How many machines do members of the Tier 1 Admins group have administrative access to? - 2

4. How many users are members of the Tier 2 Admins group? - 15
```
