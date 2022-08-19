# Hacking With PowerShell - Easy

1. [What is PowerShell?](#what-is-powershell)
2. [Basic PowerShell Commands](#basic-powershell-commands)
3. [Enumeration](#enumeration)
4. [Basic Scripting Challenge](#basic-scripting-challenge)
5. [Intermediate Scripting](#intermediate-scripting)

## What is PowerShell?

* PowerShell is the Windows Scripting Language and shell environment, built using .NET framework.

* [cmdlets](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7) are PowerShell commands, usually written in .NET; these cmdlets output objects.

```markdown
1. What is the command to get help about a particular cmdlet? - Get-Help
```

## Basic PowerShell Commands

```ps
Get-Help Get-Command
#display info about a cmdlet

Get-Help Get-Command -Examples
#view examples

Get-Command New-*
#gets all cmdlets according to pattern

#pipeline can pass objects to next cmdlet

Get-Command | Get-Member -MemberType Method
#view object details (methods and properties) of Get-Command cmdlet

Get-ChildItem | Select-Object -Property Mode, Name
#extracting particular properties from output of cmdlet, to create a new object

#filtering objects using Where-Object

Get-Service | Where-Object -Property Status -eq Stopped
Get-Service | Where-Object {$_.Status -eq "Stopped"}
#both commands check for stopped services

Get-ChildItem | Sort-Object
#sorting object
```

```ps
Get-Help Get-ChildItem -Examples
#info about cmdlet

Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -Match 'interesting-file.txt'}
#searches required file

Get-Help Get-Content -Examples

Get-Content -Path 'C:\Program Files\interesting-file.txt.txt'
#contents of file outputted

Get-Command -type cmdlet | Measure-Object
#count cmdlets

Get-Command *hash*
#search for cmdlets with 'hash' word

Get-Help Get-FileHash -Examples

Get-FileHash -Path 'C:\Program Files\interesting-file.txt.txt' -Algorithm MD5
#md5 hash of file

Test-Path -Path C:\Users\Administrator\Documents\Passwords
#checks if path exists or not

Get-Content .\Desktop\b64.txt | %{[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_))}
#this pipes the content from b64.txt, and decodes it to text
```

```markdown
1. What is the location of the file "interesting-file.txt" - C:\Program Files

2. Specify the contents of this file - notsointerestingcontent

3. How many cmdlets are installed on the system? - 6638

4. Get the MD5 hash of interesting-file.txt - 49A586A2A9456226F8A1B4CEC6FAB329

5. What is the command to get the current working directory? - Get-Location

6. Does the path "C:\Users\Administrator\Documents\Passwords" Exist? - N

7. What command would you use to make a request to a web server? - Invoke-WebRequest

8. Base64 decode the file b64.txt on Windows. - ihopeyoudidthisonwindows
```

## Enumeration

```ps
Get-LocalUser
#shows users on system

Get-LocalUser | Get-Member -MemberType Property
#view all properties related to command

Get-LocalUser | Select-Object -Property Name, SID
#get username and sid

Get-LocalUser | Select-Object -Property PasswordRequired

Get-LocalGroup | Measure-Object

Get-NetIPAddress

Get-NetTCPConnection
#shows various ports and statuses

Get-NetTCPConnection | Where-Object -Property State -eq Listen | Measure-Object
#counts listening ports

Get-NetTCPConnection -LocalPort 445

Get-HotFix | Measure-Object

Get-HotFix | Where-Object -Property HotFixID -eq KB4023834

Get-ChildItem -Path C:\ -Recurse -Filter *.bak* -ErrorAction SilentlyContinue
#searching for files with the pattern .bak
#this gives us the file location

Get-Content -Path "C:\Program Files (x86)\Internet Explorer\passwords.bak.txt"

Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Select-String "API_KEY"
#the flag can be found at the bottom part of output

Get-Process

Get-ScheduledTask

Get-Acl -Path C:\
```

```markdown
1. How many users are there on the machine? - 5

2. Which local user does this SID(S-1-5-21-1394777289-3961777894-1791813945-501) belong to? - Guest

3. How many users have their password required values set to False? - 4

4. How many local groups exist? - 24

5. What command did you use to get the IP address info? - Get-NetIPAddress

6. How many ports are listed as listening? - 20

7. What is the remote address of the local port listening on port 445? - ::

8. How many patches have been applied? - 20

9. When was the patch with ID KB4023834 installed? - 6/15/2017 12:00:00 AM

10. Find the contents of a backup file. - backpassflag

11. Search for all files containing API_KEY - fakekey123

12. What command do you do to list all the running processes? - Get-Process

13. What is the path of the scheduled task called new-sched-task? - /

14. Who is the owner of the C:\ - NT SERVICE\TrustedInstaller
```

## Basic Scripting Challenge

* We can use ```PowerShell ISE``` for creating PowerShell scripts.

```ps
$system_ports = Get-NetTCPConnection -State Listen
$text_port = Get-Content -Path C:\Users\Administrator\Desktop\ports.txt
foreach($port in $text_port){
    if($port -in $system_ports.LocalPort){
        echo $port
    }
}
```

```markdown
Here, system_ports is a variable which contains the output of the Get-NetTCPConnection cmdlet.

text_port contains a list of ports read from a file.

Next step is to iterate through all ports in text file, and check if ports are listening. For iteration, we use a for-loop.

If the port exists the LocalPort property, we print it.
```

```ps
# required script
# verbose
$emailsPath = "C:\Users\Administrator\Desktop\emails"
$emailFiles = Get-ChildItem -Path $emailsPath -Recurse -ErrorAction SilentlyContinue -Include *.txt
foreach($file in $emailFiles){
    if (Get-Content -Path $file.FullName | Select-String "password"){
        echo $file
        Get-Content -Path $file.FullName | Select-String "password" | Select Line
    }
    if (Get-Content -Path $file.FullName | Select-String "http"){
        echo $file
        Get-Content -Path $file.FullName | Select-String "http" | Select Line
    }
}
```

```markdown
1. What file contains the password? - Doc3M

2. What is the password? - johnisalegend99

3. What files contains an HTTPS link? - Doc2Mary
```

## Intermediate Scripting

```ps
# rudimentary portscanner

$ip = localhost
$portRange = 130..140
$ErrorActionPreference = 'SilentlyContinue'

"Scanning $ip ..."

foreach($port in $portRange){
    Test-NetConnection $ip -Port $port
}

"Scanning complete."
```

```markdown
1. How many open ports did you find between 130 and 140(inclusive)? - 11
```
