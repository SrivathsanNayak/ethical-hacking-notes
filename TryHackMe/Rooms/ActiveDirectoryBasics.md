# Active Directory Basics - Easy

1. [Windows Domains](#windows-domains)
2. [Active Directory](#active-directory)
3. [Managing Users in AD](#managing-users-in-ad)
4. [Managing Computers in AD](#managing-computers-in-ad)
5. [Group Policies](#group-policies)
6. [Authentication Methods](#authentication-methods)
7. [Trees, Forests and Trusts](#trees-forests-and-trusts)

## Windows Domains

* Windows domain - group of users & computers under administration.

* Using a domain ensures centralised administration of common network components in a single repository called Active Directory (AD); the server that runs the AD services is called Domain Controller (DC).

* Advantages of Windows domains include centralised identity management and security policy management.

```markdown
1. In a Windows domain, credentials are stored in a centralised repository called - Active Directory

2. The server in charge of running the Active Directory services is called - Domain Controller
```

## Active Directory

* Active Directory Domain Service (AD DS) - catalog of info of all objects in network; these objects include:

  * Users - security principals, as they can act upon resources in the network; includes people & services.

  * Machines - machine accounts are created for every computer that joins the AD domain.

  * Security groups - can include users as well as machines; can be used to grant specific privileges.

* Key security groups in a domain:

  * Domain admins
  * Server operators
  * Backup operators
  * Account operators
  * Domain users
  * Domain computers
  * Domain controllers

* AD users & computers are organised in Organizational Units (OUs), which act as container objects for classification.

* Default OUs:

  * Builtin
  * Computers
  * Domain controllers
  * Users
  * Managed service accounts

* OUs are for applying policies, whereas security groups are for granting permissions over resources.

```markdown
1. Which group normally administrates all computers and resources in a domain? - Domain admins

2. What would be the name of the machine account associated with a machine named TOM-PC? - TOM-PC$

3. What type of containers should we use to group all Quality Assurance users so that policies can be applied consistently to them? - Organizational Unit
```

## Managing Users in AD

* Users can be managed in AD Users & Computers section.

```shell
#connecting using rdp
xfreerdp /u:"THM\phillip" /p:Claire2008 /v:10.10.188.42

#in powershell
Set-ADAccountPassword sophie -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose
#Password123

Set-ADUser -ChangePasswordAtLogon $true -Identity sophie -Verbose
#gives prompt for sophie to change password at logon

#now, rdp as sophie
xfreerdp /u:"THM\sophie" /p:Password123 /v:10.10.188.42
#change password to Password123!
#get flag from desktop
```

```markdown
1. What was the flag found on Sophie's desktop? - THM{thanks_for_contacting_support}

2. The process of granting privileges to a user over some OU or other AD Object is called - Delegation
```

## Managing Computers in AD

* Computers are broadly divided into these categories:

  * Workstations
  * Servers
  * Domain controllers

```markdown
1. After organising the available computers, how many ended up in the Workstations OU? - 7

2. Is it recommended to create separate OUs for Servers and Workstations? - yay
```

## Group Policies

* GPO (Group Policy Objects) - collection of settings that can be applied to OUs; contains policies aimed at users/computers.

* GPOs can be configured using the Group Policy Management tool.

* GPOs are distributed to the network via a network share called ```SYSVOL```, which is stored in the DC.

```markdown
1. What is the name of the network share used to distribute GPOs to domain machines? - SYSVOL

2. Can a GPO be used to apply settings to users and computers? - yay
```

## Authentication Methods

* When using Windows domains, all creds are stored in DCs; for authentication, the service will ask the DC for verification.

* Network authentication protocols in Windows domains:

  * Kerberos - default protocol in any recent domain

  * NetNTLM - legacy authentication protocol kept for compatibility purposes

* Kerberos authentication:

  * Users who log into service using Kerberos will be assigned tickets.

  * Users with tickets can present them to a service to show that they have already authenticated into the network.

  * Process:

    * User sends username and timestamp encrypted using a key derived from password, to the Key Distribution Center (KDC).

    * KDC will create & send back Ticket Granting Ticket (TGT) and a Session Key; it allows user to request extra tickets for specific services.

    * TGT is encrypted using krbtgt account's password hash; encrypted TGT includes copy of Session Key.

    * When user wants to connect to a service on the network, they will use their TGT to ask KDC for a Ticket Granting Service (TGS); TGS are tickets that allow connection only to specific service.

    * For TGS, user sends username and timestamp encrypted using Session Key, along with TGT and Service Principal Name (SPN).

    * KDC sends user a TGS along with Service Session Key; TGS is encryted using key derived from Service Owner Hash.

    * TGS can be sent to desired service to authenticate & establish connection.

* NetNTLM authentication:

  * Process:

    * Client sends authentication request to server they want to access.

    * Server generates random number and sends to client as challenge.

    * Client combines NTLM password hash with challenge to generate response and sends it back to server for verification.

    * Server forwards challenge & response to DC for verification.

    * DC calculates, compares and verifies challenge & response; authentication result is sent back to server.

    * Server forwards authentication request to client.

```markdown
1. Will a current version of Windows use NetNTLM as the preferred authentication protocol by default? - nay

2. When referring to Kerberos, what type of ticket allows us to request further tickets known as TGS? - Ticket Granting Ticket

3. When using NetNTLM, is a user's password transmitted over the network at any point? - nay
```

## Trees, Forests and Trusts

* Tree - joins domains that share the same namespace; used for partitioning networks into independent units.

* With trees & forests, Enterprise Admins security group is used in order to grant a user admin privileges over all of an enterprise's domains.

* Forests - union of several trees with different namespaces into the same network.

* Trust relationships - joins for domains arranged in trees & forests; having a trust relationship between domains allow authorisation of user from one domain to another.

* One-way trust relationship - if domain A trusts domain B, then a user on B can be authorised to access resources on A.

* Two-way trust relationship - both domains mutually authorise users from the other.

```markdown
1. What is a group of Windows domains that share the same namespace called? - Tree

2. What should be configured between two domains for a user in Domain A to access a resource in Domain B? - A trust relationship
```
