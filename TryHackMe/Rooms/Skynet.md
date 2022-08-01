# Skynet - Easy

<details>
<summary>Nmap scan</summary>

```shell
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 99:23:31:bb:b1:e9:43:b7:56:94:4c:b9:e8:21:46:c5 (RSA)
|   256 57:c0:75:02:71:2d:19:31:83:db:e4:fe:67:96:68:cf (ECDSA)
|_  256 46:fa:4e:fc:10:a5:4f:57:57:d0:6d:54:f6:c3:4d:fe (ED25519)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Skynet
110/tcp open  pop3        Dovecot pop3d
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_pop3-capabilities: AUTH-RESP-CODE CAPA SASL TOP UIDL RESP-CODES PIPELINING
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_imap-capabilities: IDLE capabilities post-login LOGIN-REFERRALS LOGINDISABLEDA0001 LITERAL+ more IMAP4rev1 SASL-IR Pre-login listed ENABLE ID OK have
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h39m59s, deviation: 2h53m13s, median: -1s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2022-08-01T17:05:19
|_  start_date: N/A
|_nbstat: NetBIOS name: SKYNET, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
|   NetBIOS computer name: SKYNET\x00
|   Domain name: \x00
|   FQDN: skynet
|_  System time: 2022-08-01T12:05:19-05:00
```

</details>

<br>

```markdown
We begin with the Nmap scan with the -Pn flag.
```

```shell
nmap -Pn -T4 --top-ports 10000 -A 10.10.123.65
```

```markdown
1. What is Miles password for his emails?

2. What is the hidden directory?

3. What is the vulnerability called when you can include a remote file for malicious purposes?

4. What is the user flag?

5. What is the root flag?
```
