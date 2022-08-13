# Agent T - Easy

<details>
<summary>Nmap Scan</summary>

```shell
PORT     STATE    SERVICE   VERSION
80/tcp   open     http      PHP cli server 5.5 or later (PHP 8.1.0-dev)
|_http-title:  Admin Dashboard
280/tcp  filtered http-mgmt
6510/tcp filtered mcer-port
```

</details>
<br>

```shell
nmap -T4 -A 10.10.5.21

gobuster dir -u http://10.10.5.21 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt

gobuster dir -u http://10.10.5.21 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s 204,301,302,307,401,403

curl -I 10.10.5.21
```

```markdown
From the nmap scan, we know port 80 is open.

Checking <http://10.10.5.21>, we get an Admin Dashboard with various tabs.

It is a template dashboard website, using the SB-Admin-2 theme, but we don't have much to interact with here.

Now, the initial Gobuster scan did not give us the intended results so we used it with custom status codes.

The Gobuster scans do not give us any info, so we can move on to other forms of enumeration.

Following the given hint, we inspect the webpage headers using cURL.

This shows us a header called 'X-Powered-By: PHP/8.1.0-dev'

Looking it up gives us exploits related to RCE; we can go ahead with the ExploitDB one.

Simply running the Python exploit file gives us root.

The flag is in the root directory.
```

```markdown
1. What is the flag? - flag{4127d0530abf16d6d23973e3df8dbecb}
```
