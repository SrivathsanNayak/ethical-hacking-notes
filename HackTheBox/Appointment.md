# Appointment - Very Easy

```shell
nmap -T4 -p- -A 10.129.80.249

gobuster dir -u http://10.129.80.249 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```

```markdown
After scanning the directories, we still do not get any clue.

We can attempt for SQLi attacks in the login form.

Simply entering credentials such as "admin : ' or 1=1#", gives us the flag.
```

1. What does SQL stand for? - Structured Query Language

2. What is one of the most common type of SQL vulnerabilities? - SQL Injection

3. What does PII stand for? - Personally Identifiable Information

4. What does the OWASP Top 10 list name the classification for this vulnerability? - A03:2021-Injection

5. What service and version are running on port 80 of the target? - Apache httpd 2.4.38 ((Debian))

6. What is the standard port used for the HTTPS protocol? - 443

7. What is one luck-based method of exploiting login pages? - Brute-Forcing

8. What is a folder called in web-application terminology? - Directory

9. What response code is given for "Not Found" errors? - 404

10. What switch do we use with Gobuster to specify we're looking to discover directories, and not subdomains? - dir

11. What symbol do we use to comment out parts of the code? - #

12. Root flag? - e3d0796d002a446c0e622226f42e9672
