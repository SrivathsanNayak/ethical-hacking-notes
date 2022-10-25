# Pennyworth - Very Easy

```shell
rustscan -a 10.129.195.67 --range 0-65535 --ulimit 5000 -- -sV

#setup listener
nc -nvlp 4444
#we get reverse shell on running the code in Script Console
#read flag
```

```markdown
Open ports & services:

  * 8080 - http - Jetty 9.4.39.v20210325

Visiting the webpage on port 8080, we are led to a login page for Jenkins.

We can try all weak credentials, such as admin:password, root:admin, etc.

Eventually we get login by using root:password; this leads us to the dashboard page where we can see the version (bottom right corner).

On the dashboard itself, we can see that the Script Console uses Groovy Script.

We can try to exploit this, by Googling for 'Jenkins 2.289.1 Groovy script exploit' - the search results show multiple methods to do so.

I followed the Groovy script console method - it involves using a code snippet which launches a reverse shell.

After setting up a listener, the code can be run in the Script console - this gives us a reverse shell as root

The root flag can be found in /root/flag.txt
```

1. What does the acronym CVE stand for? - Common Vulnerabilities and Exposures

2. What do the three letters in CIA, referring to the CIA triad in cybersecurity, stand for? - Confidentiality, Integrity, Availability

3. What is the version of the service running on port 8080? - Jetty 9.4.39.v20210325

4. What version of Jenkins is running on the target? - 2.289.1

5. What type of script is accepted as input on the Jenkins Script Console? - Groovy

6. What would the "String cmd" variable from the Groovy Script snippet be equal to if the Target VM was running Windows? - cmd.exe

7. What is a different command than "ip a" we could use to display our network interfaces' information on Linux? - ifconfig

8. What switch should we use with netcat for it to use UDP transport mode? - -u

9. What is the term used to describe making a target host initiate a connection back to the attacker host? - reverse shell

10. Submit root flag - 9cdfb439c7876e703e307864c9167a15
