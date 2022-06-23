# Investigating Windows - Easy

* As the machine starts, we can check that it tries to connect to a certain IP.

* We can check the system info from the Settings.

* To view the user login history, we can check Events Viewer > Windows Logs > Security; sort by date and time.

```ps
#to find last login for user
net user John | findstr /B /C:"Last logon"

net user Jenny | findstr /B /C:"Last logon"

#to find accounts with admin privileges
net localgroup administrators
```

* To find scheduled tasks on Windows, we can check Task Scheduler; we can view more info like Triggers and Actions for each task.

* To view the events in Event Viewer for assignment of special privileges to a logon, we can use filters for Event ID 4672, and select the oldest event according to the format given in the hint.

* The attackers IP and the targeted site can be found in the ```/etc/hosts``` file, stored in the System32 drivers folder in Windows.

* Similarly, we have to go through the files in the system drive; the inetpub folder contains files with .jsp extensions.

* The last port that the attacker opened can be viewed in Windows Firewalls, in the first entry itself.

```markdown
1. What's the version and year of the Windows machine? - Windows Server 2016

2. Which user logged in last? - Administrator

3. When did John log onto the system last? - 03/02/2019 5:48:32 PM

4. What IP does the system connect to when it first starts? - 10.34.2.3

5. What two accounts had administrative privileges (other than the Administrator user)? - Jenny, Guest

6. What's the name of the scheduled task that is malicious? - Clean file system

7. What file was the task trying to run daily? - nc.ps1

8. What port did this file listen locally for? - 1348

9. When did Jenny last logon? - Never

10. At what date did the compromise take place? - 03/02/2019

11. At what time did Windows first assign special privileges to a new logon? - 03/02/2019 04:04:49 PM

12. What tool was used to get Windows passwords? - mimikatz

13. What was the attackers' external control and command servers' IP? - 76.32.97.132

14. What was the extension name of the shell uploaded via the servers website? - .jsp

15. What was the last port the attacker opened? - 1337

16. Check for DNS poisoning, what site was targeted? - google.com
```
