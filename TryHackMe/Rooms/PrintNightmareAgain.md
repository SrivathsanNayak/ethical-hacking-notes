# PrintNightmare, Again! - Easy

```markdown
We can use the FullEventLogView tool as given; go to Options > Advanced Options > enable 'Show events from all times'.

Now, to find the downloaded zip file, we can simply search for the extension '.zip' using the Find utility; this gives us the file name.

Scrolling down to see subsequent events, we can see that there are scripts named 'CVE-2021-1675', which is the Windows Prnit Spooler Elevation of Privilege vulnerability; therefore, we will see more events related to this.

Checking the next few events, we get the full path to the script for the exploit with the same CVE in the filename.

Now, as this exploit creates a malicious DLL; we need to search the keyword '.dll' from the previous event, and as a result, we get the temporary location the malicious DLL was stored to.

We now have the filename 'nightmare.dll'; searching for this will give us its full location path, that is, inside the System32 folder.

As we need to search for a Registry path, we can make use of the Find utility again by searching for the keyword 'Reg'; this gives us the path for THMPrinter.

In the next event, we can see that the spoolsv.exe process would have been blocked from nightmare.dll; it also contains the required PID.

The next few events show that a new user account was created, and moreover, it was added to the Administrators group.

Now, in order to get the password for the 'backup' user, we need to check the Powershell history, which can be found in the ConsoleHost_history file for the user 'bmurphy'.

The history file also contains the two commands the user executed to cover up their tracks, that is, by deleting the files associated with the exploit.
```

1. The user downloaded a zip file. What was the zip file saved as? - levelup.zip

2. What is the full path to the exploit the user executed? - C:\Users\bmurphy\Downloads\CVE-2021-1675-main\CVE-2021-1675.ps1

3. What was the temp location the malicious DLL was saved to? - C:\Users\bmurphy\AppData\Local\Temp\3\nightmare.dll

4. What was the full location the DLL loads from? - C:\Windows\System32\spool\drivers\x64\3\New\nightmare.dll

5. What is the primary registry path associated with this attack? - HKLM\System\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-3\THMPrinter

6. What was the PID for the process that would have been blocked from loading a non-Microsoft-signed binary? - 2600

7. What is the username of the newly created local administrator account? - backup

8. What is the password for this user? - ucGGDMyFHkqMRWwHtQ

9. What two commands did the user execute to cover their tracks? - rmdir .\CVE-2021-1675-main\,del .\levelup.zip
