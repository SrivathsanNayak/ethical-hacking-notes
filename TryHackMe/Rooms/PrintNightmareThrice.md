# PrintNightmare, thrice! - Medium

* We can begin by checking the PCAP file given and inspect the SMB2 protocol.

* The destination IP of the SMB2 protocol traffic indicates the remote address to which the employee navigated.

* In Wireshark, we can apply the SMB2 protocol filter to view only that protocol.

* Checking the SMB2 traffic, we can see that the STATUS_LOGON_FAILURE error is returned for rjones user, and the domain is THM-PRINTNIGHT0.

* Scrolling down, we can see that the user 'gentilguest' from the same domain successfully connects to SMB share IPC$

* Further activity by user gentilkiwi can be viewed by scrolling down; there are a lot of ```Create Request File``` queries after the endpoint connects to the IPC$ share.

* From Brim, with the help of the File Activity query, we can see that ```mimispool.dll``` has been downloaded, in two different locations.

* We can get back to Wireshark, check the Export Objects section to get the name of the share from which the malicious DLL was downloaded.

* Now, to check for the locations where malicious DLLs were loaded, we can check logs using Event Viewer.

* Key event logs to check include Microsoft-Windows-PrintService (Event ID 316, 808, 811) and Microsoft-Windows-Sysmon (Event ID 3, 11, 23, 26).

* Logs for event ID 11 include the locations where the malicious DLL was downloaded.

* To view the folder name of the remote printer server, we can use FullEventLogView; make sure to view events of all time, not just last 7 days (can be toggled in Advanced Options).

* Using the search term 'printnightmare.gentilkiwi', we get the folder location of the remote printer server; we can confirm this by going through File Explorer.

* The printer name added by the DLL can be found in Microsoft-Windows-PrintService logs, under event ID 321 (adding a printer driver).

* Now, as we need to search PID for elevated command prompt, we need to look for cmd.exe processes, and check the one which is related to the malicious DLL.

* As we know the event ID is 5408 for cmd.exe, we can search this event ID using 'Find' in FullEventLogView; this gives us the net command executed.

```markdown
1. What remote address did the employee navigate to? - 20.188.56.147

2. Per the PCAP, which user returns a STATUS_LOGON_FAILURE error? - THM-PRINTNIGHT0\rjones

3. Which user successfully connects to an SMB share? - THM-PRINTNIGHT0/gentilguest

4. What is the first remote SMB share the endpoint connected to? What was the first filename? What was the second? - \\printnightmare.gentilkiwi.com\IPC$,srvsvc,spoolss

5. From which remote SMB share was malicious DLL obtained? What was the path to the remote folder for the first DLL? - \\printnightmare.gentilkiwi.com\print$,\x64\3\mimispool.dll,\W32X86\3\mimispool.dll

6. What was the first location the malicious DLL was downloaded to on the endpoint? What was the second? - C:\Windows\System32\spool\drivers\x64\3\New\,C:\Windows\System32\spool\drivers\W32X86\3\New\

7. What is the folder that has the name of the remote printer server the user connected to? - C:\Windows\system32\spool\servers\printnightmare.gentilkiwi.com

8. What is the name of the printer the DLL added? - Kiwi Legit Printer

9. What was the process ID for the elevated command prompt? What was its parent process? - 5408,spoolsv.exe

10. What command did the user perform to elevate privileges? - net  localgroup administrators rjones /add
```
