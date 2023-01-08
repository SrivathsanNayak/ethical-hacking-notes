# New Hire Old Artifacts - Medium

* According to the given scenario, we have to interact with the Splunk instance to sift through the events of "Widget LLC" and check for suspicious activities.

* We need to navigate to the ```Search and Reporting``` app and configure events to be searched from "All Time".

* Now, we need to search for the given 'Web Browser Password Viewer'; we can use this string itself as a query to get the location of the binary.

* This query also gives us the company name for the binary.

* Now, as we need to find another binary from the same folder, we need to use the following query to filter such binaries:

  ```ImageLoaded="C:\\Users\\Finance01\\AppData\\Local\\*"```

* This gives us a lot of events - to only look for 'Image' path values, we can check the tab on the left which shows us certain fields and their values.

* Checking the 'Image' field values, we get a particular binary of interest; clicking on that value filters it:

  ```ImageLoaded="C:\\Users\\Finance01\\AppData\\Local\\*" Image="C:\\Users\\Finance01\\AppData\\Local\\Temp\\IonicLarge.exe"```

* Scrolling down gives an event of interest - this contains the suspicious binary, along with its original filename.

* To view further queries related to this binary, we can simply search for the string "IonicLarge.exe".

* To view the IP address this binary interacted with, we can check the values of the field 'DestinationIp'.

* In order to view the registry key targeted by the binary, we need to view the field 'TargetObject' and then view its values - this contains a common registry key path.

* Now, Googling "process killing on Windows" shows that the command ```taskkill``` is used commonly.

* So, we can use this string as a search query in order to look for processes that were killed - the fields 'CommandLine' and 'ParentCommandLine' show the commands run.

* As we need to search for ```PowerShell``` commands now, we can use that as our search query and inspect values for "CommandLine" fields - the most recent command run is the one that appears first in the results.

* In order to check the IDs used by the attacker for the above command, we can use the search query "ThreatIDDefaultAction_Ids" and then check the values from the results.

* Now, to check the malicious binary executed from the "AppData" location, we need to use it as the search query.

* In the resulting events, by taking a look at the values of the "Image" field, we get the required binary path within the first few paths given.

* To look for the DLLs loaded with this binary, we can use the following search query:

  ```Image="C:\\Users\\Finance01\\AppData\\Roaming\\EasyCalc\\EasyCalc.exe" "*.dll"```

```markdown
1. A Web Browser Password Viewer executed on the infected machine. What is the name of the binary? - C:\Users\FINANC~1\AppData\Local\Temp\11111.exe

2. What is listed as the company name? - NirSoft

3. Another suspicious binary running from the same folder was executed on the workstation. What was the name of the binary? What is listed as its original filename? - IonicLarge.exe,PalitExplorer.exe

4. The binary from the previous question made two outbound connections to a malicious IP address. What was the IP address. - 2[.]56[.]59[.]42

5. The same binary made some changes to a registry key. What was the key path? - HKLM\SOFTWARE\Policies\Microsoft\Windows Defender

6. Some processes were killed and the associated binaries were deleted. What were the names of the two binaries? - phcIAmLJMAIMSa9j9MpgJo1m.exe,WvmIOrcfsuILdX6SNwIRmGOJ.exe

7. The attacker ran several commands within a PowerShell session to change the behaviour of Windows Defender. What was the last command executed in the series of similar commands? - powershell WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ThreatIDDefaultAction_Ids=2147735503 ThreatIDDefaultAction_Actions=6 Force=True

8. Based on the previous answer, what were the four IDs set by the attacker? - 2147735503,2147737010,2147737007,2147737394

9. Another malicious binary was executed on the infected workstation from another AppData location. What was the full path to the binary? - C:\Users\Finance01\AppData\Roaming\EasyCalc\EasyCalc.exe

10. What were the DLLs that were loaded from the binary from the previous question? - ffmpeg.dll,nw.dll,nw_elf.dll
```
