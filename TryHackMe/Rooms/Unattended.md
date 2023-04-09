# Unattended - Medium

* Windows Forensics cheatsheet:

  * System info & accounts:

    * OS version - ```SOFTWARE\Microsoft\Windows NT\CurrentVersion```

    * Current Control set -

      * ```HKLM\SYSTEM\CurrentControlSet```
      * ```SYSTEM\Select\Current```
      * ```SYSTEM\Select\LastKnownGood```

    * Computer name - ```SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName```

    * Time zone info - ```SYSTEM\CurrentControlSet\Control\TimeZoneInformation```

    * Network interfaces and past networks - ```SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces```

    * Autostart programs (Autoruns) -

      * ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run```
      * ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce```
      * ```SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce```
      * ```SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run```
      * ```SOFTWARE\Microsoft\Windows\CurrentVersion\Run```

    * SAM hive and user info - ```SAM\Domains\Account\Users```

  * External, USB device forensics:

    * Device identification -

      * ```SYSTEM\CurrentControlSet\Enum\USBSTOR```
      * ```SYSTEM\CurrentControlSet\Enum\USB```

    * First/Last times - ```SYSTEM\CurrentControlSet\Enum\USBSTOR\Ven_Prod_Version\USBSerial#\Properties\{id}\####``` (0064 - first connection, 0066 - last connection, 0067 - last removal)

    * USB device volume name - ```SOFTWARE\Microsoft\Windows Portable Devices\Devices```

  * File/folder usage:

    * Recent files - ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs```

    * Office recent files -

      * ```NTUSER.DAT\Software\Microsoft\Office\VERSION```
      * ```NTUSER.DAT\Software\Microsoft\Office\VERSION\UserMRU\LiveID_####\FileMRU```

    * ShellBags -

      * ```USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags```
      * ```USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU```
      * ```NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU```
      * ```NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags```

    * Open/Save and LastVisited dialog MRUs -

      * ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU```
      * ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU```

    * Windows Explorer address/search bars -

      * ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths```
      * ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery```

  * Evidence of execution:

    * UserAssist - ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count```

    * ShimCache - ```SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache```

    * AmCache - ```Amcache.hve\Root\File\{Volume GUID}\```

    * BAM/DAM -

      * ```SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}```
      * ```SYSTEM\CurrentControlSet\Services\dam\UserSettings\{SID}```

* We are given that we have to review activity between 12:05 PM to 12:45 PM on the 19th of November 2022.

* We have the disk image at ```C:\Users\THM-RFedora\Desktop\kape-results\C```; we can use ```Registry Explorer``` tool.

* Load the ```NTUSER.DAT``` hive from the location ```C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\NTUSER.DAT```.

* We can find the terms searched using the search bar at the following location:

  ```Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery```

* We can also make use of the ```Autopsy``` tool for further queries - create a case, select 'Logical Files' (C drive from the kape-results folder), and select only 'Recent Activity' in ingest settings.

* To view downloaded files, we can check the 'Web Downloads' section - this contains a few files of interest.

* We can find the '.exe' file in the downloads, and get the timestamp as well.

* Now, to find the PNG file opened, we can hop back to ```Registry Explorer``` and filter by file extension.

* Searching for '.png', we get the required timestamp from the registry entry found under ```Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.png```.

* Now, we can also make use of the ```JLECmd``` tool - this is used to parse Jump Lists (helps users go directly to recently used files from taskbar).

```ps
#in PowerShell session
cd C:\tools\JLECmd\

.\JLECmd.exe
#shows help

.\JLECmd.exe -d "C:\Users\THM-RFedora\Desktop\kape-results\C\" --mp
#-d to parse directory
#--mp for results with greater precision
```

* Parsing through the lengthy output of ```JLECmd```, we get the 'launchcode.txt' file from Desktop.

* The output shows the interaction count and timestamp for last modification as well.

* Now, to find the generated URL for 'pastebin.com', we can search under the 'Web History' section in ```Autopsy```.

* The pastebin URL data includes the copied string under the Title information.

```markdown
1. What file type was searched for using the search bar in Windows Explorer? - .pdf

2. What top-secret keyword was searched for using the search bar in Windows Explorer? - continental

3. What is the name of the downloaded file to the Downloads folder? - 7z2201-x64.exe

4. When was the file downloaded? - 2022-11-19 12:09:19 UTC

5. Thanks to the previously downloaded file, a PNG file was opened. When was this file opened? - 2022-11-19 12:10:21

6. A text file was created in the Desktop folder. How many times was this file opened? - 2

7. When was the text file last modified? - 11/19/2022 12:12

8. The contents of the file were exfiltrated to pastebin.com. What is the generated URL of the exfiltrated data? - https://pastebin.com/1FQASAav

9. What is the string that was copied to the pastebin URL? - ne7AIRhi3PdESy9RnOrN
```
