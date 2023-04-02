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

```markdown
1. What file type was searched for using the search bar in Windows Explorer?

2. What top-secret keyword was searched for using the search bar in Windows Explorer?

3. What is the name of the downloaded file to the Downloads folder?

4. When was the file downloaded?

5. Thanks to the previously downloaded file, a PNG file was opened. When was this file opened?

6. A text file was created in the Desktop folder. How many times was this file opened?

7. When was the text file last modified?

8. The contents of the file were exfiltrated to pastebin.com. What is the generated URL of the exfiltrated data?

9. What is the string that was copied to the pastebin URL?
```
