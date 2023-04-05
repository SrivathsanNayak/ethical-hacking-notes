# KAPE - Medium

1. [Introduction](#introduction)
2. [Target Options](#target-options)
3. [Module Options](#module-options)
4. [KAPE GUI](#kape-gui)
5. [KAPE CLI](#kape-cli)
6. [Hands-on Challenge](#hands-on-challenge)

## Introduction

* KAPE (Kroll Artifact Parser & Extractor) - parses & extracts Windows forensics artifacts.

* KAPE serves 2 purposes - collect files, and process collected files as required; for this, KAPE uses the concept of Targets and Modules.

* Targets - forensic artifacts that need to be collected.

* Modules - programs that process the collected artifacts and extract info from them.

* ```kape.exe``` is the CLI version, ```gkape.exe``` is the GUI version

```markdown
1. Which binary is used to run GUI version of KAPE? - gkape.exe
```

## Target Options

* Targets are defined in KAPE using the ```.tkape``` extension; this contains info about artifact, such as path, category and file masks to collect.

* KAPE also supports Compound Targets - Targets that are compounds of multiple other targets.

* Examples of Compound Targets include ```!BasicCollection```, ```!SANS_triage``` and ```KAPEtriage```.

```markdown
1. What is the file extension for KAPE Targets? - .tkape

2. What type of Target will we use if we want to collect multiple artifacts with a single command? - Compound Targets
```

## Module Options

* Modules run specific tools against provided files; these have the extension ```.mkape```.

* The ```bin``` directory (in Modules directory) contains executables that we want to run on the system but are not natively present.

```markdown
1. What is the file extension of the Modules files? - .mkape

2. What is the name of the directory where binary files are stored, which may not be present on a typical system, but are required for a particular KAPE Module? - bin
```

## KAPE GUI

* In ```gkape.exe```, to collect Targets, we can enable the ```Use Target Options``` checkbox.

* If we want to perform forensics on the same machine, we can provide ```C:\``` for the Target source, and any Target destination.

* The ```Flush``` checkbox deletes all contents present already in Target destination.

* When using both Target and Module options, providing Module source is not required as it will use Target destination as source.

```markdown
1. In the second to last screenshot above, what target have we selected for collection? - KapeTriage

2. In the second to last screenshot above, what module have we selected for processing? - !EZParser

3. What option has to be checked to append date and time information to triage folder name? - %d

4. What option needs to be checked to add machine information to the triage folder name? - %m
```

## KAPE CLI

* KAPE is mainly a CLI tool; even in GUI it shows the commands run.

* We can run ```kape.exe``` in an elevated PowerShell session - this shows us all the switches that can be used in KAPE.

* The command to collect triage data using ```KapeTriage``` Compound Target and process it using ```!EZParser``` Compound Module would be:

```kape.exe --tsource C: --target KapeTriage --tdest C:\Users\thm-4n6\Desktop\target --mdest C:\Users\thm-4n6\Desktop\module --module !EZParser```

* KAPE can also be run in batch mode - we can provide a list of commands to be run in a file ```_kape.cli```, located in same directory as ```kape.exe```.

* When ```kape.exe``` is executed as Administrator, it will run commands mentioned in the cli file.

```markdown
1. What variable adds the collection timestamp to the target destination? - %d

2. What variable adds the machine information to the target destination? - %m

3. Which switch can be used to show debug information during processing? - debug

4. Which switch is used to list all targets available? - tlist

5. Which flag, when used with batch mode, will delete the _kape.cli, targets and modules files after the execution is complete? - cu
```

## Hands-on Challenge

* According to given scenario, the Acceptable Use Policy forbids users from connecting removable or Network drives, installing software from unknown locations and connecting to unknown networks.

* We need to find if the user violated the policy on the device by running KAPE.

* We can run the KAPE CLI tool in an elevated PowerShell session; we will be using the ```KapeTriage``` Compound Target and ```!EZParser``` module (create the folders in Desktop for target & module destination files):

  ```.\kape.exe --tsource C: --tdest C:\Users\THM-4n6\Desktop\Target --target KapeTriage --mdest C:\Users\THM-4n6\Desktop\Module --module !EZParser```

* In the module destination folder assigned, we can see that KAPE has processed the files according to categories.

* Under each category folder, we have CSV files which can be viewed using the provided EZViewer tool.

* To view info about USB devices, we can check the 'Registry' folder created; we can view the CSV file for USB devices.

* As it is given that two USB mass storage devices were used, we can find the serial number required.

* Now, to find the Network drive location from which the given software were installed, we can look into the 'FileFolderAccess' subfolder.

* This contains a CSV for 'Automatic Destinations' - the Path column contains the required directory path.

* In the CSV for 'Recent Apps' in Registry folder, we can view timestamp for ChromeSetup.exe

* Similarly, for getting search queries run on system, we can view the CSV for Word Wheel queries under the same subfolder.

* For getting required network info, we can look into the Known Networks CSV.

* For finding the drive from which KAPE was copied, we can check the Automatic Destinations CSV again.

```markdown
1. What is the Serial Number of the other USB Device? - 1C6F654E59A3B0C179D366AE

2. What was the drive letter and path of the directory from where these software were installed? - Z:\setups

3. What is the execution date and time of CHROMESETUP.EXE? - 11/25/2021 3:33

4. What search query was run on the system? - RunWallpaperSetup.cmd

5. When was the network named Network 3 first connected to? - 11/30/2021 15:44

6. KAPE was copied from a removable drive. Can you find out what was the drive letter of the drive where KAPE was copied from? - E:
```
