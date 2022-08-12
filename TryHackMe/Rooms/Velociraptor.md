# Velociraptor - Medium

1. [Introduction](#introduction)
2. [Deployment](#deployment)
3. [Interacting with client machines](#interacting-with-client-machines)
4. [Creating a new collection](#creating-a-new-collection)
5. [VFS (Virtual File System)](#vfs-virtual-file-system)
6. [VQL (Velociraptor Query Language)](#vql-velociraptor-query-language)
7. [Forensic Analysis VQL Plugins](#forensic-analysis-vql-plugins)
8. [Hunt for a nightmare](#hunt-for-a-nightmare)

## Introduction

* Velociraptor, a tool by Rapid7, is an endpoint monitoring, digital forensic and cyber response platform.

```markdown
1. Who acquired Velociraptor? - Rapid7
```

## Deployment

* The deployment in this task simulates Velociraptor running as a server in Linux and as a client running Windows.

```markdown
1. Using the documentation, how would you launch an Instant Velociraptor on Windows? - Velociraptor.exe gui
```

## Interacting with client machines

* The Windows machine is added as a client in Velociraptor.

* In the GUI, the ```Overview``` tab will show additional info about the client.

* Also, after ```Interrogate```, we can see that the ```Collected``` tab includes more artifacts. The commands that we execute in ```Shell``` are also shown in the ```Collected``` tab.

```markdown
1. What is the hostname for the client? - THM-VELOCIRAPTOR.eu-west-1.compute.internal

2. What is listed as the agent version? - 
2021-04-11T22:11:10Z

3. In the Collected tab, what was the VQL command to query the client user accounts? - LET Generic_Client_Info_Users_0_0=SELECT Name, Description, Mtime AS LastLogin FROM Artifact.Windows.Sys.Users()

4. In the Collected tab, check the results for the PowerShell whoami command you executed previously. What is the column header that shows the output of the command? - Stdout

5. In the Shell, run the following PowerShell command Get-Date. What was the PowerShell command executed with VQL to retrieve the result? - powershell -ExecutionPolicy Unrestricted -encodedCommand RwBlAHQALQBEAGEAdABlAA==
```

## Creating a new collection

* Creating a new collection involves five steps -

  * Select Artifacts
  * Configure Parameters
  * Specify Resources
  * Review
  * Launch

```markdown
1. Review the parameter description for this setting. What is this parameter specifically looking for? - Ubuntu on Windows Subsystem for Linux

2. Review the output. How many files were uploaded? - 20
```

## VFS (Virtual File System)

* The ```VFS``` allows us to inspect the client filesystem in an incident response scenario.

```markdown
1. Which accessor can access hidden NTFS files and Alternate Data Streams? - ntfs accessor

2. Which accessor provides file-like access to the registry? - registry accessor

3. What is the name of the file in $Recycle.Bin? - desktop.ini

4. There is hidden text in a file located in the Admin's Documents folder. What is the flag? - THM{VkVMT0NJUkFQVE9S}
```

## VQL (Velociraptor Query Language)

* ```Notebook``` can be used to execute VQL queries.

* Velociraptor allows packaging VQL queries inside ```Artifacts```, which are structured YAML files.

```markdown
1. What is followed after the SELECT keyword in a standard VQL query? - column selectors

2. What goes after the FROM keyword? - VQL plugin

3. What is followed by the WHERE keyword? - filter expression

4. What can you type in the Notepad interface to view a list of possible completions for a keyword? - ?

5. What plugin would you use to run PowerShell code from Velociraptor? - execve()
```

## Forensic Analysis VQL Plugins

* VQL plugins can be used for DFIR (Digital Forensics and Incident Response).

```markdown
1. What are the arguments for parse_mft()? - parse_mft(filename="C:/$MFT", accessor="ntfs")

2. What filter expression will ensure that no directories are returned in the results? - IsDir
```

## Hunt for a nightmare

* We have to use Velociraptor to create an artifact to detect the [PrintNightmare vulnerability](https://docs.velociraptor.app/exchange/artifacts/pages/printnightmare/).

* The given artifact has to be added as a custom one, to the ```Artifacts``` section in Velociraptor.

* We can construct the required VQL query to find the DLL by referring the artifact entry and the skeleton query:

```markdown
SELECT "C:/" + FullPath AS *********,FileName AS *********,parse_pe(file="C:/" + FullPath) AS **
FROM parse_mft(filename="C:/$***", accessor="****")
WHERE *** IsDir
AND FullPath =~ "Windows/System32/spool/drivers"
AND **
```

* Required query (to be created in ```Notebook```):

```markdown
SELECT "C:/" + FullPath AS Full_Path,FileName AS File_Name,parse_pe(file="C:/" + FullPath) AS PE
FROM parse_mft(filename="C:/$MFT", accessor="ntfs")
WHERE NOT IsDir
AND FullPath =~ "Windows/System32/spool/drivers"
AND PE
```

```markdown
1. What is the name in the Artifact Exchange to detect Printnightmare? - Windows.Detection.PrintNightmare

2. Per the above instructions, what is your Select clause? - SELECT "C:/" + FullPath AS Full_Path,FileName AS File_Name,parse_pe(file="C:/" + FullPath) AS PE

3. What is the name of the DLL that was  placed by the attacker? - nightmare.dll

4. What is the PDB entry? - C:\Users\caleb\source\repos\nightmare\x64\Release\nightmare.pdb
```
