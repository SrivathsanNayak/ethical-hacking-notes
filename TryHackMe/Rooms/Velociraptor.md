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

```markdown
1. Using the documentation, how would you launch an Instant Velociraptor on Windows?
```

## Interacting with client machines

```markdown
1. What is the hostname for the client?

2. What is listed as the agent version?

3. In the Collected tab, what was the VQL command to query the client user accounts?

4. In the Collected tab, check the results for the PowerShell whoami command you executed previously. What is the column header that shows the output of the command?

5. In the Shell, run the following PowerShell command Get-Date. What was the PowerShell command executed with VQL to retrieve the result?
```

## Creating a new collection

```markdown
1. Review the parameter description for this setting. What is this parameter specifically looking for?

2. Review the output. How many files were uploaded?
```

## VFS (Virtual File System)

```markdown
1. Which accessor can access hidden NTFS files and Alternate Data Streams?

2. Which accessor provides file-like access to the registry?

3. What is the name of the file in $Recycle.Bin?

4. There is hidden text in a file located in the Admin's Documents folder. What is the flag?
```

## VQL (Velociraptor Query Language)

```markdown
1. What is followed after the SELECT keyword in a standard VQL query?

2. What goes after the FROM keyword?

3. What is followed by the WHERE keyword?

4. What can you type in the Notepad interface to view a list of possible completions for a keyword?

5. What plugin would you use to run PowerShell code from Velociraptor?
```

## Forensic Analysis VQL Plugins

```markdown
1. What are the arguments for parse_mft()?

2. What filter expression will ensure that no directories are returned in the results?
```

## Hunt for a nightmare

```markdown
1. What is the name in the Artifact Exchange to detect Printnightmare?

2. Per the above instructions, what is your Select clause?

3. What is the name of the DLL that was  placed by the attacker?

4. What is the PDB entry?
```
