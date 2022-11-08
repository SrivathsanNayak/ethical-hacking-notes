# Osquery: The Basics - Easy

1. [Osquery: Interactive Mode](#osquery-interactive-mode)
2. [Schema Documentation](#schema-documentation)
3. [Creating SQL queries](#creating-sql-queries)
4. [Challenge](#challenge)

## Osquery: Interactive Mode

```markdown
1. How many tables are returned when we query "table process" in the interactive mode of Osquery?

2. Looking at the schema of the processes table, which column displays the process id for the particular process?

3. Examine the .help command, how many output display modes are available for the .mode command?
```

## Schema Documentation

```markdown
1. In Osquery version 5.5.1, how many common tables are returned, when we select both Linux and Window Operating system?

2. In Osquery version 5.5.1, how many tables for MAC OS are available?

3. In the Windows Operating system, which table is used to display the installed programs?

4. In Windows Operating system, which column contains the registry value within the registry table?
```

## Creating SQL queries

```markdown
1. Using Osquery, how many programs are installed on this host?

2. Using Osquery, what is the description for the user James?

3. When we run the following search query, what is the full SID of the user with RID '1009'?
Query: select path, key, name from registry where key = 'HKEY_USERS';

4. When we run the following search query, what is the Internet Explorer browser extension installed on this machine?
Query: select * from ie_extensions;

5. After running the following query, what is the full name of the program returned?
Query: select name,install_location from programs where name LIKE '%wireshark%';
```

## Challenge

```markdown
1. Which table stores the evidence of process execution in Windows OS?

2. One of the users seems to have executed a program to remove traces from the disk; what is the name of that program?

3. Create a search query to identify the VPN installed on this host. What is name of the software?

4. How many services are running on this host?

5. A table autoexec contains the list of executables that are automatically executed on the target machine. There seems to be a batch file that runs automatically. What is the name of that batch file (with the extension .bat)?

6. What is the full path of the batch file found in the above question?
```
