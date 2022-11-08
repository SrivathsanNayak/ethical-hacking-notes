# Osquery: The Basics - Easy

1. [Osquery: Interactive Mode](#osquery-interactive-mode)
2. [Schema Documentation](#schema-documentation)
3. [Creating SQL queries](#creating-sql-queries)
4. [Challenge](#challenge)

## Osquery: Interactive Mode

```ps
#in powershell terminal
#to enter interactive mode
osqueryi

.help
#help

.tables
#list available tables

.tables process
#check which tables are associated with processes

.schema users
#get schema (column names and types) for table 'users'

select uid, username, gid from users;
#sql query
#to display columns from table 'users'
```

```markdown
1. How many tables are returned when we query "table process" in the interactive mode of Osquery? - 3

2. Looking at the schema of the processes table, which column displays the process id for the particular process? - pid

3. Examine the .help command, how many output display modes are available for the .mode command? - 5
```

## Schema Documentation

* [Schema documentation for Osquery version 5.5.1](https://osquery.io/schema/5.5.1/)

```markdown
1. In Osquery version 5.5.1, how many common tables are returned, when we select both Linux and Window Operating system? - 56

2. In Osquery version 5.5.1, how many tables for MAC OS are available? - 180

3. In the Windows Operating system, which table is used to display the installed programs? - programs

4. In Windows Operating system, which column contains the registry value within the registry table? - data
```

## Creating SQL queries

* Exploring installed programs:

```ps
select * from programs limit 1;
#retrieve info about installed programs on endpoint (table 'programs')
#'limit 1' is used to limit only 1 result to display

select name, version, install_location, install_date from programs limit 2;
#select specific queries from table
```

* Count:

```ps
select count(*) from programs;
#count number of entries in table
```

* WHERE clause:

```ps
select * from users where username='James';
#return result based on specific criteria
```

* JOIN function:

```ps
select p.pid, p.name, p.path, u.username from processes p JOIN users u on u.uid=p.uid LIMIT 5;
#join tables using 'uid' field
```

```markdown
1. Using Osquery, how many programs are installed on this host? - 19

2. Using Osquery, what is the description for the user James? - Creative Artist

3. Query: select path, key, name from registry where key = 'HKEY_USERS';
When we run the following search query, what is the full SID of the user with RID '1009'? - S-1-5-21-1966530601-3185510712-10604624-1009

4. Query: select * from ie_extensions;
When we run the following search query, what is the Internet Explorer browser extension installed on this machine? - C:\Windows\System32\ieframe.dll

5. Query: select name,install_location from programs where name LIKE '%wireshark%';
After running the following query, what is the full name of the program returned? - Wireshark 3.6.8 64-bit
```

## Challenge

```ps
select path, last_execution_time from userassist;
#get list of programs executed

select name from programs where name like '%VPN%';
#get VPN name

select count(*) from services;
#get number of services

select name,path from autoexec where name like '%.bat%';
#get .bat file from autoexec table
```

```markdown
1. Which table stores the evidence of process execution in Windows OS? - userassist

2. One of the users seems to have executed a program to remove traces from the disk; what is the name of that program? - DiskWipe.exe

3. Create a search query to identify the VPN installed on this host. What is name of the software? - ProtonVPN

4. How many services are running on this host? - 214

5. A table autoexec contains the list of executables that are automatically executed on the target machine. There seems to be a batch file that runs automatically. What is the name of that batch file (with the extension .bat)? - batstartup.bat

6. What is the full path of the batch file found in the above question? - C:\Users\James\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat
```
