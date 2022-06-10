# Osquery - Easy

1. [Interacting with the Osquery Shell](#interacting-with-the-osquery-shell)
2. [Schema Documentation](#schema-documentation)
3. [Creating Queries](#creating-queries)
4. [Using Kolide Fleet](#using-kolide-fleet)
5. [Osquery Extensions](#osquery-extensions)
6. [Linux and Osquery](#linux-and-osquery)
7. [Windows and Osquery](#windows-and-osquery)

## Interacting with the Osquery Shell

```shell
osqueryi
#to open the osquery console

.help
#help (meta-command)

.tables
#list all tables

.tables process
#view tables associated with processes

.schema processes
#list a table's schema

.show
#show versions and other values
```

```markdown
1. What is the Osquery version? - 4.6.0.2

2. What is the SQLite version? - 3.34.0

3. What is the default output mode? - pretty

4. What is the meta-command to set the output to show one value per line? - .mode line

5. What are the 2 meta-commands to exit osqueryi? - .exit, .quit
```

## Schema Documentation

```markdown
1. What tables would you query to get the version of Osquery installed on the Windows endpoint? - osquery_info

2. How many tables are there for this version of Osquery? - 266

3. How many of the tables for this version are compatible with Windows? - 96

4. How many tables are compatible with Linux? - 155

5. What is the first table listed that is compatible with both Linux and Windows? - arp_cache
```

## Creating Queries

```shell
select * from processes;

select pid, name from processes;
#queries are very similar to SQL

select pid, name from processes where name='lsass.exe';

select pid, name, path from osquery_info join processes using (pid);
#join 2 tables
```

```markdown
1. What is the query to show the username field from the users table where the username is 3 characters long and ends with 'en'? - select username from users where username like '_en';
```

## Using Kolide Fleet

```markdown
1. What is the Osquery Enroll Secret? - k3hFh30bUrU7nAC3DmsCCyb1mT8HoDkt

2. What is the Osquery version? - 4.2.0

3. What is the path for the running osqueryd.exe process? - C:\Users\Administrator\Desktop\launcher\windows\osqueryd.exe
```

## Osquery Extensions

```markdown
1. According to the polylogyx readme, how many 'features' does the plug-in add to the Osquery core? - 25
```

## Linux and Osquery

```shell
osqueryi

.help

select * from kernel_info;

select * from users;

select * from shell_history
#this trick was referred from a blogpost because I could not get the required command

.exit

md5sum notsus

#calculate md5sum for all files in tryhackme user's directory

yara /var/osquery/yara/scanner.yara /home/alpha

yara /var/osquery/yara/scanner.yara /home/bravo

yara /var/osquery/yara/scanner.yara /home/charlie
#this gives us the malicious file

osqueryi

.schema yara

select * from yara where path='/home/tryhackme/notsus' and sigfile='/var/osquery/yara/scanner.yara';
```

```markdown
1. What is the 'current_value' for kernel.osrelease? - 4.4.0-17763-Microsoft

2. What is the uid for the bravo user? - 1002

3. One of the users performed a 'Binary Padding' attack. What was the target file in the attack? - notsus

4. What is the hash value for this file? - 3df6a21c6d0c554719cffa6ee2ae0df7

5. Check all file hashes in the home directory for each user. One file will not show any hashes. Which file is that? - fleet.zip

6. There is a file that is categorized as malicious in one of the home directories. Query the Yara table to find this file. Use the sigfile which is saved in '/var/osquery/yara/scanner.yara'. Which file is it? - notes

7. What were the 'matches'? - eicar_av_test, eicar_substring_test

8. Scan the file from Q.3 with the same Yara file. What is the entry for 'strings'? - $eicar_substring:1b
```

## Windows and Osquery

```shell
osqueryi --allow-unsafe --extension "C:\Program Files\osquery\extensions\osq-ext-bin\plgx_win_extension.ext.exe"

.help

.schema win_process_events

select * from win_process_events;

select * from services where name like 'Win%';

select * from programs;

select * from win_event_log_data;
#this shows that we need source for the query

select count(*) from win_event_log_channels;

.schema win_event_log_data

#for getting logs for notsus file

select * from win_event_log_data where source="Microsoft-Windows-Windows Defender/Operational" and eventid="1116";

select eventid from win_event_log_data where source="Microsoft-Windows-Sysmon/Operational" order by datetime limit 1;
```

```markdown
1. What is the description for the Windows Defender Service? -  Helps protect users from malware and other potentially unwanted software

2. There is another security agent on the Windows endpoint. What is the name of this agent? - AlienVault Agent

3. What is required with win_event_log_data? - source

4. How many sources are returned for win_event_log_channels? - 1076

5. What is the schema for win_event_log_data? - CREATE TABLE win_event_log_data(`time` BIGINT, `datetime` TEXT, `source` TEXT, `provider_name` TEXT, `provider_guid` TEXT, `eventid` INTEGER, `task` INTEGER, `level` INTEGER, `keywords` BIGINT, `data` TEXT, `eid` TEXT HIDDEN);

6. The previous file scanned on the Linux endpoint with Yara is on the Windows endpoint.  What date/time was this file first detected? - 2021-04-01 00:50:44

7. What is the query to find the first Sysmon event? Select only the event id, order by date/time, and limit the output to only 1 entry. - select eventid from win_event_log_data where source="Microsoft-Windows-Sysmon/Operational" order by datetime limit 1;

8. What is the Sysmon event id? - 16
```
