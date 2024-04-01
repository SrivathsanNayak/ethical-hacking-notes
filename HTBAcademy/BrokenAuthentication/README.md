# Broken Authentication

1. [Introduction](#introduction)
1. [Login Brute Forcing](#login-brute-forcing)
1. [Password Attacks](#password-attacks)
1. [Session Attacks](#session-attacks)
1. [Skill Assessment](#skill-assessment)

## Introduction

* Common authentication methods:

  * Multi-factor Authentication (MFA)
  * Form-based Authentication (FBA)
  * HTTP-based Authentication

* Authentication attacks can take place against 3 domains - ```HAS``` domain, ```IS``` domain and ```KNOWS``` (most common) domain

## Login Brute Forcing

* Default creds:

  * default, well-known creds (like admin:admin or admin:password) or using hardcoded hidden accounts in products
  * resources for default creds include [CIRT.net](https://www.cirt.net/passwords), [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv) and [SCADAPass](https://github.com/scadastrangelove/SCADAPASS/blob/master/scadapass.csv)
  * [example bruteforce script for CSV wordlist](basic_bruteforce.py)

* Weak bruteforce protections:

  * CAPTCHA:

    * there can be cases of custom or weak implementation of CAPTCHA, such as image name being same as chars in image
    * we should check source code to find CAPTCHA code value and attempt to bypass it
  
  * Rate limiting:

    * having a counter that increments after each failed attempt, an app can block a user after 'n' failed attempts within a minute
    * bruteforce attacks will not work when rate limiting is implemented, since the creds won't be validated by webapp (false negatives)
    * [example script to check rate limit](rate_limit_check.py)
  
  * Insufficient protections:

    * some web apps leverage headers like ```X-Forwarded-For``` to guess actual source IP; [CVE-2020-35590](https://nvd.nist.gov/vuln/detail/CVE-2020-35590) implements this logic, and it can be bypassed by crafting an ```X-Forwarded-For``` header
    * this can be used in case of web apps granting users access based on source IP (for example, localhost)

* Brute forcing usernames:

  * User Unknown attack:

    * at failed login, if app replies with 'unknown username' (or a similar message), we can bruteforce searching for "the password you entered for the username x is incorrect"
    * we can intercept a login request with Burp Suite and check the parameters used; we can use this in ```wfuzz``` later:

      ```shell
      wfuzz -c -z file,/opt/useful/SecLists/Usernames/top-usernames-shortlist.txt -d "Username=FUZZ&Password=dummypass" --hs "Unknown username" http://brokenauthentication.hackthebox.eu/user_unknown.php
      # --hs to hide strings that match
      # this will show which username is valid
      ```
  
  * Username existence interference:

    * some webapps prefill username input value if username is valid, but leave input value empty or with a default value when username is unknown
    * we can also check for any cookies set when username is valid or not; for example, we can have cookies named "failed_login" only when username is valid
  
  * Timing attack:

    * authentication functions can be flawed by design; for example, valid username can have a higher response time that an invalid username if the hashing algorithm used is strong enough
    * [example script to find timing difference](timing.py)
  
  * Enumerate through Password Reset:
  
    * webapp can have Password Reset function that shows "You should receive a message shortly" for a valid username and "username unknown, check data" for an invalid username, for example
  
  * Enumerate through Registration Form:

    * registration forms can also prompt to choose another username if we have entered a valid one
    * we can also use the ```+``` tag in left part of email address (student@gmail vs student+test@gmail); we can register multiple users using this tag and one actual email address, but this is a very noisy attack
  
  * Predictable usernames:

    * we can check for any patterns in usernames like "user001", "user002", and so on; or predictable naming convention like "support.it" or "support.uk"

* Brute forcing passwords:

  * Password issues:
  
    * passwords are not complex enough, not stored properly, predictable or reused

  * Policy inference:
  
    * easy to bruteforce if we understand minimum password requirements with "Password does not meet complexity requirements" message
    * we can also try this on password reset page with different password sequences (string with lower, upper, digit or special chars, or greater than 8-20 chars, for example) to understand the minimum policy requirements implemented
    * [example list of passwords to check policy requirements](passwd_policy_req.txt) (check in reverse - from max complexity to min)
    * we can later use a wordlist and extract passwords which are in the matching format:

      ```shell
      # filter lines having atleast one upper and lower char, and within 8 to 12 chars
      grep '[[:upper:]]' rockyou.txt | grep '[[:lower:]]' | grep -E '^.{8,12}$' | wc -l
      ```

    * while bruteforcing, we should also check if there are any other protections in place like anti-CSRF tokens

* Predictable reset token:

  * Reset tokens - secret data generated by app when password reset is requested; needed to prove identity before actually changing the creds

  * Reset token by email - needs to have robust token generation function

  * Weak token generation:

    * some apps create token using known values like local time or username, and then hash/encode the value
    * we should try brute forcing any weak hash using known combos like time+username or time+email when reset token is requested
    * server time can be read from ```Date header``` found in HTTP response
    * [example script to bruteforce token using time value](reset_token_time.py)
  
  * Short tokens:

    * tokens with lesser characters can be brute-forced using ```wfuzz```, for example:

      ```shell
      wfuzz -z range,00000-99999 --ss "Valid" "https://brokenauthentication.hackthebox.eu/token.php?user=admin&token=FUZZ"
      # suppose token is of 5 digits
      # and --ss is used to search string
      # if we don't know string for valid case, but for invalid, then use --hs flag
      ```
  
  * Weak cryptography - always use modern and well-known encryption algos

  * Reset token as temp password - check if reset tokens being used as temporary passwords can be reused; we can also check the algorithm used to generate the temporary passwords

## Password Attacks

* Check for logic flaws in 'forgot password' and 'password change' functionalities to attempt authentication bypass

* Guessable answers:

  * generic questions prompted when using the 'forgot password' option
  * the security answers can either be guessed, found using OSINT or even brute forced
  * [example script for attacking predictable questions](predictable_questions.py)

* Username injection:

  * after requesting a password reset, we can get a form that allows us to enter a new password
  * we can try to inject a different username or email in possible field names
  * for example, if we intercept a new password request and add the 'userid' field, we can change password for another user
  * [example script for username injection in reset password checks](username_injection.py)

## Session Attacks

* Brute forcing cookies:

  * Cookie token tampering:

    * like password reset tokens, session tokens can also be based on guessable info
    * we should try checking for any cookies that can be decoded/decrypted to give us useful info, and then try modifying it
  
  * ```rememberme``` token:

    * if algo used to generate a ```rememberme``` token or its length is not secure, we can leverage its validity timeframe (can be a week or longer) to guess it
  
  * Encrypted or encoded token:

    * check if cookies contain the result of encryption or encoding of any data
    * we can check file signatures and use tools such as [CyberChef](https://gchq.github.io/CyberChef/) and [Decodify](https://github.com/s0md3v/Decodify)
    * [example script to automate cookie value attack](cookie_tampering.py)
  
  * Weak session token:

    * even if cookies are generated by strong randomization, it is possible that it's not long enough
    * we should examine cookie values for any patterns with length and charset before starting attack
    * for example, we can use ```wfuzz``` and ```john``` (JtR) for this attack:

      ```shell
      john --incremental=LowerNum --min-length=6 --max-length=6 --stdout| wfuzz -z stdin -b HTBSESS=FUZZ --ss "Welcome" -u https://brokenauthentication.hackthebox.eu/profile.php
      # suppose cookie length is 6 and charset is lowercase chars and digits
      # john can be set in incremental mode with LowerNum charset and 6 as length
      # output is printed to stdout stream, and using pipe, wfuzz gets this from stdin stream

      # -b is for cookie HTBSESS
      # --ss used to search string in valid case
      ```

* Insecure token handling:

  * Cookies are used to send & store arbitrary data, while tokens are explicitly used to send authorization data
  * JWT (JSON Web Token) is a common form of token-based authentication; typically used in continuous authentication for SSO (Single Sign-On)
  * A token should expire after the user has been inactive for a certain time period, to avoid session fixation attacks
  * Session fixation -
  
    * carried out by phishing an user with a link that has a fixed & unknown session value
    * web app should bounce user to login page due to invalid value
    * when user logs in, the ```SESSIONID``` value remains the same, and attacker can reuse it
  
  * Token in URL - this can be carried out only if the ```Referer``` header carries the complete URL of the website; this attack is not possible since modern browsers strip out that header

## Skill Assessment

* For the given webapp, we need to escalate to a privileged user

* From the support page, we know that we have an account name called 'support'

* In the login page, we have options for 'create an account' and 'forgot password' - we can use the methods from earlier with this

* From the page to create an account, we can attempt to understand the password policy by bruteforcing different possible passwords

* We get the following reasons when unable to create an account, thus giving us an idea about the password requirements:

  * The password must start with a capital letter
  * The password must end with a digit
  * The password must contain at least one special char: $ # @
  * The password must contain at least one lowercase
  * The password is shorter than 20 characters
  * The password is longer than 29 characters

* With all these pointers, we can use the ```rockyou.txt``` wordlist and get valid passwords:

  ```shell
  grep '^[[:upper:]]' /usr/share/wordlists/rockyou.txt | grep '[[:digit:]]$' | grep '[[:lower:]]' | grep '[[:punct:]]' | grep -E '^.{20,29}$' | wc -l

  # redirect all valid passwords to a file
  grep '^[[:upper:]]' /usr/share/wordlists/rockyou.txt | grep '[[:digit:]]$' | grep '[[:lower:]]' | grep '[[:punct:]]' | grep -E '^.{20,29}$' > valid_passwords.txt
  ```

* We can also see that the login page has a rate-limiting feature, so we may want to modify the rate limiting script from earlier and use it here while bruteforcing the password for the user 'support'

* The bruteforce does not work as intended, and we get invalid credentials for all with user 'support', so we can try to create a user and enumerate for any more usernames

* After creating a mock user and logging in, we can attempt to send a message to another user in the 'Messages' section

* We can also keep in mind that the 'Support' page mentions a clue about contacting any department by adding country code

* If we enter an invalid username, we get the string "user not found"; we do have a valid user called 'support'

* We can try similar usernames by adding country code at end of 'support' (for example, 'support.uk', 'support.it', etc.), and other 'departments' like 'admin', 'guest' and 'finance'

* We can fuzz this using the ```country-codes.txt``` (stick to lowercase only) wordlist from ```SecLists``` - and we get the following valid country codes - .cn, .gr, .it, .uk, .us

* We can attempt a bruteforce with the rate limit script again - this time we can include all the usernames enumerated (with the country codes suffixed as well) along with the passwords found from 'rockyou.txt'

* One thing I did not do right with [my script](final_skill_assessment_bruteforce.py) was to check with a known password, that is, an account that I just created; this led me to the fact that the passwords being bruteforced had a line break '\n' in them, so I had to remove it; also forgot to define the number of attempts after which we would hit 'too many attempts'

* We get some valid credentials after the bruteforce and can be used to login; if we check the 'Remember me' option, the ```rememberme``` cookie is set as well

* After logging in, we can see a cookie value set for 'htb_sessid'; we can attempt to make sense of this using CyberChef

* After URL-decode and decoding from base64, we get a string made of two hex strings separated by a colon

* Logging in from all accounts, we can see that the second hex string is persistent and same for all users; the first hex string is what we will need to decode further

* Online tools like [Cipher Identifier](https://www.dcode.fr/cipher-identifier) indicate that it could be MD5 or hex data; we have already tried for hex so we can try to treat the first part of the string as MD5 hashes and try to crack it:

  ```shell
  vim md5_hashes
  # add the hashes in here

  hashcat -a 0 -m 0 md5_hashes /usr/share/wordlists/kaonashi.txt
  # we get the hashes cracked
  ```

* We can see that the first part of the string is just the MD5 hash of the username; while the second part is MD5 of the term 'support'

* Using this logic, we can craft for other users such as 'support' and 'admin' - when we try for 'admin', we get the message 'user cannot have requested role'

* We can try to check again from the Messages page, by intercepting a request, and fuzzing the username field; following the similar method as before, we get usernames like 'admin.uk' and 'admin.it'

* So, we can craft the cookie by using the above technique - concatenate MD5 strings for 'admin.uk' and 'admin', and then encode it as above
