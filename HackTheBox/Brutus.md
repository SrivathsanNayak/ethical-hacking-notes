# Brutus - Very Easy

* given scenario - a Confluence server was brute-forced via its SSH service

* extract the zip file contents using password 'hacktheblue'

* we have 3 files:

    * auth.log
    * wtmp
    * utmp.py

* checking the bruteforce attempts using ```less auth.log```, we can see multiple login failed messages

* after several attempts, the attacker is able to log in as 'root'

* to review the ```wtmp``` logs (which records a history of all logins, logouts, shutdowns & reboots), as it is a binary file we need to use tools like ```utmpdump``` or ```last```; in this case we have a script ```utmp.py``` so we can use that:

    ```sh
    less utmp.py
    # it is a utmp parser script

    python3 utmp.py wtmp -o wtmplogs

    less wtmplogs
    # we can read the logs now
    ```

* from the parsed ```wtmp``` logs, we can see the attacker IP and the timestamp when they were able to login as 'root' - here the timestamp is in local timezone, so we need to ensure it is in UTC

* we can find the session number assigned to this login attempt from ```auth.log```

* also, after the attacker logged in as 'root', they created a new user and group 'cyberjunkie' and gave it 'sudo' privileges

* finally, using the new account, the attacker executed a command to fetch a script for further persistence
