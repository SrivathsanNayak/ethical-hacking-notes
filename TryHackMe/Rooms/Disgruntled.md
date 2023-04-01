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

```markdown
1. The user installed a package on the machine using elevated privileges. According to the logs, what is the full command?

2. What was the present working directory when the previous command was run?

3. Which user was created after the package from the previous task was installed?

4. A user was then later given sudo privileges. When was the sudoers file updated?

5. A script file was opened using the 'vi' text editor. What is the name of this file?

6. What is the command used that created the file ```bomb.sh```?

7. The file was renamed and moved to a different directory. What is the full path of this file now?

8. When was the file from the previous question last modified?

9. What is the name of the file that will get created when the file mentioned executes?

10. At what time will the malicious file trigger?
```
