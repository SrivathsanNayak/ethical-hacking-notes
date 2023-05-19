# Process Management

* Process info:

  ```shell
  ps
  # print all running processes for current user

  ps aux
  # shows all running processes

  ps -eH
  # -e for processes of all users
  # -H for hierarchical format

  pstree
  # easier view for process hierarchy

  top
  # real-time updated view of processes and resources consumed
  ```

* Foreground & background processes:

  * We can run only one foreground process at a time in a shell; however, we can run multiple background processes at the same time:

    ```shell
    xeyes
    # foreground process
    # this does not allow to run other commands

    xeyes &
    # background process
    ```
  
  * We can also move a running process from foreground to background, and vice-versa:

    ```shell
    xeyes
    # foreground

    # Ctrl+Z to suspend/pause process

    jobs
    # shows suspended processes

    bg
    # move job to background

    jobs
    # xeyes is now running in background

    fg
    # move job to foreground

    # for fg and bg, we can also use job id
    # in case of multiple jobs
    ```

* Managing processes:

  * A process can be in one of these states:

    * Running - CPU executing a process

    * Sleeping - waiting on a resource; when it gets the resource, it will get into running state again

    * Stopped - when stop signal is sent to running process, CPU stops executing the process

    * Terminated - cause a process to die

    * Zombie - remains of the process when it was not cleaned up after dying; does not respond to normal signals used to shut a process down

  * Processes change their states in response to signals; ```kill``` command used to send these signals to processes:

    ```shell
    kill -l
    # shows full list of signals

    # SIGHUP used to signal to process that it should reread its config

    # SIGSTOP used to stop a process from running; Ctrl+Z

    # SIGTERM is default signal sent by kill to terminate process

    # SIGKILL used if process does not respond to SIGTERM

    xeyes &
    # program running in background

    ps -ef | grep xeyes
    # shows PID of process

    kill 55092
    # SIGTERM sent to process, terminated

    kill -9 55092
    # SIGKILL can be sent as well, if process does not respond to SIGTERM

    # pkill can be used if we do not know pid
    # kills any process which matches the criteria

    pkill xeyes
    # kills multiple instances of program

    sleep 5
    # pauses execution in shell for some time, adds delays
    ```

* Scheduling processes:

  ```shell
  less /etc/crontab
  # contains processes scheduled at system level

  crontab -e
  # personal crontab file

  # follow format 'm h dom mon dow  command'
  
  5 1 2 * * touch /home/bob/cron/crontab-ran.txt
  # runs the command at 1:05 every second day of each month

  */5 * * * * touch /home/bob/cron/crontab-ran.txt
  # runs the command every 5 minutes

  crontab -l
  # prints crontab file contents

  crontab -r
  # deletes cronjobs
  ```

  ```shell
  # init.d used to run scripts at system bootup

  ls -la /etc/init.d
  # view scripts running at startup

  ls -la /etc/rc*.d
  # shows different run-levels
  ```
