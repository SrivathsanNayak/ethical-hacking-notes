# Shells

* Currently running shell stores important config info and environment variables.

* ```printenv``` - show environment variables for current shell.

* PATH - list of directories searched in order to find commands to be executed.

* There are 2 types of environment variables - global and local - global can be accessed by anything executing in shell, but local can be accessed only by the script in which it was defined (shell variables).

  ```shell
  # in shell
  COUNT_LOCAL=24
  # creates local or shell variable

  echo $COUNT_LOCAL
  # 24

  bash
  # create sub-shell
  
  echo $COUNT_LOCAL
  # no value

  exit

  export COUNT_GLOBAL=24
  # create global or environment variable

  echo $COUNT_GLOBAL
  # 24

  bash

  echo $COUNT_GLOBAL
  # 24

  exit

  unset COUNT_GLOBAL
  # unset variable
  ```

* ```.bashrc``` file acts as a startup file for the Bash shell.

  ```shell
  vim ~/.bashrc
  # modify file if reqd
  # for shell customization

  source ~/.bashrc
  # rerun all commands in file in current shell
  ```

* ```stdin```, ```stdout``` and ```stderr``` are three data streams used in Linux:

  * ```stdin``` - used to send info to a program
  * ```stdout``` - contains all normal output from a program
  * ```stderr``` - used to display errors

* These data streams can be redirected to other files:

  ```shell
  ls /etc/ > ~/dir-contents.txt
  # > used to redirect stdout to file

  # writing to this file again can overwrite it

  ls /tmp >> ~/dir-contents.txt
  # >> to append instead of overwrite

  head < /etc/passwd
  # < used to redirect stdin to 'head' command

  find / -name sample.txt 2> errors.txt
  # 2> used to redirect stderr to file

  find / -name sample.txt 2>/dev/null
  # redirect stderr to /dev/null to ignore errors
  # this does not print any errors

  find / -name sample.txt &> all.txt
  # redirect both stdout and stderr to same file
  ```

* Pipes can be used to connect stdout of one command to stdin of another:

  ```shell
  ls -la /etc/ | less

  ls -la /etc/ | head -n 20 | tail -n 5
  ```

* In shell, ```history``` lets us check previously executed commands; we can execute a previously executed command in the format ```!n```, where n is the history number from ```history``` output.

* ```!!``` and ```!-1``` are two shorthands to execute the last executed command.

* Command substitution can be done using backticks to execute a part of the command first in a sub-shell, then the rest of the command.
