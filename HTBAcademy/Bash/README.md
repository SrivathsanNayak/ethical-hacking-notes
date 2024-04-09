# Introduction to Bash Scripting

* Bash (Bourne Again Shell) - scripting language used to communicate with UNIX OS

* Shebang - first line in script, starts with ```#!``` and includes path to specified interpreter for script

* Conditional execution:

  ```shell
  #!/bin/bash
  # only 'if' used

  value=$1

  if [ $value -gt "10" ]
  then
          echo "Given argument is greater than 10."
  fi
  ```

  ```shell
  #!/bin/bash
  # if-elif-else flow

  value=$1

  if [ $value -gt "10" ]
  then
          echo "Given argument is greater than 10."
  elif [ $value -lt "10" ]
  then
          echo "Given argument is less than 10."
  else
          echo "Given argument is not a number."
  fi
  ```

* Arguments - can pass upto 9 arguments (```$0``` to ```$9```) to the script; ```$0``` is reserved for the script

* Special variables - common IFS examples include:

  * ```$#``` - number of args passed to script
  * ```$@``` - list of command-line args
  * ```$n``` - nth arg, where 'n' is the number/position of the argument, e.g. - ```$2``` is the second arg
  * ```$$``` - PID of process
  * ```$?``` - exit status of script; 0 is successful, while 1 is failure

* Arrays -

  ```shell
  #!/bin/bash

  domains=(www.inlanefreight.com ftp.inlanefreight.com vpn.inlanefreight.com www2.inlanefreight.com)

  echo ${domains[0]}
  # www.inlanefreight.com
  ```

* Comparison operators -

  * string operators - ```==```, ```!=```, ```<```, ```>```, ```-z``` (null), ```-n``` (not null)
  
  * integer operators - ```-eq```, ```-ne```, ```-lt```, ```-le```, ```-gt```, ```-ge```

  * file operators - ```-e``` (file exists), ```-f``` (it is a file), ```-d``` (it is a directory), ```-L``` (symbolic link), ```-N``` (if file was modified after last read), ```-O``` (current user owns file), ```-G``` (file's group id matches current user's), ```-s``` (filesize greater than 0), ```-r``` (file has read permission), ```-w``` (file has write permission), ```-x``` (execute permission)

  * boolean operators - True, False - result of using logical operators ```!```, ```&&```, ```||```

  * example script:

    ```sh
    #!/bin/bash

    # Check if the specified file exists and if we have read permissions
    if [[ -e "$1" && -r "$1" ]]
    then
      echo -e "We can read the file that has been specified."
      exit 0

    elif [[ ! -e "$1" ]]
    then
      echo -e "The specified file does not exist."
      exit 2

    elif [[ -e "$1" && ! -r "$1" ]]
    then
      echo -e "We don't have read permission for this file."
      exit 1

    else
      echo -e "Error occured."
      exit 5
    fi
    ```

* Arithmetic operators -

  ```sh
  #!/bin/bash

  increase=1
  decrease=1

  echo "Addition: 10 + 10 = $((10 + 10))"
  echo "Subtraction: 10 - 10 = $((10 - 10))"
  echo "Multiplication: 10 * 10 = $((10 * 10))"
  echo "Division: 10 / 10 = $((10 / 10))"
  echo "Modulus: 10 % 4 = $((10 % 4))"

  ((increase++))
  echo "Increase Variable: $increase"

  ((decrease--))
  echo "Decrease Variable: $decrease"
  ```

* Input control:

  ```shell
  echo -e "Additional options available:"
  echo -e "\t1) Identify the corresponding network range of target domain."
  echo -e "\t2) Ping discovered hosts."
  echo -e "\t3) All checks."
  echo -e "\t*) Exit.\n"

  read -p "Select your option: " opt
  # -p ensures input is on same line
  # input stored in $opt

  case $opt in
    "1") network_range ;;
    "2") ping_host ;;
    "3") network_range && ping_host ;;
    "*") exit 0 ;;
  esac
  ```

* Output control:

  ```sh
  # Identify Network range for the specified IP address(es)
  function network_range {
    for ip in $ipaddr
    do
      netrange=$(whois $ip | grep "NetRange\|CIDR" | tee -a CIDR.txt)
      cidr=$(whois $ip | grep "CIDR" | awk '{print $2}')
      cidr_ips=$(prips $cidr)
      echo -e "\nNetRange for $ip:"
      echo -e "$netrange"
    done
  }

  # Identify IP address of the specified domain
  hosts=$(host $domain | grep "has address" | cut -d" " -f4 | tee discovered_hosts.txt)

  # tee is used to see output immediately
  # and it also stores it in a file
  # use | to transfer received output to tee
  ```

* Loops:

  * For loop:

    ```sh
    for ip in 10.10.10.170 10.10.10.174;do ping -c 1 $ip;done
    ```

    ```sh
    for ip in "10.10.10.170 10.10.10.174 10.10.10.175"
    do
      ping -c 1 $ip
    done
    ```
  
  * While loop (as long as True):

    ```sh
    stat=1
    while [ $stat -eq 1 ]
    do
      ping -c 2 $host > /dev/null 2>&1
      if [ $? -eq 0 ]
      then
        echo "$host is up."
        ((stat--))
        ((hosts_up++))
        ((hosts_total++))
      else
        echo "$host is down."
        ((stat--))
        ((hosts_total++))
      fi
    done
    ```

    ```sh
    #!/bin/bash

    counter=0

    while [ $counter -lt 10 ]
    do
      # Increase $counter by 1
      ((counter++))
      echo "Counter: $counter"

      if [ $counter == 2 ]
      then
        continue
      elif [ $counter == 4 ]
      then
        break
      fi
    done
    ```
  
  * Until loop (as long as False):

    ```sh
    #!/bin/bash

    counter=0

    until [ $counter -eq 10 ]
    do
      # Increase $counter by 1
      ((counter++))
      echo "Counter: $counter"
    done
    ```

* Branches:

  * if-elif-else

  * case statements:

    ```sh
    echo -e "Additional options available:"
    echo -e "\t1) Identify the corresponding network range of target domain."
    echo -e "\t2) Ping discovered hosts."
    echo -e "\t3) All checks."
    echo -e "\t*) Exit.\n"

    read -p "Select your option: " opt

    case $opt in
      "1") network_range ;;
      "2") ping_host ;;
      "3") network_range && ping_host ;;
      "*") exit 0 ;;
    esac
    ```

* Functions:

  ```sh
  function network_range {
    for ip in $ipaddr
    do
      netrange=$(whois $ip | grep "NetRange\|CIDR" | tee -a CIDR.txt)
      cidr=$(whois $ip | grep "CIDR" | awk '{print $2}')
      cidr_ips=$(prips $cidr)
      echo -e "\nNetRange for $ip:"
      echo -e "$netrange"
    done
  }

  # function can be called later simply using name
  # network_range
  ```

  ```sh
  #!/bin/bash

  # to pass parameters to function

  function print_pars {
    echo $1 $2 $3
  }

  one="First parameter"
  two="Second parameter"
  three="Third parameter"

  print_pars "$one" "$two" "$three"
  ```

  ```sh
  #!/bin/bash

  function given_args {

          if [ $# -lt 1 ]
          then
                  echo -e "Number of arguments: $#"
                  return 1
          else
                  echo -e "Number of arguments: $#"
                  return 0
          fi
  }

  # $? is used to read the return code

  # No arguments given
  given_args
  echo -e "Function status code: $?\n"

  # One argument given
  given_args "argument"
  echo -e "Function status code: $?\n"

  # Pass the results of the function into a variable
  content=$(given_args "argument")

  echo -e "Content of the variable: \n\t$content"
  ```

* We can debug code using ```-x``` (xtrace) and ```-v``` flags when executing script with ```bash```
