# Regex and Scripting

* Searching with Regex:

  * Regular expressions (regex) can be used to define complex pattern matching rules.

  * Online tools like [regexr](https://regexr.com/) and [regex101](https://regex101.com/) can be used to build & understand regex.

  * primary components of regex:

    * character classes
    * quantifiers and alternation
    * groups
    * anchors

  * For example, regex to find numbers >= 42:

    ```/^4[2-9]|[5-9]\d|[1-9]\d{2,}$/gm```

  * We can use regex with ```grep``` to search files:

    ```shell
    grep -E '^4[2-9]|[5-9]\d|[1-9]\d{2,}$' numbers.txt
    # this regex does not work as it contains the \d shorthand for digits
    # we have to use another form

    grep -E '^4[2-9]|[5-9][0-9]|[1-9][0-9]{2,}$' numbers.txt
    # prints all matches
    ```

* Replacing with Regex:

  * We can reference the entire matched text using ```$&```

  * To address specific parts of the matched text, we can use parentheses in regex to group these parts, and use ```$n``` to refer the part, where n is the group number, starting from 1.

* Scripting basics:

  * Bash shell scripts - series of Bash commands stored in a file; can be executed by simply running the script.

  * Hello world script:

    ```shell
    #!/bin/bash

    # comment
    echo "Hello world"
    ```

  * We can run the script using the command ```bash helloworld.sh```; another way is to run ```chmod +x helloworld.sh``` to make it an executable and then run ```./helloworld.sh```

  * Script to run basic commands:

    ```shell
    #!/bin/bash

    # execute whoami
    user=$(whoami)

    # hostname
    hostname = $(hostname)

    # current working directory
    directory=$(pwd)

    echo "User=[$user] Host=[$hostname] Current working dir=[$directory]"

    echo "Contents of current working directory: "
    ls
    ```

* Control structures:

  ```shell
  #!/bin/bash
  
  if [[ -d /etc/ ]]; then
    echo /etc/ is indeed a directory
  fi

  # Check to see if a file exists
  if [[ -e sample.txt ]]; then
    echo The file sample.txt exists
  else
    echo The file sample.txt does NOT exist
  fi

  # Check a variable value
  TEST_VAR="test"
  if [[ $TEST_VAR == "test" ]]; then
    echo TEST_VAR has a value of "test"
  elif [[ $TEST_VAR == "again" ]]; then
    echo TEST_VAR has a value of "again"
  else
    echo TEST_VAR has an unknown value
  fi
  ```

  ```shell
  #!/bin/bash

  # Create some variables
  x=1
  echo x=["$x"]
  y=2
  echo y=["$y"]
  z=2
  echo z=["$z"]


  # Perform some comparisons
  # Numeric: Not equals
  if [[ "$x" -ne "$y" ]]; then
    echo ["$x"] ne ["$y"]
  fi

  # Numeric: Equals
  if [[ "$y" -eq "$z" ]]; then
    echo ["$y"] eq ["$z"]
  fi

  # Numeric: Greater than
  if [[ "$y" -gt "$x" ]]; then
    echo ["$y"] gt ["$x"]
  fi

  # Numeric: Greater than or equal to
  if [[ "$y" -ge "$z" ]]; then
    echo ["$y"] ge ["$z"]
  fi

  # Numeric: Less than
  if [[ "$x" -lt "$y" ]]; then
    echo ["$x"] lt ["$y"]
  fi

  # Numeric: Less than or equal to
  if [[ "$y" -le "$z" ]]; then
    echo ["$y"] le ["$z"]
  fi

  # Create some variables
  a="A"
  echo a=["$a"]
  b="B"
  echo b=["$b"]
  anotherA="A"
  echo anotherA=["$anotherA"]

  # Perform some comparisons
  # String: Equals
  if [[ "$a" == "$anotherA" ]]; then
    echo ["$a"] "==" ["$anotherA"]
  fi

  # String: Not equals
  if [[ "$a" != "$b" ]]; then
    echo ["$a"] "!=" ["$b"]
  fi

  # String: Less than
  if [[ "$a" < "$b" ]]; then
    echo ["$a"] "<" ["$b"]
  fi

  # String: Greater than
  if [[ "$b" > "$a" ]]; then
    echo ["$b"] ">" ["$a"]
  fi
  ```

  ```shell
  #!/bin/bash

  # Switch off of the first command line argument
  case $1 in
  [1-3])
    message="Argument is between 1 and 3 inclusive"
    ;;
  [4-6])
    message="Argument is between 4 and 6 inclusive"
    ;;
  [7-9])
    message="Argument is between 7 and 9 inclusive"
    ;;
  1[0-9])
    message="Argument is between 10 and 19 inclusive"
    ;;
  *)
    message="I don't understand the argument or it is missing"
    ;;
  esac

  echo $message
  ```

* Loops:

  ```shell
  #!/bin/bash

  echo For loops

  # Iterate through the numbers 1 through 5 and print them out
  echo Print out a hard-coded sequence
  for i in 1 2 3 4 5; do
      echo Index=[$i]
  done

  # Same as above
  echo Print out a generated sequence
  for i in {1..5}; do
      echo Index=[$i]
  done

  # Same as above
  # Double parenthesis are used since we are doing arithmetic
  echo Print out a generated sequence using the 3-expression format
  for(( i=1; i<=5; i++ ))
  do
      echo Index=[$i]
  done

  # Print out the last line of each shell script in the current directory
  echo Print out the last line of each shell script
  for FILE in *.sh
  do
      echo ===
      echo File=[$FILE]
      tail -n 1 $FILE
  done

  echo ''

  # While loop example

  echo While loop

  echo Executing a while loop to countdown to blastoff
  counter=5
  while [[ $counter -gt 0 ]]; do
      echo Countdown [$counter]
      counter=$(($counter - 1))
  done
  echo Blastoff
  ```

  ```shell
  #!/bin/bash

  # Processing command line arguments

  # What is the name of the executed script?
  echo Name of script [$0]

  # How many were provided?
  echo Command line argument count [$#]

  # Iterate through each argument
  for arg in $@; do
    echo Argument [$arg]
  done

  # Display all the arguments as a string
  echo All arguments [$*]

  # Use parenthesis for arguments with numbers 10 or larger
  if [ "${12}" != "" ]; then
    echo Argument 12 is [${12}]
    echo Argument 12 is NOT [$12]
  fi
  ```
