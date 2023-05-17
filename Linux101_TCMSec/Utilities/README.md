# Other Utilities

* Searching & processing text:

  ```shell
  grep bob wordlist.txt
  # search for 'bob' in file

  grep -v e wordlist.txt
  # search for words that do not have 'e'

  grep error /var/log/*.log
  # search error in log files

  grep error -B 3 -A 2 /var/log/*.log
  # -B to print lines before hit
  # -A to print lines after hit

  sort random.txt
  # used to sort contents alphabetically

  sort -nr random-numbers.txt
  # -n for numbers and -r for reverse order

  # uniq filters only adjacent duplicate lines
  sort random-words.txt | uniq
  # alphabetic, non-dupli output

  wc words.txt
  # prints lines, words and bytes in file

  grep bob words.txt | wc -l
  # count no. of occurrences
  ```

* Manipulating text:

  ```shell
  # sed, stream editor
  # processes text as stream

  sed 's/Suite/Ste/' sample.txt
  # replaces Suite by Ste
  # s for substitution
  # works for only one occurrence per line

  sed 's/Suite/Ste/g' sample.txt
  # g for global

  sed '$s/Suite/Ste/' sample.txt
  # substitutes only last match

  sed '/Suite/d' sample.txt
  # deletes all lines which contain 'Suite'

  sed '/ee/ s/Suite/Ste/g' sample.txt
  # looks for match 'ee' in line
  # if found, substitutes all occurrences of 'Suite' by 'Ste' in line

  sed 's/$/\n/g' sample.txt
  # add new line at end of line

  sed 's/$/\n/g' sample.txt | sed 's/,/\n/g' sample.txt
  # add new line at end of line, then replace commas with new lines

  # we can do this in a single command
  # by combining multiple expressions using -e

  sed -e 's/$/\n/g' -e 's/,/\n/g' sample.txt
  ```

  ```shell
  # awk, breaks each input line into separate fields
  # default delim is space

  echo first second third | awk '{print $2}'
  # second
  # space-separated words, awk prints 2nd word

  awk -F ',' '{print $1}' sample.txt
  # -F for delimiter
  # prints first field from comma separated values in each line

  awk -F ',' '{print $1}' sample.txt | awk '{print $2 "," $1}'
  # print first field from comma separated values, then reorder as last name, first name

  awk -F ',' '/Dakota/ {print NR,$1}' sample.txt
  # print first field with comma delim
  # only from lines which have 'Dakota'
  # NR prints record number or row number
  ```

  ```shell
  # tr, translate
  # replace and delete chars from stdin

  cat sample.txt | tr ',' '\t'
  # replace comma as delim by tabs

  cat sample.txt | tr 'a-z' 'A-Z'
  # lowercase to uppercase
  # we can also use sets for this

  cat sample.txt | tr '[:lower:]' '[:upper:]'
  ```

* Networking:

  ```shell
  ping google.com
  # test two-way connectivity

  ping -c 4 google.com
  # sends 4 packets

  ifconfig
  # lists network interfaces configured

  ip a
  # modern alternative to ifconfig

  ip -s link
  # provides stats

  ip help
  # for more options

  ip route
  # view routing info

  route
  # similar info as 'ip route'

  nslookup google.com
  # dns lookup

  dig google.com
  # dns lookup with more info

  dig -x 8.8.8.8
  # reverse lookup

  netstat -at
  # view open TCP connections

  netstat -lt
  # listening TCP ports
  ```

* File transfer utilities:

  ```shell
  scp file.txt 192.168.100.4:/home/bob/
  # file transfer from local system to remote system

  scp -r files 192.168.100.4:/home/bob/
  # copy directory from local to remote

  scp 192.168.100.4:/home/bob/remote-file.txt backup/
  # copy file from remote to local

  scp file.txt sally@192.168.100.4:/home/sally
  # local to remote copy for specific user
  ```

  ```shell
  # rsync only copies files from source to destination which have changed
  # better than scp

  rsync -avzh file.txt 192.168.100.4:/home/bob
  # local to remote file transfer
  # -a for archive, preserving directory, permissions
  # -v for verbose, -z for compressing data
  # -h for human readable output
  ```

* Converting text files:

  ```shell
  # each OS treats EOL and EOF in text files differently

  file sample-dos-file.txt
  # shows CRLF line terminators, for Windows

  file sample-macos-file.txt
  # CR line terminators

  unix2dos sample-unix-file.txt
  # converts Unix to DOS text format

  unix2dos sample-unix-file.txt output-file.txt
  # -n to create new file instead of modifying original

  unix2dos -c mac sample-unix-file.txt
  # converts Unix to MacOS text format

  dos2unix sample-dos-file.txt
  # converts DOS to Unix text format
  
  dos2unix -c mac sample-mac-file.txt
  # converts MacOS to Unix text format
  ```

* Common text editors include ```nano``` and ```vim```.
