# Attacking Web Apps with ffuf

1. [Basic Fuzzing](#basic-fuzzing)
1. [Domain Fuzzing](#domain-fuzzing)
1. [Parameter Fuzzing](#parameter-fuzzing)

## Basic Fuzzing

* Fuzzing - testing technique that sends various types of user input to an interface and check its reaction

* Directory fuzzing:

  ```shell
  ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://94.237.63.93:35182/FUZZ -s
  # -s for silent
  ```

* Page fuzzing:

  ```shell
  # fuzz extensions with a common term like 'index'
  # we can also use two wordlists if needed
  ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://94.237.63.93:35182/blog/indexFUZZ -s

  # checking for files with php extension
  ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://94.237.63.93:35182/blog/FUZZ.php -s
  ```

* Recursive fuzzing:

  ```shell
  ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://94.237.63.93:35182/FUZZ -recursion -recursion-depth 1 -e .php -v -s
  # recursive depth can be increased, but will take more time
  # -e to specify extension
  # check with other directories like /blog and /forum manually as well
  ```

## Domain Fuzzing

* For IP-to-domain mapping, we can add domain names to local file using ```sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'```; then we can visit the website at <http://academy.htb:PORT>

* Sub-domain fuzzing:

  ```shell
  # search for websites in format *.inlanefreight.com
  ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/ -s
  ```

* Vhost fuzzing:

  ```shell
  # vhost is a subdomain on same server with same IP
  # but single IP can have multiple websites
  # vhosts may or may not have public DNS records, unlike subdomains which have public DNS records

  # here we are fuzzing HTTP headers
  ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:35182/ -H 'Host: FUZZ.academy.htb'
  # this will give incorrect results, so we need to filter by size

  ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:35182/ -H 'Host: FUZZ.academy.htb' -fs 986

  # once we get the result, we can add that page to /etc/hosts file as well
  ```

## Parameter Fuzzing

* GET Request fuzzing:

  ```shell
  # fuzzing for parameters added in URL
  ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:35182/admin/admin.php?FUZZ=key
  # again, filter by correct size to get correct response

  ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:35182/admin/admin.php?FUZZ=key -fs 798
  ```

* POST Request fuzzing:

  ```shell
  # for this, instead of adding to URL
  # we need to fuzz HTTP data

  # in PHP, POST data 'content-type' can only accept "application/x-www-form-urlencoded"

  ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:35182/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded'
  # -X POST as we are sending POST request
  # filter by size

  ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:35182/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs 798

  # to view the response with fuzzing, use curl
  curl http://admin.academy.htb:35182/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'
  ```

* Value fuzzing:

  ```shell
  # create custom wordlist of 1-1000 to fuzz ID value
  for i in $(seq 1 1000); do echo $i >> ids.txt; done

  ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:35182/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded'
  # use filter size

  ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:35182/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 768
  ```
