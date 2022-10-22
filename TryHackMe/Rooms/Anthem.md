# Anthem - Easy

1. [Website Analysis](#website-analysis)
2. [Spot the flags](#spot-the-flags)
3. [Final stage](#final-stage)

## Website Analysis

```shell
rustscan -a 10.10.35.181 --range 0-65535 --ulimit 5000 -- -sV -A

gobuster dir -u http://10.10.35.181 -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,bak -t 16

cmseek
#used to detect cms
```

* Open ports & services:

  * 80 - http
  * 3389 - ms-wbt-server

* We can check the website on port 80 and look for clues; it is a blogpage website for Anthem.com

* Gobuster enumerated directories:

  * /archive
  * /authors
  * /blog
  * /categories
  * /install
  * /rss
  * /search
  * /sitemap
  * /tags
  * /umbraco

* We can check which CMS is being used by the website using the cmseek tool; it shows the CMS is umbraco

* Checking /robots.txt, we get a string "UmbracoIsTheBest!", which could be a possible password; it also includes four disallowed directories, we can check them.

* /umbraco leads to a login page; we need email and password of the administrator user.

* Going through the blogs, we get a poem; upon searching the poem on Google, we get the author as Solomon Grundy, who also happens to be the administrator of the website.

* For the email, we can see that in the other blog, Jane Doe's email is JD@anthem.com

* So, for Solomon Grundy (admin), the email should be SG@anthem.com

* We can attempt to log into /umbraco with the credentials SG@anthem.com:UmbracoIsTheBest!; and we succeed.

```markdown
1. What port is for the web server? - 80

2. What port is for remote desktop service? - 3389

3. What is a possible password in one of the pages web crawlers check for? - UmbracoIsTheBest!

4. What CMS is the website using? - umbraco

5. What is the domain of the website? - Anthem.com

6. What's the name of the Administrator? - Solomon Grundy

7. Can we find the email address of the administrator? - SG@anthem.com
```

## Spot the flags

* For getting the flags, we need to inspect all the pages.

* Flag 1 can be found in the meta description of the webpage.

* Flag 2 can be found in the comments of the source code of the main webpage.

* Flag 3 can be found upon navigating to the /authors directory.

* Flag 4 can be found in the 2nd blog's meta description.

```markdown
1. What is flag 1? - THM{L0L_WH0_US3S_M3T4}

2. What is flag 2? - THM{G!T_G00D}

3. What is flag 3? - THM{L0L_WH0_D15}

4. What is flag 4? - THM{AN0TH3R_M3TA}
```

## Final stage

```shell
xfreerdp /u:SG /p:"UmbracoIsTheBest\!" /v:10.10.35.181 /port:3389
#this works
```

* On clicking the 'Help' section in /umbraco, we can see that it is Version 7.15.4; we can search for an exploit.

* We did not get any particular exploit, so we can try connecting over RDP on port 3389, using SG as username and the password as /umbraco password.

* This works and we can connect via RDP; user flag can be found in desktop.

* Now, for admin password, it is given that it is hidden; so we can enable 'hidden items' and search for the password.

* There is a hidden file in C:\backup, by the name of restore.txt; we cannot open the file at first.

* Checking the properties of this file shows that this file is owned by nobody; so we can manually set permissions in the Security tab for our user SG.

* Once we do that, we can read the file and get admin password.

* We can login as Administrator now; the root flag can be found in Admin's desktop.

```markdown
1. user.txt - THM{N00T_NO0T}

2. Can we spot the admin password? - ChangeMeBaby1MoreTime

3. root.txt - THM{Y0U_4R3_1337}
```
