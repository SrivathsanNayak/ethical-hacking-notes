# Advent Of Cyber 2 - Easy

1. [A Christmas Crisis](#a-christmas-crisis)
2. [The Elf Strikes Back](#the-elf-strikes-back)
3. [Christmas Chaos](#christmas-chaos)
4. [Santa's Watching](#santas-watching)
5. [Someone stole Santa's gift list](#someone-stole-santas-gift-list)
6. [Be careful with what you wish on a Christmas night](#be-careful-with-what-you-wish-on-a-christmas-night)
7. [The Grinch Really Did Steal Christmas](#the-grinch-really-did-steal-christmas)
8. [What's Under the Christmas Tree](#whats-under-the-christmas-tree)
9. [Anyone can be Santa](#anyone-can-be-santa)
10. [Don't be sElfish](#dont-be-selfish)
11. [The Rogue Gnome](#the-rogue-gnome)
12. [Ready, set, elf](#ready-set-elf)
13. [Coal for Christmas](#coal-for-christmas)
14. [Where's Rudolph](#wheres-rudolph)
15. [There's a Python in my stocking](#theres-a-python-in-my-stocking)
16. [Help! Where is Santa](#help-where-is-santa)
17. [ReverseELFneering](#reverseelfneering)
18. [The Bits of Christmas](#the-bits-of-christmas)
19. [The Naughty or Nice List](#the-naughty-or-nice-list)
20. [PowershELlf to the rescue](#powershellf-to-the-rescue)
21. [Time for some ELForensics](#time-for-some-elforensics)
22. [Elf McEager becomes CyberElf](#elf-mceager-becomes-cyberelf)
23. [The Grinch strikes again](#the-grinch-strikes-again)
24. [The Trial Before Christmas](#the-trial-before-christmas)

## A Christmas Crisis

```markdown
According to the instructions, we register by creating an account on the IP address.

Using those credentials, we log into our account.

In Developer tools, we can view more info about cookies.

Name of cookie used for authentication - auth.

Clearly, the value of this cookie is encoded in hexadecimal.

Now, after decoding the value of cookie, we get a JSON string.

Here, the string is quite predictable as all we have to do is replace the username part, and convert the JSON string to hex.

For Santa's cookie, we just need to replace the username part to 'santa' and convert to hex and remove whitespace.

Once we paste Santa's cookie value in the Developer Tools section and refresh the website, we get admin controls.

On turning everything back to normal, we get the flag required.
```

## The Elf Strikes Back

```markdown
The reference material highlights that with POST requests the data being sent is included in the "body" of the request, while with GET requests, the data is included in the URL as a "parameter".

We are also given an ID number - ODIzODI5MTNiYmYw - to gain access to upload section of site.

Once we go to the website, we are told to enter our ID as a GET parameter.

So we need to append '?id=ODIzODI5MTNiYmYw' to the URL.

This leads to the upload page. We get to know that image files are accepted by the site.

Now, on checking the page source code, we get to know that the accepted file extensions include .jpg, .jpeg and .png

So we can use a PHP reverse shell file, but rename it with the extension .jpg.php, to bypass the filter.

This file gets uploaded, and we can check the uploads in /uploads/ directory.

Set up a listener using 'nc -nvlp 1234'

Once we go to the /uploads/ directory and select the reverse shell file (with the .jpg.php extension), the page indefinitely loads.

At our netcat listener, we have received the reverse shell, and now we can view the flag at /var/www/flag.txt

Flag - THM{MGU3Y2UyMGUwNjExYTY4NTAxOWJhMzhh}
```

## Christmas Chaos

```markdown
For this room, we have to use Burp Suite to brute-force and do a dictionary attack on the login form.

We have to start Burp to intercept the traffic, proxy should be turned on.

Once we are on the login form, we have to enter random credentials and submit details into the form.

The request would be captured by Proxy in Burp, and we have to forward it to Intruder, where we can do the Cluster Bomb attack as given in the reference.

Once the attack is done, we get the credentials admin:12345

Using credentials to login, we get the flag.
```

## Santa's Watching

```markdown
The reference material has given commands for tools such as gobuster and wfuzz

wfuzz command required for given URL question - wfuzz -c -z file,big.txt http://shibes.xyz/api.php?breed=FUZZ

Now, we need to use gobuster to find the API directory (for the given IP)
Command - gobuster dir -u http://10.10.187.195 -w /usr/share/seclists/Discovery/Web-Content/big.txt -x php

This gives us the directory /api, where we find the file site-log.php

Now, we need to fuzz the date parameter on /site-log.php, so the URL should look like /site-log.php?date=DATE

The date parameter required for fuzzing are given to us in a wordlist file.

We can use wfuzz.

Command - wfuzz -z file,wordlist --hh 0 http://10.10.187.195/api/site-log.php?date=FUZZ
Here, '--h 0' is used to hide responses with 0 characters.

As a result, we get the payload on date=20201125.

Flag - THM{D4t3_AP1}
```

## Someone stole Santa's gift list

```shell
```

## Be careful with what you wish on a Christmas night

```shell
```

## The Grinch Really Did Steal Christmas

```shell
```

## What's Under the Christmas Tree

```shell
```

## Anyone can be Santa

```shell
```

## Don't be sElfish

```shell
```

## The Rogue Gnome

```shell
```

## Ready, set, elf

```shell
```

## Coal for Christmas

```shell
```

## Where's Rudolph

```markdown
The reference material gives us a list of resources which can be used for OSINT in this case:

<https://namechk.com/>
<https://whatsmyname.app/>
<https://namecheckup.com/>
<https://github.com/WebBreacher/WhatsMyName>
<https://github.com/sherlock-project/sherlock>

Now, it's given that the Reddit username of Rudolph is 'IGuidetheClaus2020'.

On Googling the username, we can view the Reddit and Twitter profile.
```

```markdown
1. What URL will take me directly to Rudolph's Reddit comment history? - https://www.reddit.com/user/IGuidetheClaus2020/comments/

2. According to Rudolph, where was he born? - Chicago

3. Rudolph mentions Robert.  Can you use Google to tell me Robert's last name? - May

4. On what other social media platform might Rudolph have an account? - Twitter

5. What is Rudolph's username on that platform? - IGuideClaus2020
```

```markdown
Now that we have found both profiles of Rudolph, we have to use reverse image searching to find details about the photo, such as location, and other metadata.

exiftool is a great tool for getting metadata from images.

We can also use discovered emails and usernames to search through breached data to identify possible passwords, names, and other data.
```

```markdown
6. What appears to be Rudolph's favorite TV show right now? - Bachelorette

7. Based on Rudolph's post history, he took part in a parade.  Where did the parade take place? - Chicago

8. Okay, you found the city, but where specifically was one of the photos taken? - 41.891815, 87.624277

9. Did you find a flag too? - {FLAG}ALWAYSCHECKTHEEXIFD4T4

10. Has Rudolph been pwned? What password of his appeared in a breach? - spygame

11. Based on all the information gathered.  It's likely that Rudolph is in the Windy City and is staying in a hotel on Magnificent Mile.  What are the street numbers of the hotel address? - 540
```

## There's a Python in my stocking

```shell
```

## Help! Where is Santa

```shell
```

## ReverseELFneering

```shell
```

## The Bits of Christmas

```shell
```

## The Naughty or Nice List

```shell
```

## PowershELlf to the rescue

```shell
```

## Time for some ELForensics

```shell
```

## Elf McEager becomes CyberElf

```shell
```

## The Grinch strikes again

```shell
```

## The Trial Before Christmas

```shell
```
