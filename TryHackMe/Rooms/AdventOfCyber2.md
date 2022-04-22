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

```shell
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

```shell
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
