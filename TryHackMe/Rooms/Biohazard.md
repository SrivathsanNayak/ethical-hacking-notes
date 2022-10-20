# Biohazard - Medium

1. [Introduction](#introduction)
2. [The Mansion](#the-mansion)
3. [The Guard house](#the-guard-house)
4. [The Revisit](#the-revisit)
5. [Underground laboratory](#underground-laboratory)

## Introduction

```shell
rustscan -a 10.10.193.97 --range 0-65535 --ulimit 5000 -- -sV
```

```markdown
Open ports & services:

  * 21 - ftp - vsftpd 3.0.3
  * 22 - ssh - OpenSSH 7.6p1
  * 80 - http - Apache httpd 2.4.29 (Ubuntu)

We can explore the website now; in the background we can enumerate for directories.

The website gives some info about the STARS alpha team; it also contains a link to /mansionmain, which leads us to the Main Hall.
```

```markdown
1. How many open ports? - 3

2. What is the team name in operation? - STARS alpha team
```

## The Mansion

```shell
gobuster dir -u http://10.10.193.97 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak
```

```markdown
The source code of /mansionmain contains a clue about /diningRoom, which leads to the page for the Dining Room.

/diningRoom offers us an emblem.php link, which gives us the emblem flag. After collecting it, we are told to refresh /diningRoom.

On refreshing /diningRoom, we get an input form, where we can enter a flag; for now we can leave it as we do not have any flag

The source code for /diningRoom includes a base64 code, which translates to a hint about the /teaRoom.

/teamRoom includes two things - a note about /artRoom and a lockpick flag.

/artRoom includes a map of the mansion, which contains some more links to be visited.

Directories enumerated so far (manual enumeration, gobuster and the mansion map combined):

  * /index.html - visited
  * /images - visited
  * /css - visited
  * /js - visited
  * /attic - visited
  * /mansionmain - visited
  * /diningRoom - visited
  * /teaRoom - visited
  * /artRoom - visited
  * /barRoom - visited
  * /diningRoom2F
  * /tigerStatusRoom
  * /galleryRoom
  * /studyRoom
  * /armorRoom

Now, we can enumerate all the links one-by-one, so as to explore the mansion completely.

In the /images directory, there are multiple image files; we can download all of them and conduct steganography to check for clues using tools - namely steghide, stegseek, exiftool, binwalk, zsteg, and foremost.

In /attic, we are given a locked door with a shield symbol on it. We have an input form which accepts a flag, we'll revisit this room later.

/barRoom contains a locked door, and it can be opened with a 'lockpick'; so we will try the lockpick flag as the input.

It works and we are led deeper in the bar room; we find two things - an input to 'play the piano', and a note called 'moonlight sonata'.

The note gives us an encoded clue for music sheet; when decoded from base32 it gives us the music sheet flag.

Back to the deeper bar room, we can play the piano using the music sheet flag, and it leads us to 'Secret bar room'.

This room contains the gold emblem flag, and now upon refreshing, we again have an input form here.

Now, going back to the /diningRoom, if we use the gold emblem flag as input, we are given another encoded string; ROT-13 and ROT-47 do not yield anything so we can come back to this later.

Also, if we use the emblem flag in the secret bar room, we get a clue 'rebecca'; maybe the encoded string and this clue have something in common.

If we use Vignere decode on the encoded string with 'rebecca' as key, we get the following string:

    there is a shield key inside the dining room. The html page is called the_great_shield_key

So, we navigate to /diningRoom/the_great_shield_key.html
This gives us the shield flag.

We can use the shield flag as input in /attic to lead to a deeper attic; it offers us a note about crests; we can save it for now and explore the other pages.


```

```markdown
1. What is the emblem flag? - emblem{fec832623ea498e20bf4fe1821d58727}

2. What is the lock pick flag? - lock_pick{037b35e2ff90916a9abf99129c8e1837}

3. What is the music sheet flag? - music_sheet{362d72deaf65f5bdc63daece6a1f676e}

4. What is the gold emblem flag? - gold_emblem{58a8c41a9d08b8a4e38d02a4d7ff4843}

5. What is the shield key flag?

6. What is the blue gem flag?

7. What is the FTP username?

8. What is the FTP password?
```

## The Guard house

```shell
```

```markdown
```

```markdown
1. Where is the hidden directory mentioned by Barry?

2. Password for the encrypted file

3. What is the helmet key flag?
```

## The Revisit

```shell
```

```markdown
```

```markdown
1. What is the SSH login username?

2. What is the SSH login password?

3. Who the STARS bravo team leader?
```

## Underground Laboratory

```shell
```

```markdown
```

```markdown
1. Where you found Chris?

2. Who is the traitor?

3. The login password for the traitor?

4. The name of the ultimate form?

5. The root flag
```
