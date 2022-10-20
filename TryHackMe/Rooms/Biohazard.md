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

  * /index.html
  * /images
  * /css
  * /js
  * /attic
  * /mansionmain
  * /diningRoom
  * /teaRoom
  * /artRoom
  * /barRoom
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

We can use the shield flag as input in /attic to lead to a deeper attic; it offers us a note about crest-4; we can save it for now and explore the other pages.

/diningRoom2F page mentions the blue gem; however, its source code includes another cryptic string, which can be cracked using ROT-13.

This gives us a hint about the blue gem; we can find it now in /diningRoom/sapphire.html; this gives us the blue jewel flag.

Moving to the /tigerStatusRoom, we have the option to place a gem on the tiger's eye, that is, use the blue gem flag as input. Upon doing so, we receive another note regarding the crests; this one is about crest-1.

Now, /galleryRoom offers a note about crest-2, we save it for later.

/studyRoom has a locked door, we can input a helmet flag here, but we do not have it yet, so we will save this page for later.

/armorRoom includes an input accepting a shield symbol; when we enter the shield flag here, it leads us to a deeper armor room, which offers us another note.

Now, we have four notes for us, all of them contain clues about a crest; we can use CyberChef for the decoding process.

For each crest, there are two types of hints - number of times it has been encoded, and the number of characters in the crest; we can use this to our advantage.

Crest-1 can be decoded from base64, then decoded from base32, to give the 14-character string "RlRQIHVzZXI6IG".

Crest-2 can be decoded from base32, then decoded from base58 to give the 18-char string "h1bnRlciwgRlRQIHBh".

Crest-3 can be decoded first from base64, then from binary, and finally decoded from hex - to give us a 19-char string "c3M6IHlvdV9jYW50X2h".

Finally, crest-4 can be decoded first from base58, followed by decode from hex, to give us 17-char string "pZGVfZm9yZXZlcg==".

Now, according to the notes, we need to concatenate all 4 crests in order to produce a final encoded clue.

When combined, the four crests give us a base64-encoded string; when decoded it gives us the FTP credentials, hunter:you_cant_hide_forever
```

```markdown
1. What is the emblem flag? - emblem{fec832623ea498e20bf4fe1821d58727}

2. What is the lock pick flag? - lock_pick{037b35e2ff90916a9abf99129c8e1837}

3. What is the music sheet flag? - music_sheet{362d72deaf65f5bdc63daece6a1f676e}

4. What is the gold emblem flag? - gold_emblem{58a8c41a9d08b8a4e38d02a4d7ff4843}

5. What is the shield key flag? - shield_key{48a7a9227cd7eb89f0a062590798cbac}

6. What is the blue gem flag? - blue_jewel{e1d457e96cac640f863ec7bc475d48aa} 

7. What is the FTP username? - hunter

8. What is the FTP password? - you_cant_hide_forever
```

## The Guard house

```shell
ftp 10.10.193.97
#use the creds found earlier

ls -la
#use get command to transfer all files from ftp to our machine

steghide info 001-key.jpg
#shows an embedded txt file

steghide extract -sf 001-key.jpg
#extracts data

cat key-001.txt
#first clue

exiftool 002-key.jpg
#comment gives encoded text, second clue

binwalk -e 003-key.jpg
#extracts zip file

gpg --decrypt helmet_key.txt.gpg
#use password and get helmet flag
```

```markdown
Now we can log into FTP using the creds we found in the previous task.

We have five files in the FTP directory, we can transfer them to our machine and inspect for clues.

The .txt file gives us a clue about a directory /hidden_closet, which requires the helmet flag for input - now we have two rooms, /studyRoom and /hidden_closet, which require the helmet flag.

Carrying on with the inspection, we have three image files and a .gpg file, which is supposed to be the encrypted helmet flag.

We can use stego techniques to get clues from the image files.

Using steghide, we extract our 1st clue "cGxhbnQ0Ml9jYW" from 1st key image.

Using exiftool on the 2nd key image gives us a comment "5fYmVfZGVzdHJveV9", which is our 2nd clue.

Using binwalk on 3rd key image, we get a zip file, which contains a txt file with the 3rd clue "3aXRoX3Zqb2x0"

Combining all 3 clues gives us a base64 encoded string, which when decoded gives us the following string:

    plant42_can_be_destroy_with_vjolt

This can be used as password for the encrypted gpg file, which gives us the helmet flag.
```

```markdown
1. Where is the hidden directory mentioned by Barry? - /hidden_closet/

2. Password for the encrypted file - plant42_can_be_destroy_with_vjolt

3. What is the helmet key flag? - helmet_key{458493193501d2b94bbab2e727f8db4b}
```

## The Revisit

```markdown
Now that we have the helmet flag, we can revisit the two rooms, study room and closet room.

/studyRoom accepts the helmet flag and leads us to book, which gives us a .tar.gz file; this file contains a txt file with the SSH user 'umbrella_guest'

Similarly, /hidden_closet accepts helmet flag too and it leads us to an underground cave. We are introduced to Enrico, leader of STARS bravo team.

In this page, we are given two items - MO disk 1 and a wolf medal.

MO disk 1 contains encoded text and the wolf medal gives us the SSH password "T_virus_rules".

We can use the SSH creds to log into SSH now; we will look into the encoded text later.
```

```markdown
1. What is the SSH login username? - umbrella_guest

2. What is the SSH login password? - T_virus_rules

3. Who the STARS bravo team leader? - Enrico
```

## Underground Laboratory

```shell
ssh umbrella_guest@10.10.193.97

ls -la

cd .jailcell

ls -la

cat chris.txt
#contains more clues

su weasker

cd ../weasker

ls -la

cat weasker_note.txt

#checking privesc
cat /etc/crontab

sudo -l
#we can run all commands as sudo

sudo su
#switch to root

cat /root/root.txt
```

```markdown
After SSHing, we can see that there is a directory .jailcell

Inside it there is a file named chris.txt; this contains the following clues:

  * Weasker is the traitor
  * MO disk 2 - albert

Now, we can use the clue 'albert' to decode the encoded text we found earlier using Vigenere Decode. This gives us the login password for weasker.

We can switch to user 'weasker' now and check the directory for clues.

weasker's home directory has a note in it, which contains more clues to the story.

Now, we need to find the root flag; we can check for privesc.

Using 'sudo -l' we can check which commands we can run as sudo; turns out we can run all commands as sudo.

Therefore, we can switch to root user and get the root flag at /root/root.txt
```

```markdown
1. Where you found Chris? - jailcell

2. Who is the traitor? - Weasker

3. The login password for the traitor? - stars_members_are_my_guinea_pig

4. The name of the ultimate form? - Tyrant

5. The root flag - 3c5794a00dc56c35f2bf096571edf3bf
```
