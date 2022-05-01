# picoGym Challenges

Writeups for practice challenges in picoGym:

  1. [Obedient Cat](#obedient-cat)
  2. [Mod 26](#mod-26)
  3. [Wave a Flag](#wave-a-flag)
  4. [Nice Netcat](#nice-netcat)
  5. [2Warm](#2warm)
  6. [Python Wrangling](#python-wrangling)
  7. [Information](#information)
  8. [Transformation](#transformation)
  9. [GET aHEAD](#get-ahead)
  10. [Static ain't always noise](#static-aint-always-noise)
  11. [Matryoshka doll](#matryoshka-doll)
  12. [Mind your Ps and Qs](#mind-your-ps-and-qs)
  13. [Tab, Tab, Attack](#tab-tab-attack)
  14. [Insp3ct0r](#insp3ct0r)
  15. [The Numbers](#the-numbers)
  16. [Glory of the Garden](#glory-of-the-garden)
  17. [Scavenger Hunt](#scavenger-hunt)
  18. [Who are you?](#who-are-you)
  19. [Cookies](#cookies)
  20. [Magikarp Ground Mission](#magikarp-ground-mission)
  21. [Where are the robots](#where-are-the-robots)
  22. [MacroHard WeakEdge](#macrohard-weakedge)
  23. [Vault Door Training](#vault-door-training)
  24. [Strings It](#strings-it)
  25. [Caesar](#caesar)
  26. [Bases](#bases)
  27. [Codebook](#codebook)
  28. [convertme.py](#convertme.py)
  29. [HashingJobApp](#hashingjobapp)
  30. [fixme1.py](#fixme1.py)
  31. [fixme2.py](#fixme2.py)
  32. [Glitch Cat](#glitch-cat)
  33. [PW Crack 1](#pw-crack-1)
  34. [PW Crack 2](#pw-crack-2)
  35. [PW Crack 3](#pw-crack-3)
  36. [PW Crack 4](#pw-crack-4)
  37. [PW Crack 5](#pw-crack-5)
  38. [Serpentine](#serpentine)
  39. [Based](#based)
  40. [Plumbing](#plumbing)
  41. [flag_shop](#flagshop)
  42. [mus1c](#mus1c)
  43. [So Meta](#so-meta)
  44. [extensions](#extensions)
  45. [What Lies Within](#what-lies-within)

For all questions, the flag is in the format of picoCTF{}

---

## Obedient Cat

* We are given a file in the question.

* As it is given that the answer is in the clear, all we have to do is use ```cat flag``` to get the flag.

## Mod 26

* We have a string given in the question.

* The question mentions ROT13, so applying ROT13 with the help of [CyberChef](https://gchq.github.io/CyberChef/), we get the flag.

## Wave a Flag

* The question presents us with a binary. We have to invoke help flags.

* To solve this, we have to first use ```chmod +x filename``` so that we can execute the program. Then, we can run the program using ```./filename```.

* To add a help flag, we use ```./filename -h```, which gives us the flag in response.

* Alternatively, using ```strings``` will also help us in finding the flag.

## Nice Netcat

* The question gives us a command ```nc mercury.picoctf.net 21135```

* On executing that command, we get a list of numbers.

* When we convert these numbers from decimal to ASCII, we get the flag.

## Warmed Up

* The question asks us 0x3D (base 16) in decimal (base 10).

* This can be found out by multiplying the digits (in hexadecimal representation) by 16 raised to the position of the digit, and then adding those up.

* So this would be (3*16^1)+(13*16^0) = 61

## 2Warm

* We need to convert 42 (base 10) to binary (base 2).

* This can be done by simply expressing 42 as sum of powers of 2, so 42 = 32+8+2.

* Then, we have to find the power (raised to), and place 1 in that digit position, and 0 for the rest of them.

* So, here we have 42 = 2^5 + 2^3 + 2^1, therefore binary representation would be 101010, since we need to start from index 0.

## Python Wrangling

* The question gives us a Python script, a password, and an encrypted flag.

* We have to run the script with the password to decrypt the flag.

* Firstly, we have to note the password using ```cat pw.txt```.

* Then running the Python script without any parameters ```python3 ende.py``` shows us the usage of the script.

* So, we use ```python3 ende.py -d flag.txt.en``` to decrypt the encrypted flag, and we get a prompt to enter the password, and if entered correctly, we get the flag.

## Information

* The question gives us an image, which contains the flag.

* We can use tools such as ```exiftool``` and ```steghide``` to check for the flag.

* Using ```exiftool cat.jpg``` gives us some info, but it does not seem to be that useful.

* However, the metadata contains a string under License which looks like it is base64-encoded.

* Upon decoding that string from base64 to text, we get the flag.

## Transformation

* The question presents us with a code segment and a file containing random Chinese characters.

* Using ```file enc```, we get to know that those are UTF-8 Unicode characters.

* With the help of the given code segment, we have to reverse engineer our way to the string, so that we can get the flag by decoding the encoded string.

* [This writeup](https://vishnuram1999.github.io/transformation_pico_ctf_2021.html) has explained the process clearly.

## GET aHEAD

* The question is about web exploitation, so it presents us with a link. We need to find the flag there.

* The title itself is suggesting us a clue; we have to get header of the webpage.

* We can use ```curl -I websitelink.com``` to get the header, which contains the flag.

## Static ain't always noise

* We are given a binary and a bash script. We have to analyze it and find the flag.

* On simply using ```strings staticbinary```, we get the flag.

## Matryoshka doll

* We are given an image, and we have to apply forensics to find the secret.

* On executing ```file dolls.jpg```, we get to know that it is a PNG image.

* Using ```binwalk -e dolls.jpg```, we get more info about the image.

* As the title suggests, it consists of multiple layers of different files.

* As an alternative, we can also use ```hexdump -C 2_c.jpg | grep "PK"``` to see if the image file is actually a zip file.

* We keep repeating the process, as the files are hidden inside more files, until we get ```flag.txt``` inside the third layer.

## Mind your Ps and Qs

* The question gives us a file for RSA values.

* It contains the values for ```c```, ```n```, and ```e```.

* We can use an online tool to crack this. For example, [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool).

* With the help of RsaCtfTool, we can crack the algorithm using the following command ```python3 RsaCtfTool.py -n {valueOfn} -e {valueOfe} --uncipher {valueOfc}```

* This will give us the flag as plaintext.

## Tab, Tab, Attack

* The question presents us with a zip file with a really long name.

* Using ```unzip```, we unzip the file, giving way to more folders with long, gibberish names. We have to find our flag in one of these files.

* The final directory contains an executable, we can simply use ```strings``` to get the required flag.

## Insp3ct0r

* Given, a link that leads to a webpage requiring inspection.

* Using developer tools, we can view the first part of the flag in the HTML code, in one of the comments.

* The second part of the flag is found in one of the CSS comments.

* The third and final part of the flag is found in the JS code.

## The Numbers

* We are given an image and we have to find the flag.

* Using ```exiftool``` and ```hexdump``` does not give any useful output.

* However, executing ```hexdump -C the_numbers.png | grep "PK"``` gives us a positive output, so this might contain a zip file inside.

* We can confirm our assumption by using ```binwalk -e the_numbers.png```, which gives us a file.

* The file, however, does not contain anything significant.

* On a second glance, the numbers in the image include curly braces, that is, this could be the flag itself.

* So, decoding the numbers using A1Z26 cipher, we get the flag.

## Glory of the Garden

* We are given an image file of a garden; using forensics we have to find the flag.

* Using ```exiftool```, we get some details with regards to the image.

* We do not get anything using ```binwalk``` or ```steghide``` as well.

* However, using ```strings``` gives us the flag.

## Scavenger Hunt

* We are given a website link, we have to find the flag using that.

* The first part of the flag is in the HTML code, can be viewed using Developer tools.

* The second part is included in the CSS code.

* The third part is found in the /robots.txt file, as the clue is given in JS code about Google indexing its webpage.

* The fourth part is found out from the Apache server clue given in the /robots.txt file; that is, /.htaccess.

* The fifth part is derived from the fact that the webpage has been created on a Mac computer, so we have to go to /.DS_Store to get the final part of the flag.

## Who are you?

* We are given a website which requires us to use a PicoBrowser in order to login.

* The source code contains a particular code segment which looks out of place; we can try to edit it with the help of tools such as ```Burp Suite``` and ```curl```.

* We also attempted to scan the website directories using ```ffuf``` but to no avail.

* Getting back to ```Burp Suite```, we modified the User-Agent header's value to 'PicoBrowser', as the message on the browser said "Only people who use the official PicoBrowser are allowed on this site!".

* This gives us a different error message "I don't trust users visiting from another site". This signals us towards adding the Referer header, with value of current website "mercury.picoctf.net:46199"

* This gives us an error message saying "Sorry, this site only worked in 2018". So, we will add a Date header with any date in 2018, with value being "Wed, 21 Oct 2018 07:28:00 GMT".

* This gives us an error message saying "I don't trust users who can be tracked". This can be resolved by adding a DNT header with the value 1, denoting that the user can't be tracked.

* This gives us one more message "This website is only for people from Sweden", so we add a header for X-Forwarded-For, which shows the originating IP address. We will have to add an IP address from Sweden as the value, and it could be found on the web.

* The error message this time is "You're in Sweden but you don't speak Swedish?", indicating that we will have to edit the header for language, that is, the Accept-Language header should be used with the value "sv-SE". This gives us the flag.

## Cookies

* We are given the link to a website and told to figure out the best cookie.

* The website contains a form where we can submit cookie names.

* As this does not give us much idea about it, we can use ```curl``` to get some clues.

* Running the command ```curl -c - mercury.picoctf.net:29649``` gives us the cookies of the website, it does not contain anything however.

* Back in the website, we have 'snickerdoodle' written in the entry field, so we enter that and submit.

* On submitting, the cookies value in the Inspect tab turns from -1 to 0.

* We can fiddle with the value by incrementing it by 1.

* Finally, when the cookie value is 18, you will get the flag.

## Magikarp Ground Mission

* Given, an instance for which we have to login using SSH.

* Once we log into it using given creds, we have to do ```ls```.

* The three parts of the flags are in the file system only, we just have to follow along the clues with the help of commands such as ```cd``` to move through directories and ```cat``` to print the files.

## Where are the robots

* We have been given the link and told to find the robots.

* By instinct, we will go to /robots.txt.

* It contains a disallow rule for a particular link.

* When we visit that link, we get the flag.

## MacroHard WeakEdge

* We have been given a .pptm file, which is related to PPTs.

* Trying basic forensics tools like ```strings``` and ```file``` does not give anything useful.

* However, using ```binwalk -e``` to extract the file contents gives us a zip file.

* The zip file contains a lot of folders and files, however, one particular file called 'hidden' contains some characters.

* After removing whitespace characters and converting it to base64, we get the flag.

## Vault Door Training

* We are given a .java file, and we have to reverse-engineer it using the source code to get the flag.

* The source code contains checks for passwords, and the substring used is given below.

* We just have to prepend the picoCTF{} part to the flag value given below, and that would give us the flag required.

## Strings It

* We are given an executable, we have to find the flag without running the file.

* As suggested in the filename and name of the challenge, we have to use ```strings filename```.

* We have to include ```grep``` as well, so that we can find the flag easily.

* So, our command should be ```strings filename | grep "pico"```, and this will give us the flag.

## Caesar

* We are given a file containing ciphertext.

* It contains jumbled characters as the flag.

* Assuming from the name, this could be related to the Caesar cipher.

* As the characters are shifted by a certain number of characters, we can use online tools to decode this.

* Shifting by 1, we get the string required for the flag.

## Bases

* We are given a random looking string.

* While it seems random, due to the inclusion of numbers and characters, and the hint being related to bases, we can converted it to different base systems.

* On converting the given string from base64 to ascii, we get the flag text.

## Codebook

* We are given two files, code.py and codebook.txt

* We have to run code.py in the same directory as codebook.txt

* After downloading the files, we simply have to run ```python3 code.py```, this prints the flag.

## convertme.py

* We are given a Python script, and we have to convert the given number from decimal to binary to get the flag.

* On running the script using ```python3 convertme.py```, we are prompted to enter the binary equivalent of a number.

* Once we enter the binary, we get the flag.

## HashingJobApp

* We are given a command ```nc saturn.picoctf.net 63116```.

* This gives us a prompt to enter MD5 hash for a given phrase.

* We can do so using online tools such as [CyberChef](https://gchq.github.io/CyberChef/), it has an option to calculate the MD5 hash of text.

* After three rounds of calculating MD5 hashes for random phrases, we get the flag required.

## fixme1.py

* We are given a Python script, we have to fix the syntax error to print the flag.

* We first need to run the script using ```python3 fixme1.py```.

* This gives us an error about the intendation.

* Once fixed (by removing the unnecessary intendation), we can run it again; this gives us the flag.

## fixme2.py

* Similar to the previous challenge, we are given a Python script with a syntax error.

* On running the script by ```python3 fixme2.py```, we get an error in the ```if``` statement.

* We can fix the error by adding one more equal sign, to make it ```flag == ""```

* Now, on running the program, we get the flag.

## Glitch Cat

* We are given a command ```nc saturn.picoctf.net 53933```.

* This prints a partial flag ```picoCTF{gl17ch_m3_n07_```, followed by other characters.

* It includes the ```chr()``` function, which is used to get character from Unicode code integer.

* So, we can manually convert the Unicode integers to their equivalent string representations.

* As the characters are given in ```0x``` format, we know that those have to be converted from hex to ascii.

* Converting those characters, we get the string ```a4392d2e```.

* Appending this to our partial flag, and completing it with a closing bracket, we get our flag.

## PW Crack 1

* Given, we have a password checker file and an encrypted flag.

* At first, the encrypted flag seems to contain gibberish text.

* On running the password checker using ```python3 level1.py```, we are prompted to enter a password.

* As we do not know the password yet, we view the program using ```vim python3```, which shows us the code.

* We can observe that the program checks if entered password is equal to '691d' or not, and then prints flag.

* So, we run the program again, and enter '691d' this time, and we get the flag.

## PW Crack 2

* Similar to previous challenge, we have two files - password checker and encrypted password.

* Here, we can start by viewing the code using ```vim level2.py```.

* It shows that the program checks if password is equal to ```chr()``` conversions of some strings in hex.

* When we convert the strings from hex to ascii and remove whitespace, we get '4ec9'.

* Now, we can run the program using ```python3 level2.py``` and when prompted enter '4ec9' to get the flag.

## PW Crack 3

* We are given three files - password checker, encrypted flag and hash.

* It is given that there are 7 potential passwords, out of which only 1 is correct.

* We can view the hash file using ```bvi level3.hash.bin```; ```bvi``` is vi for binary.

* We can view the Python script using ```vim level3.py```.

* We can see the 7 candidate passwords given.

* The password that we enter is passed onto a function, converted to bytes, encoded using md5 and then converted to byte-equivalent form.

* As we have only 7 candidates here, we can try them one-by-one.

* Upon trying 'dba8', we get the flag.

## PW Crack 4

* Similar to previous challenge, we are given three files - password checker, encrypted flag and the hash file.

* However, this time we have 100 potential passwords, so trial-and-error cannot be an option.

* Use ```bvi level4.hash.bin``` to view the hash file.

* For the script, we can edit it and add a for-loop so that it tries all the passwords, as the automation will take less time.

* Modified code segment:

```python
def level_4_pw_check(pos_pw):
    #user_pw = input("Please enter correct password for flag: ")
    user_pw_hash = hash_pw(pos_pw)
    
    if( user_pw_hash == correct_pw_hash ):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), pos_pw)
        print(decryption)
        return
    print("That password is incorrect")

#pos_pw_list - 100 potential passwords here

for pos_pw in pos_pw_list:
    level_4_pw_check(pos_pw)
```

* If we run this program using ```python3 level4.py | grep "flag" -C 1```, which runs our script and greps one line above and below the line where 'flag' is found, we get our flag required.

## PW Crack 5

* Similar to previous challenge, we are given three files - password checker, encrypted flag and hash.

* This time, instead of being given the list of potential passwords, we are given a huge dictionary of passwords.

* The python script is similar to previous two problems.

* We have to modify the program such that the dictionary values are tried for the user password.

* Modified code segment:

```python
def level_5_pw_check(user_pw):
    #user_pw = input("Please enter correct password for flag: ")
    user_pw_hash = hash_pw(user_pw)
    
    if( user_pw_hash != correct_pw_hash ):
        return
    
    else:
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return


dictfile = open('dictionary.txt', 'r')
lines = dictfile.readlines()

for line in lines:
    level_5_pw_check(line.strip())
```

* Running this program using ```python3 level5.py``` gives us the flag.

## Serpentine

* We are given a Python script, we have to find the flag inside it.

* ```python3 serpentine.py``` runs the script, but it tells us that flag can be found in source code.

* Using ```vim serpentine.py```, we can view the script; it shows us the function print_flag(), which prints the flag.

* However, the function is not called in the first place. So we edit the script and add a line so that the function is called this time.

* Now, on running the program again, we get the flag.

## Based

* We are given a command ```nc jupiter.challenges.picoctf.org 29221```.

* On running that, we are prompted to decode numbers of different bases to words.

* We can do that using CyberChef tool.

* After decoding three different terms to ascii, we get the flag.

## Plumbing

* We are told to connect to ```jupiter.challenges.picoctf.org 7480```, we can do so using ```nc```.

* When we run ```nc jupiter.challenges.picoctf.org 7480```, we get a lot of output, and there is no time to read through it.

* So, we can redirect the output to a text file, and then search the file for the flag value.

* We can do this using ```nc jupiter.challenges.picoctf.org 7480 > plumbing.txt```.

* We can stop the ```nc``` connection after a while using ```Ctrl+C``` or ```Ctrl+\```.

* Now, we need to search for the flag inside file.

* ```cat plumbing.txt | grep "pico"``` does it for us, and gives us the flag.

## flag_shop

* We are given a command ```nc jupiter.challenges.picoctf.org 4906``` and a C program.

* The C program is the code for the ```nc``` connection program.

* Now, looking at the hint, it mentions 2's complement.

* So, we can use the concept of integer overflow, and add a really big number which is larger than signed and unsigned numbers.

* For example, here, when we press '2' in the program, we are directed to choose flags.

* Choose the 1st option, and on being prompted, enter a really large number; this will increase our balance due to overflow.

* After this, we can buy the 1337 flag.

* Reference - <https://d3vnull.com/integer-overflow/>

## mus1c

* We are given a lyrics.txt file, we have to put it in the flag format.

* We can view it using ```gedit lyrics.txt&```, so that it opens as a background process.

* The hint uses the term 'rockstar', and the lyrics uses the terms ```shout```, ```put```, and ```build``` a lot.

* Googling these terms together gives us info about Rockstar language, a programming language.

* After searching for an online Rockstar language compiler, we can copy-paste the lyrics there.

* The output is a bunch of numbers, which, when converted to ascii, give us the flag.

## So Meta

* We are given a picture, we have to find the flag.

* Using ```exiftool```, we get the flag.

## extensions

* We are given a flag.txt file, we have to find the flag.

* ```cat flag.txt``` shows gibberish output.

* ```file flag.txt``` shows that this is a PNG file.

* We use ```mv flag.txt flag.png``` to edit the file extension.

* ```display flag.png``` gives us the flag.

## What Lies Within

* We are given a buildings.png file.

* The image does not have anything in particular, but ```exiftool``` shows that it can be a zip file.

* ```binwalk -e``` extracts the files from the image for us.
