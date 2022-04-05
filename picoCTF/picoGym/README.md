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
