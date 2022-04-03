# picoGym Challenges

Writeups for practice challenges in picoGym:

  1. [Obedient Cat](#obedient-cat)
  2. [Mod 26](#mod-26)
  3. [Wave a Flag](#wave-a-flag)
  4. [Nice Netcat](#nice-netcat)
  5. [2Warm](#2warm)

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
