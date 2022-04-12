# Crack The Hash Level 2 - Medium

* ```Haiti``` can be used to identify the hash type:

```shell
haiti -h #shows help commands

haiti 741ebf5166b9ece4cca88a3868c44871e8370707cf19af3ceaa4a6fba006f224ae03f39153492853
#shows that it is a ripemd-320 hash
#along with john the ripper and hashcat specifics
```

* ```wordlistctl``` is a script, used to install, update and search wordlists:

```shell
python3 wordlistctl.py #run wordlistctl
#by default in /usr/share/wordlists

python3 wordlistctl.py search rockyou
#searches and fetches all instances of rockyou list

python3 wordlistctl.py fetch -l rockyou
#installs rockyou

python3 wordlistctl.py search -l rockyou
#searches rockyou locally

python3 wordlistctl.py fetch -l rockyou -d
#decompresses wordlist

python3 wordlistctl.py search facebook
#search for wordlist about particular subject

python3 wordlistctl.py list -g fuzzing
#list all wordlists from a category
```

* Rules can be added in ```JtR``` by editing the .conf files:

```shell
locate john.conf
#in ~/src/john/run

#rule for border mutation, appending all 2 digits combinations at end of each password
#add in john-local.conf
[List.Rules:THM01]
$[0-9]$[0-9]

#while using JtR with the rule we just created
cd ~/src/john/run

./john ~/hash.txt --format=raw-sha1 --wordlist=/usr/share/SecLists/Passwords/Common-Credentials/10k-most-common.txt --rules=THM01
#moonligh56
```

* [Mentalist](https://github.com/sc0tfree/mentalist) can be used for graphical custom wordlist generation:

```shell
#after creating the custom list, it can be used normally
~/src/john/run/john hash2.txt --format=raw-md5 --wordlist=/usr/share/wordlists/misc/dogs_custom.txt
#mOlo$$u$
```

* [CeWL](https://github.com/digininja/CeWL) can be used to generate wordlist from a website:

```shell
./cewl.rb -d 2 -w $(pwd)/example.txt https://example.org
#to download all words from example.org with a depth of 2
```

* [TTPassGen](https://github.com/tp7309/TTPassGen) can be used to craft wordlists from scratch:

```shell
ttpassgen --rule '[?d]{4:4:*}' pin.txt
#wordlist containing all 4 digits PIN code

ttpassgen --rule '[?l]{1:3:*}' abc.txt
#wordlist of all lowercase chars combo of length 1 to 3

ttpassgen --dictlist 'pin.txt,abc.txt' --rule '$0[-]{1}$1' combination.txt
#combine multiple wordlists

~/src/john/run/john hash3.txt --format=raw-md5 --wordlist=combination.txt
#1551-li
```

* [This article](https://akimbocore.com/article/custom-rules-for-john-the-ripper/) is a great reference for understanding and implementing the custom rules for JtR.

* Challenge:

```shell
#hash1 - b16f211a8ad7f97778e5006c7cecdf31
#from advice, we get to know that we have to use english male name
#and border mutation

haiti b16f211a8ad7f97778e5006c7cecdf31
#shows that it is a md5 hash

#using wordlistctl, we can fetch the required wordlist
python3 wordlistctl.py search male

#specifying search term
python3 wordlistctl.py search maleNames
#shows required wordlist

sudo python3 wordlistctl.py fetch malenames-usa-top1000 -d
#fetches required wordlist and stores in /usr/share/wordlists/usernames

#for custom rule, we have to edit conf file
vim ~/src/john/run/john-local.conf
#add rule for border mutation
#cAz"[0-9!@#$%^&+_-*()][0-9!@#$%^&+_-*()][0-9!@#$%^&+_-*()][0-9!@#$%^&+_-*()][0-9!@#$%^&+_-*()]"
#this repeats the pattern 5 times
#we have to get the number of iterations using trial and error

#now run JtR
~/src/john/run/john chall1.txt --format=raw-md5 --wordlist=/usr/share/wordlists/usernames/malenames-usa-top1000.txt --rules=Chall1
#Zachariah1234*
```

```shell
#hash2 - 7463fcb720de92803d179e7f83070f97
#advice - english female name, border mutation, similar to hash1

haiti 7463fcb720de92803d179e7f83070f97
#md5 hash

#we have the femalenames-usa-top1000.txt wordlist already
#now we have to edit conf file and add custom rule for border mutation
#cAz"[0-9!@#$%^&+_-*()][0-9!@#$%^&+_-*()][0-9!@#$%^&+_-*()]"

#run JtR
~/src/john/run/john chall2.txt --format=raw-md5 --wordlist=/usr/share/wordlists/usernames/femalenames-usa-top1000.txt --rules=Chall2
#Angelita35!
```

```shell
#hash3 - f4476669333651be5b37ec6d81ef526f
#advice - mexican town names, female, freak/1337 mutation (uses symbols)

haiti f4476669333651be5b37ec6d81ef526f
#md5 hash

#search for town wordlists
python3 wordlistctl.py search city
#this gives city-state-country as a wordlist

sudo python3 wordlistctl.py fetch city-state-country -d
#fetches required wordlist, stored in /usr/share/wordlists/misc/

#this contains all countries and cities, so we need to select only Mexican towns
cat /usr/share/wordlists/misc/city-state-country.txt | dos2unix | rg 'Mexico$' | cut -f 1 -d ',' | uniq > mexico.txt

#before using mentalist, we have to remove spaces from the wordlist using custom Python script

#after that, for freak mutation and lowercase all, we have to use mentalist
sudo mentalist
#we can add the custom rules for 1337 mutation and save the process

#run JtR or hashcat using the custom wordlist
#for me, JtR did not work so I ended up using hashcat
hashcat -m 0 -a 0 -r /usr/share/hashcat/rules/Incisive-leetspeak.rule chall3.txt /usr/share/wordlists/misc/mexico_custom.txt
#here, -m 0 is for md5, -a 0 is for dictionary attack
#the leetspeak rule is for 1337 mutation
#Tl@xc@l@ncing0
```

```shell
#hash4 - a3a321e1c246c773177363200a6c0466a5030afc
#advice - own name(David Guettapan), case mutation, uppercase/lowercase variations, loves Eminem
haiti a3a321e1c246c773177363200a6c0466a5030afc
#sha1

#for case mutation, we can use one of the inbuilt rules called NT
~/src/john/run/john chall4.txt --format=raw-sha1 --wordlist=davidguettapan.txt --rules=NT
#DavIDgUEtTApAn
```

```shell
#hash5 - d5e085772469d544a447bc8250890949
#advice - loves Adele (songs, lyrics), long password, reversed order
haiti d5e085772469d544a447bc8250890949
#md5

#we can use a lyric-based wordlist generator called lyricpass (https://github.com/initstring/lyricpass)
sudo python3 lyricpass.py -a "Adele"
#this generates two files, one containing the raw lyrics and one with the passphrases
#we can use both files

#we can add custom rule in john-local.conf, to lowercase and reverse lyrics and remove punctuation
#r - for reversing
~/src/john/run/john chall5.txt --format=raw-md5 --wordlist=/usr/share/wordlists/raw-lyrics-2022-04-12-12.18.09 --rules=Chall5
#uoy ot miws ot em rof peed oot ro ediw oot si revir oN
```

```shell
#hash6 - 377081d69d23759c5946a95d1b757adc
#advice - phone number, from Sint Maarten
haiti 377081d69d23759c5946a95d1b757adc
#md5

#we can use pnwgen (https://github.com/toxydose/pnwgen) for phone number wordlists
#for Sint Maarten, prefix is +721, and phone number is of 7 digits
sudo python3 pnwgen.py +1721 '' 7

~/src/john/run/john chall6.txt --format=raw-md5 --wordlist=/usr/share/wordlists/pnwgen/wordlist.txt
#+17215440375
```

```shell
#hash7 - ba6e8f9cd4140ac8b8d2bf96c9acd2fb58c0827d556b78e331d1113fcbfe425ca9299fe917f6015978f7e1644382d1ea45fd581aed6298acde2fa01e7d83cdbd
#advice - refer last competition project of NIST, keccak

#haiti shows that it is either SHA-512, SHA3-512 or Keccak-512
#as there is no mutation here, we can directly try to crack it with these three formats
~/src/john/run/john chall7.txt --format=raw-sha3 --wordlist=/usr/share/wordlists/rockyou.txt #SHA3-512
#!@#redrose!@#
```

```shell
#hash8 - 9f7376709d3fe09b389a27876834a13c6f275ed9a806d4c8df78f0ce1aad8fb343316133e810096e0999eaf1d2bca37c336e1b7726b213e001333d636e896617
#advice - choose word from sponsors list, then repeat 2,3,4 or 5 times; use a hardcore cryptographic hash function, used in GNU core utilities and by WireGuard

#haiti shows that the hash is either SHA-512, SHA3-512, Keccak-512, or BLAKE2-512
#as we have to choose any random word from the given website, we can use CeWL
./cewl.rb -d 2 -w $(pwd)/wordlist_website.txt http://10.10.16.251/rtfm.re/en/sponsors/index.html

#to duplicate the word, we have to use rule 'dd'
~/src/john/run/john chall8.txt --format=raw-keccak --wordlist=wordlist_website.txt --rules=Chall8
#hackinghackinghackinghacking
```

```shell
#hash9 - $6$kI6VJ0a31.SNRsLR$Wk30X8w8iEC2FpasTo0Z5U7wke0TpfbDtSwayrNebqKjYWC4gjKoNEJxO/DkP.YFTLVFirQ5PEh4glQIHuKfA/
#advice - strong hash+salt used
#online hash identifier suggests that it could be sha512crypt $6$

~/src/john/run/john chall9.txt --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt
#kakashi1
```
