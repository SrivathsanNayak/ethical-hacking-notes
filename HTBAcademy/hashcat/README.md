# Cracking Passwords with Hashcat

1. [Hashes](#hashes)
1. [Hashcat Attack Types](#hashcat-attack-types)
1. [Wordlists](#wordlists)
1. [Cracking](#cracking)

## Hashes

* Hashing - converting text to unique string using a hash function; one-way process.

* Only way to attack hashing is to use a list containing possible passwords (hashed and compared to original hash).

* Common hashing algorithms on Unix systems include SHA-512, Blowfish, BCrypt & Argon2.

* Salting - adding a random piece of data to plaintext password before hashing it; increases computation time but does not prevent brute-force.

* Encryption - converting data into a different format; unlike hashing, it is reversible by decryption. Encryption can be symmetric or asymmetric.

* Identifying hashes:

  * Most hashing algos produce hashes of constant length
  * Hashes can be stored in certain formats like ```hash:salt``` or ```$id$salt$hash```

* We can use command-line tools like ```hashid``` (use with ```-m``` flag to determine corresponding ```hashcat``` hash mode) or refer [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) to detect hashes.

* ```Hashcat``` - open-source password cracking tool.

## Hashcat Attack Types

* Dictionary attack:

  * read from a wordlist to crack the hashes; useful for weak passwords, and faster than other attack types:

    ```shell
    hashcat -a 0 -m 1400 sha256_hash_example /usr/share/wordlists/rockyou.txt
    ```

* Combination attack:

  * takes in 2 wordlists as input & combines them (joins words):

    ```shell
    hashcat -a 1 --stdout file1 file2
    # --stdout to debug and see how the tool is combining the words

    hashcat -a 1 -m 0 md5_hash_combo wordlist1 wordlist2
    ```

* Mask attack:

  * generate words matching a specific pattern; useful when password length/format is known

  * mask can be created using [static chars, range or placeholders](https://hashcat.net/wiki/doku.php?id=mask_attack):

    ```shell
    hashcat -a 3 -m 0 50a742905949102c961929823a2e8ca0 -1 02 'HASHCAT?l?l?l?l?l20?1?d'
    # -1 02 is to denote a placeholder for the '?1?' part in mask
    # so we can have either 0 or 2 at that position
    # ?l denotes lowercase alphabets, ?d denotes digits
    ```

* Hybrid mode:

  * variation of combination attack; multiple modes can be used:

    ```shell
    # for example, suppose we have hashed "football1$"
    # we need to use wordlist and append a string to it
    hashcat -a 6 -m 0 hybrid_hash rockyou.txt '?d?s'

    # to prepend mask to words from wordlist, we use attack mode 7
    # for example, for "2015football"
    hashcat -a 7 -m 0 hybrid_hash_prefix -1 01 '20?1?d' rockyou.txt
    ```

## Wordlists

* Crunch:

  * to create wordlists based on parameters like words of certain lengths or patterns:

    ```shell
    crunch 4 8 -o wordlist
    # create wordlist with length 4-8 chars using default charset

    crunch 17 17 -t ILFREIGHT201%@@@@ -o wordlist
    # create wordlist using pattern "ILFREIGHTYYYYXXXX" where "XXXX" contains letters and "YYYY" is year

    crunch 12 12 -t 10031998@@@@ -d 1 -o wordlist
    # specified repetition using -d
    ```

* CUPP:

  * creates highly customized wordlists based on info gathered from OSINT:

    ```shell
    python3 cupp.py -i
    # enter all known info about target
    # generates dictionary wordlist customized for victim
    ```

* Kwprocessor:

  * creates wordlists with keyboard walks or patterns:

    ```shell
    # after manually installing tool
    kwp -s 1 basechars/full.base keymaps/en-us.keymap routes/2-to-10-max-3-direction-changes.route
    # generates words with chars reachable while holding Shift '-s', using full base, standard keymap and 3 direction changes route
    ```

* Princeprocessor:

  * generates passwords using PRINCE algorithm (Probability Infinite Chained Elements):

    ```shell
    # after manually installing tool
    ./pp64.bin --keyspace < words
    # find number of combinations

    ./pp64.bin -o wordlist.txt < words
    # create wordlist, by default words limited to 16 in length

    ./pp64.bin --pw-min=10 --pw-max=25 -o wordlist.txt < words
    # output words between 10-25 in length

    ./pp64.bin --elem-cnt-min=3 -o wordlist.txt < words
    # output words with 3 elements minimum
    ```

* CeWL:

  * create custom wordlists; spiders & scrapes website to get words:

    ```shell
    cewl -d 5 -m 8 -e http://inlanefreight.com/blog -w wordlist.txt
    # scrapes upto 5 pages in depth
    # includes words greater than 8 only
    # -e to extract emails from websites
    ```

* ```hashcat``` stores previously cracked passwords in ```hashcat.potfile``` file.

* [hashcat-utils](https://github.com/hashcat/hashcat-utils) contains more tools for advanced password cracking.

* Rule-based attacks:

  * rules are used for operations on input wordlist like prefixing, suffixing, toggling case, cutting and reversing

  * rules can be created using [functions](https://hashcat.net/wiki/doku.php?id=rule_based_attack#implemented_compatible_functions), which take word as input and output a modified version

  * [reject rules](https://hashcat.net/wiki/doku.php?id=rule_based_attack#rules_used_to_reject_plains) can be used to prevent using words that do not match target specifications; to be used ```-j``` or ```-k``` flag with ```hashcat```

    ```shell
    echo 'c so0 si1 se3 ss5 sa@ $2 $0 $1 $9' > rule.txt
    # create a rule file
    # c - capitalize first letter
    # so0 - substitute o with 0 for l33tspeak
    # $2 - append 2 at end of string
    # so we are appending 2019 at end of string
    ```

    ```shell
    echo 'password_ilfreight' > test.txt
    # store password in a file

    hashcat -r rule.txt test.txt --stdout
    # debug rules
    # shows how the password will look like when rule applied
    ```

    ```shell
    # for SHA1 hash of password 'St@r5h1p2019'
    hashcat -a 0 -m 100 sha1_hash /usr/share/wordlists/rockyou.txt -r rule.txt
    # we can use multiple rules with repeated -r flag

    ls -la /usr/share/hashcat/rules
    # list rules

    hashcat -a 0 -m 100 -g 1000 hashfile /usr/share/wordlists/rockyou.txt
    # -g 1000 - generates 1000 random rules and applies to each word
    # no certainty to success as generated rules are random
    ```
  
  * Other popular rules include [nsa-rules](https://github.com/NSAKEY/nsa-rules), [Hob0Rules](https://github.com/praetorian-inc/Hob0Rules) and [corporate.rule](https://github.com/sparcflow/HackLikeALegend/blob/master/old/chap3/corporate.rule)

## Cracking

* Cracking common hashes:

  * Database dumps:

    ```shell
    # create sha1 hash list from list of words
    for i in $(cat words); do echo -n $i | sha1sum | tr -d ' -';done

    hashcat -m 100 sha1hashes /usr/share/wordlists/rockyou.txt
    ```
  
  * Linux shadow file:

    ```shell
    # sha512crypt hashes found in /etc/shadow on Linux
    # the complete hash contains 9 fields separated by colons - first two being username and encrypted hash

    hashcat -m 1800 only_sha512crypt_hash /usr/share/wordlists/rockyou.txt
    ```
  
  * AD (Active Directory) password hash types:

    ```shell
    # fetch NTLM hash for user with RDP access to server
    # cannot be used for pass-the-hash attack

    hashcat -a 0 -m 1000 ntlm_hash /usr/share/wordlists/rockyou.txt

    # using inbuilt rules
    hashcat -a 0 -m 1000 ntlm /usr/share/wordlists/rockyou.txt -r /usr/share/doc/hashcat/rules/T0XlC-insert_space_and_special_0_F.rule
    ```

    ```shell
    # for netNTLMv2 hash
    # obtained from MITM attacks done by Responder

    hashcat -a 0 -m 5600 ntlmv2_hash /usr/share/wordlists/rockyou.txt
    ```
  
  * NTDS dumps:

    ```shell
    # assuming we already have hashes in NTDS file
    # clean it up to get only the hashes

    cat DC01.inlanefreight.local.ntds | cut -d : -f 4 > ntds_hashes.txt

    hashcat -a 0 -m 1000 ntds_hashes.txt /usr/share/wordlists/kaonashi.txt

    # in case of too many hashes, we can extract it all to a file

    # if username is also required
    hashcat -a 0 -m 1000 DC01.inlanefreight.local.ntds --username /usr/share/wordlists/kaonashi.txt
    ```

* Miscellaneous cracking:

  * Cracking password-protected Microsoft Office documents:

    ```shell
    # hashcat supports hash modes for MS Office 2007, 2010, 2013, and older hash modes

    # extract hash from password-protected document
    office2john word_protected.docx
    # gives MS Office 2013 hash
    # slower hash to crack

    hashcat -m 9600 office_hash /usr/share/wordlists/rockyou.txt
    ```
  
  * Cracking password-protected zip files:

    ```shell
    zip2john secret.zip > ziphash.txt

    # for PKZIP (Compressed)
    hashcat -a 0 -m 17200 ziphash.txt /usr/share/wordlists/rockyou.txt
    ```

    ```shell
    zip2john misc_hashes.zip
    # gives error "is not encrypted, or stored with non-handled compression type"

    zipinfo -v misc_hashes.zip
    # view info about zip file
    # extract without password as it is not protected

    unzip misc_hashes.zip
    # we get a .7z file

    zipinfo -v hashcat.7z
    # "End-of-central-directory signature not found." error

    # zip2john will not work here, so we have to use 7z2john

    7z2john hashcat.7z > 7zhash.txt
    
    # we can use john here as well
    john --wordlist=/usr/share/wordlists/rockyou.txt 7zhash.txt --format=7z
    ```
  
  * Cracking password-protected KeePass files:

    ```shell
    keepass2john Master.kdbx > keepasshash.txt

    # for KeePass 2 AES without keyfile
    hashcat -a 0 -m 13400 keepasshash.txt /usr/share/wordlists/rockyou.txt
    ```
  
  * Cracking password-protected PDFs:

    ```shell
    pdf2john protected.pdf > pdfhash.txt

    # for Acrobat 5-8
    hashcat -a 0 -m 10500 pdfhash.txt /usr/share/wordlists/rockyou.txt
    ```

* Cracking wireless handshakes:

  * Cracking MIC:

    ```shell
    # install hashcat-utils for cap2hccapx tool

    # capture 4-way handshake using airodump-ng
    # we get a .cap file that can be converted to hash

    hcxpcapngtool -o mic-01.22000 corp_question1-01.cap

    hashcat -a 0 -m 22000 mic-01.22000 /usr/share/wordlists/rockyou.txt
    ```
  
  * Cracking PMKID:

    ```shell
    # extract PMKID hash from .cap using hcxpcapngtool from hcxtools

    hcxpcapngtool -o mic-02.22000 cracking_pmkid_question2.cap

    hashcat -a 0 -m 22000 mic-02.22000 /usr/share/wordlists/rockyou.txt
    ```
