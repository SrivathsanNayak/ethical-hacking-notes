# Crack The Hash - Easy

## Level 1

* We can use tools like hash-id.py to identify the hashes, then we can use tools like Hashcat, John The Ripper or even online ones to crack the hashes.

* If password length is known, filter out the passwords matching that criteria to a separate file.

* For example, command for filtering 4-letter passwords: ```awk 'length($0) == 4' /usr/share/wordlists/rockyou.txt > rockyou_length4.txt```

* 48bb6e862e54f2a795ffc4e541caed4d - easy

```shell
john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 l1h1.txt
```

* CBFDAC6008F9CAB4083784CBD1874F76618D2A97 - password123

```shell
john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha1 l1h2.txt
```

* 1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032 - letmein

```shell
john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha256 l1h3.txt
```

* $2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom - bleh

```shell
hashcat -m 3200 -a 0 l1h4.txt /usr/share/wordlists/rockyou.txt
```

* 279412f945939ba78ce0758d3fd83daa - Eternity22

---

## Level 2

* F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85 - paule

```shell
hashcat -m 1400 -a 0 l2h1.txt rockyou_length5.txt
```

* 1DFECA0C002AE40B8619ECF94819CC1B - n63umy8lkf4i

```shell
hashcat -m 1000 -a 0 l2h2.txt rockyou_length12.txt
```

```markdown
Hash: $6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.
Salt: aReallyHardSalt
```

```shell
hashcat -m 1800 -a 0 l2h3.txt rockyou_length6.txt

Password: waka99
```

* We could use the salt values given to us if required. For the next hash, salt was used.

```markdown
Hash: e5d8870e5bdd26602cab8dbe07a942c8669e56d6
Salt: tryhackme
```

```shell
hashcat -m 160 -a 0 l2h4.txt rockyou_length12.txt

Password: 481616481616
```
